use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Component, Path},
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_COMPLETENESS_VERSION,
    CROSS_LANGUAGE_CONTRACT_PROPERTY, CROSS_LANGUAGE_CONTRACT_VERSION,
    CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, Condition, CrossLanguageAdapterDelta,
    CrossLanguageCanonicalIdentity, CrossLanguageCapabilityStatus, CrossLanguageCompletenessLedger,
    CrossLanguageFormat, CrossLanguageFormatCoverage, CrossLanguageMappingKind,
    CrossLanguageNodeKind, CrossLanguageProfileIdentity, CrossLanguageRelationKind, DependencySite,
    Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile, Properties,
    ResolutionStatus, build_cross_language_edge_id, build_cross_language_site_id,
    cross_language_node_id, cross_language_profile_id, stable_id_from_value,
    validate_cross_language_adapter_delta,
};
use prost::Message as _;
use prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    MethodDescriptorProto, ServiceDescriptorProto, field_descriptor_proto,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

pub const PROTOBUF_CAPABILITY: &str = "protobuf-contract-v1";
pub const PROTOBUF_DESCRIPTOR_SUFFIX: &str = ".depgraph-protobuf-descriptor.pb";
pub const MAX_PROTOBUF_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROTOBUF_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PROTOBUF_FILES: usize = 4_096;
pub const MAX_PROTOBUF_TOKENS: usize = 1_000_000;
pub const MAX_PROTOBUF_DEPTH: usize = 64;
pub const MAX_PROTOBUF_DESCRIPTOR_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PROTOBUF_DESCRIPTOR_FILES: usize = 4_096;

const EXTRACTOR: &str = "depgraph-protobuf-adapter";
const MAX_PARTICIPATING_PROFILES: usize = 64;
const MAX_BOUNDED_TEXT: usize = 4_096;
const MAX_REASONS: usize = 64;

/// Parses repository-local `.proto` files and explicitly named binary
/// `FileDescriptorSet` inputs without running protoc, plugins, project code, or
/// network clients.
pub fn scan_protobuf_repository(
    root: &Path,
    participating_profile_ids: &[String],
) -> Result<Option<CrossLanguageAdapterDelta>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("Protobuf scan root {} is unavailable", root.display()))?;
    if !canonical_root.is_dir() {
        bail!("Protobuf scan root must be a directory");
    }
    let mut participating_profile_ids = participating_profile_ids.to_vec();
    participating_profile_ids.sort();
    participating_profile_ids.dedup();
    if participating_profile_ids.is_empty()
        || participating_profile_ids.len() > MAX_PARTICIPATING_PROFILES
        || participating_profile_ids
            .iter()
            .any(|value| !bounded_text(value))
    {
        bail!("Protobuf participating profile IDs must be a bounded non-empty set");
    }

    let sources = inventory_proto_sources(&canonical_root)?;
    let admitted_sources = sources
        .iter()
        .filter_map(|record| {
            record
                .file
                .clone()
                .map(|file| (record.locator.clone(), file))
        })
        .collect::<BTreeMap<_, _>>();
    let descriptors = inventory_descriptor_sets(&canonical_root, &admitted_sources)?;
    if sources.is_empty() && descriptors.records.is_empty() {
        return Ok(None);
    }

    let input_digest = digest_value(&json!({
        "sources": sources.iter().map(SourceRecord::identity_value).collect::<Vec<_>>(),
        "descriptors": descriptors.identity_value(),
    }));
    let profile_identity = CrossLanguageProfileIdentity {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        contract_input_digest: input_digest,
        adapter_capability_versions: vec![PROTOBUF_CAPABILITY.to_owned()],
        participating_profile_ids,
    };
    let profile_id = cross_language_profile_id(&profile_identity);
    let mut builder =
        ProtobufGraphBuilder::new(profile_id.clone(), admitted_sources, descriptors.proofs);
    builder.build()?;
    for reason in sources
        .iter()
        .filter_map(|record| record.reason.as_deref())
        .chain(descriptors.reasons.iter().map(String::as_str))
    {
        builder.insert_reason(reason);
    }

    let skipped_count = sources
        .iter()
        .filter(|record| record.file.is_none())
        .count() as u64
        + descriptors.skipped_count;
    let status = if builder.unresolved_count > 0 || skipped_count > 0 || !builder.reasons.is_empty()
    {
        CrossLanguageCapabilityStatus::Incomplete
    } else {
        CrossLanguageCapabilityStatus::Complete
    };
    let ledger = CrossLanguageCompletenessLedger {
        schema_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        entries: vec![CrossLanguageFormatCoverage {
            format: CrossLanguageFormat::Protobuf,
            capability: PROTOBUF_CAPABILITY.to_owned(),
            status,
            input_count: sources.len() as u64 + descriptors.records.len() as u64,
            node_count: builder.cross_node_ids.len() as u64,
            site_count: builder.sites.len() as u64,
            edge_count: builder.edges.len() as u64,
            external_count: 0,
            unresolved_count: builder.unresolved_count,
            skipped_count,
            reasons: builder.reasons.iter().cloned().collect(),
        }],
    };
    let profile = Profile {
        id: profile_id,
        language: "cross-language".to_owned(),
        toolchain: None,
        command: None,
        target: None,
        features: Vec::new(),
        environment: BTreeMap::new(),
        source_revision: None,
        properties: BTreeMap::from([
            (
                CROSS_LANGUAGE_CONTRACT_PROPERTY.to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            (
                CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY.to_owned(),
                serde_json::to_value(profile_identity)?,
            ),
            (
                CROSS_LANGUAGE_COMPLETENESS_PROPERTY.to_owned(),
                serde_json::to_value(ledger)?,
            ),
        ]),
    };
    let delta = CrossLanguageAdapterDelta {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        profile,
        nodes: builder.nodes.into_values().collect(),
        sites: builder.sites.into_values().collect(),
        edges: builder.edges.into_values().collect(),
    };
    validate_cross_language_adapter_delta(&delta)
        .map_err(anyhow::Error::from)
        .context("Protobuf adapter produced an invalid common-contract closure")?;
    Ok(Some(delta))
}

#[derive(Clone, Debug)]
struct SourceRecord {
    locator: String,
    digest: String,
    file: Option<ProtoFile>,
    reason: Option<String>,
}

impl SourceRecord {
    fn identity_value(&self) -> Value {
        json!({
            "locator": self.locator,
            "digest": self.digest,
            "status": if self.file.is_some() { "admitted" } else { "skipped" },
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug)]
struct ProtoFile {
    digest: String,
    version: String,
    package: String,
    imports: Vec<ProtoImport>,
    messages: BTreeMap<String, ProtoMessage>,
    enums: BTreeSet<String>,
    services: BTreeMap<String, ProtoService>,
    line_columns: Vec<u32>,
}

#[derive(Clone, Debug)]
struct ProtoImport {
    path: String,
    kind: ImportKind,
    span: SourceSpan,
    ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportKind {
    Normal,
    Public,
    Weak,
}

impl ImportKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Public => "public",
            Self::Weak => "weak",
        }
    }
}

#[derive(Clone, Debug)]
struct ProtoMessage {
    coordinate: String,
    span: SourceSpan,
    descriptor_path: Vec<i32>,
    fields: Vec<ProtoField>,
}

#[derive(Clone, Debug)]
struct ProtoField {
    name: String,
    number: i32,
    label: FieldLabel,
    type_name: String,
    oneof: Option<String>,
    span: SourceSpan,
    descriptor_path: Vec<i32>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum FieldLabel {
    Normal,
    Optional,
    Required,
    Repeated,
}

#[derive(Clone, Debug)]
struct ProtoService {
    coordinate: String,
    methods: Vec<ProtoMethod>,
}

#[derive(Clone, Debug)]
struct ProtoMethod {
    name: String,
    coordinate: String,
    input_type: String,
    output_type: String,
    client_streaming: bool,
    server_streaming: bool,
    span: SourceSpan,
    descriptor_path: Vec<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceSpan {
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

fn inventory_proto_sources(root: &Path) -> Result<Vec<SourceRecord>> {
    let mut records = Vec::new();
    let mut total_bytes = 0_usize;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.depth() == 0
            || entry.path().extension().and_then(|value| value.to_str()) != Some("proto")
        {
            continue;
        }
        let Some(locator) = repository_locator(root, entry.path()) else {
            continue;
        };
        if records.len() >= MAX_PROTOBUF_FILES {
            records.push(skipped_source(
                &locator,
                "protobuf-file-count-limit-exceeded",
            ));
            continue;
        }
        if entry.file_type().is_symlink() {
            records.push(skipped_source(
                &locator,
                "protobuf-source-symlink-not-admitted",
            ));
            continue;
        }
        if !entry.file_type().is_file() {
            records.push(skipped_source(&locator, "protobuf-source-is-not-a-file"));
            continue;
        }
        let len = match entry.metadata() {
            Ok(metadata) => metadata.len() as usize,
            Err(_) => {
                records.push(skipped_source(
                    &locator,
                    "protobuf-source-metadata-unavailable",
                ));
                continue;
            }
        };
        if len > MAX_PROTOBUF_FILE_BYTES {
            records.push(skipped_source(
                &locator,
                "protobuf-source-byte-limit-exceeded",
            ));
            continue;
        }
        if total_bytes.saturating_add(len) > MAX_PROTOBUF_TOTAL_BYTES {
            records.push(skipped_source(
                &locator,
                "protobuf-inventory-byte-limit-exceeded",
            ));
            continue;
        }
        total_bytes += len;
        let bytes = match read_bounded(entry.path(), MAX_PROTOBUF_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => {
                records.push(skipped_source(&locator, "protobuf-source-read-failed"));
                continue;
            }
        };
        let digest = sha256_prefixed(&bytes);
        match parse_proto_file(&locator, &digest, &bytes) {
            Ok(file) => records.push(SourceRecord {
                locator,
                digest,
                file: Some(file),
                reason: None,
            }),
            Err(reason) => records.push(SourceRecord {
                locator,
                digest,
                file: None,
                reason: Some(reason),
            }),
        }
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));
    Ok(records)
}

fn skipped_source(locator: &str, reason: &str) -> SourceRecord {
    SourceRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        file: None,
        reason: Some(reason.to_owned()),
    }
}

fn parse_proto_file(
    _locator: &str,
    digest: &str,
    bytes: &[u8],
) -> std::result::Result<ProtoFile, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "protobuf-source-is-not-utf8".to_owned())?;
    let tokens = tokenize_proto(source)?;
    let line_columns = source
        .split('\n')
        .map(|line| line.trim_end_matches('\r').chars().count() as u32 + 1)
        .collect::<Vec<_>>();
    ProtoParser::new(digest, tokens, line_columns).parse()
}

#[derive(Clone, Debug)]
struct Token {
    text: String,
    kind: TokenKind,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier,
    String,
    Number,
    Symbol,
}

fn tokenize_proto(source: &str) -> std::result::Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    let mut line = 1_u32;
    let mut column = 1_u32;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            advance(byte, &mut line, &mut column);
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                advance(bytes[index], &mut line, &mut column);
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index;
            advance(bytes[index], &mut line, &mut column);
            advance(bytes[index + 1], &mut line, &mut column);
            index += 2;
            let mut closed = false;
            while index + 1 < bytes.len() {
                if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    advance(bytes[index], &mut line, &mut column);
                    advance(bytes[index + 1], &mut line, &mut column);
                    index += 2;
                    closed = true;
                    break;
                }
                advance(bytes[index], &mut line, &mut column);
                index += 1;
                if index.saturating_sub(start) > MAX_PROTOBUF_FILE_BYTES {
                    return Err("protobuf-comment-byte-limit-exceeded".to_owned());
                }
            }
            if !closed {
                return Err("protobuf-unterminated-block-comment".to_owned());
            }
            continue;
        }
        if tokens.len() >= MAX_PROTOBUF_TOKENS {
            return Err("protobuf-token-count-limit-exceeded".to_owned());
        }
        let start_line = line;
        let start_column = column;
        if byte.is_ascii_alphabetic() || byte == b'_' {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                advance(bytes[index], &mut line, &mut column);
                index += 1;
            }
            tokens.push(Token {
                text: source[start..index].to_owned(),
                kind: TokenKind::Identifier,
                span: SourceSpan {
                    start_line,
                    start_column,
                    end_line: line,
                    end_column: column,
                },
            });
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'.' | b'+' | b'-'))
            {
                advance(bytes[index], &mut line, &mut column);
                index += 1;
            }
            tokens.push(Token {
                text: source[start..index].to_owned(),
                kind: TokenKind::Number,
                span: SourceSpan {
                    start_line,
                    start_column,
                    end_line: line,
                    end_column: column,
                },
            });
            continue;
        }
        if matches!(byte, b'"' | b'\'') {
            let quote = byte;
            advance(byte, &mut line, &mut column);
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < bytes.len() {
                let current = bytes[index];
                if current == quote {
                    advance(current, &mut line, &mut column);
                    index += 1;
                    closed = true;
                    break;
                }
                if current == b'\n' || current == b'\r' {
                    return Err("protobuf-string-contains-newline".to_owned());
                }
                if current == b'\\' {
                    let Some(escaped) = bytes.get(index + 1).copied() else {
                        return Err("protobuf-unterminated-string".to_owned());
                    };
                    let decoded = match escaped {
                        b'\\' => '\\',
                        b'"' => '"',
                        b'\'' => '\'',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        _ => return Err("protobuf-unsupported-string-escape".to_owned()),
                    };
                    value.push(decoded);
                    advance(current, &mut line, &mut column);
                    advance(escaped, &mut line, &mut column);
                    index += 2;
                    continue;
                }
                if !current.is_ascii() {
                    return Err("protobuf-non-ascii-string-not-admitted".to_owned());
                }
                value.push(char::from(current));
                advance(current, &mut line, &mut column);
                index += 1;
            }
            if !closed {
                return Err("protobuf-unterminated-string".to_owned());
            }
            tokens.push(Token {
                text: value,
                kind: TokenKind::String,
                span: SourceSpan {
                    start_line,
                    start_column,
                    end_line: line,
                    end_column: column,
                },
            });
            continue;
        }
        if !byte.is_ascii() {
            return Err("protobuf-non-ascii-token-not-admitted".to_owned());
        }
        advance(byte, &mut line, &mut column);
        index += 1;
        tokens.push(Token {
            text: char::from(byte).to_string(),
            kind: TokenKind::Symbol,
            span: SourceSpan {
                start_line,
                start_column,
                end_line: line,
                end_column: column,
            },
        });
    }
    Ok(tokens)
}

fn advance(byte: u8, line: &mut u32, column: &mut u32) {
    if byte == b'\n' {
        *line += 1;
        *column = 1;
    } else {
        *column += 1;
    }
}

struct ProtoParser {
    digest: String,
    tokens: Vec<Token>,
    cursor: usize,
    version: Option<String>,
    package: String,
    imports: Vec<ProtoImport>,
    messages: BTreeMap<String, ProtoMessage>,
    enums: BTreeSet<String>,
    services: BTreeMap<String, ProtoService>,
    line_columns: Vec<u32>,
}

impl ProtoParser {
    fn new(digest: &str, tokens: Vec<Token>, line_columns: Vec<u32>) -> Self {
        Self {
            digest: digest.to_owned(),
            tokens,
            cursor: 0,
            version: None,
            package: String::new(),
            imports: Vec::new(),
            messages: BTreeMap::new(),
            enums: BTreeSet::new(),
            services: BTreeMap::new(),
            line_columns,
        }
    }

    fn parse(mut self) -> std::result::Result<ProtoFile, String> {
        while self.cursor < self.tokens.len() {
            match self.peek_text() {
                Some("syntax") => self.parse_version("syntax")?,
                Some("edition") => self.parse_version("edition")?,
                Some("package") => self.parse_package()?,
                Some("import") => self.parse_import()?,
                Some("message") => {
                    let index = self
                        .messages
                        .values()
                        .filter(|message| message.descriptor_path.len() == 2)
                        .count();
                    self.parse_message("", vec![4, to_i32(index)?], 0)?;
                }
                Some("enum") => {
                    let index = self
                        .enums
                        .iter()
                        .filter(|name| {
                            self.package.is_empty()
                                || name.strip_prefix(&self.package).is_some_and(|rest| {
                                    rest.starts_with('.') && !rest[1..].contains('.')
                                })
                        })
                        .count();
                    self.parse_enum("", vec![5, to_i32(index)?], 0)?;
                }
                Some("service") => {
                    let index = self.services.len();
                    self.parse_service(vec![6, to_i32(index)?])?;
                }
                Some(";") => {
                    self.cursor += 1;
                }
                _ => self.skip_statement_or_block()?,
            }
        }
        let version = self
            .version
            .ok_or_else(|| "protobuf-syntax-or-edition-is-missing".to_owned())?;
        Ok(ProtoFile {
            digest: self.digest,
            version,
            package: self.package,
            imports: self.imports,
            messages: self.messages,
            enums: self.enums,
            services: self.services,
            line_columns: self.line_columns,
        })
    }

    fn parse_version(&mut self, keyword: &str) -> std::result::Result<(), String> {
        self.expect(keyword)?;
        self.expect("=")?;
        let token = self
            .bump()
            .ok_or_else(|| "protobuf-version-is-missing".to_owned())?;
        if token.kind != TokenKind::String {
            return Err("protobuf-version-is-not-a-string".to_owned());
        }
        let version = match (keyword, token.text.as_str()) {
            ("syntax", "proto2" | "proto3") => token.text,
            ("edition", value)
                if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                format!("edition:{value}")
            }
            _ => return Err("unsupported-protobuf-version".to_owned()),
        };
        if self.version.replace(version).is_some() {
            return Err("duplicate-protobuf-version".to_owned());
        }
        self.expect(";")?;
        Ok(())
    }

    fn parse_package(&mut self) -> std::result::Result<(), String> {
        self.expect("package")?;
        let package = self.parse_qualified_name(false)?;
        self.expect(";")?;
        if !self.package.is_empty() {
            return Err("duplicate-protobuf-package".to_owned());
        }
        self.package = package;
        Ok(())
    }

    fn parse_import(&mut self) -> std::result::Result<(), String> {
        let start = self.expect("import")?.span;
        let kind = match self.peek_text() {
            Some("public") => {
                self.cursor += 1;
                ImportKind::Public
            }
            Some("weak") => {
                self.cursor += 1;
                ImportKind::Weak
            }
            _ => ImportKind::Normal,
        };
        let path = self
            .bump()
            .filter(|token| token.kind == TokenKind::String)
            .ok_or_else(|| "protobuf-import-path-is-missing".to_owned())?;
        let end = self.expect(";")?.span;
        let ordinal = self.imports.len();
        self.imports.push(ProtoImport {
            path: path.text,
            kind,
            span: merge_span(start, end),
            ordinal,
        });
        Ok(())
    }

    fn parse_message(
        &mut self,
        parent: &str,
        descriptor_path: Vec<i32>,
        depth: usize,
    ) -> std::result::Result<(), String> {
        if depth >= MAX_PROTOBUF_DEPTH {
            return Err("protobuf-nesting-depth-limit-exceeded".to_owned());
        }
        let start = self.expect("message")?.span;
        let name = self.expect_identifier()?.text;
        let coordinate = qualify(&self.package, parent, &name);
        self.expect("{")?;
        let mut fields = Vec::new();
        let mut nested_message_index = 0_usize;
        let mut nested_enum_index = 0_usize;
        while self.peek_text() != Some("}") {
            if self.cursor >= self.tokens.len() {
                return Err("protobuf-message-is-unterminated".to_owned());
            }
            match self.peek_text() {
                Some("message") => {
                    let mut path = descriptor_path.clone();
                    path.extend([3, to_i32(nested_message_index)?]);
                    nested_message_index += 1;
                    self.parse_message(&coordinate, path, depth + 1)?;
                }
                Some("enum") => {
                    let mut path = descriptor_path.clone();
                    path.extend([4, to_i32(nested_enum_index)?]);
                    nested_enum_index += 1;
                    self.parse_enum(&coordinate, path, depth + 1)?;
                }
                Some("oneof") => self.parse_oneof(&coordinate, &descriptor_path, &mut fields)?,
                Some("option" | "reserved" | "extensions" | "extend" | "group") => {
                    self.skip_statement_or_block()?
                }
                Some(";") => self.cursor += 1,
                _ => {
                    let checkpoint = self.cursor;
                    match self.parse_field(&coordinate, &descriptor_path, None, fields.len()) {
                        Ok(field) => fields.push(field),
                        Err(_) => {
                            self.cursor = checkpoint;
                            self.skip_statement_or_block()?;
                        }
                    }
                }
            }
        }
        let end = self.expect("}")?.span;
        self.consume(";");
        let message = ProtoMessage {
            coordinate: coordinate.clone(),
            span: merge_span(start, end),
            descriptor_path,
            fields,
        };
        if self.messages.insert(coordinate, message).is_some() {
            return Err("duplicate-protobuf-message".to_owned());
        }
        Ok(())
    }

    fn parse_oneof(
        &mut self,
        scope: &str,
        message_path: &[i32],
        fields: &mut Vec<ProtoField>,
    ) -> std::result::Result<(), String> {
        self.expect("oneof")?;
        let name = self.expect_identifier()?.text;
        self.expect("{")?;
        while self.peek_text() != Some("}") {
            if self.cursor >= self.tokens.len() {
                return Err("protobuf-oneof-is-unterminated".to_owned());
            }
            if matches!(self.peek_text(), Some("option" | ";")) {
                self.skip_statement_or_block()?;
                continue;
            }
            let checkpoint = self.cursor;
            match self.parse_field(scope, message_path, Some(name.clone()), fields.len()) {
                Ok(field) => fields.push(field),
                Err(_) => {
                    self.cursor = checkpoint;
                    self.skip_statement_or_block()?;
                }
            }
        }
        self.expect("}")?;
        self.consume(";");
        Ok(())
    }

    fn parse_field(
        &mut self,
        _scope: &str,
        message_path: &[i32],
        oneof: Option<String>,
        field_index: usize,
    ) -> std::result::Result<ProtoField, String> {
        let start = self
            .tokens
            .get(self.cursor)
            .map(|token| token.span)
            .ok_or_else(|| "protobuf-field-is-missing".to_owned())?;
        let label = match self.peek_text() {
            Some("optional") => {
                self.cursor += 1;
                FieldLabel::Optional
            }
            Some("required") => {
                self.cursor += 1;
                FieldLabel::Required
            }
            Some("repeated") => {
                self.cursor += 1;
                FieldLabel::Repeated
            }
            _ => FieldLabel::Normal,
        };
        let type_name = if self.consume("map") {
            self.expect("<")?;
            let key = self.parse_qualified_name(true)?;
            self.expect(",")?;
            let value = self.parse_qualified_name(true)?;
            self.expect(">")?;
            format!("map<{key},{value}>")
        } else {
            self.parse_qualified_name(true)?
        };
        let name = self.expect_identifier()?.text;
        self.expect("=")?;
        let number = self
            .bump()
            .filter(|token| token.kind == TokenKind::Number)
            .ok_or_else(|| "protobuf-field-number-is-missing".to_owned())?;
        let number = number
            .text
            .parse::<i32>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| "protobuf-field-number-is-invalid".to_owned())?;
        let end = self.skip_to_semicolon()?;
        let mut descriptor_path = message_path.to_vec();
        descriptor_path.extend([2, to_i32(field_index)?]);
        Ok(ProtoField {
            name,
            number,
            label,
            type_name,
            oneof,
            span: merge_span(start, end),
            descriptor_path,
        })
    }

    fn parse_enum(
        &mut self,
        parent: &str,
        _descriptor_path: Vec<i32>,
        depth: usize,
    ) -> std::result::Result<(), String> {
        if depth >= MAX_PROTOBUF_DEPTH {
            return Err("protobuf-nesting-depth-limit-exceeded".to_owned());
        }
        self.expect("enum")?;
        let name = self.expect_identifier()?.text;
        let coordinate = qualify(&self.package, parent, &name);
        self.expect("{")?;
        self.skip_balanced_body()?;
        self.consume(";");
        if !self.enums.insert(coordinate) {
            return Err("duplicate-protobuf-enum".to_owned());
        }
        Ok(())
    }

    fn parse_service(&mut self, descriptor_path: Vec<i32>) -> std::result::Result<(), String> {
        self.expect("service")?;
        let name = self.expect_identifier()?.text;
        let coordinate = qualify(&self.package, "", &name);
        self.expect("{")?;
        let mut methods = Vec::new();
        while self.peek_text() != Some("}") {
            if self.cursor >= self.tokens.len() {
                return Err("protobuf-service-is-unterminated".to_owned());
            }
            if self.peek_text() == Some("rpc") {
                methods.push(self.parse_rpc(&coordinate, &descriptor_path, methods.len())?);
            } else {
                self.skip_statement_or_block()?;
            }
        }
        self.expect("}")?;
        self.consume(";");
        let service = ProtoService {
            coordinate: coordinate.clone(),
            methods,
        };
        if self.services.insert(coordinate, service).is_some() {
            return Err("duplicate-protobuf-service".to_owned());
        }
        Ok(())
    }

    fn parse_rpc(
        &mut self,
        service: &str,
        service_path: &[i32],
        method_index: usize,
    ) -> std::result::Result<ProtoMethod, String> {
        let start = self.expect("rpc")?.span;
        let name = self.expect_identifier()?.text;
        self.expect("(")?;
        let client_streaming = self.consume("stream");
        let input_type = self.parse_qualified_name(true)?;
        self.expect(")")?;
        self.expect("returns")?;
        self.expect("(")?;
        let server_streaming = self.consume("stream");
        let output_type = self.parse_qualified_name(true)?;
        self.expect(")")?;
        let end = if self.consume("{") {
            self.skip_balanced_body()?
        } else {
            self.expect(";")?.span
        };
        let mut descriptor_path = service_path.to_vec();
        descriptor_path.extend([2, to_i32(method_index)?]);
        Ok(ProtoMethod {
            name: name.clone(),
            coordinate: format!("{service}/{name}"),
            input_type,
            output_type,
            client_streaming,
            server_streaming,
            span: merge_span(start, end),
            descriptor_path,
        })
    }

    fn parse_qualified_name(
        &mut self,
        allow_leading_dot: bool,
    ) -> std::result::Result<String, String> {
        let mut value = String::new();
        if allow_leading_dot && self.consume(".") {
            value.push('.');
        }
        value.push_str(&self.expect_identifier()?.text);
        while self.consume(".") {
            value.push('.');
            value.push_str(&self.expect_identifier()?.text);
        }
        if !bounded_text(&value) {
            return Err("protobuf-qualified-name-is-unbounded".to_owned());
        }
        Ok(value)
    }

    fn skip_statement_or_block(&mut self) -> std::result::Result<(), String> {
        if self.cursor >= self.tokens.len() {
            return Ok(());
        }
        self.cursor += 1;
        let mut delimiters = Vec::<&str>::new();
        while self.cursor < self.tokens.len() {
            let text = self.tokens[self.cursor].text.as_str();
            match text {
                "{" => delimiters.push("}"),
                "[" => delimiters.push("]"),
                "(" => delimiters.push(")"),
                "<" => delimiters.push(">"),
                "}" | "]" | ")" | ">" if delimiters.last().copied() == Some(text) => {
                    delimiters.pop();
                    self.cursor += 1;
                    if delimiters.is_empty() && text == "}" {
                        self.consume(";");
                        return Ok(());
                    }
                    continue;
                }
                ";" if delimiters.is_empty() => {
                    self.cursor += 1;
                    return Ok(());
                }
                "}" if delimiters.is_empty() => return Ok(()),
                _ => {}
            }
            if delimiters.len() > MAX_PROTOBUF_DEPTH {
                return Err("protobuf-skip-depth-limit-exceeded".to_owned());
            }
            self.cursor += 1;
        }
        if delimiters.is_empty() {
            Ok(())
        } else {
            Err("protobuf-unterminated-declaration".to_owned())
        }
    }

    fn skip_balanced_body(&mut self) -> std::result::Result<SourceSpan, String> {
        let mut depth = 1_usize;
        while let Some(token) = self.bump() {
            match token.text.as_str() {
                "{" => {
                    depth += 1;
                    if depth > MAX_PROTOBUF_DEPTH {
                        return Err("protobuf-nesting-depth-limit-exceeded".to_owned());
                    }
                }
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(token.span);
                    }
                }
                _ => {}
            }
        }
        Err("protobuf-block-is-unterminated".to_owned())
    }

    fn skip_to_semicolon(&mut self) -> std::result::Result<SourceSpan, String> {
        let mut delimiters = Vec::<&str>::new();
        while let Some(token) = self.bump() {
            match token.text.as_str() {
                "[" => delimiters.push("]"),
                "(" => delimiters.push(")"),
                "{" => delimiters.push("}"),
                "<" => delimiters.push(">"),
                "]" | ")" | "}" | ">" if delimiters.last().copied() == Some(&token.text) => {
                    delimiters.pop();
                }
                ";" if delimiters.is_empty() => return Ok(token.span),
                _ => {}
            }
        }
        Err("protobuf-field-is-unterminated".to_owned())
    }

    fn expect(&mut self, expected: &str) -> std::result::Result<Token, String> {
        self.bump()
            .filter(|token| token.text == expected)
            .ok_or_else(|| "protobuf-unexpected-token".to_owned())
    }

    fn expect_identifier(&mut self) -> std::result::Result<Token, String> {
        self.bump()
            .filter(|token| token.kind == TokenKind::Identifier)
            .ok_or_else(|| "protobuf-identifier-is-missing".to_owned())
    }

    fn consume(&mut self, expected: &str) -> bool {
        if self.peek_text() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn bump(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.cursor).cloned();
        self.cursor += usize::from(token.is_some());
        token
    }

    fn peek_text(&self) -> Option<&str> {
        self.tokens
            .get(self.cursor)
            .map(|token| token.text.as_str())
    }
}

fn qualify(package: &str, parent: &str, name: &str) -> String {
    if !parent.is_empty() {
        format!("{parent}.{name}")
    } else if !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_owned()
    }
}

fn merge_span(start: SourceSpan, end: SourceSpan) -> SourceSpan {
    SourceSpan {
        start_line: start.start_line,
        start_column: start.start_column,
        end_line: end.end_line,
        end_column: end.end_column,
    }
}

fn to_i32(value: usize) -> std::result::Result<i32, String> {
    i32::try_from(value).map_err(|_| "protobuf-descriptor-index-limit-exceeded".to_owned())
}

#[derive(Clone, Debug)]
struct DescriptorInventory {
    records: Vec<DescriptorRecord>,
    proofs: BTreeMap<String, DescriptorProof>,
    reasons: BTreeSet<String>,
    skipped_count: u64,
}

impl DescriptorInventory {
    fn identity_value(&self) -> Value {
        json!(
            self.records
                .iter()
                .map(DescriptorRecord::identity_value)
                .collect::<Vec<_>>()
        )
    }
}

#[derive(Clone, Debug)]
struct DescriptorRecord {
    locator: String,
    digest: String,
    status: &'static str,
    reason: Option<String>,
    correlated_sources: Vec<String>,
}

impl DescriptorRecord {
    fn identity_value(&self) -> Value {
        json!({
            "locator": self.locator,
            "digest": self.digest,
            "status": self.status,
            "reason": self.reason,
            "correlated_sources": self.correlated_sources,
        })
    }
}

#[derive(Clone, Debug)]
struct DescriptorProof {
    descriptor_locator: String,
    descriptor_digest: String,
    file_ordinal: u64,
    locations: BTreeMap<Vec<i32>, SourceSpan>,
}

fn inventory_descriptor_sets(
    root: &Path,
    sources: &BTreeMap<String, ProtoFile>,
) -> Result<DescriptorInventory> {
    let all_types = source_type_names(sources);
    let mut records = Vec::new();
    let mut candidates = BTreeMap::<String, Vec<DescriptorProof>>::new();
    let mut reasons = BTreeSet::new();
    let mut skipped_count = 0_u64;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.depth() == 0 {
            continue;
        }
        let Some(locator) = repository_locator(root, entry.path()) else {
            continue;
        };
        if !locator.ends_with(PROTOBUF_DESCRIPTOR_SUFFIX) {
            continue;
        }
        if entry.file_type().is_symlink() {
            skipped_count += 1;
            reasons.insert("protobuf-descriptor-symlink-not-admitted".to_owned());
            records.push(skipped_descriptor(
                &locator,
                "protobuf-descriptor-symlink-not-admitted",
            ));
            continue;
        }
        if !entry.file_type().is_file() {
            skipped_count += 1;
            reasons.insert("protobuf-descriptor-is-not-a-file".to_owned());
            records.push(skipped_descriptor(
                &locator,
                "protobuf-descriptor-is-not-a-file",
            ));
            continue;
        }
        let len = match entry.metadata() {
            Ok(metadata) => metadata.len() as usize,
            Err(_) => {
                skipped_count += 1;
                reasons.insert("protobuf-descriptor-metadata-unavailable".to_owned());
                records.push(skipped_descriptor(
                    &locator,
                    "protobuf-descriptor-metadata-unavailable",
                ));
                continue;
            }
        };
        if len > MAX_PROTOBUF_DESCRIPTOR_BYTES {
            skipped_count += 1;
            reasons.insert("protobuf-descriptor-byte-limit-exceeded".to_owned());
            records.push(skipped_descriptor(
                &locator,
                "protobuf-descriptor-byte-limit-exceeded",
            ));
            continue;
        }
        let bytes = match read_bounded(entry.path(), MAX_PROTOBUF_DESCRIPTOR_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => {
                skipped_count += 1;
                reasons.insert("protobuf-descriptor-read-failed".to_owned());
                records.push(skipped_descriptor(
                    &locator,
                    "protobuf-descriptor-read-failed",
                ));
                continue;
            }
        };
        let digest = sha256_prefixed(&bytes);
        let set = match FileDescriptorSet::decode(bytes.as_slice()) {
            Ok(set) => set,
            Err(_) => {
                skipped_count += 1;
                reasons.insert("protobuf-descriptor-decode-failed".to_owned());
                records.push(DescriptorRecord {
                    locator,
                    digest,
                    status: "skipped",
                    reason: Some("protobuf-descriptor-decode-failed".to_owned()),
                    correlated_sources: Vec::new(),
                });
                continue;
            }
        };
        if set.file.is_empty() || set.file.len() > MAX_PROTOBUF_DESCRIPTOR_FILES {
            skipped_count += 1;
            reasons.insert("protobuf-descriptor-file-count-invalid".to_owned());
            records.push(DescriptorRecord {
                locator,
                digest,
                status: "skipped",
                reason: Some("protobuf-descriptor-file-count-invalid".to_owned()),
                correlated_sources: Vec::new(),
            });
            continue;
        }

        let mut local_names = BTreeSet::new();
        let mut correlated_sources = Vec::new();
        let mut local_proofs = Vec::new();
        let mut record_reason = None;
        for (ordinal, descriptor) in set.file.iter().enumerate() {
            let Some(source_locator) = descriptor.name.as_deref() else {
                record_reason = Some("protobuf-descriptor-source-name-missing");
                break;
            };
            if !valid_proto_locator(source_locator) {
                record_reason = Some("protobuf-descriptor-source-name-out-of-root");
                break;
            }
            if !local_names.insert(source_locator.to_owned()) {
                record_reason = Some("protobuf-descriptor-source-name-duplicate");
                break;
            }
            let Some(source) = sources.get(source_locator) else {
                record_reason = Some("protobuf-descriptor-source-missing");
                break;
            };
            let source_shape = match source_shape(source, &all_types) {
                Ok(shape) => shape,
                Err(reason) => {
                    record_reason = Some(reason);
                    break;
                }
            };
            let descriptor_shape = match descriptor_shape(descriptor) {
                Ok(shape) => shape,
                Err(reason) => {
                    record_reason = Some(reason);
                    break;
                }
            };
            if source_shape != descriptor_shape {
                record_reason = Some("protobuf-descriptor-source-mismatch");
                break;
            }
            let locations = match descriptor_locations(descriptor, source) {
                Ok(locations) => locations,
                Err(reason) => {
                    record_reason = Some(reason);
                    break;
                }
            };
            correlated_sources.push(source_locator.to_owned());
            local_proofs.push((
                source_locator.to_owned(),
                DescriptorProof {
                    descriptor_locator: locator.clone(),
                    descriptor_digest: digest.clone(),
                    file_ordinal: ordinal as u64,
                    locations,
                },
            ));
        }
        if let Some(reason) = record_reason {
            skipped_count += 1;
            reasons.insert(reason.to_owned());
            records.push(DescriptorRecord {
                locator,
                digest,
                status: "skipped",
                reason: Some(reason.to_owned()),
                correlated_sources: Vec::new(),
            });
            continue;
        }
        correlated_sources.sort();
        for (source, proof) in local_proofs {
            candidates.entry(source).or_default().push(proof);
        }
        records.push(DescriptorRecord {
            locator,
            digest,
            status: "admitted",
            reason: None,
            correlated_sources,
        });
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));

    let mut proofs = BTreeMap::new();
    for (source, source_proofs) in candidates {
        if source_proofs.len() == 1 {
            proofs.insert(source, source_proofs.into_iter().next().unwrap());
        } else {
            reasons.insert("ambiguous-protobuf-descriptor-provenance".to_owned());
            skipped_count += source_proofs.len() as u64;
        }
    }
    Ok(DescriptorInventory {
        records,
        proofs,
        reasons,
        skipped_count,
    })
}

fn skipped_descriptor(locator: &str, reason: &str) -> DescriptorRecord {
    DescriptorRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        status: "skipped",
        reason: Some(reason.to_owned()),
        correlated_sources: Vec::new(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ContractShape {
    version: String,
    package: String,
    imports: BTreeMap<String, ImportKind>,
    messages: BTreeMap<String, MessageShape>,
    enums: BTreeSet<String>,
    services: BTreeMap<String, ServiceShape>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct MessageShape {
    fields: BTreeMap<String, FieldShape>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct FieldShape {
    number: i32,
    label: FieldLabel,
    type_name: String,
    oneof: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ServiceShape {
    methods: BTreeMap<String, MethodShape>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct MethodShape {
    input_type: String,
    output_type: String,
    client_streaming: bool,
    server_streaming: bool,
}

fn source_shape(
    source: &ProtoFile,
    all_types: &BTreeSet<String>,
) -> std::result::Result<ContractShape, &'static str> {
    if source.version.starts_with("edition:") {
        return Err("protobuf-descriptor-edition-not-supported");
    }
    let mut imports = BTreeMap::new();
    for import in &source.imports {
        insert_same(&mut imports, import.path.clone(), import.kind)
            .map_err(|_| "duplicate-protobuf-import")?;
    }
    let mut messages = BTreeMap::new();
    for message in source.messages.values() {
        let mut fields = BTreeMap::new();
        for field in &message.fields {
            let type_name = canonical_type(
                &field.type_name,
                &message.coordinate,
                &source.package,
                all_types,
            );
            let shape = FieldShape {
                number: field.number,
                label: field.label,
                type_name,
                oneof: field.oneof.clone(),
            };
            insert_same(&mut fields, field.name.clone(), shape)
                .map_err(|_| "duplicate-protobuf-field")?;
        }
        messages.insert(message.coordinate.clone(), MessageShape { fields });
    }
    let mut services = BTreeMap::new();
    for service in source.services.values() {
        let mut methods = BTreeMap::new();
        for method in &service.methods {
            let shape = MethodShape {
                input_type: canonical_type(
                    &method.input_type,
                    &source.package,
                    &source.package,
                    all_types,
                ),
                output_type: canonical_type(
                    &method.output_type,
                    &source.package,
                    &source.package,
                    all_types,
                ),
                client_streaming: method.client_streaming,
                server_streaming: method.server_streaming,
            };
            insert_same(&mut methods, method.name.clone(), shape)
                .map_err(|_| "duplicate-protobuf-method")?;
        }
        services.insert(service.coordinate.clone(), ServiceShape { methods });
    }
    Ok(ContractShape {
        version: source.version.clone(),
        package: source.package.clone(),
        imports,
        messages,
        enums: source.enums.clone(),
        services,
    })
}

fn descriptor_shape(
    descriptor: &FileDescriptorProto,
) -> std::result::Result<ContractShape, &'static str> {
    let version = descriptor
        .syntax
        .clone()
        .unwrap_or_else(|| "proto2".to_owned());
    if !matches!(version.as_str(), "proto2" | "proto3") {
        return Err("unsupported-protobuf-descriptor-version");
    }
    let package = descriptor.package.clone().unwrap_or_default();
    let public = descriptor_index_set(&descriptor.public_dependency, descriptor.dependency.len())?;
    let weak = descriptor_index_set(&descriptor.weak_dependency, descriptor.dependency.len())?;
    if !public.is_disjoint(&weak) {
        return Err("protobuf-descriptor-import-kind-conflict");
    }
    let mut imports = BTreeMap::new();
    for (index, path) in descriptor.dependency.iter().enumerate() {
        if !valid_proto_locator(path) {
            return Err("protobuf-descriptor-import-out-of-root");
        }
        let kind = if public.contains(&index) {
            ImportKind::Public
        } else if weak.contains(&index) {
            ImportKind::Weak
        } else {
            ImportKind::Normal
        };
        insert_same(&mut imports, path.clone(), kind)
            .map_err(|_| "duplicate-protobuf-descriptor-import")?;
    }

    let mut map_entries = BTreeMap::new();
    collect_map_entries(
        &descriptor.message_type,
        &package,
        "",
        &version,
        &mut map_entries,
    )?;
    let mut messages = BTreeMap::new();
    let mut enums = BTreeSet::new();
    for message in &descriptor.message_type {
        collect_descriptor_message(
            message,
            &package,
            "",
            &version,
            &map_entries,
            &mut messages,
            &mut enums,
        )?;
    }
    for enumeration in &descriptor.enum_type {
        let name = required_name(enumeration.name.as_deref())?;
        if !enums.insert(qualify(&package, "", name)) {
            return Err("duplicate-protobuf-descriptor-enum");
        }
    }
    let mut services = BTreeMap::new();
    for service in &descriptor.service {
        let service_shape = descriptor_service_shape(service)?;
        let name = required_name(service.name.as_deref())?;
        if services
            .insert(qualify(&package, "", name), service_shape)
            .is_some()
        {
            return Err("duplicate-protobuf-descriptor-service");
        }
    }
    Ok(ContractShape {
        version,
        package,
        imports,
        messages,
        enums,
        services,
    })
}

fn descriptor_index_set(
    values: &[i32],
    dependency_count: usize,
) -> std::result::Result<BTreeSet<usize>, &'static str> {
    let mut indexes = BTreeSet::new();
    for value in values {
        let index = usize::try_from(*value)
            .ok()
            .filter(|index| *index < dependency_count)
            .ok_or("protobuf-descriptor-import-index-invalid")?;
        if !indexes.insert(index) {
            return Err("protobuf-descriptor-import-index-duplicate");
        }
    }
    Ok(indexes)
}

fn collect_map_entries(
    descriptors: &[DescriptorProto],
    package: &str,
    parent: &str,
    version: &str,
    output: &mut BTreeMap<String, String>,
) -> std::result::Result<(), &'static str> {
    for descriptor in descriptors {
        let name = required_name(descriptor.name.as_deref())?;
        let coordinate = qualify(package, parent, name);
        if descriptor
            .options
            .as_ref()
            .and_then(|options| options.map_entry)
            == Some(true)
        {
            if descriptor.field.len() != 2 {
                return Err("protobuf-descriptor-map-entry-invalid");
            }
            let key = descriptor_field_type(&descriptor.field[0], version, &BTreeMap::new())?;
            let value = descriptor_field_type(&descriptor.field[1], version, &BTreeMap::new())?;
            output.insert(coordinate.clone(), format!("map<{key},{value}>"));
        }
        collect_map_entries(
            &descriptor.nested_type,
            package,
            &coordinate,
            version,
            output,
        )?;
    }
    Ok(())
}

fn collect_descriptor_message(
    descriptor: &DescriptorProto,
    package: &str,
    parent: &str,
    version: &str,
    map_entries: &BTreeMap<String, String>,
    messages: &mut BTreeMap<String, MessageShape>,
    enums: &mut BTreeSet<String>,
) -> std::result::Result<(), &'static str> {
    let name = required_name(descriptor.name.as_deref())?;
    let coordinate = qualify(package, parent, name);
    if descriptor
        .options
        .as_ref()
        .and_then(|options| options.map_entry)
        != Some(true)
    {
        let oneofs = descriptor
            .oneof_decl
            .iter()
            .map(|oneof| required_name(oneof.name.as_deref()).map(str::to_owned))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut fields = BTreeMap::new();
        for field in &descriptor.field {
            let field_name = required_name(field.name.as_deref())?;
            let type_name = descriptor_field_type(field, version, map_entries)?;
            let map_field = type_name.starts_with("map<");
            let label = if map_field {
                FieldLabel::Normal
            } else {
                descriptor_field_label(field, version)?
            };
            let oneof = if field.proto3_optional == Some(true) {
                None
            } else {
                match field.oneof_index {
                    Some(index) => oneofs
                        .get(
                            usize::try_from(index)
                                .map_err(|_| "protobuf-descriptor-oneof-index-invalid")?,
                        )
                        .cloned()
                        .ok_or("protobuf-descriptor-oneof-index-invalid")?
                        .into(),
                    None => None,
                }
            };
            let number = field
                .number
                .filter(|number| *number > 0)
                .ok_or("protobuf-descriptor-field-number-invalid")?;
            insert_same(
                &mut fields,
                field_name.to_owned(),
                FieldShape {
                    number,
                    label,
                    type_name,
                    oneof,
                },
            )
            .map_err(|_| "duplicate-protobuf-descriptor-field")?;
        }
        if messages
            .insert(coordinate.clone(), MessageShape { fields })
            .is_some()
        {
            return Err("duplicate-protobuf-descriptor-message");
        }
    }
    for enumeration in &descriptor.enum_type {
        let enum_name = required_name(enumeration.name.as_deref())?;
        if !enums.insert(qualify(package, &coordinate, enum_name)) {
            return Err("duplicate-protobuf-descriptor-enum");
        }
    }
    for nested in &descriptor.nested_type {
        collect_descriptor_message(
            nested,
            package,
            &coordinate,
            version,
            map_entries,
            messages,
            enums,
        )?;
    }
    Ok(())
}

fn descriptor_field_type(
    field: &FieldDescriptorProto,
    _version: &str,
    map_entries: &BTreeMap<String, String>,
) -> std::result::Result<String, &'static str> {
    if let Some(type_name) = field.type_name.as_deref() {
        let canonical = type_name.trim_start_matches('.');
        if !bounded_text(canonical) {
            return Err("protobuf-descriptor-type-name-invalid");
        }
        return Ok(map_entries
            .get(canonical)
            .cloned()
            .unwrap_or_else(|| canonical.to_owned()));
    }
    let field_type = field
        .r#type
        .and_then(|value| field_descriptor_proto::Type::try_from(value).ok())
        .ok_or("protobuf-descriptor-field-type-missing")?;
    Ok(match field_type {
        field_descriptor_proto::Type::Double => "double",
        field_descriptor_proto::Type::Float => "float",
        field_descriptor_proto::Type::Int64 => "int64",
        field_descriptor_proto::Type::Uint64 => "uint64",
        field_descriptor_proto::Type::Int32 => "int32",
        field_descriptor_proto::Type::Fixed64 => "fixed64",
        field_descriptor_proto::Type::Fixed32 => "fixed32",
        field_descriptor_proto::Type::Bool => "bool",
        field_descriptor_proto::Type::String => "string",
        field_descriptor_proto::Type::Group => "group",
        field_descriptor_proto::Type::Message => {
            return Err("protobuf-descriptor-message-type-name-missing");
        }
        field_descriptor_proto::Type::Bytes => "bytes",
        field_descriptor_proto::Type::Uint32 => "uint32",
        field_descriptor_proto::Type::Enum => {
            return Err("protobuf-descriptor-enum-type-name-missing");
        }
        field_descriptor_proto::Type::Sfixed32 => "sfixed32",
        field_descriptor_proto::Type::Sfixed64 => "sfixed64",
        field_descriptor_proto::Type::Sint32 => "sint32",
        field_descriptor_proto::Type::Sint64 => "sint64",
    }
    .to_owned())
}

fn descriptor_field_label(
    field: &FieldDescriptorProto,
    version: &str,
) -> std::result::Result<FieldLabel, &'static str> {
    let label = field
        .label
        .and_then(|value| field_descriptor_proto::Label::try_from(value).ok())
        .ok_or("protobuf-descriptor-field-label-missing")?;
    Ok(match label {
        field_descriptor_proto::Label::Repeated => FieldLabel::Repeated,
        field_descriptor_proto::Label::Required => FieldLabel::Required,
        field_descriptor_proto::Label::Optional
            if version == "proto3" && field.proto3_optional != Some(true) =>
        {
            FieldLabel::Normal
        }
        field_descriptor_proto::Label::Optional => FieldLabel::Optional,
    })
}

fn descriptor_service_shape(
    service: &ServiceDescriptorProto,
) -> std::result::Result<ServiceShape, &'static str> {
    let mut methods = BTreeMap::new();
    for method in &service.method {
        let name = required_name(method.name.as_deref())?;
        insert_same(
            &mut methods,
            name.to_owned(),
            descriptor_method_shape(method)?,
        )
        .map_err(|_| "duplicate-protobuf-descriptor-method")?;
    }
    Ok(ServiceShape { methods })
}

fn descriptor_method_shape(
    method: &MethodDescriptorProto,
) -> std::result::Result<MethodShape, &'static str> {
    Ok(MethodShape {
        input_type: required_name(method.input_type.as_deref())?
            .trim_start_matches('.')
            .to_owned(),
        output_type: required_name(method.output_type.as_deref())?
            .trim_start_matches('.')
            .to_owned(),
        client_streaming: method.client_streaming.unwrap_or(false),
        server_streaming: method.server_streaming.unwrap_or(false),
    })
}

fn required_name(value: Option<&str>) -> std::result::Result<&str, &'static str> {
    value
        .filter(|value| bounded_text(value))
        .ok_or("protobuf-descriptor-name-missing-or-invalid")
}

fn descriptor_locations(
    descriptor: &FileDescriptorProto,
    source: &ProtoFile,
) -> std::result::Result<BTreeMap<Vec<i32>, SourceSpan>, &'static str> {
    let mut locations = BTreeMap::new();
    let Some(info) = &descriptor.source_code_info else {
        return Ok(locations);
    };
    for location in &info.location {
        if location.path.is_empty()
            || location.path.len() > MAX_PROTOBUF_DEPTH
            || location.path.iter().any(|value| *value < 0)
        {
            return Err("protobuf-descriptor-source-path-invalid");
        }
        let span = match location.span.as_slice() {
            [start_line, start_column, end_column] => {
                descriptor_span(*start_line, *start_column, *start_line, *end_column, source)?
            }
            [start_line, start_column, end_line, end_column] => {
                descriptor_span(*start_line, *start_column, *end_line, *end_column, source)?
            }
            _ => return Err("protobuf-descriptor-source-span-invalid"),
        };
        if locations.insert(location.path.clone(), span).is_some() {
            return Err("protobuf-descriptor-source-path-ambiguous");
        }
    }
    Ok(locations)
}

fn descriptor_span(
    start_line: i32,
    start_column: i32,
    end_line: i32,
    end_column: i32,
    source: &ProtoFile,
) -> std::result::Result<SourceSpan, &'static str> {
    let (start_line_index, start_column, end_line_index, end_column) = (
        usize::try_from(start_line).map_err(|_| "protobuf-descriptor-source-span-invalid")?,
        u32::try_from(start_column).map_err(|_| "protobuf-descriptor-source-span-invalid")?,
        usize::try_from(end_line).map_err(|_| "protobuf-descriptor-source-span-invalid")?,
        u32::try_from(end_column).map_err(|_| "protobuf-descriptor-source-span-invalid")?,
    );
    let start_limit = source
        .line_columns
        .get(start_line_index)
        .ok_or("protobuf-descriptor-source-span-invalid")?;
    let end_limit = source
        .line_columns
        .get(end_line_index)
        .ok_or("protobuf-descriptor-source-span-invalid")?;
    if start_column + 1 > *start_limit
        || end_column + 1 > *end_limit
        || (start_line_index, start_column) > (end_line_index, end_column)
    {
        return Err("protobuf-descriptor-source-span-invalid");
    }
    Ok(SourceSpan {
        start_line: start_line_index as u32 + 1,
        start_column: start_column + 1,
        end_line: end_line_index as u32 + 1,
        end_column: end_column + 1,
    })
}

fn source_type_names(sources: &BTreeMap<String, ProtoFile>) -> BTreeSet<String> {
    sources
        .values()
        .flat_map(|source| {
            source
                .messages
                .keys()
                .chain(source.enums.iter())
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect()
}

fn canonical_type(raw: &str, scope: &str, package: &str, all_types: &BTreeSet<String>) -> String {
    if is_scalar_type(raw) || raw.starts_with("map<") {
        return raw.to_owned();
    }
    let trimmed = raw.trim_start_matches('.');
    if raw.starts_with('.') || all_types.contains(trimmed) {
        return trimmed.to_owned();
    }
    let mut current = scope.to_owned();
    loop {
        let candidate = if current.is_empty() {
            trimmed.to_owned()
        } else {
            format!("{current}.{trimmed}")
        };
        if all_types.contains(&candidate) {
            return candidate;
        }
        let Some((parent, _)) = current.rsplit_once('.') else {
            break;
        };
        current = parent.to_owned();
    }
    let package_candidate = if package.is_empty() {
        trimmed.to_owned()
    } else {
        format!("{package}.{trimmed}")
    };
    if all_types.contains(&package_candidate) {
        package_candidate
    } else {
        trimmed.to_owned()
    }
}

fn is_scalar_type(value: &str) -> bool {
    matches!(
        value,
        "double"
            | "float"
            | "int32"
            | "int64"
            | "uint32"
            | "uint64"
            | "sint32"
            | "sint64"
            | "fixed32"
            | "fixed64"
            | "sfixed32"
            | "sfixed64"
            | "bool"
            | "string"
            | "bytes"
            | "group"
    )
}

struct ProtobufGraphBuilder {
    profile_id: String,
    sources: BTreeMap<String, ProtoFile>,
    proofs: BTreeMap<String, DescriptorProof>,
    all_types: BTreeSet<String>,
    all_enums: BTreeSet<String>,
    nodes: BTreeMap<String, GraphNode>,
    cross_node_ids: BTreeSet<String>,
    sites: BTreeMap<String, DependencySite>,
    edges: BTreeMap<String, GraphEdge>,
    schema_ids: BTreeMap<String, String>,
    message_ids: BTreeMap<String, Vec<String>>,
    service_ids: BTreeMap<(String, String), String>,
    operation_ids: BTreeMap<(String, String), String>,
    unresolved_count: u64,
    reasons: BTreeSet<String>,
}

impl ProtobufGraphBuilder {
    fn new(
        profile_id: String,
        sources: BTreeMap<String, ProtoFile>,
        proofs: BTreeMap<String, DescriptorProof>,
    ) -> Self {
        let all_types = source_type_names(&sources);
        let all_enums = sources
            .values()
            .flat_map(|source| source.enums.iter().cloned())
            .collect();
        Self {
            profile_id,
            sources,
            proofs,
            all_types,
            all_enums,
            nodes: BTreeMap::new(),
            cross_node_ids: BTreeSet::new(),
            sites: BTreeMap::new(),
            edges: BTreeMap::new(),
            schema_ids: BTreeMap::new(),
            message_ids: BTreeMap::new(),
            service_ids: BTreeMap::new(),
            operation_ids: BTreeMap::new(),
            unresolved_count: 0,
            reasons: BTreeSet::new(),
        }
    }

    fn build(&mut self) -> Result<()> {
        let locators = self.sources.keys().cloned().collect::<Vec<_>>();
        for locator in &locators {
            let source = self.sources[locator].clone();
            let package_coordinate = if source.package.is_empty() {
                "package <global>".to_owned()
            } else {
                format!("package {}", source.package)
            };
            let schema_id =
                self.add_cross_node(CrossLanguageNodeKind::Schema, locator, &package_coordinate)?;
            self.schema_ids.insert(locator.clone(), schema_id);
            for message in source.messages.values() {
                let id = self.add_cross_node(
                    CrossLanguageNodeKind::Message,
                    locator,
                    &message.coordinate,
                )?;
                self.message_ids
                    .entry(message.coordinate.clone())
                    .or_default()
                    .push(id);
            }
            for service in source.services.values() {
                let service_id = self.add_cross_node(
                    CrossLanguageNodeKind::Service,
                    locator,
                    &service.coordinate,
                )?;
                self.service_ids
                    .insert((locator.clone(), service.coordinate.clone()), service_id);
                for method in &service.methods {
                    let operation_id = self.add_cross_node(
                        CrossLanguageNodeKind::Operation,
                        locator,
                        &method.coordinate,
                    )?;
                    self.operation_ids
                        .insert((locator.clone(), method.coordinate.clone()), operation_id);
                }
            }
        }
        for ids in self.message_ids.values_mut() {
            ids.sort();
            ids.dedup();
        }
        for locator in locators {
            self.build_source_relations(&locator)?;
        }
        Ok(())
    }

    fn build_source_relations(&mut self, locator: &str) -> Result<()> {
        let source = self.sources[locator].clone();
        let schema_id = self.schema_ids[locator].clone();
        let mut seen_imports = BTreeSet::new();
        for import in &source.imports {
            let reason = if !valid_proto_locator(&import.path) {
                Some("protobuf-import-out-of-root")
            } else if !seen_imports.insert(import.path.clone()) {
                Some("duplicate-protobuf-import")
            } else if !self.schema_ids.contains_key(&import.path) {
                Some("protobuf-import-is-missing")
            } else {
                None
            };
            let (target, status, precision, mapping) = if let Some(reason) = reason {
                (
                    self.unknown_node(locator, &import.path, reason)?,
                    ResolutionStatus::Unresolved,
                    Precision::Heuristic,
                    CrossLanguageMappingKind::Unresolved,
                )
            } else {
                (
                    self.schema_ids[&import.path].clone(),
                    ResolutionStatus::Resolved,
                    Precision::Exact,
                    self.exact_mapping_kind(locator),
                )
            };
            self.add_relation(RelationInput {
                source: &schema_id,
                target: &target,
                relation: CrossLanguageRelationKind::ReferencesSchema,
                source_locator: locator,
                descriptor_path: &[3, to_i32(import.ordinal).map_err(anyhow::Error::msg)?],
                span: import.span,
                specifier: import.path.clone(),
                status,
                precision,
                mapping,
                reason,
                conditions: vec![(
                    "protobuf.import_kind",
                    Value::String(import.kind.as_str().to_owned()),
                )],
            })?;
        }

        for message in source.messages.values() {
            let Some(message_id) = self.unique_message_id(&message.coordinate) else {
                self.insert_reason("ambiguous-protobuf-message-coordinate");
                continue;
            };
            self.add_relation(RelationInput {
                source: &schema_id,
                target: &message_id,
                relation: CrossLanguageRelationKind::ReferencesSchema,
                source_locator: locator,
                descriptor_path: &message.descriptor_path,
                span: message.span,
                specifier: message.coordinate.clone(),
                status: ResolutionStatus::Resolved,
                precision: Precision::Exact,
                mapping: self.exact_mapping_kind(locator),
                reason: None,
                conditions: vec![("protobuf.declaration", Value::String("message".to_owned()))],
            })?;
            for field in &message.fields {
                for referenced_type in referenced_field_types(
                    &field.type_name,
                    &message.coordinate,
                    &source.package,
                    &self.all_types,
                ) {
                    if self.all_enums.contains(&referenced_type) || is_scalar_type(&referenced_type)
                    {
                        continue;
                    }
                    let (target, status, precision, mapping, reason) =
                        if let Some(target) = self.unique_message_id(&referenced_type) {
                            (
                                target,
                                ResolutionStatus::Resolved,
                                Precision::Exact,
                                self.exact_mapping_kind(locator),
                                None,
                            )
                        } else {
                            let reason = if self.message_ids.contains_key(&referenced_type) {
                                "ambiguous-protobuf-message-coordinate"
                            } else {
                                "protobuf-field-type-is-unresolved"
                            };
                            (
                                self.unknown_node(locator, &referenced_type, reason)?,
                                ResolutionStatus::Unresolved,
                                Precision::Heuristic,
                                CrossLanguageMappingKind::Unresolved,
                                Some(reason),
                            )
                        };
                    let mut conditions = vec![
                        ("protobuf.field", Value::String(field.name.clone())),
                        ("protobuf.field_number", Value::Number(field.number.into())),
                    ];
                    if let Some(oneof) = &field.oneof {
                        conditions.push(("protobuf.oneof", Value::String(oneof.clone())));
                    }
                    self.add_relation(RelationInput {
                        source: &message_id,
                        target: &target,
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        source_locator: locator,
                        descriptor_path: &field.descriptor_path,
                        span: field.span,
                        specifier: referenced_type,
                        status,
                        precision,
                        mapping,
                        reason,
                        conditions,
                    })?;
                }
            }
        }

        for service in source.services.values() {
            let service_id =
                self.service_ids[&(locator.to_owned(), service.coordinate.clone())].clone();
            for method in &service.methods {
                let operation_id =
                    self.operation_ids[&(locator.to_owned(), method.coordinate.clone())].clone();
                let stream_conditions = vec![
                    (
                        "protobuf.client_streaming",
                        Value::Bool(method.client_streaming),
                    ),
                    (
                        "protobuf.server_streaming",
                        Value::Bool(method.server_streaming),
                    ),
                ];
                self.add_relation(RelationInput {
                    source: &service_id,
                    target: &operation_id,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    source_locator: locator,
                    descriptor_path: &method.descriptor_path,
                    span: method.span,
                    specifier: method.coordinate.clone(),
                    status: ResolutionStatus::Resolved,
                    precision: Precision::Exact,
                    mapping: self.exact_mapping_kind(locator),
                    reason: None,
                    conditions: stream_conditions.clone(),
                })?;
                self.add_method_message_relation(
                    locator,
                    &source,
                    method,
                    &operation_id,
                    true,
                    stream_conditions.clone(),
                )?;
                self.add_method_message_relation(
                    locator,
                    &source,
                    method,
                    &operation_id,
                    false,
                    stream_conditions,
                )?;
            }
        }
        Ok(())
    }

    fn add_method_message_relation(
        &mut self,
        locator: &str,
        source: &ProtoFile,
        method: &ProtoMethod,
        operation_id: &str,
        input: bool,
        mut conditions: Vec<(&'static str, Value)>,
    ) -> Result<()> {
        let raw_type = if input {
            &method.input_type
        } else {
            &method.output_type
        };
        let coordinate =
            canonical_type(raw_type, &source.package, &source.package, &self.all_types);
        let (target, status, precision, mapping, reason) =
            if let Some(target) = self.unique_message_id(&coordinate) {
                (
                    target,
                    ResolutionStatus::Resolved,
                    Precision::Exact,
                    self.exact_mapping_kind(locator),
                    None,
                )
            } else {
                let reason = if self.message_ids.contains_key(&coordinate) {
                    "ambiguous-protobuf-message-coordinate"
                } else {
                    "protobuf-method-type-is-unresolved"
                };
                (
                    self.unknown_node(locator, &coordinate, reason)?,
                    ResolutionStatus::Unresolved,
                    Precision::Heuristic,
                    CrossLanguageMappingKind::Unresolved,
                    Some(reason),
                )
            };
        conditions.push((
            "protobuf.message_direction",
            Value::String(if input { "request" } else { "response" }.to_owned()),
        ));
        self.add_relation(RelationInput {
            source: operation_id,
            target: &target,
            relation: if input {
                CrossLanguageRelationKind::AcceptsMessage
            } else {
                CrossLanguageRelationKind::ReturnsMessage
            },
            source_locator: locator,
            descriptor_path: &method.descriptor_path,
            span: method.span,
            specifier: coordinate,
            status,
            precision,
            mapping,
            reason,
            conditions,
        })?;
        Ok(())
    }

    fn exact_mapping_kind(&self, locator: &str) -> CrossLanguageMappingKind {
        if self.proofs.contains_key(locator) {
            CrossLanguageMappingKind::Descriptor
        } else {
            CrossLanguageMappingKind::ContractInternal
        }
    }

    fn unique_message_id(&self, coordinate: &str) -> Option<String> {
        self.message_ids
            .get(coordinate)
            .filter(|ids| ids.len() == 1)
            .and_then(|ids| ids.first().cloned())
    }

    fn add_cross_node(
        &mut self,
        kind: CrossLanguageNodeKind,
        locator: &str,
        coordinate: &str,
    ) -> Result<String> {
        if !bounded_text(locator) || !bounded_text(coordinate) {
            bail!("Protobuf canonical identity exceeds its bounded contract");
        }
        let source = self
            .sources
            .get(locator)
            .with_context(|| format!("Protobuf node references unknown source {locator}"))?;
        let identity = CrossLanguageCanonicalIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            format: CrossLanguageFormat::Protobuf,
            repository_contract_locator: locator.to_owned(),
            format_version: source.version.clone(),
            coordinate: coordinate.to_owned(),
            profile_id: self.profile_id.clone(),
        };
        let id = cross_language_node_id(kind, &identity);
        let node = GraphNode {
            id: id.clone(),
            kind: kind.as_str().to_owned(),
            locator: format!("cross-language:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                (
                    "canonical_identity".to_owned(),
                    serde_json::to_value(identity)?,
                ),
                (
                    "format".to_owned(),
                    Value::String(CrossLanguageFormat::Protobuf.as_str().to_owned()),
                ),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node)
            .map_err(|_| anyhow::anyhow!("conflicting Protobuf node identity"))?;
        self.cross_node_ids.insert(id.clone());
        Ok(id)
    }

    fn unknown_node(&mut self, locator: &str, identity: &str, reason: &str) -> Result<String> {
        let id = stable_id_from_value(
            "unknown_target",
            &json!({
                "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
                "format": "protobuf",
                "profile_id": self.profile_id,
                "locator": locator,
                "identity": bounded_reason(identity),
                "reason": reason,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "unknown_target".to_owned(),
            locator: format!("unknown:protobuf:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                ("format".to_owned(), Value::String("protobuf".to_owned())),
                ("reason_code".to_owned(), Value::String(reason.to_owned())),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node)
            .map_err(|_| anyhow::anyhow!("conflicting Protobuf unknown node identity"))?;
        self.insert_reason(reason);
        Ok(id)
    }

    fn add_relation(&mut self, input: RelationInput<'_>) -> Result<String> {
        let source = self.sources.get(input.source_locator).with_context(|| {
            format!(
                "Protobuf relation references unknown source {}",
                input.source_locator
            )
        })?;
        let mut condition_items = vec![
            (
                "protobuf.coordinate".to_owned(),
                Value::String(input.specifier.clone()),
            ),
            (
                "protobuf.source".to_owned(),
                Value::String(input.source_locator.to_owned()),
            ),
        ];
        condition_items.extend(
            input
                .conditions
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone())),
        );
        let condition = Condition::All {
            conditions: condition_items
                .into_iter()
                .map(|(key, value)| Condition::Eq { key, value })
                .collect(),
        }
        .canonicalize();
        let proof = self.proofs.get(input.source_locator);
        let exact_descriptor = input.mapping == CrossLanguageMappingKind::Descriptor;
        let contract_digest = if exact_descriptor {
            proof
                .map(|proof| proof.descriptor_digest.clone())
                .context("descriptor mapping has no descriptor proof")?
        } else {
            source.digest.clone()
        };
        let mut properties = Properties::from([
            (
                "contract_version".to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            ("format".to_owned(), Value::String("protobuf".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(self.profile_id.clone()),
            ),
            (
                "format_version".to_owned(),
                Value::String(source.version.clone()),
            ),
            ("contract_digest".to_owned(), Value::String(contract_digest)),
            (
                "occurrence_kind".to_owned(),
                serde_json::to_value(input.relation)?,
            ),
            (
                "mapping_kind".to_owned(),
                serde_json::to_value(input.mapping)?,
            ),
            (
                "protobuf_coordinate".to_owned(),
                Value::String(input.specifier.clone()),
            ),
            (
                "source_digest".to_owned(),
                Value::String(source.digest.clone()),
            ),
        ]);
        let (path, span) = if exact_descriptor {
            let proof = proof.expect("descriptor proof was checked");
            properties.insert(
                "descriptor_locator".to_owned(),
                Value::String(proof.descriptor_locator.clone()),
            );
            properties.insert(
                "descriptor_digest".to_owned(),
                Value::String(proof.descriptor_digest.clone()),
            );
            properties.insert(
                "descriptor_file_ordinal".to_owned(),
                Value::Number(proof.file_ordinal.into()),
            );
            properties.insert(
                "descriptor_path".to_owned(),
                serde_json::to_value(input.descriptor_path)?,
            );
            if let Some(span) = proof.locations.get(input.descriptor_path) {
                (Some(input.source_locator.to_owned()), Some(*span))
            } else {
                properties.insert(
                    "artifact_identity".to_owned(),
                    Value::String(format!(
                        "{}#{}",
                        proof.descriptor_digest, proof.file_ordinal
                    )),
                );
                properties.insert(
                    "ordinal".to_owned(),
                    Value::Number(descriptor_path_ordinal(input.descriptor_path).into()),
                );
                (None, None)
            }
        } else {
            (Some(input.source_locator.to_owned()), Some(input.span))
        };
        let evidence = vec![Evidence {
            kind: EvidenceKind::Semantic,
            extractor: EXTRACTOR.to_owned(),
            extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
            path,
            start_line: span.map(|span| span.start_line),
            start_column: span.map(|span| span.start_column),
            end_line: span.map(|span| span.end_line),
            end_column: span.map(|span| span.end_column),
            detail: None,
            properties,
        }];
        let mut site = DependencySite {
            id: String::new(),
            source: input.source.to_owned(),
            kind: input.relation.as_str().to_owned(),
            specifier: input.specifier,
            resolution_status: input.status,
            target_ids: vec![input.target.to_owned()],
            profile_id: self.profile_id.clone(),
            condition: condition.clone(),
            precision: input.precision,
            reason: input.reason.map(bounded_reason),
            evidence: evidence.clone(),
        };
        site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
        let mut edge = GraphEdge {
            id: String::new(),
            source: input.source.to_owned(),
            target: input.target.to_owned(),
            kind: input.relation.as_str().to_owned(),
            site_id: Some(site.id.clone()),
            phase: Phase::Semantic,
            environment: None,
            profile_id: self.profile_id.clone(),
            condition,
            resolution_status: input.status,
            precision: input.precision,
            generated: false,
            evidence,
        };
        edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
        let site_id = site.id.clone();
        insert_same(&mut self.sites, site.id.clone(), site)
            .map_err(|_| anyhow::anyhow!("conflicting Protobuf site identity"))?;
        insert_same(&mut self.edges, edge.id.clone(), edge)
            .map_err(|_| anyhow::anyhow!("conflicting Protobuf edge identity"))?;
        if input.status == ResolutionStatus::Unresolved {
            self.unresolved_count += 1;
            if let Some(reason) = input.reason {
                self.insert_reason(reason);
            }
        }
        Ok(site_id)
    }

    fn insert_reason(&mut self, reason: &str) {
        if self.reasons.len() < MAX_REASONS || self.reasons.contains(reason) {
            self.reasons.insert(bounded_reason(reason));
        }
    }
}

struct RelationInput<'a> {
    source: &'a str,
    target: &'a str,
    relation: CrossLanguageRelationKind,
    source_locator: &'a str,
    descriptor_path: &'a [i32],
    span: SourceSpan,
    specifier: String,
    status: ResolutionStatus,
    precision: Precision,
    mapping: CrossLanguageMappingKind,
    reason: Option<&'a str>,
    conditions: Vec<(&'static str, Value)>,
}

fn referenced_field_types(
    raw: &str,
    scope: &str,
    package: &str,
    all_types: &BTreeSet<String>,
) -> Vec<String> {
    if let Some(inner) = raw
        .strip_prefix("map<")
        .and_then(|value| value.strip_suffix('>'))
    {
        return inner
            .split_once(',')
            .into_iter()
            .flat_map(|(key, value)| [key, value])
            .map(|value| canonical_type(value, scope, package, all_types))
            .collect();
    }
    vec![canonical_type(raw, scope, package, all_types)]
}

fn descriptor_path_ordinal(path: &[i32]) -> u64 {
    path.iter().fold(0_u64, |value, component| {
        (value.wrapping_mul(257).wrapping_add(*component as u64 + 1)) % 1_000_001
    })
}

fn inventory_entry_allowed(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".depgraph" | "node_modules" | "target" | "dist" | "build")
    )
}

fn repository_locator(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_str()?.to_owned()),
            _ => return None,
        }
    }
    let locator = parts.join("/");
    (!locator.is_empty() && !locator.contains('\\')).then_some(locator)
}

fn valid_proto_locator(locator: &str) -> bool {
    !locator.is_empty()
        && locator.ends_with(".proto")
        && !locator.starts_with('/')
        && !locator.contains('\\')
        && locator.as_bytes().get(1) != Some(&b':')
        && locator
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
        && Path::new(locator)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("bounded Protobuf read exceeded its byte limit");
    }
    Ok(bytes)
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest_value(value: &Value) -> String {
    sha256_prefixed(
        serde_json::to_vec(value)
            .expect("bounded Protobuf identity is serializable")
            .as_slice(),
    )
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_BOUNDED_TEXT && !value.chars().any(char::is_control)
}

fn bounded_reason(value: &str) -> String {
    value.chars().take(256).collect()
}

fn insert_same<K: Ord, V: PartialEq>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
) -> std::result::Result<(), ()> {
    match map.get(&key) {
        Some(existing) if existing == &value => Ok(()),
        Some(_) => Err(()),
        None => {
            map.insert(key, value);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCapabilityStatus,
        CrossLanguageCompletenessLedger, ResolutionStatus, validate_cross_language_adapter_delta,
    };
    use prost::Message as _;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto, SourceCodeInfo, field_descriptor_proto,
        source_code_info,
    };

    use super::*;

    const A_PROTO: &str = r#"syntax = "proto3";
package acme.v1;
import public "b.proto";
message Envelope {
  b.v1.Payload payload = 1;
  message Meta { string id = 1; }
  Meta meta = 2;
}
service Greeter {
  rpc Get (Envelope) returns (stream b.v1.Payload);
}
"#;

    const B_PROTO: &str = r#"syntax = "proto3";
package b.v1;
import weak "a.proto";
message Payload {
  string value = 1;
}
"#;

    fn field(
        name: &str,
        number: i32,
        field_type: field_descriptor_proto::Type,
        type_name: Option<&str>,
    ) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.to_owned()),
            number: Some(number),
            label: Some(field_descriptor_proto::Label::Optional as i32),
            r#type: Some(field_type as i32),
            type_name: type_name.map(str::to_owned),
            ..Default::default()
        }
    }

    fn descriptor_set(tampered_package: bool, with_location: bool) -> FileDescriptorSet {
        let meta = DescriptorProto {
            name: Some("Meta".to_owned()),
            field: vec![field("id", 1, field_descriptor_proto::Type::String, None)],
            ..Default::default()
        };
        let envelope = DescriptorProto {
            name: Some("Envelope".to_owned()),
            field: vec![
                field(
                    "payload",
                    1,
                    field_descriptor_proto::Type::Message,
                    Some(".b.v1.Payload"),
                ),
                field(
                    "meta",
                    2,
                    field_descriptor_proto::Type::Message,
                    Some(".acme.v1.Envelope.Meta"),
                ),
            ],
            nested_type: vec![meta],
            ..Default::default()
        };
        let payload = DescriptorProto {
            name: Some("Payload".to_owned()),
            field: vec![field(
                "value",
                1,
                field_descriptor_proto::Type::String,
                None,
            )],
            ..Default::default()
        };
        let method = MethodDescriptorProto {
            name: Some("Get".to_owned()),
            input_type: Some(".acme.v1.Envelope".to_owned()),
            output_type: Some(".b.v1.Payload".to_owned()),
            server_streaming: Some(true),
            ..Default::default()
        };
        FileDescriptorSet {
            file: vec![
                FileDescriptorProto {
                    name: Some("a.proto".to_owned()),
                    package: Some(
                        if tampered_package {
                            "tampered.v1"
                        } else {
                            "acme.v1"
                        }
                        .to_owned(),
                    ),
                    dependency: vec!["b.proto".to_owned()],
                    public_dependency: vec![0],
                    message_type: vec![envelope],
                    service: vec![ServiceDescriptorProto {
                        name: Some("Greeter".to_owned()),
                        method: vec![method],
                        ..Default::default()
                    }],
                    source_code_info: with_location.then(|| SourceCodeInfo {
                        location: vec![source_code_info::Location {
                            path: vec![6, 0, 2, 0],
                            span: vec![0, 0, 1],
                            ..Default::default()
                        }],
                    }),
                    syntax: Some("proto3".to_owned()),
                    ..Default::default()
                },
                FileDescriptorProto {
                    name: Some("b.proto".to_owned()),
                    package: Some("b.v1".to_owned()),
                    dependency: vec!["a.proto".to_owned()],
                    weak_dependency: vec![0],
                    message_type: vec![payload],
                    syntax: Some("proto3".to_owned()),
                    ..Default::default()
                },
            ],
        }
    }

    fn write_descriptor(path: &Path, set: &FileDescriptorSet) {
        fs::write(path, set.encode_to_vec()).unwrap();
    }

    fn write_positive_fixture(root: &Path, reverse_creation: bool) {
        if reverse_creation {
            fs::write(root.join("b.proto"), B_PROTO).unwrap();
            fs::write(root.join("a.proto"), A_PROTO).unwrap();
        } else {
            fs::write(root.join("a.proto"), A_PROTO).unwrap();
            fs::write(root.join("b.proto"), B_PROTO).unwrap();
        }
        write_descriptor(
            &root.join(format!("contracts{PROTOBUF_DESCRIPTOR_SUFFIX}")),
            &descriptor_set(false, true),
        );
        fs::write(
            root.join("build.rs"),
            "fn main() { std::fs::write(\"PROJECT_CODE_EXECUTED\", \"bad\").unwrap(); }",
        )
        .unwrap();
    }

    fn ledger(delta: &CrossLanguageAdapterDelta) -> CrossLanguageCompletenessLedger {
        serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap()
    }

    fn node_coordinate(node: &GraphNode) -> Option<&str> {
        node.properties
            .get("canonical_identity")?
            .get("coordinate")?
            .as_str()
    }

    #[test]
    fn source_and_descriptor_graph_is_exact_deterministic_and_checkout_independent() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_positive_fixture(first.path(), false);
        write_positive_fixture(second.path(), true);

        let first = scan_protobuf_repository(first.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        let second = scan_protobuf_repository(second.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&first).unwrap();
        assert_eq!(first, second);
        let coverage = &ledger(&first).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Complete);
        assert_eq!(coverage.input_count, 3);
        assert_eq!(coverage.unresolved_count, 0);
        assert_eq!(coverage.skipped_count, 0);
        for coordinate in [
            "acme.v1.Envelope",
            "acme.v1.Envelope.Meta",
            "b.v1.Payload",
            "acme.v1.Greeter",
            "acme.v1.Greeter/Get",
        ] {
            assert!(
                first
                    .nodes
                    .iter()
                    .any(|node| node_coordinate(node) == Some(coordinate)),
                "missing {coordinate}"
            );
        }
        assert!(
            first
                .sites
                .iter()
                .filter(|site| site.specifier == "a.proto" || site.specifier == "b.proto")
                .all(|site| site.resolution_status == ResolutionStatus::Resolved)
        );
        assert!(first.sites.iter().all(|site| {
            site.evidence[0]
                .properties
                .get("mapping_kind")
                .and_then(Value::as_str)
                == Some("descriptor")
        }));
        let located_method_evidence = first.sites.iter().filter(|site| {
            site.specifier == "acme.v1.Greeter/Get" || site.kind != "references_schema"
        });
        assert!(
            located_method_evidence
                .into_iter()
                .any(|site| site.evidence[0].path.as_deref() == Some("a.proto"))
        );
        assert!(!first.nodes.is_empty());
    }

    #[test]
    fn source_only_editions_and_artifact_only_descriptors_do_not_invent_spans() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("edition.proto"),
            r#"edition = "2023";
package edition.v1;
message Request { string id = 1; }
service EditionService { rpc Read (Request) returns (Request); }
"#,
        )
        .unwrap();
        let source_only =
            scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
                .unwrap()
                .unwrap();
        assert_eq!(
            ledger(&source_only).entries[0].status,
            CrossLanguageCapabilityStatus::Complete
        );
        assert!(source_only.sites.iter().all(|site| {
            site.evidence[0].path.as_deref() == Some("edition.proto")
                && site.evidence[0]
                    .properties
                    .get("mapping_kind")
                    .and_then(Value::as_str)
                    == Some("contract_internal")
        }));

        let descriptors = tempfile::tempdir().unwrap();
        fs::write(descriptors.path().join("a.proto"), A_PROTO).unwrap();
        fs::write(descriptors.path().join("b.proto"), B_PROTO).unwrap();
        write_descriptor(
            &descriptors
                .path()
                .join(format!("contracts{PROTOBUF_DESCRIPTOR_SUFFIX}")),
            &descriptor_set(false, false),
        );
        let descriptor =
            scan_protobuf_repository(descriptors.path(), &["protobuf:production".to_owned()])
                .unwrap()
                .unwrap();
        assert!(descriptor.sites.iter().all(|site| {
            site.evidence[0].path.is_none()
                && site.evidence[0].start_line.is_none()
                && site.evidence[0]
                    .properties
                    .contains_key("artifact_identity")
        }));
    }

    #[test]
    fn missing_and_out_of_root_imports_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("broken.proto"),
            r#"syntax = "proto3";
package broken.v1;
import "missing.proto";
import public "../outside.proto";
message Request { Missing value = 1; }
service Broken { rpc Read (Request) returns (Missing); }
"#,
        )
        .unwrap();
        let delta = scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        let coverage = &ledger(&delta).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Incomplete);
        assert!(coverage.unresolved_count >= 4);
        for reason in [
            "protobuf-import-is-missing",
            "protobuf-import-out-of-root",
            "protobuf-field-type-is-unresolved",
            "protobuf-method-type-is-unresolved",
        ] {
            assert!(coverage.reasons.iter().any(|value| value == reason));
        }
        assert!(
            delta
                .sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::Unresolved)
                .all(|site| {
                    site.evidence[0]
                        .properties
                        .get("mapping_kind")
                        .and_then(Value::as_str)
                        == Some("unresolved")
                })
        );
    }

    #[test]
    fn descriptor_tamper_ambiguity_and_invalid_locations_never_create_descriptor_proof() {
        for case in ["tamper", "ambiguous", "span"] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join("a.proto"), A_PROTO).unwrap();
            fs::write(root.path().join("b.proto"), B_PROTO).unwrap();
            match case {
                "tamper" => write_descriptor(
                    &root
                        .path()
                        .join(format!("tampered{PROTOBUF_DESCRIPTOR_SUFFIX}")),
                    &descriptor_set(true, false),
                ),
                "ambiguous" => {
                    let set = descriptor_set(false, false);
                    write_descriptor(
                        &root.path().join(format!("one{PROTOBUF_DESCRIPTOR_SUFFIX}")),
                        &set,
                    );
                    write_descriptor(
                        &root.path().join(format!("two{PROTOBUF_DESCRIPTOR_SUFFIX}")),
                        &set,
                    );
                }
                "span" => {
                    let mut set = descriptor_set(false, true);
                    set.file[0].source_code_info.as_mut().unwrap().location[0].span =
                        vec![999, 0, 999, 1];
                    write_descriptor(
                        &root
                            .path()
                            .join(format!("span{PROTOBUF_DESCRIPTOR_SUFFIX}")),
                        &set,
                    );
                }
                _ => unreachable!(),
            }
            let delta = scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
                .unwrap()
                .unwrap();
            validate_cross_language_adapter_delta(&delta).unwrap();
            let coverage = &ledger(&delta).entries[0];
            assert_eq!(
                coverage.status,
                CrossLanguageCapabilityStatus::Incomplete,
                "{case}"
            );
            assert!(
                delta.sites.iter().all(|site| {
                    site.evidence[0]
                        .properties
                        .get("mapping_kind")
                        .and_then(Value::as_str)
                        != Some("descriptor")
                }),
                "{case}"
            );
            let expected = match case {
                "tamper" => "protobuf-descriptor-source-mismatch",
                "ambiguous" => "ambiguous-protobuf-descriptor-provenance",
                "span" => "protobuf-descriptor-source-span-invalid",
                _ => unreachable!(),
            };
            assert!(
                coverage.reasons.iter().any(|reason| reason == expected),
                "{case}: {:?}",
                coverage.reasons
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sources_and_descriptor_sets_are_never_admitted() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside.proto"), A_PROTO).unwrap();
        write_descriptor(
            &outside.path().join("outside.pb"),
            &descriptor_set(false, false),
        );
        symlink(
            outside.path().join("outside.proto"),
            root.path().join("linked.proto"),
        )
        .unwrap();
        symlink(
            outside.path().join("outside.pb"),
            root.path()
                .join(format!("linked{PROTOBUF_DESCRIPTOR_SUFFIX}")),
        )
        .unwrap();
        let delta = scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
            .unwrap()
            .unwrap();
        let coverage = &ledger(&delta).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Incomplete);
        assert_eq!(coverage.node_count, 0);
        assert!(
            coverage
                .reasons
                .iter()
                .any(|reason| reason == "protobuf-source-symlink-not-admitted")
        );
        assert!(
            coverage
                .reasons
                .iter()
                .any(|reason| reason == "protobuf-descriptor-symlink-not-admitted")
        );
    }

    #[test]
    fn malformed_inputs_are_bounded_and_empty_repositories_are_ignored() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
                .unwrap()
                .is_none()
        );
        assert!(scan_protobuf_repository(root.path(), &[]).is_err());
        fs::write(
            root.path().join("broken.proto"),
            "syntax = \"proto3\"; message Broken { message Nested {",
        )
        .unwrap();
        fs::write(
            root.path()
                .join(format!("broken{PROTOBUF_DESCRIPTOR_SUFFIX}")),
            b"not-a-descriptor",
        )
        .unwrap();
        let delta = scan_protobuf_repository(root.path(), &["protobuf:production".to_owned()])
            .unwrap()
            .unwrap();
        let coverage = &ledger(&delta).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Incomplete);
        assert_eq!(coverage.input_count, 2);
        assert_eq!(coverage.skipped_count, 2);
        assert!(delta.nodes.is_empty());
    }
}
