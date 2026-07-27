use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use crate::bounded_query::read_bounded_repository_file;
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
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

pub const GRAPHQL_CAPABILITY: &str = "graphql-contract-v1";
pub const GRAPHQL_FORMAT_VERSION: &str = "graphql-spec-2021";
pub const MAX_GRAPHQL_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_GRAPHQL_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_GRAPHQL_FILES: usize = 4_096;
pub const MAX_GRAPHQL_INVENTORY_ENTRIES: usize = 1_000_000;
pub const MAX_GRAPHQL_TOKENS: usize = 1_000_000;
pub const MAX_GRAPHQL_DEPTH: usize = 64;
pub const MAX_GRAPHQL_DEFINITIONS: usize = 100_000;
pub const MAX_GRAPHQL_SELECTIONS: usize = 250_000;

const EXTRACTOR: &str = "depgraph-graphql-adapter";
const MAX_PARTICIPATING_PROFILES: usize = 64;
const MAX_BOUNDED_TEXT: usize = 4_096;
const MAX_REASONS: usize = 64;

/// Inventories repository GraphQL SDL and executable documents as inert,
/// bounded data. It never loads project configuration, performs introspection,
/// starts project code, or opens a network client.
pub fn scan_graphql_repository(
    root: &Path,
    participating_profiles: &[Profile],
) -> Result<Option<CrossLanguageAdapterDelta>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("GraphQL scan root {} is unavailable", root.display()))?;
    if !canonical_root.is_dir() {
        bail!("GraphQL scan root must be a directory");
    }
    let mut participating_profiles = participating_profiles.to_vec();
    participating_profiles.sort_by(|left, right| left.id.cmp(&right.id));
    if participating_profiles.is_empty()
        || participating_profiles.len() > MAX_PARTICIPATING_PROFILES
        || participating_profiles
            .iter()
            .any(|profile| !bounded_text(&profile.id))
        || participating_profiles
            .windows(2)
            .any(|profiles| profiles[0].id == profiles[1].id)
    {
        bail!("GraphQL participating profiles must be a bounded non-empty set");
    }
    let participating_profile_ids = participating_profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();

    let records = inventory_graphql_sources(&canonical_root)?;
    if records.is_empty() {
        return Ok(None);
    }
    let documents = records
        .iter()
        .filter_map(|record| {
            record
                .document
                .clone()
                .map(|document| (record.locator.clone(), document))
        })
        .collect::<BTreeMap<_, _>>();
    let input_digest = digest_value(&json!(
        records
            .iter()
            .map(SourceRecord::identity_value)
            .collect::<Vec<_>>()
    ));
    let profile_identity = CrossLanguageProfileIdentity {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        contract_input_digest: input_digest,
        adapter_capability_versions: vec![GRAPHQL_CAPABILITY.to_owned()],
        participating_profile_ids,
    };
    let profile_id = cross_language_profile_id(&profile_identity);
    let mut builder = GraphQlGraphBuilder::new(profile_id.clone(), documents);
    builder.build()?;
    for reason in records.iter().filter_map(|record| record.reason.as_deref()) {
        builder.insert_reason(reason);
    }
    let skipped_count = records
        .iter()
        .filter(|record| record.document.is_none())
        .count() as u64;
    let status = if builder.unresolved_count > 0 || skipped_count > 0 || !builder.reasons.is_empty()
    {
        CrossLanguageCapabilityStatus::Incomplete
    } else {
        CrossLanguageCapabilityStatus::Complete
    };
    let ledger = CrossLanguageCompletenessLedger {
        schema_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        entries: vec![CrossLanguageFormatCoverage {
            format: CrossLanguageFormat::Graphql,
            capability: GRAPHQL_CAPABILITY.to_owned(),
            status,
            input_count: records.len() as u64,
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
        participating_profiles,
        nodes: builder.nodes.into_values().collect(),
        sites: builder.sites.into_values().collect(),
        edges: builder.edges.into_values().collect(),
    };
    validate_cross_language_adapter_delta(&delta)
        .map_err(anyhow::Error::from)
        .context("GraphQL adapter produced an invalid common-contract closure")?;
    Ok(Some(delta))
}

#[derive(Clone, Debug)]
struct SourceRecord {
    locator: String,
    digest: String,
    document: Option<GraphQlDocument>,
    reason: Option<String>,
}

impl SourceRecord {
    fn identity_value(&self) -> Value {
        json!({
            "locator": self.locator,
            "digest": self.digest,
            "status": if self.document.is_some() { "admitted" } else { "skipped" },
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug)]
struct GraphQlDocument {
    digest: String,
    definitions: Vec<Definition>,
}

#[derive(Clone, Debug)]
enum Definition {
    Schema(SchemaDefinition),
    Type(TypeDefinition),
    Directive(DirectiveDefinition),
    Operation(OperationDefinition),
    Fragment(FragmentDefinition),
}

#[derive(Clone, Debug)]
struct SchemaDefinition {
    extend: bool,
    roots: BTreeMap<OperationKind, String>,
    directives: Vec<DirectiveUse>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct TypeDefinition {
    kind: TypeKind,
    name: String,
    extend: bool,
    fields: Vec<FieldDefinition>,
    referenced_types: Vec<TypeReferenceSite>,
    directives: Vec<DirectiveUse>,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum TypeKind {
    Enum,
    Input,
    Interface,
    Object,
    Scalar,
    Union,
}

impl TypeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Enum => "enum",
            Self::Input => "input",
            Self::Interface => "interface",
            Self::Object => "object",
            Self::Scalar => "scalar",
            Self::Union => "union",
        }
    }
}

#[derive(Clone, Debug)]
struct FieldDefinition {
    name: String,
    arguments: Vec<TypeReferenceSite>,
    output: TypeReferenceSite,
    directives: Vec<DirectiveUse>,
}

#[derive(Clone, Debug)]
struct TypeReferenceSite {
    named_type: String,
    rendered: String,
    role: &'static str,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct DirectiveDefinition {
    name: String,
    arguments: Vec<TypeReferenceSite>,
    directives: Vec<DirectiveUse>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct OperationDefinition {
    kind: OperationKind,
    name: String,
    variables: Vec<TypeReferenceSite>,
    directives: Vec<DirectiveUse>,
    selections: Vec<Selection>,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum OperationKind {
    Mutation,
    Query,
    Subscription,
}

impl OperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mutation => "mutation",
            Self::Query => "query",
            Self::Subscription => "subscription",
        }
    }

    const fn default_root(self) -> &'static str {
        match self {
            Self::Mutation => "Mutation",
            Self::Query => "Query",
            Self::Subscription => "Subscription",
        }
    }
}

#[derive(Clone, Debug)]
struct FragmentDefinition {
    name: String,
    type_condition: String,
    directives: Vec<DirectiveUse>,
    selections: Vec<Selection>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
enum Selection {
    Field(FieldSelection),
    FragmentSpread(FragmentSpread),
    InlineFragment(InlineFragment),
}

#[derive(Clone, Debug)]
struct FieldSelection {
    response_name: String,
    field_name: String,
    directives: Vec<DirectiveUse>,
    selections: Vec<Selection>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct FragmentSpread {
    name: String,
    directives: Vec<DirectiveUse>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct InlineFragment {
    type_condition: Option<String>,
    directives: Vec<DirectiveUse>,
    selections: Vec<Selection>,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
struct DirectiveUse {
    name: String,
    dynamic: bool,
    static_booleans: BTreeMap<String, bool>,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceSpan {
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

fn inventory_graphql_sources(root: &Path) -> Result<Vec<SourceRecord>> {
    let mut records = Vec::new();
    let mut total_bytes = 0_usize;
    let mut inventory_entries = 0_usize;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        record_graphql_inventory_entry(&mut inventory_entries)?;
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
        if !is_graphql_locator(&locator) {
            continue;
        }
        if entry.file_type().is_symlink() {
            push_graphql_source_record(
                &mut records,
                skipped_source(&locator, "graphql-source-symlink-not-admitted"),
            )?;
            continue;
        }
        if !entry.file_type().is_file() {
            push_graphql_source_record(
                &mut records,
                skipped_source(&locator, "graphql-source-is-not-a-file"),
            )?;
            continue;
        }
        let bytes = match read_bounded_repository_file(root, entry.path(), MAX_GRAPHQL_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                let reason = if error.code == "query_file_size_or_type_invalid" {
                    "graphql-source-byte-limit-exceeded"
                } else {
                    "graphql-source-read-failed"
                };
                push_graphql_source_record(&mut records, skipped_source(&locator, reason))?;
                continue;
            }
        };
        let Some(next_total_bytes) = total_bytes.checked_add(bytes.len()) else {
            bail!("GraphQL source inventory byte count overflowed");
        };
        if next_total_bytes > MAX_GRAPHQL_TOTAL_BYTES {
            push_graphql_source_record(
                &mut records,
                skipped_source(&locator, "graphql-source-total-byte-limit-exceeded"),
            )?;
            continue;
        }
        total_bytes = next_total_bytes;
        let digest = sha256_prefixed(&bytes);
        let source = match std::str::from_utf8(&bytes) {
            Ok(source) => source,
            Err(_) => {
                push_graphql_source_record(
                    &mut records,
                    SourceRecord {
                        locator,
                        digest,
                        document: None,
                        reason: Some("graphql-source-is-not-utf8".to_owned()),
                    },
                )?;
                continue;
            }
        };
        let document = match parse_graphql_document(source, &digest) {
            Ok(document) => document,
            Err(reason) => {
                push_graphql_source_record(
                    &mut records,
                    SourceRecord {
                        locator,
                        digest,
                        document: None,
                        reason: Some(reason),
                    },
                )?;
                continue;
            }
        };
        push_graphql_source_record(
            &mut records,
            SourceRecord {
                locator,
                digest,
                document: Some(document),
                reason: None,
            },
        )?;
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));
    Ok(records)
}

fn record_graphql_inventory_entry(inventory_entries: &mut usize) -> Result<()> {
    *inventory_entries = inventory_entries
        .checked_add(1)
        .context("GraphQL inventory entry count overflowed")?;
    if *inventory_entries > MAX_GRAPHQL_INVENTORY_ENTRIES {
        bail!("GraphQL inventory exceeds its closed entry limit");
    }
    Ok(())
}

fn push_graphql_source_record(records: &mut Vec<SourceRecord>, record: SourceRecord) -> Result<()> {
    if records.len() >= MAX_GRAPHQL_FILES {
        bail!("GraphQL inventory exceeds its closed source-file limit");
    }
    records.push(record);
    Ok(())
}

fn skipped_source(locator: &str, reason: &str) -> SourceRecord {
    SourceRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        document: None,
        reason: Some(reason.to_owned()),
    }
}

fn is_graphql_locator(locator: &str) -> bool {
    [".graphql", ".graphqls", ".gql"]
        .iter()
        .any(|suffix| locator.ends_with(suffix))
}

fn parse_graphql_document(
    source: &str,
    digest: &str,
) -> std::result::Result<GraphQlDocument, String> {
    let tokens = tokenize_graphql(source)?;
    let mut parser = GraphQlParser::new(tokens);
    let definitions = parser.parse_document()?;
    if definitions.is_empty() {
        return Err("graphql-document-is-empty".to_owned());
    }
    Ok(GraphQlDocument {
        digest: digest.to_owned(),
        definitions,
    })
}

#[derive(Clone, Debug)]
struct Token {
    text: String,
    kind: TokenKind,
    span: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Name,
    Number,
    Punctuator,
    String,
}

fn tokenize_graphql(source: &str) -> std::result::Result<Vec<Token>, String> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0_usize;
    let mut line = 1_u32;
    let mut column = 1_u32;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if byte == b',' || byte.is_ascii_whitespace() {
            advance_graphql(byte, &mut line, &mut column);
            cursor += 1;
            continue;
        }
        if byte == b'#' {
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                advance_graphql(bytes[cursor], &mut line, &mut column);
                cursor += 1;
            }
            continue;
        }
        if tokens.len() >= MAX_GRAPHQL_TOKENS {
            return Err("graphql-token-count-limit-exceeded".to_owned());
        }
        let start_line = line;
        let start_column = column;
        let start = cursor;
        let kind = if byte.is_ascii_alphabetic() || byte == b'_' {
            cursor += 1;
            column += 1;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
                column += 1;
            }
            TokenKind::Name
        } else if byte == b'-' || byte.is_ascii_digit() {
            cursor += 1;
            column += 1;
            while cursor < bytes.len()
                && matches!(
                    bytes[cursor],
                    b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                )
            {
                cursor += 1;
                column += 1;
            }
            TokenKind::Number
        } else if byte == b'"' {
            let block = bytes.get(cursor..cursor + 3) == Some(b"\"\"\"");
            let delimiter = if block { 3 } else { 1 };
            for _ in 0..delimiter {
                cursor += 1;
                column += 1;
            }
            let mut escaped = false;
            loop {
                if cursor >= bytes.len() {
                    return Err("graphql-string-is-unterminated".to_owned());
                }
                if block && bytes.get(cursor..cursor + 3) == Some(b"\"\"\"") {
                    for _ in 0..3 {
                        cursor += 1;
                        column += 1;
                    }
                    break;
                }
                let current = bytes[cursor];
                if !block && current == b'"' && !escaped {
                    cursor += 1;
                    column += 1;
                    break;
                }
                if !block && matches!(current, b'\n' | b'\r') {
                    return Err("graphql-string-contains-newline".to_owned());
                }
                escaped = !block && current == b'\\' && !escaped;
                if current != b'\\' {
                    escaped = false;
                }
                advance_graphql(current, &mut line, &mut column);
                cursor += 1;
            }
            TokenKind::String
        } else if bytes.get(cursor..cursor + 3) == Some(b"...") {
            cursor += 3;
            column += 3;
            TokenKind::Punctuator
        } else if matches!(
            byte,
            b'!' | b'$'
                | b'&'
                | b'('
                | b')'
                | b':'
                | b'='
                | b'@'
                | b'['
                | b']'
                | b'{'
                | b'|'
                | b'}'
        ) {
            cursor += 1;
            column += 1;
            TokenKind::Punctuator
        } else {
            return Err("graphql-source-contains-invalid-token".to_owned());
        };
        let text = source
            .get(start..cursor)
            .ok_or_else(|| "graphql-token-is-not-utf8".to_owned())?;
        if text.len() > MAX_BOUNDED_TEXT {
            return Err("graphql-token-byte-limit-exceeded".to_owned());
        }
        tokens.push(Token {
            text: text.to_owned(),
            kind,
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

fn advance_graphql(byte: u8, line: &mut u32, column: &mut u32) {
    if byte == b'\n' {
        *line = line.saturating_add(1);
        *column = 1;
    } else {
        *column = column.saturating_add(1);
    }
}

struct GraphQlParser {
    tokens: Vec<Token>,
    cursor: usize,
    definitions: usize,
    selections: usize,
    operations: usize,
    anonymous_operations: usize,
}

impl GraphQlParser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            cursor: 0,
            definitions: 0,
            selections: 0,
            operations: 0,
            anonymous_operations: 0,
        }
    }

    fn parse_document(&mut self) -> std::result::Result<Vec<Definition>, String> {
        let mut definitions = Vec::new();
        while self.cursor < self.tokens.len() {
            while self.peek_kind() == Some(TokenKind::String) {
                self.cursor += 1;
            }
            if self.cursor >= self.tokens.len() {
                break;
            }
            if self.definitions >= MAX_GRAPHQL_DEFINITIONS {
                return Err("graphql-definition-count-limit-exceeded".to_owned());
            }
            let extend = self.consume("extend");
            let definition = match self.peek_text() {
                Some("schema") => Definition::Schema(self.parse_schema(extend)?),
                Some("scalar" | "type" | "interface" | "input" | "enum" | "union") => {
                    Definition::Type(self.parse_type(extend)?)
                }
                Some("directive") if !extend => Definition::Directive(self.parse_directive()?),
                Some("query" | "mutation" | "subscription") if !extend => {
                    Definition::Operation(self.parse_operation(false)?)
                }
                Some("fragment") if !extend => Definition::Fragment(self.parse_fragment()?),
                Some("{") if !extend => Definition::Operation(self.parse_operation(true)?),
                _ => return Err("graphql-definition-is-unsupported".to_owned()),
            };
            if matches!(&definition, Definition::Operation(_)) {
                self.operations += 1;
            }
            self.definitions += 1;
            definitions.push(definition);
        }
        if self.anonymous_operations > 0 && self.operations > 1 {
            return Err("graphql-anonymous-operation-is-ambiguous".to_owned());
        }
        Ok(definitions)
    }

    fn parse_schema(&mut self, extend: bool) -> std::result::Result<SchemaDefinition, String> {
        let start = self.expect("schema")?.span;
        let directives = self.parse_directives()?;
        let mut roots = BTreeMap::new();
        let end = if extend && self.peek_text() != Some("{") {
            directives.last().map_or(start, |directive| directive.span)
        } else {
            self.expect("{")?;
            while self.peek_text() != Some("}") {
                let kind = self.parse_operation_kind()?;
                self.expect(":")?;
                let target = self.expect_name()?.text;
                if roots.insert(kind, target).is_some() {
                    return Err("duplicate-graphql-schema-root".to_owned());
                }
            }
            self.expect("}")?.span
        };
        Ok(SchemaDefinition {
            extend,
            roots,
            directives,
            span: merge_span(start, end),
        })
    }

    fn parse_type(&mut self, extend: bool) -> std::result::Result<TypeDefinition, String> {
        let keyword = self
            .bump()
            .filter(|token| token.kind == TokenKind::Name)
            .ok_or_else(|| "graphql-type-kind-is-missing".to_owned())?;
        let kind = match keyword.text.as_str() {
            "scalar" => TypeKind::Scalar,
            "type" => TypeKind::Object,
            "interface" => TypeKind::Interface,
            "input" => TypeKind::Input,
            "enum" => TypeKind::Enum,
            "union" => TypeKind::Union,
            _ => return Err("graphql-type-kind-is-unsupported".to_owned()),
        };
        let start = keyword.span;
        let name = self.expect_name()?.text;
        let mut referenced_types = Vec::new();
        if self.consume("implements") {
            self.consume("&");
            loop {
                let token = self.expect_name()?;
                referenced_types.push(TypeReferenceSite {
                    named_type: token.text.clone(),
                    rendered: token.text,
                    role: "implements",
                    span: token.span,
                });
                if !self.consume("&") {
                    break;
                }
            }
        }
        let directives = self.parse_directives()?;
        let mut fields = Vec::new();
        let end = match kind {
            TypeKind::Scalar => directives.last().map_or(start, |directive| directive.span),
            TypeKind::Union => {
                if extend && !directives.is_empty() && self.peek_text() != Some("=") {
                    directives.last().map_or(start, |directive| directive.span)
                } else {
                    self.expect("=")?;
                    self.consume("|");
                    let token = self.expect_name()?;
                    let mut end = token.span;
                    referenced_types.push(TypeReferenceSite {
                        named_type: token.text.clone(),
                        rendered: token.text,
                        role: "union_member",
                        span: token.span,
                    });
                    while self.consume("|") {
                        let token = self.expect_name()?;
                        end = token.span;
                        referenced_types.push(TypeReferenceSite {
                            named_type: token.text.clone(),
                            rendered: token.text,
                            role: "union_member",
                            span: token.span,
                        });
                    }
                    end
                }
            }
            TypeKind::Enum => {
                if extend && !directives.is_empty() && self.peek_text() != Some("{") {
                    directives.last().map_or(start, |directive| directive.span)
                } else {
                    self.expect("{")?;
                    while self.peek_text() != Some("}") {
                        while self.peek_kind() == Some(TokenKind::String) {
                            self.cursor += 1;
                        }
                        self.expect_name()?;
                        self.parse_directives()?;
                    }
                    self.expect("}")?.span
                }
            }
            TypeKind::Input | TypeKind::Interface | TypeKind::Object => {
                if extend
                    && self.peek_text() != Some("{")
                    && (!directives.is_empty() || !referenced_types.is_empty())
                {
                    directives
                        .last()
                        .map(|directive| directive.span)
                        .or_else(|| referenced_types.last().map(|reference| reference.span))
                        .unwrap_or(start)
                } else {
                    self.expect("{")?;
                    while self.peek_text() != Some("}") {
                        while self.peek_kind() == Some(TokenKind::String) {
                            self.cursor += 1;
                        }
                        fields.push(self.parse_field_definition(kind == TypeKind::Input)?);
                    }
                    self.expect("}")?.span
                }
            }
        };
        Ok(TypeDefinition {
            kind,
            name,
            extend,
            fields,
            referenced_types,
            directives,
            span: merge_span(start, end),
        })
    }

    fn parse_field_definition(
        &mut self,
        input_field: bool,
    ) -> std::result::Result<FieldDefinition, String> {
        let name = self.expect_name()?;
        let arguments = if !input_field && self.consume("(") {
            self.parse_input_value_definitions("argument")?
        } else {
            Vec::new()
        };
        self.expect(":")?;
        let output = self.parse_type_reference(if input_field {
            "input_field"
        } else {
            "field_output"
        })?;
        if input_field && self.consume("=") {
            self.skip_value()?;
        }
        let directives = self.parse_directives()?;
        Ok(FieldDefinition {
            name: name.text,
            arguments,
            output,
            directives,
        })
    }

    fn parse_input_value_definitions(
        &mut self,
        role: &'static str,
    ) -> std::result::Result<Vec<TypeReferenceSite>, String> {
        let mut values = Vec::new();
        while self.peek_text() != Some(")") {
            while self.peek_kind() == Some(TokenKind::String) {
                self.cursor += 1;
            }
            self.expect_name()?;
            self.expect(":")?;
            values.push(self.parse_type_reference(role)?);
            if self.consume("=") {
                self.skip_value()?;
            }
            self.parse_directives()?;
        }
        self.expect(")")?;
        Ok(values)
    }

    fn parse_directive(&mut self) -> std::result::Result<DirectiveDefinition, String> {
        let start = self.expect("directive")?.span;
        self.expect("@")?;
        let name = self.expect_name()?.text;
        let arguments = if self.consume("(") {
            self.parse_input_value_definitions("directive_argument")?
        } else {
            Vec::new()
        };
        self.consume("repeatable");
        self.expect("on")?;
        self.consume("|");
        let mut end = self.expect_name()?.span;
        while self.consume("|") {
            end = self.expect_name()?.span;
        }
        Ok(DirectiveDefinition {
            name,
            arguments,
            directives: Vec::new(),
            span: merge_span(start, end),
        })
    }

    fn parse_operation(
        &mut self,
        shorthand: bool,
    ) -> std::result::Result<OperationDefinition, String> {
        let (kind, start, name) = if shorthand {
            self.anonymous_operations += 1;
            (
                OperationKind::Query,
                self.peek()
                    .map(|token| token.span)
                    .ok_or_else(|| "graphql-operation-is-missing".to_owned())?,
                format!("anonymous#{}", self.anonymous_operations),
            )
        } else {
            let token = self
                .bump()
                .ok_or_else(|| "graphql-operation-kind-is-missing".to_owned())?;
            let kind = parse_operation_kind_text(&token.text)?;
            let name = if matches!(self.peek_text(), Some("(" | "@" | "{")) {
                self.anonymous_operations += 1;
                format!("anonymous#{}", self.anonymous_operations)
            } else {
                self.expect_name()?.text
            };
            (kind, token.span, name)
        };
        let variables = if self.consume("(") {
            let mut variables = Vec::new();
            while self.peek_text() != Some(")") {
                self.expect("$")?;
                self.expect_name()?;
                self.expect(":")?;
                variables.push(self.parse_type_reference("variable")?);
                if self.consume("=") {
                    self.skip_value()?;
                }
                self.parse_directives()?;
            }
            self.expect(")")?;
            variables
        } else {
            Vec::new()
        };
        let directives = self.parse_directives()?;
        let (selections, end) = self.parse_selection_set(0)?;
        Ok(OperationDefinition {
            kind,
            name,
            variables,
            directives,
            selections,
            span: merge_span(start, end),
        })
    }

    fn parse_fragment(&mut self) -> std::result::Result<FragmentDefinition, String> {
        let start = self.expect("fragment")?.span;
        let name = self.expect_name()?.text;
        if name == "on" {
            return Err("graphql-fragment-name-is-invalid".to_owned());
        }
        self.expect("on")?;
        let type_condition = self.expect_name()?.text;
        let directives = self.parse_directives()?;
        let (selections, end) = self.parse_selection_set(0)?;
        Ok(FragmentDefinition {
            name,
            type_condition,
            directives,
            selections,
            span: merge_span(start, end),
        })
    }

    fn parse_selection_set(
        &mut self,
        depth: usize,
    ) -> std::result::Result<(Vec<Selection>, SourceSpan), String> {
        if depth >= MAX_GRAPHQL_DEPTH {
            return Err("graphql-selection-depth-limit-exceeded".to_owned());
        }
        self.expect("{")?;
        let mut selections = Vec::new();
        while self.peek_text() != Some("}") {
            if self.selections >= MAX_GRAPHQL_SELECTIONS {
                return Err("graphql-selection-count-limit-exceeded".to_owned());
            }
            let selection = if self.consume("...") {
                let start = self.tokens[self.cursor - 1].span;
                if self.consume("on") {
                    let type_condition = Some(self.expect_name()?.text);
                    let directives = self.parse_directives()?;
                    let (nested, end) = self.parse_selection_set(depth + 1)?;
                    Selection::InlineFragment(InlineFragment {
                        type_condition,
                        directives,
                        selections: nested,
                        span: merge_span(start, end),
                    })
                } else if self.peek_text() == Some("@") {
                    let directives = self.parse_directives()?;
                    let (nested, end) = self.parse_selection_set(depth + 1)?;
                    Selection::InlineFragment(InlineFragment {
                        type_condition: None,
                        directives,
                        selections: nested,
                        span: merge_span(start, end),
                    })
                } else {
                    let name = self.expect_name()?;
                    let directives = self.parse_directives()?;
                    let end = directives
                        .last()
                        .map_or(name.span, |directive| directive.span);
                    Selection::FragmentSpread(FragmentSpread {
                        name: name.text,
                        directives,
                        span: merge_span(start, end),
                    })
                }
            } else {
                let first = self.expect_name()?;
                let start = first.span;
                let (response_name, field_name) = if self.consume(":") {
                    (first.text, self.expect_name()?.text)
                } else {
                    (first.text.clone(), first.text)
                };
                if self.consume("(") {
                    self.skip_balanced("(", ")")?;
                }
                let directives = self.parse_directives()?;
                let (nested, end) = if self.peek_text() == Some("{") {
                    self.parse_selection_set(depth + 1)?
                } else {
                    (
                        Vec::new(),
                        directives.last().map_or(start, |directive| directive.span),
                    )
                };
                Selection::Field(FieldSelection {
                    response_name,
                    field_name,
                    directives,
                    selections: nested,
                    span: merge_span(start, end),
                })
            };
            self.selections += 1;
            selections.push(selection);
        }
        let end = self.expect("}")?.span;
        Ok((selections, end))
    }

    fn parse_directives(&mut self) -> std::result::Result<Vec<DirectiveUse>, String> {
        let mut directives = Vec::new();
        while self.consume("@") {
            let start = self.tokens[self.cursor - 1].span;
            let name = self.expect_name()?;
            let mut dynamic = false;
            let mut static_booleans = BTreeMap::new();
            let mut end = name.span;
            if self.consume("(") {
                let begin = self.cursor;
                self.skip_balanced("(", ")")?;
                let values = &self.tokens[begin..self.cursor - 1];
                dynamic = values.iter().any(|token| token.text == "$");
                static_booleans = parse_static_boolean_arguments(values);
                end = self.tokens[self.cursor - 1].span;
            }
            directives.push(DirectiveUse {
                name: name.text,
                dynamic,
                static_booleans,
                span: merge_span(start, end),
            });
        }
        Ok(directives)
    }

    fn parse_type_reference(
        &mut self,
        role: &'static str,
    ) -> std::result::Result<TypeReferenceSite, String> {
        self.parse_type_reference_at_depth(role, 0)
    }

    fn parse_type_reference_at_depth(
        &mut self,
        role: &'static str,
        depth: usize,
    ) -> std::result::Result<TypeReferenceSite, String> {
        if depth >= MAX_GRAPHQL_DEPTH {
            return Err("graphql-type-depth-limit-exceeded".to_owned());
        }
        let start = self
            .peek()
            .map(|token| token.span)
            .ok_or_else(|| "graphql-type-reference-is-missing".to_owned())?;
        let (named_type, mut rendered, mut end) = if self.consume("[") {
            let inner = self.parse_type_reference_at_depth(role, depth + 1)?;
            let close = self.expect("]")?;
            (
                inner.named_type,
                format!("[{}]", inner.rendered),
                close.span,
            )
        } else {
            let name = self.expect_name()?;
            (name.text.clone(), name.text, name.span)
        };
        if self.consume("!") {
            rendered.push('!');
            end = self.tokens[self.cursor - 1].span;
        }
        Ok(TypeReferenceSite {
            named_type,
            rendered,
            role,
            span: merge_span(start, end),
        })
    }

    fn parse_operation_kind(&mut self) -> std::result::Result<OperationKind, String> {
        let token = self.expect_name()?;
        parse_operation_kind_text(&token.text)
    }

    fn skip_value(&mut self) -> std::result::Result<(), String> {
        match self.peek_text() {
            Some("[") => {
                self.cursor += 1;
                self.skip_balanced("[", "]")
            }
            Some("{") => {
                self.cursor += 1;
                self.skip_balanced("{", "}")
            }
            Some("$") => {
                self.cursor += 1;
                self.expect_name().map(|_| ())
            }
            Some(_) => {
                self.cursor += 1;
                Ok(())
            }
            None => Err("graphql-value-is-missing".to_owned()),
        }
    }

    fn skip_balanced(&mut self, open: &str, close: &str) -> std::result::Result<(), String> {
        let mut depth = 1_usize;
        while depth > 0 {
            let token = self
                .bump()
                .ok_or_else(|| "graphql-delimited-value-is-unterminated".to_owned())?;
            if token.text == open {
                depth += 1;
                if depth > MAX_GRAPHQL_DEPTH {
                    return Err("graphql-value-depth-limit-exceeded".to_owned());
                }
            } else if token.text == close {
                depth -= 1;
            }
        }
        Ok(())
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn peek_text(&self) -> Option<&str> {
        self.peek().map(|token| token.text.as_str())
    }

    fn peek_kind(&self) -> Option<TokenKind> {
        self.peek().map(|token| token.kind)
    }

    fn consume(&mut self, expected: &str) -> bool {
        if self.peek_text() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &str) -> std::result::Result<Token, String> {
        let token = self
            .bump()
            .ok_or_else(|| format!("graphql-expected-{expected}"))?;
        if token.text == expected {
            Ok(token)
        } else {
            Err(format!("graphql-expected-{expected}"))
        }
    }

    fn expect_name(&mut self) -> std::result::Result<Token, String> {
        self.bump()
            .filter(|token| token.kind == TokenKind::Name)
            .ok_or_else(|| "graphql-name-is-missing".to_owned())
    }

    fn bump(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.cursor).cloned();
        self.cursor += usize::from(token.is_some());
        token
    }
}

fn parse_operation_kind_text(value: &str) -> std::result::Result<OperationKind, String> {
    match value {
        "mutation" => Ok(OperationKind::Mutation),
        "query" => Ok(OperationKind::Query),
        "subscription" => Ok(OperationKind::Subscription),
        _ => Err("graphql-operation-kind-is-invalid".to_owned()),
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

#[derive(Clone)]
struct LocatedType {
    locator: String,
    definition: TypeDefinition,
}

#[derive(Clone)]
struct LocatedDirective {
    locator: String,
    definition: DirectiveDefinition,
}

#[derive(Clone)]
struct LocatedOperation {
    locator: String,
    definition: OperationDefinition,
}

#[derive(Clone)]
struct LocatedFragment {
    locator: String,
    definition: FragmentDefinition,
}

struct GraphQlGraphBuilder {
    profile_id: String,
    documents: BTreeMap<String, GraphQlDocument>,
    nodes: BTreeMap<String, GraphNode>,
    cross_node_ids: BTreeSet<String>,
    sites: BTreeMap<String, DependencySite>,
    edges: BTreeMap<String, GraphEdge>,
    schema_ids: BTreeMap<String, String>,
    type_groups: BTreeMap<String, Vec<LocatedType>>,
    type_ids: BTreeMap<String, String>,
    valid_types: BTreeSet<String>,
    directive_groups: BTreeMap<String, Vec<LocatedDirective>>,
    directive_ids: BTreeMap<String, String>,
    operations: Vec<LocatedOperation>,
    operation_ids: BTreeMap<(String, String), String>,
    ambiguous_operation_keys: BTreeSet<(String, String)>,
    fragments: BTreeMap<String, Vec<LocatedFragment>>,
    fragment_ids: BTreeMap<String, Vec<String>>,
    fragment_cycles: BTreeSet<String>,
    schema_roots: BTreeMap<OperationKind, Vec<(String, String, SourceSpan)>>,
    schema_definition_count: usize,
    unresolved_count: u64,
    reasons: BTreeSet<String>,
}

impl GraphQlGraphBuilder {
    fn new(profile_id: String, documents: BTreeMap<String, GraphQlDocument>) -> Self {
        Self {
            profile_id,
            documents,
            nodes: BTreeMap::new(),
            cross_node_ids: BTreeSet::new(),
            sites: BTreeMap::new(),
            edges: BTreeMap::new(),
            schema_ids: BTreeMap::new(),
            type_groups: BTreeMap::new(),
            type_ids: BTreeMap::new(),
            valid_types: BTreeSet::new(),
            directive_groups: BTreeMap::new(),
            directive_ids: BTreeMap::new(),
            operations: Vec::new(),
            operation_ids: BTreeMap::new(),
            ambiguous_operation_keys: BTreeSet::new(),
            fragments: BTreeMap::new(),
            fragment_ids: BTreeMap::new(),
            fragment_cycles: BTreeSet::new(),
            schema_roots: BTreeMap::new(),
            schema_definition_count: 0,
            unresolved_count: 0,
            reasons: BTreeSet::new(),
        }
    }

    fn build(&mut self) -> Result<()> {
        self.collect_definitions()?;
        self.create_nodes()?;
        self.fragment_cycles = detect_fragment_cycles(&self.fragments);
        if !self.fragment_cycles.is_empty() {
            self.insert_reason("graphql-fragment-cycle");
        }
        self.build_schema_and_type_relations()?;
        self.build_fragment_relations()?;
        self.build_operation_relations()?;
        Ok(())
    }

    fn collect_definitions(&mut self) -> Result<()> {
        let documents = self
            .documents
            .iter()
            .map(|(locator, document)| (locator.clone(), document.clone()))
            .collect::<Vec<_>>();
        for (locator, document) in documents {
            for definition in document.definitions {
                match definition {
                    Definition::Schema(schema) => {
                        if !schema.extend {
                            self.schema_definition_count += 1;
                        }
                        if schema.extend && schema.roots.is_empty() && schema.directives.is_empty()
                        {
                            self.insert_reason("graphql-empty-schema-extension");
                        }
                        for (kind, target) in &schema.roots {
                            self.schema_roots.entry(*kind).or_default().push((
                                locator.clone(),
                                target.clone(),
                                schema.span,
                            ));
                        }
                        if schema
                            .directives
                            .iter()
                            .any(|directive| is_federation_directive(&directive.name))
                        {
                            self.insert_reason("graphql-federated-boundary");
                        }
                    }
                    Definition::Type(definition) => {
                        self.type_groups
                            .entry(definition.name.clone())
                            .or_default()
                            .push(LocatedType {
                                locator: locator.clone(),
                                definition,
                            });
                    }
                    Definition::Directive(definition) => {
                        self.directive_groups
                            .entry(definition.name.clone())
                            .or_default()
                            .push(LocatedDirective {
                                locator: locator.clone(),
                                definition,
                            });
                    }
                    Definition::Operation(definition) => {
                        self.operations.push(LocatedOperation {
                            locator: locator.clone(),
                            definition,
                        });
                    }
                    Definition::Fragment(definition) => {
                        self.fragments
                            .entry(definition.name.clone())
                            .or_default()
                            .push(LocatedFragment {
                                locator: locator.clone(),
                                definition,
                            });
                    }
                }
            }
        }
        self.operations.sort_by(|left, right| {
            (&left.locator, left.definition.kind, &left.definition.name).cmp(&(
                &right.locator,
                right.definition.kind,
                &right.definition.name,
            ))
        });
        for definitions in self.type_groups.values_mut() {
            definitions.sort_by(|left, right| {
                (
                    left.definition.extend,
                    &left.locator,
                    left.definition.span.start_line,
                )
                    .cmp(&(
                        right.definition.extend,
                        &right.locator,
                        right.definition.span.start_line,
                    ))
            });
        }
        for definitions in self.directive_groups.values_mut() {
            definitions.sort_by(|left, right| left.locator.cmp(&right.locator));
        }
        for definitions in self.fragments.values_mut() {
            definitions.sort_by(|left, right| left.locator.cmp(&right.locator));
        }
        Ok(())
    }

    fn create_nodes(&mut self) -> Result<()> {
        let locators = self.documents.keys().cloned().collect::<Vec<_>>();
        for locator in locators {
            let id = self.add_cross_node(
                CrossLanguageNodeKind::Schema,
                &locator,
                &format!("schema {locator}"),
            )?;
            self.schema_ids.insert(locator, id);
        }

        let type_names = self.type_groups.keys().cloned().collect::<Vec<_>>();
        for name in type_names {
            let definitions = self.type_groups[&name].clone();
            let bases = definitions
                .iter()
                .filter(|definition| !definition.definition.extend)
                .collect::<Vec<_>>();
            let owner = bases
                .first()
                .copied()
                .or_else(|| definitions.first())
                .context("GraphQL type group unexpectedly empty")?;
            let kinds = definitions
                .iter()
                .map(|definition| definition.definition.kind)
                .collect::<BTreeSet<_>>();
            let id = self.add_cross_node(
                CrossLanguageNodeKind::Message,
                &owner.locator,
                &format!("{} {name}", owner.definition.kind.as_str()),
            )?;
            self.type_ids.insert(name.clone(), id);
            if bases.len() == 1 && kinds.len() == 1 {
                self.valid_types.insert(name.clone());
            } else if bases.is_empty() {
                self.insert_reason("graphql-extension-base-is-missing");
            } else {
                self.insert_reason("ambiguous-graphql-type-definition");
            }
            let mut field_names = BTreeMap::<String, usize>::new();
            for definition in definitions {
                for field in definition.definition.fields {
                    *field_names.entry(field.name).or_default() += 1;
                }
            }
            if field_names.values().any(|count| *count > 1) {
                self.insert_reason("ambiguous-graphql-field-definition");
            }
        }

        let directive_names = self.directive_groups.keys().cloned().collect::<Vec<_>>();
        for name in directive_names {
            let definitions = self.directive_groups[&name].clone();
            let owner = &definitions[0];
            let id = self.add_cross_node(
                CrossLanguageNodeKind::Message,
                &owner.locator,
                &format!("directive @{name}"),
            )?;
            self.directive_ids.insert(name, id);
            if definitions.len() > 1 {
                self.insert_reason("ambiguous-graphql-directive-definition");
            }
        }

        let fragment_names = self.fragments.keys().cloned().collect::<Vec<_>>();
        for name in fragment_names {
            let definitions = self.fragments[&name].clone();
            let mut ids = Vec::new();
            for fragment in definitions {
                ids.push(self.add_cross_node(
                    CrossLanguageNodeKind::Message,
                    &fragment.locator,
                    &format!(
                        "fragment {} on {}",
                        fragment.definition.name, fragment.definition.type_condition
                    ),
                )?);
            }
            if ids.len() > 1 {
                self.insert_reason("ambiguous-graphql-fragment-definition");
            }
            self.fragment_ids.insert(name, ids);
        }

        for operation in self.operations.clone() {
            let coordinate = format!(
                "{} {}",
                operation.definition.kind.as_str(),
                operation.definition.name
            );
            let id = self.add_cross_node(
                CrossLanguageNodeKind::Operation,
                &operation.locator,
                &coordinate,
            )?;
            let key = (operation.locator.clone(), coordinate);
            if self.operation_ids.insert(key.clone(), id).is_some() {
                self.ambiguous_operation_keys.insert(key);
                self.insert_reason("ambiguous-graphql-operation-definition");
            }
        }
        Ok(())
    }

    fn build_schema_and_type_relations(&mut self) -> Result<()> {
        let type_names = self.type_groups.keys().cloned().collect::<Vec<_>>();
        for name in type_names {
            let definitions = self.type_groups[&name].clone();
            let target = self.type_ids[&name].clone();
            let valid = self.valid_types.contains(&name);
            for located in definitions {
                let schema_id = self.schema_ids[&located.locator].clone();
                self.relation_or_unknown(RelationRequest {
                    source: &schema_id,
                    target: valid.then_some(target.as_str()),
                    relation: CrossLanguageRelationKind::ReferencesSchema,
                    locator: &located.locator,
                    span: located.definition.span,
                    coordinate: format!(
                        "{} {}",
                        located.definition.kind.as_str(),
                        located.definition.name
                    ),
                    reason: (!valid).then_some("ambiguous-graphql-type-definition"),
                    conditions: vec![(
                        "graphql.definition_kind",
                        Value::String(located.definition.kind.as_str().to_owned()),
                    )],
                })?;
                if valid {
                    self.build_one_type_relations(&target, &located)?;
                }
            }
        }

        let directive_names = self.directive_groups.keys().cloned().collect::<Vec<_>>();
        for name in directive_names {
            let definitions = self.directive_groups[&name].clone();
            let target = self.directive_ids[&name].clone();
            let valid = definitions.len() == 1;
            for located in definitions {
                let schema_id = self.schema_ids[&located.locator].clone();
                self.relation_or_unknown(RelationRequest {
                    source: &schema_id,
                    target: valid.then_some(target.as_str()),
                    relation: CrossLanguageRelationKind::ReferencesSchema,
                    locator: &located.locator,
                    span: located.definition.span,
                    coordinate: format!("directive @{}", located.definition.name),
                    reason: (!valid).then_some("ambiguous-graphql-directive-definition"),
                    conditions: vec![(
                        "graphql.definition_kind",
                        Value::String("directive".to_owned()),
                    )],
                })?;
                for argument in &located.definition.arguments {
                    self.add_type_reference(
                        &target,
                        CrossLanguageRelationKind::ReferencesSchema,
                        &located.locator,
                        argument,
                        &[],
                    )?;
                }
                self.add_directive_uses(
                    &target,
                    CrossLanguageRelationKind::ReferencesSchema,
                    &located.locator,
                    &located.definition.directives,
                )?;
            }
        }

        let roots = self.schema_roots.clone();
        for (kind, declarations) in roots {
            if declarations.len() > 1 {
                self.insert_reason("ambiguous-graphql-schema-root");
            }
            for (locator, target_name, span) in declarations {
                let schema_id = self.schema_ids[&locator].clone();
                let target = self.unique_type_id(&target_name);
                self.relation_or_unknown(RelationRequest {
                    source: &schema_id,
                    target: target.as_deref(),
                    relation: CrossLanguageRelationKind::ReferencesSchema,
                    locator: &locator,
                    span,
                    coordinate: format!("{} root {target_name}", kind.as_str()),
                    reason: target
                        .is_none()
                        .then_some("graphql-schema-root-type-is-unresolved"),
                    conditions: vec![(
                        "graphql.operation_type",
                        Value::String(kind.as_str().to_owned()),
                    )],
                })?;
            }
        }
        Ok(())
    }

    fn build_one_type_relations(&mut self, type_id: &str, located: &LocatedType) -> Result<()> {
        for reference in &located.definition.referenced_types {
            self.add_type_reference(
                type_id,
                CrossLanguageRelationKind::ReferencesSchema,
                &located.locator,
                reference,
                &[],
            )?;
        }
        for field in &located.definition.fields {
            for argument in &field.arguments {
                self.add_type_reference(
                    type_id,
                    CrossLanguageRelationKind::ReferencesSchema,
                    &located.locator,
                    argument,
                    &[("graphql.field", Value::String(field.name.clone()))],
                )?;
            }
            self.add_type_reference(
                type_id,
                CrossLanguageRelationKind::ReferencesSchema,
                &located.locator,
                &field.output,
                &[("graphql.field", Value::String(field.name.clone()))],
            )?;
            self.add_directive_uses(
                type_id,
                CrossLanguageRelationKind::ReferencesSchema,
                &located.locator,
                &field.directives,
            )?;
        }
        self.add_directive_uses(
            type_id,
            CrossLanguageRelationKind::ReferencesSchema,
            &located.locator,
            &located.definition.directives,
        )?;
        Ok(())
    }

    fn build_fragment_relations(&mut self) -> Result<()> {
        let names = self.fragments.keys().cloned().collect::<Vec<_>>();
        for name in names {
            let fragments = self.fragments[&name].clone();
            let fragment_ids = self.fragment_ids[&name].clone();
            let ambiguity_reason =
                (fragments.len() > 1).then_some("ambiguous-graphql-fragment-definition");
            for (index, fragment) in fragments.iter().enumerate() {
                let source_id = &fragment_ids[index];
                let target = self.unique_type_id(&fragment.definition.type_condition);
                let reason = ambiguity_reason.or_else(|| {
                    target
                        .is_none()
                        .then_some("graphql-fragment-type-is-unresolved")
                });
                self.relation_or_unknown(RelationRequest {
                    source: source_id,
                    target: target.as_deref().filter(|_| reason.is_none()),
                    relation: CrossLanguageRelationKind::ReferencesSchema,
                    locator: &fragment.locator,
                    span: fragment.definition.span,
                    coordinate: format!("fragment {} type", fragment.definition.name),
                    reason,
                    conditions: vec![(
                        "graphql.fragment",
                        Value::String(fragment.definition.name.clone()),
                    )],
                })?;
                self.add_directive_uses(
                    source_id,
                    CrossLanguageRelationKind::ReferencesSchema,
                    &fragment.locator,
                    &fragment.definition.directives,
                )?;
                self.build_fragment_selection_relations(
                    source_id,
                    &fragment.locator,
                    &fragment.definition.type_condition,
                    &fragment.definition.selections,
                    &fragment.definition.name,
                    ambiguity_reason,
                )?;
            }
        }
        Ok(())
    }

    fn build_fragment_selection_relations(
        &mut self,
        source_id: &str,
        locator: &str,
        current_type: &str,
        selections: &[Selection],
        fragment_name: &str,
        forced_reason: Option<&'static str>,
    ) -> Result<()> {
        for selection in selections {
            match selection {
                Selection::FragmentSpread(spread) => {
                    let target = self.unique_fragment_id(&spread.name);
                    let cycle = self.fragment_cycles.contains(fragment_name)
                        && self.fragment_cycles.contains(&spread.name);
                    let reason = if let Some(reason) = forced_reason {
                        Some(reason)
                    } else if cycle {
                        Some("graphql-fragment-cycle")
                    } else if let Some(reason) = directive_boundary_reason(&spread.directives) {
                        Some(reason)
                    } else if self
                        .fragments
                        .get(&spread.name)
                        .is_some_and(|fragments| fragments.len() > 1)
                    {
                        Some("ambiguous-graphql-fragment-definition")
                    } else if target.is_none() {
                        Some("graphql-fragment-is-missing")
                    } else {
                        None
                    };
                    self.relation_or_unknown(RelationRequest {
                        source: source_id,
                        target: target.as_deref().filter(|_| reason.is_none()),
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        locator,
                        span: spread.span,
                        coordinate: format!("fragment spread {}", spread.name),
                        reason,
                        conditions: directive_conditions(&spread.directives),
                    })?;
                }
                Selection::InlineFragment(inline) => {
                    let next_type = inline.type_condition.as_deref().unwrap_or(current_type);
                    if let Some(type_condition) = &inline.type_condition {
                        let target = self.unique_type_id(type_condition);
                        let reason = forced_reason
                            .or_else(|| directive_boundary_reason(&inline.directives))
                            .or_else(|| {
                                target
                                    .is_none()
                                    .then_some("graphql-inline-fragment-type-is-unresolved")
                            });
                        self.relation_or_unknown(RelationRequest {
                            source: source_id,
                            target: target.as_deref().filter(|_| reason.is_none()),
                            relation: CrossLanguageRelationKind::ReferencesSchema,
                            locator,
                            span: inline.span,
                            coordinate: format!("inline fragment on {type_condition}"),
                            reason,
                            conditions: directive_conditions(&inline.directives),
                        })?;
                    }
                    self.build_fragment_selection_relations(
                        source_id,
                        locator,
                        next_type,
                        &inline.selections,
                        fragment_name,
                        forced_reason,
                    )?;
                }
                Selection::Field(field) => {
                    self.build_field_selection(
                        source_id,
                        SelectionOwner::Fragment,
                        locator,
                        current_type,
                        field,
                        forced_reason,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn build_operation_relations(&mut self) -> Result<()> {
        for operation in self.operations.clone() {
            let coordinate = format!(
                "{} {}",
                operation.definition.kind.as_str(),
                operation.definition.name
            );
            let operation_key = (operation.locator.clone(), coordinate.clone());
            let operation_id = self.operation_ids[&operation_key].clone();
            let operation_reason = self
                .ambiguous_operation_keys
                .contains(&operation_key)
                .then_some("ambiguous-graphql-operation-definition");
            let root_name = self
                .operation_root(operation.definition.kind)
                .unwrap_or_else(|| operation.definition.kind.default_root().to_owned());
            let ambiguous_root = self
                .schema_roots
                .get(&operation.definition.kind)
                .is_some_and(|roots| roots.len() > 1);
            let root_id = (!ambiguous_root)
                .then(|| self.operation_root(operation.definition.kind))
                .flatten()
                .and_then(|name| self.unique_type_id(&name));
            let schema_root_reason = if ambiguous_root {
                Some("ambiguous-graphql-schema-root")
            } else if self.operation_root(operation.definition.kind).is_none() {
                Some("graphql-operation-root-is-not-declared")
            } else if root_id.is_none() {
                Some("graphql-operation-root-type-is-unresolved")
            } else {
                None
            };
            let root_reason = operation_reason.or(schema_root_reason);
            self.relation_or_unknown(RelationRequest {
                source: &operation_id,
                target: root_id.as_deref().filter(|_| root_reason.is_none()),
                relation: CrossLanguageRelationKind::ReturnsMessage,
                locator: &operation.locator,
                span: operation.definition.span,
                coordinate: format!("{} root {root_name}", operation.definition.kind.as_str()),
                reason: root_reason,
                conditions: vec![(
                    "graphql.operation_type",
                    Value::String(operation.definition.kind.as_str().to_owned()),
                )],
            })?;
            for variable in &operation.definition.variables {
                self.add_type_reference(
                    &operation_id,
                    CrossLanguageRelationKind::AcceptsMessage,
                    &operation.locator,
                    variable,
                    &[(
                        "graphql.operation",
                        Value::String(operation.definition.name.clone()),
                    )],
                )?;
            }
            self.add_directive_uses(
                &operation_id,
                CrossLanguageRelationKind::AcceptsMessage,
                &operation.locator,
                &operation.definition.directives,
            )?;
            let selection_root = if schema_root_reason.is_none() {
                root_name.as_str()
            } else {
                "<unresolved-root>"
            };
            for selection in &operation.definition.selections {
                self.build_operation_selection(
                    &operation_id,
                    &operation.locator,
                    selection_root,
                    selection,
                    &mut BTreeSet::new(),
                    operation_reason,
                    0,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_operation_selection(
        &mut self,
        operation_id: &str,
        locator: &str,
        current_type: &str,
        selection: &Selection,
        visited_fragments: &mut BTreeSet<String>,
        forced_reason: Option<&'static str>,
        traversal_depth: usize,
    ) -> Result<()> {
        let depth_reason = (traversal_depth >= MAX_GRAPHQL_DEPTH)
            .then_some("graphql-selection-expansion-depth-exceeded");
        if depth_reason.is_some() {
            self.insert_reason("graphql-selection-expansion-depth-exceeded");
        }
        match selection {
            Selection::Field(field) => {
                self.build_field_selection(
                    operation_id,
                    SelectionOwner::Operation,
                    locator,
                    current_type,
                    field,
                    forced_reason.or(depth_reason),
                )?;
                if traversal_depth < MAX_GRAPHQL_DEPTH
                    && let Some(next_type) = self.field_output_type(current_type, &field.field_name)
                {
                    for nested in &field.selections {
                        self.build_operation_selection(
                            operation_id,
                            locator,
                            &next_type,
                            nested,
                            visited_fragments,
                            forced_reason,
                            traversal_depth + 1,
                        )?;
                    }
                }
            }
            Selection::FragmentSpread(spread) => {
                let target = self.unique_fragment_id(&spread.name);
                let cycle = self.fragment_cycles.contains(&spread.name);
                let boundary_reason = if cycle {
                    Some("graphql-fragment-cycle")
                } else if let Some(reason) = directive_boundary_reason(&spread.directives) {
                    Some(reason)
                } else if self
                    .fragments
                    .get(&spread.name)
                    .is_some_and(|fragments| fragments.len() > 1)
                {
                    Some("ambiguous-graphql-fragment-definition")
                } else if target.is_none() {
                    Some("graphql-fragment-is-missing")
                } else {
                    None
                };
                let reason = forced_reason.or(depth_reason).or(boundary_reason);
                self.relation_or_unknown(RelationRequest {
                    source: operation_id,
                    target: target.as_deref().filter(|_| reason.is_none()),
                    relation: CrossLanguageRelationKind::ReturnsMessage,
                    locator,
                    span: spread.span,
                    coordinate: format!("fragment spread {}", spread.name),
                    reason,
                    conditions: directive_conditions(&spread.directives),
                })?;
                if boundary_reason.is_none()
                    && traversal_depth < MAX_GRAPHQL_DEPTH
                    && visited_fragments.insert(spread.name.clone())
                {
                    if let Some(fragment) = self.unique_fragment(&spread.name).cloned() {
                        for nested in &fragment.definition.selections {
                            self.build_operation_selection(
                                operation_id,
                                &fragment.locator,
                                &fragment.definition.type_condition,
                                nested,
                                visited_fragments,
                                forced_reason,
                                traversal_depth + 1,
                            )?;
                        }
                    }
                    visited_fragments.remove(&spread.name);
                }
            }
            Selection::InlineFragment(inline) => {
                let next_type = inline.type_condition.as_deref().unwrap_or(current_type);
                if let Some(type_condition) = &inline.type_condition {
                    let target = self.unique_type_id(type_condition);
                    let reason = forced_reason
                        .or(depth_reason)
                        .or_else(|| directive_boundary_reason(&inline.directives))
                        .or_else(|| {
                            target
                                .is_none()
                                .then_some("graphql-inline-fragment-type-is-unresolved")
                        });
                    self.relation_or_unknown(RelationRequest {
                        source: operation_id,
                        target: target.as_deref().filter(|_| reason.is_none()),
                        relation: CrossLanguageRelationKind::ReturnsMessage,
                        locator,
                        span: inline.span,
                        coordinate: format!("inline fragment on {type_condition}"),
                        reason,
                        conditions: directive_conditions(&inline.directives),
                    })?;
                } else if let Some(reason) = forced_reason.or(depth_reason) {
                    self.relation_or_unknown(RelationRequest {
                        source: operation_id,
                        target: None,
                        relation: CrossLanguageRelationKind::ReturnsMessage,
                        locator,
                        span: inline.span,
                        coordinate: "inline fragment".to_owned(),
                        reason: Some(reason),
                        conditions: directive_conditions(&inline.directives),
                    })?;
                }
                if traversal_depth < MAX_GRAPHQL_DEPTH {
                    for nested in &inline.selections {
                        self.build_operation_selection(
                            operation_id,
                            locator,
                            next_type,
                            nested,
                            visited_fragments,
                            forced_reason,
                            traversal_depth + 1,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn build_field_selection(
        &mut self,
        source_id: &str,
        owner: SelectionOwner,
        locator: &str,
        current_type: &str,
        field: &FieldSelection,
        forced_reason: Option<&'static str>,
    ) -> Result<()> {
        let field_output = self.field_output_type(current_type, &field.field_name);
        let mut reason = if let Some(reason) = forced_reason {
            Some(reason)
        } else if field.field_name.starts_with("__") {
            Some("graphql-introspection-not-admitted")
        } else if let Some(reason) = directive_boundary_reason(&field.directives) {
            Some(reason)
        } else if field_output.is_none() {
            Some("graphql-selected-field-is-unresolved")
        } else {
            None
        };
        let output_name = field_output.unwrap_or_else(|| field.field_name.clone());
        if is_builtin_scalar(&output_name) && !field.selections.is_empty() {
            reason = Some("graphql-scalar-selection-is-invalid");
        }
        if is_builtin_scalar(&output_name) && reason.is_none() {
            return Ok(());
        }
        let target = self.unique_type_id(&output_name);
        if target.is_none() && reason.is_none() {
            reason = Some("graphql-selected-type-is-unresolved");
        }
        let mut conditions = vec![
            ("graphql.field", Value::String(field.field_name.clone())),
            (
                "graphql.response_name",
                Value::String(field.response_name.clone()),
            ),
        ];
        conditions.extend(directive_conditions(&field.directives));
        self.relation_or_unknown(RelationRequest {
            source: source_id,
            target: target.as_deref().filter(|_| reason.is_none()),
            relation: match owner {
                SelectionOwner::Fragment => CrossLanguageRelationKind::ReferencesSchema,
                SelectionOwner::Operation => CrossLanguageRelationKind::ReturnsMessage,
            },
            locator,
            span: field.span,
            coordinate: format!("{current_type}.{}", field.field_name),
            reason,
            conditions,
        })
    }

    fn add_type_reference(
        &mut self,
        source: &str,
        relation: CrossLanguageRelationKind,
        locator: &str,
        reference: &TypeReferenceSite,
        extra_conditions: &[(&'static str, Value)],
    ) -> Result<()> {
        if is_builtin_scalar(&reference.named_type) {
            return Ok(());
        }
        let target = self.unique_type_id(&reference.named_type);
        let mut conditions = vec![
            (
                "graphql.type_reference",
                Value::String(reference.rendered.clone()),
            ),
            (
                "graphql.reference_role",
                Value::String(reference.role.to_owned()),
            ),
        ];
        conditions.extend(extra_conditions.iter().cloned());
        self.relation_or_unknown(RelationRequest {
            source,
            target: target.as_deref(),
            relation,
            locator,
            span: reference.span,
            coordinate: reference.rendered.clone(),
            reason: target
                .is_none()
                .then_some("graphql-type-reference-is-unresolved"),
            conditions,
        })
    }

    fn add_directive_uses(
        &mut self,
        source: &str,
        relation: CrossLanguageRelationKind,
        locator: &str,
        directives: &[DirectiveUse],
    ) -> Result<()> {
        for directive in directives {
            if is_builtin_directive(&directive.name) {
                if directive.dynamic {
                    self.insert_reason("graphql-dynamic-directive");
                }
                continue;
            }
            let target = self.unique_directive_id(&directive.name);
            let reason = if is_federation_directive(&directive.name) {
                Some("graphql-federated-boundary")
            } else if directive.dynamic {
                Some("graphql-dynamic-directive")
            } else if target.is_none() {
                Some("graphql-directive-is-unresolved")
            } else {
                None
            };
            self.relation_or_unknown(RelationRequest {
                source,
                target: target.as_deref().filter(|_| reason.is_none()),
                relation,
                locator,
                span: directive.span,
                coordinate: format!("@{}", directive.name),
                reason,
                conditions: directive_conditions(std::slice::from_ref(directive)),
            })?;
        }
        Ok(())
    }

    fn field_output_type(&self, current_type: &str, field_name: &str) -> Option<String> {
        let definitions = self.type_groups.get(current_type)?;
        if !self.valid_types.contains(current_type) {
            return None;
        }
        let fields = definitions
            .iter()
            .flat_map(|definition| definition.definition.fields.iter())
            .filter(|field| field.name == field_name)
            .collect::<Vec<_>>();
        (fields.len() == 1).then(|| fields[0].output.named_type.clone())
    }

    fn operation_root(&self, kind: OperationKind) -> Option<String> {
        let declared = self
            .schema_roots
            .get(&kind)
            .filter(|roots| roots.len() == 1)
            .and_then(|roots| roots.first())
            .map(|(_, target, _)| target.clone());
        if declared.is_some() {
            declared
        } else if self.schema_definition_count == 0 {
            Some(kind.default_root().to_owned())
        } else {
            None
        }
    }

    fn unique_type_id(&self, name: &str) -> Option<String> {
        self.valid_types
            .contains(name)
            .then(|| self.type_ids.get(name).cloned())
            .flatten()
    }

    fn unique_directive_id(&self, name: &str) -> Option<String> {
        self.directive_groups
            .get(name)
            .filter(|definitions| definitions.len() == 1)
            .and_then(|_| self.directive_ids.get(name).cloned())
    }

    fn unique_fragment_id(&self, name: &str) -> Option<String> {
        self.fragments
            .get(name)
            .filter(|fragments| fragments.len() == 1)?;
        self.fragment_ids
            .get(name)
            .filter(|ids| ids.len() == 1)
            .and_then(|ids| ids.first().cloned())
    }

    fn unique_fragment(&self, name: &str) -> Option<&LocatedFragment> {
        self.fragments
            .get(name)
            .filter(|fragments| fragments.len() == 1)
            .and_then(|fragments| fragments.first())
    }

    fn add_cross_node(
        &mut self,
        kind: CrossLanguageNodeKind,
        locator: &str,
        coordinate: &str,
    ) -> Result<String> {
        if !bounded_text(locator) || !bounded_text(coordinate) {
            bail!("GraphQL canonical identity exceeds its bounded contract");
        }
        let identity = CrossLanguageCanonicalIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            format: CrossLanguageFormat::Graphql,
            repository_contract_locator: locator.to_owned(),
            format_version: GRAPHQL_FORMAT_VERSION.to_owned(),
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
                ("format".to_owned(), Value::String("graphql".to_owned())),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node)
            .map_err(|_| anyhow::anyhow!("conflicting GraphQL node identity"))?;
        self.cross_node_ids.insert(id.clone());
        Ok(id)
    }

    fn unknown_node(&mut self, locator: &str, identity: &str, reason: &str) -> Result<String> {
        let id = stable_id_from_value(
            "unknown_target",
            &json!({
                "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
                "format": "graphql",
                "profile_id": self.profile_id,
                "locator": locator,
                "identity": bounded_reason(identity),
                "reason": reason,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "unknown_target".to_owned(),
            locator: format!("unknown:graphql:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                ("format".to_owned(), Value::String("graphql".to_owned())),
                ("reason_code".to_owned(), Value::String(reason.to_owned())),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node)
            .map_err(|_| anyhow::anyhow!("conflicting GraphQL unknown node identity"))?;
        self.insert_reason(reason);
        Ok(id)
    }

    fn relation_or_unknown(&mut self, request: RelationRequest<'_>) -> Result<()> {
        let effective_reason = request
            .target
            .is_none()
            .then(|| request.reason.unwrap_or("graphql-target-is-unresolved"));
        let (target, status, precision, mapping) = if let Some(target) = request.target {
            (
                target.to_owned(),
                ResolutionStatus::Resolved,
                Precision::Exact,
                CrossLanguageMappingKind::ContractInternal,
            )
        } else {
            let reason = effective_reason.expect("unresolved GraphQL relations have a reason");
            (
                self.unknown_node(request.locator, &request.coordinate, reason)?,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
            )
        };
        let mut condition_items = vec![(
            "graphql.coordinate".to_owned(),
            Value::String(request.coordinate.clone()),
        )];
        condition_items.extend(
            request
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
        let document = self.documents.get(request.locator).with_context(|| {
            format!(
                "GraphQL relation references unknown document {}",
                request.locator
            )
        })?;
        let evidence = vec![Evidence {
            kind: EvidenceKind::Semantic,
            extractor: EXTRACTOR.to_owned(),
            extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
            path: Some(request.locator.to_owned()),
            start_line: Some(request.span.start_line),
            start_column: Some(request.span.start_column),
            end_line: Some(request.span.end_line),
            end_column: Some(request.span.end_column),
            detail: None,
            properties: Properties::from([
                (
                    "contract_version".to_owned(),
                    Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
                ),
                ("format".to_owned(), Value::String("graphql".to_owned())),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
                (
                    "format_version".to_owned(),
                    Value::String(GRAPHQL_FORMAT_VERSION.to_owned()),
                ),
                (
                    "contract_digest".to_owned(),
                    Value::String(document.digest.clone()),
                ),
                (
                    "occurrence_kind".to_owned(),
                    serde_json::to_value(request.relation)?,
                ),
                ("mapping_kind".to_owned(), serde_json::to_value(mapping)?),
                (
                    "graphql_coordinate".to_owned(),
                    Value::String(request.coordinate.clone()),
                ),
                (
                    "source_digest".to_owned(),
                    Value::String(document.digest.clone()),
                ),
                (
                    "source_contract_locator".to_owned(),
                    Value::String(request.locator.to_owned()),
                ),
            ]),
        }];
        let mut site = DependencySite {
            id: String::new(),
            source: request.source.to_owned(),
            kind: request.relation.as_str().to_owned(),
            specifier: request.coordinate,
            resolution_status: status,
            target_ids: vec![target.clone()],
            profile_id: self.profile_id.clone(),
            condition: condition.clone(),
            precision,
            reason: effective_reason.map(bounded_reason),
            evidence: evidence.clone(),
        };
        site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
        let mut edge = GraphEdge {
            id: String::new(),
            source: request.source.to_owned(),
            target,
            kind: request.relation.as_str().to_owned(),
            site_id: Some(site.id.clone()),
            phase: Phase::Semantic,
            environment: None,
            profile_id: self.profile_id.clone(),
            condition,
            resolution_status: status,
            precision,
            generated: false,
            evidence,
        };
        edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
        insert_same(&mut self.sites, site.id.clone(), site)
            .map_err(|_| anyhow::anyhow!("conflicting GraphQL site identity"))?;
        insert_same(&mut self.edges, edge.id.clone(), edge)
            .map_err(|_| anyhow::anyhow!("conflicting GraphQL edge identity"))?;
        if status == ResolutionStatus::Unresolved {
            self.unresolved_count += 1;
            if let Some(reason) = effective_reason {
                self.insert_reason(reason);
            }
        }
        Ok(())
    }

    fn insert_reason(&mut self, reason: &str) {
        if self.reasons.len() < MAX_REASONS || self.reasons.contains(reason) {
            self.reasons.insert(bounded_reason(reason));
        }
    }
}

#[derive(Clone, Copy)]
enum SelectionOwner {
    Fragment,
    Operation,
}

struct RelationRequest<'a> {
    source: &'a str,
    target: Option<&'a str>,
    relation: CrossLanguageRelationKind,
    locator: &'a str,
    span: SourceSpan,
    coordinate: String,
    reason: Option<&'a str>,
    conditions: Vec<(&'static str, Value)>,
}

fn detect_fragment_cycles(fragments: &BTreeMap<String, Vec<LocatedFragment>>) -> BTreeSet<String> {
    let adjacency = fragments
        .iter()
        .filter(|(_, definitions)| definitions.len() == 1)
        .map(|(name, definitions)| {
            (
                name.clone(),
                fragment_spreads(&definitions[0].definition.selections),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut visited = BTreeSet::new();
    let mut finish_order = Vec::new();
    for name in adjacency.keys() {
        if visited.contains(name) {
            continue;
        }
        let mut stack = vec![(name.clone(), false)];
        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                finish_order.push(current);
                continue;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            stack.push((current.clone(), true));
            if let Some(neighbors) = adjacency.get(&current) {
                for neighbor in neighbors.iter().rev() {
                    if adjacency.contains_key(neighbor) && !visited.contains(neighbor) {
                        stack.push((neighbor.clone(), false));
                    }
                }
            }
        }
    }

    let mut reverse = adjacency
        .keys()
        .map(|name| (name.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for (source, targets) in &adjacency {
        for target in targets {
            if let Some(predecessors) = reverse.get_mut(target) {
                predecessors.push(source.clone());
            }
        }
    }

    let mut assigned = BTreeSet::new();
    let mut cycles = BTreeSet::new();
    for name in finish_order.into_iter().rev() {
        if !assigned.insert(name.clone()) {
            continue;
        }
        let mut component = Vec::new();
        let mut stack = vec![name];
        while let Some(current) = stack.pop() {
            component.push(current.clone());
            for predecessor in reverse.get(&current).into_iter().flatten().rev() {
                if assigned.insert(predecessor.clone()) {
                    stack.push(predecessor.clone());
                }
            }
        }
        let cyclic = component.len() > 1
            || component.first().is_some_and(|only| {
                adjacency
                    .get(only)
                    .is_some_and(|targets| targets.contains(only))
            });
        if cyclic {
            cycles.extend(component);
        }
    }
    cycles
}

fn fragment_spreads(selections: &[Selection]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for selection in selections {
        match selection {
            Selection::FragmentSpread(spread) => {
                names.insert(spread.name.clone());
            }
            Selection::Field(field) => names.extend(fragment_spreads(&field.selections)),
            Selection::InlineFragment(inline) => {
                names.extend(fragment_spreads(&inline.selections));
            }
        }
    }
    names
}

fn directive_boundary_reason(directives: &[DirectiveUse]) -> Option<&'static str> {
    if directives
        .iter()
        .any(|directive| is_federation_directive(&directive.name))
    {
        Some("graphql-federated-boundary")
    } else if directives.iter().any(|directive| directive.dynamic) {
        Some("graphql-dynamic-directive")
    } else {
        None
    }
}

fn directive_conditions(directives: &[DirectiveUse]) -> Vec<(&'static str, Value)> {
    let mut conditions = Vec::new();
    if !directives.is_empty() {
        conditions.push((
            "graphql.directive_state",
            Value::Array(
                directives
                    .iter()
                    .map(|directive| {
                        json!({
                            "name": directive.name,
                            "dynamic": directive.dynamic,
                            "static_booleans": directive.static_booleans,
                        })
                    })
                    .collect(),
            ),
        ));
        conditions.push((
            "graphql.directive_count",
            Value::from(directives.len() as u64),
        ));
    }
    conditions
}

fn parse_static_boolean_arguments(tokens: &[Token]) -> BTreeMap<String, bool> {
    let mut arguments = BTreeMap::new();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while index < tokens.len() {
        match tokens[index].text.as_str() {
            "[" | "{" | "(" => {
                depth = depth.saturating_add(1);
                index += 1;
            }
            "]" | "}" | ")" => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ if depth == 0
                && index + 2 < tokens.len()
                && tokens[index].kind == TokenKind::Name
                && tokens[index + 1].text == ":" =>
            {
                let value = match tokens[index + 2].text.as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                };
                if let Some(value) = value {
                    arguments.insert(tokens[index].text.clone(), value);
                }
                index += 3;
            }
            _ => index += 1,
        }
    }
    arguments
}

fn is_builtin_scalar(name: &str) -> bool {
    matches!(name, "Boolean" | "Float" | "ID" | "Int" | "String")
}

fn is_builtin_directive(name: &str) -> bool {
    matches!(
        name,
        "deprecated" | "include" | "oneOf" | "skip" | "specifiedBy"
    )
}

fn is_federation_directive(name: &str) -> bool {
    matches!(
        name,
        "composeDirective"
            | "external"
            | "extends"
            | "inaccessible"
            | "key"
            | "link"
            | "override"
            | "provides"
            | "requires"
            | "shareable"
            | "tag"
    )
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

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn digest_value(value: &Value) -> String {
    sha256_prefixed(
        serde_json::to_vec(value)
            .expect("bounded GraphQL identity is serializable")
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
    use std::fs;

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCapabilityStatus,
        CrossLanguageCompletenessLedger, CrossLanguageRelationKind, Profile, ResolutionStatus,
        validate_cross_language_adapter_delta,
    };

    use super::*;

    const SCHEMA: &str = r#"
directive @auth(role: String!) on FIELD_DEFINITION | OBJECT
type Query @auth(role: "reader") {
  user(id: ID!): User
}
type User {
  id: ID!
}
"#;

    const EXTENSION: &str = r#"
extend type User {
  name: String!
}
"#;

    const OPERATION: &str = r#"
query GetUser($id: ID!) {
  user(id: $id) {
    ...UserFields @skip(if: false)
  }
}
fragment UserFields on User {
  id
  name
}
"#;

    fn participating_profiles() -> Vec<Profile> {
        vec![Profile {
            id: "polyglot:production".to_owned(),
            language: "polyglot".to_owned(),
            toolchain: None,
            command: None,
            target: None,
            features: Vec::new(),
            environment: BTreeMap::new(),
            source_revision: None,
            properties: BTreeMap::new(),
        }]
    }

    fn write_positive_fixture(root: &Path, reverse: bool) {
        let entries = [
            ("schema.graphqls", SCHEMA),
            ("extension.graphql", EXTENSION),
            ("operation.gql", OPERATION),
        ];
        let iterator: Box<dyn Iterator<Item = &(&str, &str)>> = if reverse {
            Box::new(entries.iter().rev())
        } else {
            Box::new(entries.iter())
        };
        for (path, source) in iterator {
            fs::write(root.join(path), source).unwrap();
        }
        fs::write(
            root.join(".graphqlrc.js"),
            "throw new Error('project config must never execute')",
        )
        .unwrap();
    }

    #[test]
    fn sdl_extensions_operations_fragments_and_selections_are_complete_and_deterministic() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_positive_fixture(first.path(), false);
        write_positive_fixture(second.path(), true);

        let first = scan_graphql_repository(first.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let second = scan_graphql_repository(second.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&first).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert_eq!(first.participating_profiles, participating_profiles());
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            first.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Complete
        );
        assert_eq!(ledger.entries[0].unresolved_count, 0);
        assert!(first.nodes.iter().any(|node| node.kind == "schema"));
        assert!(first.nodes.iter().any(|node| node.kind == "operation"));
        assert!(first.nodes.iter().any(|node| {
            node.kind == "message"
                && node.properties["canonical_identity"]["coordinate"] == "object User"
        }));
        assert!(first.edges.iter().any(|edge| {
            edge.kind == CrossLanguageRelationKind::ReturnsMessage.as_str()
                && edge.resolution_status == ResolutionStatus::Resolved
        }));
    }

    #[test]
    fn expanded_fragment_evidence_uses_the_fragment_source_locator() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("schema.graphqls"),
            "type Query { user: User }\ntype User { friend: User }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("operation.graphql"),
            "query Friends { user { ...UserFields } }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("fragment.graphql"),
            "fragment UserFields on User { friend { friend } }\n",
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let operation_id = delta
            .nodes
            .iter()
            .find(|node| {
                node.kind == "operation"
                    && node.properties["canonical_identity"]["coordinate"] == "query Friends"
            })
            .unwrap()
            .id
            .clone();
        assert!(delta.edges.iter().any(|edge| {
            edge.source == operation_id
                && edge.evidence[0].properties["graphql_coordinate"] == "User.friend"
                && edge.evidence[0].path.as_deref() == Some("fragment.graphql")
        }));
    }

    #[test]
    fn duplicate_fragment_and_operation_definitions_fail_closed_without_panicking() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("duplicates.graphql"),
            r#"
type Query { value: String }
query Duplicate { ...Shared }
query Duplicate { ...Shared }
fragment Shared on Query { value }
fragment Shared on Query { value }
"#,
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let reasons = delta
            .sites
            .iter()
            .filter_map(|site| site.reason.as_deref())
            .collect::<BTreeSet<_>>();
        assert!(reasons.contains("ambiguous-graphql-fragment-definition"));
        assert!(reasons.contains("ambiguous-graphql-operation-definition"));
        assert!(
            delta
                .sites
                .iter()
                .filter(|site| {
                    matches!(
                        site.reason.as_deref(),
                        Some(
                            "ambiguous-graphql-fragment-definition"
                                | "ambiguous-graphql-operation-definition"
                        )
                    )
                })
                .all(|site| site.resolution_status == ResolutionStatus::Unresolved)
        );
    }

    #[test]
    fn long_fragment_expansion_is_iterative_and_bounded() {
        let root = tempfile::tempdir().unwrap();
        let fragment_count = 1_024;
        let mut source = "type Query { value: String }\nquery Long { ...F0 }\n".to_owned();
        for index in 0..fragment_count {
            if index + 1 == fragment_count {
                source.push_str(&format!("fragment F{index} on Query {{ value }}\n"));
            } else {
                source.push_str(&format!(
                    "fragment F{index} on Query {{ ...F{} }}\n",
                    index + 1
                ));
            }
        }
        fs::write(root.path().join("long.graphql"), source).unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("graphql-selection-expansion-depth-exceeded")
        }));
    }

    #[test]
    fn explicit_anonymous_operations_and_type_nesting_are_validated_boundedly() {
        let valid = tempfile::tempdir().unwrap();
        fs::write(
            valid.path().join("anonymous.graphql"),
            "type Query { value: String }\nquery { value }\n",
        )
        .unwrap();
        let delta = scan_graphql_repository(valid.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(delta.nodes.iter().any(|node| {
            node.kind == "operation"
                && node.properties["canonical_identity"]["coordinate"] == "query anonymous#1"
        }));

        let ambiguous = tempfile::tempdir().unwrap();
        fs::write(
            ambiguous.path().join("ambiguous.graphql"),
            "type Query { value: String }\nquery { value }\nquery Named { value }\n",
        )
        .unwrap();
        let delta = scan_graphql_repository(ambiguous.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"graphql-anonymous-operation-is-ambiguous".to_owned())
        );

        let deep = tempfile::tempdir().unwrap();
        let source = format!(
            "type Query {{ deep: {}String{} }}",
            "[".repeat(MAX_GRAPHQL_DEPTH + 1),
            "]".repeat(MAX_GRAPHQL_DEPTH + 1)
        );
        fs::write(deep.path().join("deep-type.graphql"), source).unwrap();
        let delta = scan_graphql_repository(deep.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"graphql-type-depth-limit-exceeded".to_owned())
        );
    }

    #[test]
    fn directive_only_type_extensions_and_enum_value_descriptions_are_admitted() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("extensions.graphql"),
            r#"
directive @metadata(enabled: Boolean!) on OBJECT | ENUM | UNION
type Query { result: Result }
type Product { id: ID! }
enum Color {
  "Primary color"
  RED
}
union Result = Product
extend type Query @metadata(enabled: true)
extend enum Color @metadata(enabled: false)
extend union Result @metadata(enabled: true)
"#,
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(ledger.entries[0].skipped_count, 0);
        assert!(
            delta
                .nodes
                .iter()
                .any(|node| node.properties["canonical_identity"]["coordinate"] == "enum Color")
        );
    }

    #[test]
    fn directive_conditions_preserve_names_boolean_arguments_and_order() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("conditions.graphql"),
            r#"
directive @feature(enabled: Boolean!) on FIELD
directive @guard(allowed: Boolean!) on FIELD
type Query { value: Result }
type Result { id: ID! }
query Conditional {
  value @feature(enabled: true) @guard(allowed: false) { id }
}
"#,
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let condition = delta
            .sites
            .iter()
            .find(|site| {
                site.evidence.first().is_some_and(|evidence| {
                    evidence.path.as_deref() == Some("conditions.graphql")
                        && evidence.properties["graphql_coordinate"] == "Query.value"
                }) && serde_json::to_string(&site.condition)
                    .is_ok_and(|condition| condition.contains("graphql.directive_state"))
            })
            .map(|site| serde_json::to_value(&site.condition).unwrap())
            .unwrap();
        let serialized = serde_json::to_string(&condition).unwrap();
        for expected in [
            "graphql.directive_state",
            "feature",
            "enabled",
            "true",
            "guard",
            "allowed",
            "false",
        ] {
            assert!(serialized.contains(expected), "{expected}: {serialized}");
        }
        assert!(serialized.find("feature").unwrap() < serialized.find("guard").unwrap());
    }

    #[test]
    fn missing_type_fragment_dynamic_federation_and_introspection_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("schema.graphql"),
            r#"
extend schema @link(url: "https://specs.apollo.dev/federation/v2.3")
type Query {
  remote: Missing @key(fields: "id")
}
"#,
        )
        .unwrap();
        fs::write(
            root.path().join("query.graphql"),
            r#"
query Remote($flag: Boolean!) {
  remote @skip(if: $flag) {
    ...MissingFragment
  }
  __schema { queryType { name } }
}
"#,
        )
        .unwrap();
        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let reasons = delta
            .sites
            .iter()
            .filter_map(|site| site.reason.as_deref())
            .collect::<BTreeSet<_>>();
        assert!(reasons.contains("graphql-federated-boundary"));
        assert!(reasons.contains("graphql-type-reference-is-unresolved"));
        assert!(reasons.contains("graphql-dynamic-directive"));
        assert!(reasons.contains("graphql-fragment-is-missing"));
        assert!(reasons.contains("graphql-introspection-not-admitted"));
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(ledger.entries[0].skipped_count, 0);
        assert!(
            delta
                .sites
                .iter()
                .filter(|site| { site.resolution_status == ResolutionStatus::Unresolved })
                .all(|site| {
                    site.target_ids.iter().all(|target| {
                        delta
                            .nodes
                            .iter()
                            .any(|node| &node.id == target && node.kind == "unknown_target")
                    })
                })
        );
    }

    #[test]
    fn cyclic_fragments_are_bounded_reasoned_and_checkout_independent() {
        let source = r#"
type Query { user: User }
type User { id: ID! }
query Cycle { user { ...A } }
fragment A on User { id ...B }
fragment B on User { id ...A }
"#;
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        fs::write(first.path().join("cycle.graphql"), source).unwrap();
        fs::write(second.path().join("cycle.graphql"), source).unwrap();
        let first = scan_graphql_repository(first.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let second = scan_graphql_repository(second.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert!(
            first
                .sites
                .iter()
                .any(|site| { site.reason.as_deref() == Some("graphql-fragment-cycle") })
        );
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            first.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Incomplete
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sources_are_ledgered_without_reading_external_graphql() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(
            outside.path().join("secret.graphql"),
            "type Query { secret: String }",
        )
        .unwrap();
        symlink(
            outside.path().join("secret.graphql"),
            root.path().join("linked.graphql"),
        )
        .unwrap();
        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(!serde_json::to_string(&delta).unwrap().contains("secret"));
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(ledger.entries[0].skipped_count, 1);
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"graphql-source-symlink-not-admitted".to_owned())
        );
    }

    #[test]
    fn malformed_deep_and_empty_inputs_are_bounded() {
        let empty = tempfile::tempdir().unwrap();
        assert!(
            scan_graphql_repository(empty.path(), &participating_profiles())
                .unwrap()
                .is_none()
        );

        let malformed = tempfile::tempdir().unwrap();
        fs::write(
            malformed.path().join("broken.graphql"),
            "type Query { broken: [String }",
        )
        .unwrap();
        let delta = scan_graphql_repository(malformed.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(ledger.entries[0].skipped_count, 1);

        let deep = tempfile::tempdir().unwrap();
        let mut source = "query Deep {".to_owned();
        for _ in 0..=MAX_GRAPHQL_DEPTH {
            source.push_str(" field {");
        }
        source.push_str(&"}".repeat(MAX_GRAPHQL_DEPTH + 2));
        fs::write(deep.path().join("deep.graphql"), source).unwrap();
        let delta = scan_graphql_repository(deep.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(ledger.entries[0].skipped_count, 1);
        assert!(
            scan_graphql_repository(deep.path(), &[])
                .unwrap_err()
                .to_string()
                .contains("profile")
        );
    }

    #[test]
    fn graphql_inventory_limits_fail_closed_without_growing_records() {
        let mut inventory_entries = MAX_GRAPHQL_INVENTORY_ENTRIES - 1;
        record_graphql_inventory_entry(&mut inventory_entries).unwrap();
        assert_eq!(inventory_entries, MAX_GRAPHQL_INVENTORY_ENTRIES);
        assert!(record_graphql_inventory_entry(&mut inventory_entries).is_err());

        let mut records = Vec::new();
        for index in 0..MAX_GRAPHQL_FILES {
            push_graphql_source_record(
                &mut records,
                skipped_source(&format!("source-{index}.graphql"), "test-skip"),
            )
            .unwrap();
        }
        assert!(
            push_graphql_source_record(
                &mut records,
                skipped_source("overflow.graphql", "test-skip"),
            )
            .is_err()
        );
        assert_eq!(records.len(), MAX_GRAPHQL_FILES);
    }
}
