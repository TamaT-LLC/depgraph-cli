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
use petgraph::{algo::kosaraju_scc, graphmap::DiGraphMap};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

pub const OPENAPI_CAPABILITY: &str = "openapi-contract-v1";
pub const MAX_OPENAPI_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_OPENAPI_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_OPENAPI_DOCUMENTS: usize = 256;
pub const MAX_OPENAPI_INVENTORY_ENTRIES: usize = 1_000_000;
pub const MAX_OPENAPI_VALUES: usize = 100_000;
pub const MAX_OPENAPI_DEPTH: usize = 96;
pub const MAX_OPENAPI_SCALAR_BYTES: usize = 64 * 1024;
pub const MAX_OPENAPI_REFERENCES: usize = 10_000;
pub const MAX_OPENAPI_REFERENCE_DEPTH: usize = 64;

const EXTRACTOR: &str = "depgraph-openapi-adapter";
const MAX_PARTICIPATING_PROFILES: usize = 64;
const MAX_REASON_BYTES: usize = 256;

/// Safely inventories repository-local OpenAPI 3.1 JSON/YAML files and builds
/// one common-contract closure. No project code, custom loader, command, or
/// network client is involved.
///
/// `Ok(None)` means the bounded inventory found no OpenAPI input. Named
/// OpenAPI candidates that are malformed, unsupported, or unsafe still return
/// an incomplete delta so the coverage ledger cannot silently omit them.
pub fn scan_openapi_repository(
    root: &Path,
    participating_profiles: &[Profile],
) -> Result<Option<CrossLanguageAdapterDelta>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("OpenAPI scan root {} is unavailable", root.display()))?;
    if !canonical_root.is_dir() {
        bail!("OpenAPI scan root must be a directory");
    }
    let mut participating_profiles = participating_profiles.to_vec();
    participating_profiles.sort_by(|left, right| left.id.cmp(&right.id));
    if participating_profiles.is_empty()
        || participating_profiles.len() > MAX_PARTICIPATING_PROFILES
        || participating_profiles
            .iter()
            .any(|profile| !bounded_text(&profile.id, MAX_OPENAPI_SCALAR_BYTES))
        || participating_profiles
            .windows(2)
            .any(|profiles| profiles[0].id == profiles[1].id)
    {
        bail!("OpenAPI participating profiles must be a bounded non-empty set");
    }
    let participating_profile_ids = participating_profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect();

    let inventory = inventory_openapi_documents(&canonical_root)?;
    if inventory.is_empty() {
        return Ok(None);
    }
    let input_digest = digest_input_records(&inventory);
    let profile_identity = CrossLanguageProfileIdentity {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        contract_input_digest: input_digest,
        adapter_capability_versions: vec![OPENAPI_CAPABILITY.to_owned()],
        participating_profile_ids,
    };
    let profile_id = cross_language_profile_id(&profile_identity);

    let documents = inventory
        .iter()
        .filter_map(|record| {
            record
                .document
                .clone()
                .map(|doc| (doc.locator.clone(), doc))
        })
        .collect::<BTreeMap<_, _>>();
    let mut builder = OpenApiGraphBuilder::new(profile_id.clone(), documents);
    builder.build()?;

    let skipped_count = inventory
        .iter()
        .filter(|record| record.document.is_none())
        .count() as u64;
    for record in &inventory {
        if let Some(reason) = &record.reason {
            builder.reasons.insert(reason.clone());
        }
    }
    builder.mark_recursive_schema_sites();

    let status = if builder.unresolved_count > 0 || skipped_count > 0 || !builder.reasons.is_empty()
    {
        CrossLanguageCapabilityStatus::Incomplete
    } else {
        CrossLanguageCapabilityStatus::Complete
    };
    let ledger = CrossLanguageCompletenessLedger {
        schema_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        entries: vec![CrossLanguageFormatCoverage {
            format: CrossLanguageFormat::Openapi,
            capability: OPENAPI_CAPABILITY.to_owned(),
            status,
            input_count: inventory.len() as u64,
            node_count: builder.cross_node_ids.len() as u64,
            site_count: builder.sites.len() as u64,
            edge_count: builder.edges.len() as u64,
            external_count: builder.external_count,
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
        .context("OpenAPI adapter produced an invalid common-contract closure")?;
    Ok(Some(delta))
}

#[derive(Clone, Debug)]
struct InputRecord {
    locator: String,
    digest: String,
    document: Option<OpenApiDocument>,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
struct OpenApiDocument {
    locator: String,
    version: String,
    digest: String,
    root: Value,
    end_line: u32,
    end_column: u32,
}

fn inventory_openapi_documents(root: &Path) -> Result<Vec<InputRecord>> {
    let mut records = Vec::new();
    let mut probed_bytes = 0_usize;
    let mut inventory_entries = 0_usize;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        record_openapi_inventory_entry(&mut inventory_entries)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        if entry.depth() == 0 || !is_json_or_yaml(entry.path()) {
            continue;
        }
        let locator = match repository_locator(root, entry.path()) {
            Some(locator) => locator,
            None => continue,
        };
        let named_candidate = named_openapi_candidate(&locator);
        if entry.file_type().is_symlink() {
            if named_candidate {
                push_openapi_inventory_record(
                    &mut records,
                    skipped_record(&locator, "symlink-input-not-admitted"),
                )?;
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes =
            match read_bounded_repository_file(root, entry.path(), MAX_OPENAPI_DOCUMENT_BYTES) {
                Ok(bytes) => bytes,
                Err(error) if named_candidate => {
                    let reason = if error.code == "query_file_size_or_type_invalid" {
                        "input-byte-limit-exceeded"
                    } else {
                        "input-read-failed"
                    };
                    push_openapi_inventory_record(&mut records, skipped_record(&locator, reason))?;
                    continue;
                }
                Err(_) => continue,
            };
        let Some(total_bytes) = probed_bytes.checked_add(bytes.len()) else {
            bail!("OpenAPI inventory byte count overflowed");
        };
        if total_bytes > MAX_OPENAPI_TOTAL_BYTES {
            if named_candidate {
                push_openapi_inventory_record(
                    &mut records,
                    skipped_record(&locator, "inventory-byte-limit-exceeded"),
                )?;
            }
            continue;
        }
        probed_bytes = total_bytes;
        if !named_candidate && !contains_openapi_marker(&bytes) {
            continue;
        }
        let digest = sha256_prefixed(&bytes);
        match parse_openapi_document(&locator, &digest, &bytes) {
            Ok(document) => push_openapi_inventory_record(
                &mut records,
                InputRecord {
                    locator,
                    digest,
                    document: Some(document),
                    reason: None,
                },
            )?,
            Err(reason) => push_openapi_inventory_record(
                &mut records,
                InputRecord {
                    locator,
                    digest,
                    document: None,
                    reason: Some(reason),
                },
            )?,
        }
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));
    Ok(records)
}

fn record_openapi_inventory_entry(inventory_entries: &mut usize) -> Result<()> {
    *inventory_entries = inventory_entries
        .checked_add(1)
        .context("OpenAPI inventory entry count overflowed")?;
    if *inventory_entries > MAX_OPENAPI_INVENTORY_ENTRIES {
        bail!("OpenAPI inventory exceeds its closed entry limit");
    }
    Ok(())
}

fn push_openapi_inventory_record(
    records: &mut Vec<InputRecord>,
    record: InputRecord,
) -> Result<()> {
    if records.len() >= MAX_OPENAPI_DOCUMENTS {
        bail!("OpenAPI inventory exceeds its closed document limit");
    }
    records.push(record);
    Ok(())
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

fn is_json_or_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "json" | "yaml" | "yml"
            )
        })
}

fn named_openapi_candidate(locator: &str) -> bool {
    let lower = locator.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    name.contains("openapi")
        || name.contains("swagger")
        || lower
            .split('/')
            .any(|component| matches!(component, "openapi" | "api-spec" | "api-schema"))
}

fn contains_openapi_marker(bytes: &[u8]) -> bool {
    bytes
        .windows(b"openapi".len())
        .any(|window| window.eq_ignore_ascii_case(b"openapi"))
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

fn skipped_record(locator: &str, reason: &str) -> InputRecord {
    InputRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        document: None,
        reason: Some(reason.to_owned()),
    }
}

fn parse_openapi_document(
    locator: &str,
    digest: &str,
    bytes: &[u8],
) -> std::result::Result<OpenApiDocument, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| "input-is-not-utf8".to_owned())?;
    let first = source
        .trim_start_matches('\u{feff}')
        .trim_start()
        .chars()
        .next()
        .ok_or_else(|| "input-is-empty".to_owned())?;
    let root = if matches!(first, '{' | '[') {
        parse_bounded_json(bytes)?
    } else {
        parse_bounded_yaml(source)?
    };
    validate_value_bounds(&root, 0, &mut 0_usize)?;
    let object = root
        .as_object()
        .ok_or_else(|| "openapi-root-is-not-an-object".to_owned())?;
    let version = object
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or_else(|| "openapi-version-is-missing".to_owned())?;
    if !matches!(version, "3.1.0" | "3.1.1") {
        return Err("unsupported-openapi-version".to_owned());
    }
    if object.contains_key("overlay") {
        return Err("openapi-overlay-is-not-supported".to_owned());
    }
    if let Some(paths) = object.get("paths")
        && !paths.is_object()
    {
        return Err("openapi-paths-is-not-an-object".to_owned());
    }
    if let Some(webhooks) = object.get("webhooks")
        && !webhooks.is_object()
    {
        return Err("openapi-webhooks-is-not-an-object".to_owned());
    }
    let (end_line, end_column) = source_end_position(source)?;
    Ok(OpenApiDocument {
        locator: locator.to_owned(),
        version: version.to_owned(),
        digest: digest.to_owned(),
        root,
        end_line,
        end_column,
    })
}

fn source_end_position(source: &str) -> std::result::Result<(u32, u32), String> {
    let line_count = source.split('\n').count();
    let last_line = source.rsplit('\n').next().unwrap_or_default();
    let line = u32::try_from(line_count).map_err(|_| "input-line-limit-exceeded".to_owned())?;
    let column = u32::try_from(last_line.chars().count().saturating_add(1))
        .map_err(|_| "input-column-limit-exceeded".to_owned())?;
    Ok((line.max(1), column.max(1)))
}

fn digest_input_records(records: &[InputRecord]) -> String {
    digest_value(&json!(
        records
            .iter()
            .map(|record| json!({
                "locator": record.locator,
                "digest": record.digest,
                "status": if record.document.is_some() { "admitted" } else { "skipped" },
                "reason": record.reason,
            }))
            .collect::<Vec<_>>()
    ))
}

fn digest_value(value: &Value) -> String {
    let stable = stable_id_from_value("openapi-input", value);
    format!(
        "sha256:{}",
        stable
            .strip_prefix("openapi-input:sha256:")
            .expect("stable input IDs use the requested namespace")
    )
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn bounded_scalar_text(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

struct BoundedJsonSeed<'a> {
    values: &'a mut usize,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonSeed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_OPENAPI_DEPTH {
            return Err(de::Error::custom("maximum OpenAPI JSON depth exceeded"));
        }
        *self.values = self.values.saturating_add(1);
        if *self.values > MAX_OPENAPI_VALUES {
            return Err(de::Error::custom(
                "maximum OpenAPI JSON value count exceeded",
            ));
        }
        deserializer.deserialize_any(BoundedJsonVisitor {
            values: self.values,
            depth: self.depth,
        })
    }
}

struct BoundedJsonVisitor<'a> {
    values: &'a mut usize,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedJsonVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a bounded JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> {
        if !bounded_scalar_text(&value, MAX_OPENAPI_SCALAR_BYTES) {
            return Err(E::custom("invalid bounded JSON scalar"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(BoundedJsonSeed {
            values: self.values,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !bounded_text(&key, MAX_OPENAPI_SCALAR_BYTES) {
                return Err(de::Error::custom("invalid bounded JSON object key"));
            }
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value_seed(BoundedJsonSeed {
                values: self.values,
                depth: self.depth + 1,
            })?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

fn parse_bounded_json(bytes: &[u8]) -> std::result::Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut values = 0_usize;
    let value = BoundedJsonSeed {
        values: &mut values,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| "invalid-or-unbounded-json".to_owned())?;
    deserializer
        .end()
        .map_err(|_| "trailing-json-data".to_owned())?;
    Ok(value)
}

fn validate_value_bounds(
    value: &Value,
    depth: usize,
    values: &mut usize,
) -> std::result::Result<(), String> {
    if depth > MAX_OPENAPI_DEPTH {
        return Err("openapi-value-depth-limit-exceeded".to_owned());
    }
    *values = values.saturating_add(1);
    if *values > MAX_OPENAPI_VALUES {
        return Err("openapi-value-count-limit-exceeded".to_owned());
    }
    match value {
        Value::String(value) if !bounded_scalar_text(value, MAX_OPENAPI_SCALAR_BYTES) => {
            Err("openapi-scalar-limit-exceeded".to_owned())
        }
        Value::Array(items) => {
            for item in items {
                validate_value_bounds(item, depth + 1, values)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            for (key, value) in object {
                if !bounded_text(key, MAX_OPENAPI_SCALAR_BYTES) {
                    return Err("openapi-key-limit-exceeded".to_owned());
                }
                validate_value_bounds(value, depth + 1, values)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Debug)]
struct YamlLine {
    indent: usize,
    content: String,
}

struct SafeYamlParser {
    lines: Vec<YamlLine>,
    index: usize,
}

fn parse_bounded_yaml(source: &str) -> std::result::Result<Value, String> {
    let lines = preprocess_yaml(source)?;
    if lines.is_empty() {
        return Err("yaml-document-is-empty".to_owned());
    }
    let mut parser = SafeYamlParser { lines, index: 0 };
    let indent = parser.lines[0].indent;
    if indent != 0 {
        return Err("yaml-root-must-start-at-column-one".to_owned());
    }
    let value = parser.parse_block(indent, 0)?;
    if parser.index != parser.lines.len() {
        return Err("yaml-document-has-unconsumed-content".to_owned());
    }
    Ok(value)
}

fn preprocess_yaml(source: &str) -> std::result::Result<Vec<YamlLine>, String> {
    let mut lines = Vec::new();
    for raw in source.lines() {
        if raw.contains('\t') {
            return Err("yaml-tabs-are-not-supported".to_owned());
        }
        let indent = raw
            .chars()
            .take_while(|character| *character == ' ')
            .count();
        if indent > MAX_OPENAPI_DEPTH * 8 {
            return Err("yaml-indentation-limit-exceeded".to_owned());
        }
        let content = strip_yaml_comment(&raw[indent..])?.trim_end().to_owned();
        if content.trim().is_empty() || matches!(content.trim(), "---" | "...") {
            continue;
        }
        if content.starts_with('%') {
            return Err("yaml-directives-are-not-supported".to_owned());
        }
        if contains_yaml_graph_syntax(&content) {
            return Err("yaml-tags-anchors-and-aliases-are-not-supported".to_owned());
        }
        if content.len() > MAX_OPENAPI_SCALAR_BYTES {
            return Err("yaml-line-limit-exceeded".to_owned());
        }
        lines.push(YamlLine { indent, content });
        if lines.len() > MAX_OPENAPI_VALUES {
            return Err("yaml-value-count-limit-exceeded".to_owned());
        }
    }
    Ok(lines)
}

fn strip_yaml_comment(line: &str) -> std::result::Result<&str, String> {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let bytes = line.as_bytes();
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if double => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double && (index == 0 || bytes[index - 1].is_ascii_whitespace()) => {
                return Ok(&line[..index]);
            }
            _ => {}
        }
    }
    if single || double || escaped {
        return Err("unterminated-yaml-quoted-scalar".to_owned());
    }
    Ok(line)
}

fn contains_yaml_graph_syntax(line: &str) -> bool {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut previous = None;
    for character in line.chars() {
        if escaped {
            escaped = false;
            previous = Some(character);
            continue;
        }
        match character {
            '\\' if double => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '&' | '*' | '!' if !single && !double => {
                if previous.is_none_or(|value: char| {
                    value.is_ascii_whitespace() || matches!(value, ':' | '[' | '{' | ',' | '-')
                }) {
                    return true;
                }
            }
            _ => {}
        }
        previous = Some(character);
    }
    false
}

impl SafeYamlParser {
    fn parse_block(&mut self, indent: usize, depth: usize) -> std::result::Result<Value, String> {
        if depth > MAX_OPENAPI_DEPTH || self.index >= self.lines.len() {
            return Err("yaml-depth-or-content-limit-exceeded".to_owned());
        }
        if self.lines[self.index].indent != indent {
            return Err("yaml-indentation-is-not-canonical".to_owned());
        }
        if self.lines[self.index].content == "-" || self.lines[self.index].content.starts_with("- ")
        {
            self.parse_sequence(indent, depth)
        } else {
            self.parse_mapping(indent, depth, None)
        }
    }

    fn parse_mapping(
        &mut self,
        indent: usize,
        depth: usize,
        first: Option<(String, String)>,
    ) -> std::result::Result<Value, String> {
        let mut object = Map::new();
        if let Some((key, raw_value)) = first {
            self.insert_mapping_value(&mut object, key, raw_value, indent, depth)?;
        }
        while self.index < self.lines.len() {
            let line = &self.lines[self.index];
            if line.indent < indent {
                break;
            }
            if line.indent != indent || line.content == "-" || line.content.starts_with("- ") {
                return Err("yaml-mapping-indentation-is-invalid".to_owned());
            }
            let (key, raw_value) = split_yaml_mapping(&line.content)?;
            self.index += 1;
            self.insert_mapping_value(&mut object, key, raw_value, indent, depth)?;
        }
        Ok(Value::Object(object))
    }

    fn insert_mapping_value(
        &mut self,
        object: &mut Map<String, Value>,
        raw_key: String,
        raw_value: String,
        indent: usize,
        depth: usize,
    ) -> std::result::Result<(), String> {
        let key = parse_yaml_key(&raw_key)?;
        if key == "<<" {
            return Err("yaml-merge-keys-are-not-supported".to_owned());
        }
        if object.contains_key(&key) {
            return Err("duplicate-yaml-mapping-key".to_owned());
        }
        let value = if raw_value.is_empty() {
            if self.index < self.lines.len() && self.lines[self.index].indent > indent {
                let child_indent = self.lines[self.index].indent;
                self.parse_block(child_indent, depth + 1)?
            } else {
                Value::Null
            }
        } else if matches!(raw_value.as_str(), "|" | "|-" | "|+" | ">" | ">-" | ">+") {
            self.parse_block_scalar(indent, raw_value.starts_with('>'))?
        } else {
            parse_yaml_scalar(&raw_value)?
        };
        object.insert(key, value);
        Ok(())
    }

    fn parse_sequence(
        &mut self,
        indent: usize,
        depth: usize,
    ) -> std::result::Result<Value, String> {
        let mut values = Vec::new();
        while self.index < self.lines.len() {
            let line = &self.lines[self.index];
            if line.indent < indent {
                break;
            }
            if line.indent != indent || !(line.content == "-" || line.content.starts_with("- ")) {
                return Err("yaml-sequence-indentation-is-invalid".to_owned());
            }
            let item = line
                .content
                .strip_prefix('-')
                .unwrap()
                .trim_start()
                .to_owned();
            self.index += 1;
            let value = if item.is_empty() {
                if self.index >= self.lines.len() || self.lines[self.index].indent <= indent {
                    Value::Null
                } else {
                    self.parse_block(self.lines[self.index].indent, depth + 1)?
                }
            } else if let Ok((key, raw_value)) = split_yaml_mapping(&item) {
                let map_indent = self
                    .lines
                    .get(self.index)
                    .filter(|line| line.indent > indent)
                    .map_or(indent + 2, |line| line.indent);
                self.parse_mapping(map_indent, depth + 1, Some((key, raw_value)))?
            } else {
                if self.index < self.lines.len() && self.lines[self.index].indent > indent {
                    return Err("yaml-scalar-sequence-item-has-nested-content".to_owned());
                }
                parse_yaml_scalar(&item)?
            };
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn parse_block_scalar(
        &mut self,
        parent_indent: usize,
        folded: bool,
    ) -> std::result::Result<Value, String> {
        let mut parts = Vec::new();
        while self.index < self.lines.len() && self.lines[self.index].indent > parent_indent {
            parts.push(self.lines[self.index].content.clone());
            self.index += 1;
        }
        let separator = if folded { " " } else { "\n" };
        let value = parts.join(separator);
        if value.len() > MAX_OPENAPI_SCALAR_BYTES {
            return Err("yaml-block-scalar-limit-exceeded".to_owned());
        }
        Ok(Value::String(value))
    }
}

fn split_yaml_mapping(line: &str) -> std::result::Result<(String, String), String> {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut flow_depth = 0_i32;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if double => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '[' | '{' if !single && !double => flow_depth += 1,
            ']' | '}' if !single && !double => flow_depth -= 1,
            ':' if !single && !double && flow_depth == 0 => {
                let next = line[index + 1..].chars().next();
                if next.is_none_or(char::is_whitespace) {
                    let key = line[..index].trim().to_owned();
                    let value = line[index + 1..].trim().to_owned();
                    if key.is_empty() {
                        return Err("yaml-mapping-key-is-empty".to_owned());
                    }
                    return Ok((key, value));
                }
            }
            _ => {}
        }
    }
    Err("yaml-line-is-not-a-mapping".to_owned())
}

fn parse_yaml_key(raw: &str) -> std::result::Result<String, String> {
    match parse_yaml_scalar(raw)? {
        Value::String(value) if bounded_text(&value, MAX_OPENAPI_SCALAR_BYTES) => Ok(value),
        Value::Number(value) => Ok(value.to_string()),
        _ => Err("yaml-mapping-key-must-be-a-scalar-string".to_owned()),
    }
}

fn parse_yaml_scalar(raw: &str) -> std::result::Result<Value, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(Value::Null);
    }
    if value.starts_with('"') {
        let parsed: String =
            serde_json::from_str(value).map_err(|_| "invalid-yaml-double-quote".to_owned())?;
        return bounded_scalar_text(&parsed, MAX_OPENAPI_SCALAR_BYTES)
            .then_some(Value::String(parsed))
            .ok_or_else(|| "yaml-scalar-limit-exceeded".to_owned());
    }
    if value.starts_with('\'') {
        if !value.ends_with('\'') || value.len() < 2 {
            return Err("invalid-yaml-single-quote".to_owned());
        }
        let parsed = value[1..value.len() - 1].replace("''", "'");
        return bounded_scalar_text(&parsed, MAX_OPENAPI_SCALAR_BYTES)
            .then_some(Value::String(parsed))
            .ok_or_else(|| "yaml-scalar-limit-exceeded".to_owned());
    }
    if value.starts_with('{') || value.starts_with('[') {
        return parse_bounded_json(value.as_bytes())
            .map_err(|_| "unsupported-yaml-flow-value".to_owned());
    }
    match value {
        "null" | "Null" | "NULL" | "~" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        ".nan" | ".NaN" | ".NAN" | ".inf" | ".Inf" | ".INF" | "-.inf" | "+.inf" => {
            return Err("non-finite-yaml-number".to_owned());
        }
        _ => {}
    }
    if let Ok(integer) = value.parse::<i64>() {
        return Ok(Value::Number(integer.into()));
    }
    if let Ok(unsigned) = value.parse::<u64>() {
        return Ok(Value::Number(unsigned.into()));
    }
    if let Ok(float) = value.parse::<f64>()
        && let Some(number) = Number::from_f64(float)
    {
        return Ok(Value::Number(number));
    }
    if !bounded_scalar_text(value, MAX_OPENAPI_SCALAR_BYTES) {
        return Err("yaml-scalar-limit-exceeded".to_owned());
    }
    Ok(Value::String(value.to_owned()))
}

struct OpenApiGraphBuilder {
    profile_id: String,
    documents: BTreeMap<String, OpenApiDocument>,
    nodes: BTreeMap<String, GraphNode>,
    sites: BTreeMap<String, DependencySite>,
    edges: BTreeMap<String, GraphEdge>,
    cross_node_ids: BTreeSet<String>,
    service_ids: BTreeMap<String, String>,
    document_node_ids: BTreeMap<String, String>,
    message_ids: BTreeMap<(String, String), String>,
    scanned_schema_nodes: BTreeSet<String>,
    reference_arcs: Vec<(String, String, String)>,
    reasons: BTreeSet<String>,
    external_count: u64,
    unresolved_count: u64,
    reference_count: usize,
}

impl OpenApiGraphBuilder {
    fn new(profile_id: String, documents: BTreeMap<String, OpenApiDocument>) -> Self {
        Self {
            profile_id,
            documents,
            nodes: BTreeMap::new(),
            sites: BTreeMap::new(),
            edges: BTreeMap::new(),
            cross_node_ids: BTreeSet::new(),
            service_ids: BTreeMap::new(),
            document_node_ids: BTreeMap::new(),
            message_ids: BTreeMap::new(),
            scanned_schema_nodes: BTreeSet::new(),
            reference_arcs: Vec::new(),
            reasons: BTreeSet::new(),
            external_count: 0,
            unresolved_count: 0,
            reference_count: 0,
        }
    }

    fn build(&mut self) -> Result<()> {
        let locators = self.documents.keys().cloned().collect::<Vec<_>>();
        for locator in &locators {
            let service_id =
                self.add_cross_node(CrossLanguageNodeKind::Service, locator, "openapi-service")?;
            let document_id =
                self.add_cross_node(CrossLanguageNodeKind::Schema, locator, "openapi-document")?;
            self.service_ids.insert(locator.clone(), service_id);
            self.document_node_ids.insert(locator.clone(), document_id);
        }

        for locator in &locators {
            let document = self
                .documents
                .get(locator)
                .cloned()
                .context("admitted OpenAPI document disappeared")?;
            if let Some(schemas) = document
                .root
                .pointer("/components/schemas")
                .and_then(Value::as_object)
            {
                for (name, schema) in sorted_object(schemas) {
                    let pointer = format!("/components/schemas/{}", pointer_escape(&name));
                    let (message_id, _) = self.ensure_message(locator, &pointer)?;
                    let document_id = self.document_node_ids[locator].clone();
                    self.add_relation(RelationInput {
                        source: &document_id,
                        target: &message_id,
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        evidence_locator: locator,
                        pointer: &pointer,
                        status: ResolutionStatus::Resolved,
                        precision: Precision::Exact,
                        mapping: CrossLanguageMappingKind::ContractInternal,
                        reason: None,
                        conditions: Vec::new(),
                    })?;
                    self.scan_schema_refs(&message_id, locator, &pointer, &schema)?;
                }
            }
        }

        for locator in locators {
            self.process_document_paths(&locator)?;
            self.process_document_webhooks(&locator)?;
        }
        Ok(())
    }

    fn add_cross_node(
        &mut self,
        kind: CrossLanguageNodeKind,
        locator: &str,
        coordinate: &str,
    ) -> Result<String> {
        if !bounded_contract_text(locator) || !bounded_contract_text(coordinate) {
            bail!("OpenAPI canonical identity exceeds its bounded contract");
        }
        let document = self
            .documents
            .get(locator)
            .with_context(|| format!("OpenAPI node references unknown document {locator}"))?;
        let identity = CrossLanguageCanonicalIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            format: CrossLanguageFormat::Openapi,
            repository_contract_locator: locator.to_owned(),
            format_version: document.version.clone(),
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
                    Value::String(CrossLanguageFormat::Openapi.as_str().to_owned()),
                ),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
            ]),
        };
        insert_identical(&mut self.nodes, id.clone(), node, "OpenAPI node")?;
        self.cross_node_ids.insert(id.clone());
        Ok(id)
    }

    fn ensure_message(&mut self, locator: &str, pointer: &str) -> Result<(String, bool)> {
        let key = (locator.to_owned(), pointer.to_owned());
        if let Some(id) = self.message_ids.get(&key) {
            return Ok((id.clone(), false));
        }
        if !valid_json_pointer(pointer) {
            bail!("OpenAPI schema pointer is invalid or unbounded");
        }
        let coordinate = if pointer.is_empty() {
            "schema #".to_owned()
        } else {
            format!("schema #{pointer}")
        };
        let id = self.add_cross_node(CrossLanguageNodeKind::Message, locator, &coordinate)?;
        self.message_ids.insert(key, id.clone());
        Ok((id, true))
    }

    fn process_document_paths(&mut self, locator: &str) -> Result<()> {
        let paths = self
            .documents
            .get(locator)
            .and_then(|document| document.root.get("paths"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (raw_path, path_item) in sorted_object(&paths) {
            let pointer = format!("/paths/{}", pointer_escape(&raw_path));
            let path = match normalize_path_template(&raw_path) {
                Some(path) => path,
                None => {
                    let service = self.service_ids[locator].clone();
                    let target =
                        self.unknown_node(locator, &pointer, "invalid-openapi-path-template")?;
                    self.add_relation(RelationInput {
                        source: &service,
                        target: &target,
                        relation: CrossLanguageRelationKind::ProvidesOperation,
                        evidence_locator: locator,
                        pointer: &pointer,
                        status: ResolutionStatus::Unresolved,
                        precision: Precision::Heuristic,
                        mapping: CrossLanguageMappingKind::Unresolved,
                        reason: Some("invalid-openapi-path-template"),
                        conditions: Vec::new(),
                    })?;
                    continue;
                }
            };
            self.process_path_item(locator, &path, &pointer, path_item, None, 0)?;
        }
        Ok(())
    }

    fn process_document_webhooks(&mut self, locator: &str) -> Result<()> {
        let webhooks = self
            .documents
            .get(locator)
            .and_then(|document| document.root.get("webhooks"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (index, (name, path_item)) in sorted_object(&webhooks).into_iter().enumerate() {
            if !bounded_contract_text(&name) {
                let service = self.service_ids[locator].clone();
                let target =
                    self.unknown_node(locator, "/webhooks", "webhook-name-is-unbounded")?;
                self.add_relation(RelationInput {
                    source: &service,
                    target: &target,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    evidence_locator: locator,
                    pointer: "/webhooks",
                    status: ResolutionStatus::Unresolved,
                    precision: Precision::Heuristic,
                    mapping: CrossLanguageMappingKind::Unresolved,
                    reason: Some("webhook-name-is-unbounded"),
                    conditions: Vec::new(),
                })?;
                continue;
            }
            let pointer = format!("/webhooks/{}", pointer_escape(&name));
            let synthetic_path = format!("/webhook/{index}");
            let operation_context = format!("webhook {name}");
            self.process_path_item(
                locator,
                &synthetic_path,
                &pointer,
                path_item,
                Some(&operation_context),
                0,
            )?;
        }
        Ok(())
    }

    fn process_path_item(
        &mut self,
        locator: &str,
        path: &str,
        pointer: &str,
        path_item: Value,
        operation_context: Option<&str>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_OPENAPI_REFERENCE_DEPTH {
            self.reasons
                .insert("callback-depth-limit-exceeded".to_owned());
            return Ok(());
        }
        let resolved = self.resolve_object(locator, pointer, path_item)?;
        let object = match resolved {
            ObjectResolution::Resolved { value, .. } => value,
            ObjectResolution::External { identity } => {
                let service = self.service_ids[locator].clone();
                let target = self.external_node(&identity)?;
                self.add_relation(RelationInput {
                    source: &service,
                    target: &target,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    evidence_locator: locator,
                    pointer,
                    status: ResolutionStatus::External,
                    precision: Precision::Exact,
                    mapping: CrossLanguageMappingKind::ExternalReference,
                    reason: Some("remote-path-item-not-fetched"),
                    conditions: Vec::new(),
                })?;
                return Ok(());
            }
            ObjectResolution::Unresolved { reason } => {
                let service = self.service_ids[locator].clone();
                let target = self.unknown_node(locator, pointer, &reason)?;
                self.add_relation(RelationInput {
                    source: &service,
                    target: &target,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    evidence_locator: locator,
                    pointer,
                    status: ResolutionStatus::Unresolved,
                    precision: Precision::Heuristic,
                    mapping: CrossLanguageMappingKind::Unresolved,
                    reason: Some(&reason),
                    conditions: Vec::new(),
                })?;
                return Ok(());
            }
        };
        let Some(path_object) = object.as_object() else {
            self.reasons.insert("path-item-is-not-an-object".to_owned());
            return Ok(());
        };
        let inherited_parameters = path_object
            .get("parameters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for method in HTTP_METHODS {
            let Some(operation) = path_object.get(method).cloned() else {
                continue;
            };
            let operation_pointer = format!("{pointer}/{method}");
            let coordinate = operation_context.map_or_else(
                || format!("{method} {path}"),
                |context| format!("{context} #{operation_pointer} {method}"),
            );
            let operation_id =
                self.add_cross_node(CrossLanguageNodeKind::Operation, locator, &coordinate)?;
            let service_id = self.service_ids[locator].clone();
            self.add_relation(RelationInput {
                source: &service_id,
                target: &operation_id,
                relation: CrossLanguageRelationKind::ProvidesOperation,
                evidence_locator: locator,
                pointer: &operation_pointer,
                status: ResolutionStatus::Resolved,
                precision: Precision::Exact,
                mapping: CrossLanguageMappingKind::ContractInternal,
                reason: None,
                conditions: vec![
                    ("openapi.http_method", method.to_owned()),
                    ("openapi.path_template", path.to_owned()),
                ],
            })?;
            let Some(operation_object) = operation.as_object() else {
                let target =
                    self.unknown_node(locator, &operation_pointer, "operation-is-not-an-object")?;
                self.add_relation(RelationInput {
                    source: &operation_id,
                    target: &target,
                    relation: CrossLanguageRelationKind::AcceptsMessage,
                    evidence_locator: locator,
                    pointer: &operation_pointer,
                    status: ResolutionStatus::Unresolved,
                    precision: Precision::Heuristic,
                    mapping: CrossLanguageMappingKind::Unresolved,
                    reason: Some("operation-is-not-an-object"),
                    conditions: vec![("openapi.http_method", method.to_owned())],
                })?;
                continue;
            };
            for (index, parameter) in inherited_parameters.iter().cloned().enumerate() {
                self.process_parameter(
                    &operation_id,
                    locator,
                    &format!("{pointer}/parameters/{index}"),
                    parameter,
                    method,
                    path,
                )?;
            }
            for (index, parameter) in operation_object
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .cloned()
                .enumerate()
            {
                self.process_parameter(
                    &operation_id,
                    locator,
                    &format!("{operation_pointer}/parameters/{index}"),
                    parameter,
                    method,
                    path,
                )?;
            }
            if let Some(request_body) = operation_object.get("requestBody").cloned() {
                self.process_message_container(
                    &operation_id,
                    locator,
                    &format!("{operation_pointer}/requestBody"),
                    request_body,
                    CrossLanguageRelationKind::AcceptsMessage,
                    method,
                    path,
                    None,
                )?;
            }
            if let Some(responses) = operation_object.get("responses").and_then(Value::as_object) {
                for (status, response) in sorted_object(responses) {
                    if !bounded_contract_text(&status) {
                        self.reasons
                            .insert("response-status-is-unbounded".to_owned());
                        continue;
                    }
                    self.process_message_container(
                        &operation_id,
                        locator,
                        &format!("{operation_pointer}/responses/{}", pointer_escape(&status)),
                        response,
                        CrossLanguageRelationKind::ReturnsMessage,
                        method,
                        path,
                        Some(&status),
                    )?;
                }
            }
            if let Some(callbacks) = operation_object.get("callbacks").and_then(Value::as_object) {
                for (callback_name, callback) in sorted_object(callbacks) {
                    let callback_pointer = format!(
                        "{operation_pointer}/callbacks/{}",
                        pointer_escape(&callback_name)
                    );
                    self.process_callback(
                        &coordinate,
                        locator,
                        &callback_pointer,
                        callback,
                        depth + 1,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn process_parameter(
        &mut self,
        operation_id: &str,
        evidence_locator: &str,
        pointer: &str,
        parameter: Value,
        method: &str,
        path: &str,
    ) -> Result<()> {
        match self.resolve_object(evidence_locator, pointer, parameter)? {
            ObjectResolution::Resolved {
                locator,
                pointer: resolved_pointer,
                value,
            } => {
                let Some(object) = value.as_object() else {
                    return self.add_unresolved_message_relation(
                        operation_id,
                        evidence_locator,
                        pointer,
                        CrossLanguageRelationKind::AcceptsMessage,
                        "parameter-is-not-an-object",
                        method,
                        path,
                        None,
                    );
                };
                if let Some(schema) = object.get("schema").cloned() {
                    self.attach_schema(
                        operation_id,
                        evidence_locator,
                        pointer,
                        &locator,
                        &format!("{resolved_pointer}/schema"),
                        schema,
                        CrossLanguageRelationKind::AcceptsMessage,
                        method,
                        path,
                        None,
                        None,
                    )?;
                }
                if let Some(content) = object.get("content").and_then(Value::as_object) {
                    self.process_content(
                        operation_id,
                        evidence_locator,
                        pointer,
                        &locator,
                        &format!("{resolved_pointer}/content"),
                        content,
                        CrossLanguageRelationKind::AcceptsMessage,
                        method,
                        path,
                        None,
                    )?;
                }
            }
            ObjectResolution::External { identity } => {
                let target = self.external_node(&identity)?;
                self.add_relation(RelationInput {
                    source: operation_id,
                    target: &target,
                    relation: CrossLanguageRelationKind::AcceptsMessage,
                    evidence_locator,
                    pointer,
                    status: ResolutionStatus::External,
                    precision: Precision::Exact,
                    mapping: CrossLanguageMappingKind::ExternalReference,
                    reason: Some("remote-parameter-not-fetched"),
                    conditions: operation_conditions(method, path, None, None),
                })?;
            }
            ObjectResolution::Unresolved { reason } => {
                self.add_unresolved_message_relation(
                    operation_id,
                    evidence_locator,
                    pointer,
                    CrossLanguageRelationKind::AcceptsMessage,
                    &reason,
                    method,
                    path,
                    None,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_message_container(
        &mut self,
        operation_id: &str,
        evidence_locator: &str,
        pointer: &str,
        container: Value,
        relation: CrossLanguageRelationKind,
        method: &str,
        path: &str,
        response_status: Option<&str>,
    ) -> Result<()> {
        match self.resolve_object(evidence_locator, pointer, container)? {
            ObjectResolution::Resolved {
                locator,
                pointer: resolved_pointer,
                value,
            } => {
                let Some(object) = value.as_object() else {
                    return self.add_unresolved_message_relation(
                        operation_id,
                        evidence_locator,
                        pointer,
                        relation,
                        "message-container-is-not-an-object",
                        method,
                        path,
                        response_status,
                    );
                };
                if let Some(content) = object.get("content").and_then(Value::as_object) {
                    self.process_content(
                        operation_id,
                        evidence_locator,
                        pointer,
                        &locator,
                        &format!("{resolved_pointer}/content"),
                        content,
                        relation,
                        method,
                        path,
                        response_status,
                    )?;
                }
            }
            ObjectResolution::External { identity } => {
                let target = self.external_node(&identity)?;
                self.add_relation(RelationInput {
                    source: operation_id,
                    target: &target,
                    relation,
                    evidence_locator,
                    pointer,
                    status: ResolutionStatus::External,
                    precision: Precision::Exact,
                    mapping: CrossLanguageMappingKind::ExternalReference,
                    reason: Some("remote-message-container-not-fetched"),
                    conditions: operation_conditions(method, path, None, response_status),
                })?;
            }
            ObjectResolution::Unresolved { reason } => {
                self.add_unresolved_message_relation(
                    operation_id,
                    evidence_locator,
                    pointer,
                    relation,
                    &reason,
                    method,
                    path,
                    response_status,
                )?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_content(
        &mut self,
        operation_id: &str,
        evidence_locator: &str,
        evidence_pointer: &str,
        schema_locator: &str,
        content_pointer: &str,
        content: &Map<String, Value>,
        relation: CrossLanguageRelationKind,
        method: &str,
        path: &str,
        response_status: Option<&str>,
    ) -> Result<()> {
        for (media_type, media) in sorted_object(content) {
            if !bounded_contract_text(&media_type) {
                self.reasons.insert("media-type-is-unbounded".to_owned());
                continue;
            }
            let Some(schema) = media.get("schema").cloned() else {
                continue;
            };
            let schema_pointer =
                format!("{content_pointer}/{}/schema", pointer_escape(&media_type));
            self.attach_schema(
                operation_id,
                evidence_locator,
                evidence_pointer,
                schema_locator,
                &schema_pointer,
                schema,
                relation,
                method,
                path,
                Some(&media_type),
                response_status,
            )?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn attach_schema(
        &mut self,
        operation_id: &str,
        evidence_locator: &str,
        evidence_pointer: &str,
        schema_locator: &str,
        schema_pointer: &str,
        schema: Value,
        relation: CrossLanguageRelationKind,
        method: &str,
        path: &str,
        media_type: Option<&str>,
        response_status: Option<&str>,
    ) -> Result<()> {
        let (message_id, created) = self.ensure_message(schema_locator, schema_pointer)?;
        self.add_relation(RelationInput {
            source: operation_id,
            target: &message_id,
            relation,
            evidence_locator,
            pointer: evidence_pointer,
            status: ResolutionStatus::Resolved,
            precision: Precision::Exact,
            mapping: CrossLanguageMappingKind::ContractInternal,
            reason: None,
            conditions: operation_conditions(method, path, media_type, response_status),
        })?;
        if created || self.scanned_schema_nodes.insert(message_id.clone()) {
            self.scan_schema_refs(&message_id, schema_locator, schema_pointer, &schema)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_unresolved_message_relation(
        &mut self,
        operation_id: &str,
        evidence_locator: &str,
        pointer: &str,
        relation: CrossLanguageRelationKind,
        reason: &str,
        method: &str,
        path: &str,
        response_status: Option<&str>,
    ) -> Result<()> {
        let target = self.unknown_node(evidence_locator, pointer, reason)?;
        self.add_relation(RelationInput {
            source: operation_id,
            target: &target,
            relation,
            evidence_locator,
            pointer,
            status: ResolutionStatus::Unresolved,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::Unresolved,
            reason: Some(reason),
            conditions: operation_conditions(method, path, None, response_status),
        })?;
        Ok(())
    }

    fn process_callback(
        &mut self,
        parent_coordinate: &str,
        evidence_locator: &str,
        pointer: &str,
        callback: Value,
        depth: usize,
    ) -> Result<()> {
        match self.resolve_object(evidence_locator, pointer, callback)? {
            ObjectResolution::Resolved {
                locator,
                pointer: resolved_pointer,
                value,
            } => {
                let Some(callback_object) = value.as_object() else {
                    self.reasons.insert("callback-is-not-an-object".to_owned());
                    return Ok(());
                };
                for (index, (expression, path_item)) in
                    sorted_object(callback_object).into_iter().enumerate()
                {
                    let callback_pointer =
                        format!("{resolved_pointer}/{}", pointer_escape(&expression));
                    let synthetic_path = format!("/callback/{index}");
                    let operation_context = format!("callback {parent_coordinate}");
                    self.process_path_item(
                        &locator,
                        &synthetic_path,
                        &callback_pointer,
                        path_item,
                        Some(&operation_context),
                        depth,
                    )?;
                }
            }
            ObjectResolution::External { identity } => {
                let service = self.service_ids[evidence_locator].clone();
                let target = self.external_node(&identity)?;
                self.add_relation(RelationInput {
                    source: &service,
                    target: &target,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    evidence_locator,
                    pointer,
                    status: ResolutionStatus::External,
                    precision: Precision::Exact,
                    mapping: CrossLanguageMappingKind::ExternalReference,
                    reason: Some("remote-callback-not-fetched"),
                    conditions: Vec::new(),
                })?;
            }
            ObjectResolution::Unresolved { reason } => {
                let service = self.service_ids[evidence_locator].clone();
                let target = self.unknown_node(evidence_locator, pointer, &reason)?;
                self.add_relation(RelationInput {
                    source: &service,
                    target: &target,
                    relation: CrossLanguageRelationKind::ProvidesOperation,
                    evidence_locator,
                    pointer,
                    status: ResolutionStatus::Unresolved,
                    precision: Precision::Heuristic,
                    mapping: CrossLanguageMappingKind::Unresolved,
                    reason: Some(&reason),
                    conditions: Vec::new(),
                })?;
            }
        }
        Ok(())
    }

    fn scan_schema_refs(
        &mut self,
        source_id: &str,
        locator: &str,
        pointer: &str,
        schema: &Value,
    ) -> Result<()> {
        if !self.scanned_schema_nodes.insert(source_id.to_owned()) {
            return Ok(());
        }
        let mut references = Vec::new();
        collect_schema_references(schema, pointer, 0, &mut references)?;
        for (reference_pointer, reference) in references {
            self.reference_count += 1;
            if self.reference_count > MAX_OPENAPI_REFERENCES {
                let target = self.unknown_node(
                    locator,
                    &reference_pointer,
                    "reference-fanout-limit-exceeded",
                )?;
                self.add_relation(RelationInput {
                    source: source_id,
                    target: &target,
                    relation: CrossLanguageRelationKind::ReferencesSchema,
                    evidence_locator: locator,
                    pointer: &reference_pointer,
                    status: ResolutionStatus::Unresolved,
                    precision: Precision::Heuristic,
                    mapping: CrossLanguageMappingKind::Unresolved,
                    reason: Some("reference-fanout-limit-exceeded"),
                    conditions: Vec::new(),
                })?;
                break;
            }
            match self.resolve_reference(locator, &reference) {
                ReferenceResolution::Resolved {
                    locator: target_locator,
                    pointer: target_pointer,
                    ..
                } => {
                    let (target_id, _) = self.ensure_message(&target_locator, &target_pointer)?;
                    let site_id = self.add_relation(RelationInput {
                        source: source_id,
                        target: &target_id,
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        evidence_locator: locator,
                        pointer: &reference_pointer,
                        status: ResolutionStatus::Resolved,
                        precision: Precision::Exact,
                        mapping: CrossLanguageMappingKind::ContractInternal,
                        reason: None,
                        conditions: Vec::new(),
                    })?;
                    self.reference_arcs
                        .push((site_id, source_id.to_owned(), target_id));
                }
                ReferenceResolution::External { identity } => {
                    let target = self.external_node(&identity)?;
                    self.add_relation(RelationInput {
                        source: source_id,
                        target: &target,
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        evidence_locator: locator,
                        pointer: &reference_pointer,
                        status: ResolutionStatus::External,
                        precision: Precision::Exact,
                        mapping: CrossLanguageMappingKind::ExternalReference,
                        reason: Some("remote-reference-not-fetched"),
                        conditions: Vec::new(),
                    })?;
                }
                ReferenceResolution::Unresolved { reason } => {
                    let target = self.unknown_node(locator, &reference_pointer, &reason)?;
                    self.add_relation(RelationInput {
                        source: source_id,
                        target: &target,
                        relation: CrossLanguageRelationKind::ReferencesSchema,
                        evidence_locator: locator,
                        pointer: &reference_pointer,
                        status: ResolutionStatus::Unresolved,
                        precision: Precision::Heuristic,
                        mapping: CrossLanguageMappingKind::Unresolved,
                        reason: Some(&reason),
                        conditions: Vec::new(),
                    })?;
                }
            }
        }
        Ok(())
    }

    fn resolve_object(
        &self,
        locator: &str,
        pointer: &str,
        value: Value,
    ) -> Result<ObjectResolution> {
        let mut current_locator = locator.to_owned();
        let mut current_pointer = pointer.to_owned();
        let mut current_value = value;
        let mut visited = BTreeSet::new();
        for _ in 0..=MAX_OPENAPI_REFERENCE_DEPTH {
            let Some(reference) = current_value
                .as_object()
                .and_then(|object| object.get("$ref"))
                .and_then(Value::as_str)
            else {
                return Ok(ObjectResolution::Resolved {
                    locator: current_locator,
                    pointer: current_pointer,
                    value: current_value,
                });
            };
            let key = (current_locator.clone(), current_pointer.clone());
            if !visited.insert(key) {
                return Ok(ObjectResolution::Unresolved {
                    reason: "cyclic-object-reference".to_owned(),
                });
            }
            match self.resolve_reference(&current_locator, reference) {
                ReferenceResolution::Resolved {
                    locator,
                    pointer,
                    value,
                } => {
                    current_locator = locator;
                    current_pointer = pointer;
                    current_value = value;
                }
                ReferenceResolution::External { identity } => {
                    return Ok(ObjectResolution::External { identity });
                }
                ReferenceResolution::Unresolved { reason } => {
                    return Ok(ObjectResolution::Unresolved { reason });
                }
            }
        }
        Ok(ObjectResolution::Unresolved {
            reason: "reference-depth-limit-exceeded".to_owned(),
        })
    }

    fn resolve_reference(&self, base_locator: &str, reference: &str) -> ReferenceResolution {
        if !bounded_contract_text(reference) {
            return ReferenceResolution::Unresolved {
                reason: "reference-is-unbounded".to_owned(),
            };
        }
        if let Some(remote) = remote_reference_identity(reference) {
            return remote;
        }
        if reference.contains('\\') || reference.contains('?') {
            return ReferenceResolution::Unresolved {
                reason: "reference-path-is-unsafe".to_owned(),
            };
        }
        let (raw_path, raw_fragment) = reference
            .split_once('#')
            .map_or((reference, ""), |(path, fragment)| (path, fragment));
        let decoded_path = match percent_decode(raw_path) {
            Some(path) => path,
            None => {
                return ReferenceResolution::Unresolved {
                    reason: "reference-path-encoding-is-invalid".to_owned(),
                };
            }
        };
        let locator = if decoded_path.is_empty() {
            base_locator.to_owned()
        } else {
            match resolve_repository_reference(base_locator, &decoded_path) {
                Some(locator) => locator,
                None => {
                    return ReferenceResolution::Unresolved {
                        reason: "reference-escapes-repository".to_owned(),
                    };
                }
            }
        };
        let Some(document) = self.documents.get(&locator) else {
            return ReferenceResolution::Unresolved {
                reason: "local-reference-not-admitted".to_owned(),
            };
        };
        let fragment = match percent_decode(raw_fragment) {
            Some(fragment) => fragment,
            None => {
                return ReferenceResolution::Unresolved {
                    reason: "reference-fragment-encoding-is-invalid".to_owned(),
                };
            }
        };
        let pointer = if fragment.is_empty() {
            String::new()
        } else if fragment.starts_with('/') && valid_json_pointer(&fragment) {
            fragment
        } else {
            return ReferenceResolution::Unresolved {
                reason: "reference-fragment-is-not-json-pointer".to_owned(),
            };
        };
        let Some(value) = document.root.pointer(&pointer).cloned() else {
            return ReferenceResolution::Unresolved {
                reason: "reference-target-is-missing".to_owned(),
            };
        };
        ReferenceResolution::Resolved {
            locator,
            pointer,
            value,
        }
    }

    fn unknown_node(&mut self, locator: &str, pointer: &str, reason: &str) -> Result<String> {
        let reason = bounded_reason(reason);
        let id = stable_id_from_value(
            "unknown_target",
            &json!({
                "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
                "format": "openapi",
                "profile_id": self.profile_id,
                "locator": locator,
                "pointer": pointer,
                "reason": reason,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "unknown_target".to_owned(),
            locator: format!("unknown:openapi:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                ("format".to_owned(), Value::String("openapi".to_owned())),
                ("reason_code".to_owned(), Value::String(reason.clone())),
            ]),
        };
        insert_identical(&mut self.nodes, id.clone(), node, "OpenAPI unknown node")?;
        self.reasons.insert(reason);
        Ok(id)
    }

    fn external_node(&mut self, identity: &str) -> Result<String> {
        let id = stable_id_from_value(
            "external_system",
            &json!({
                "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
                "format": "openapi",
                "profile_id": self.profile_id,
                "authority_identity": identity,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "external_system".to_owned(),
            locator: format!("external:openapi:{id}"),
            display_name: None,
            properties: BTreeMap::from([(
                "format".to_owned(),
                Value::String("openapi".to_owned()),
            )]),
        };
        insert_identical(&mut self.nodes, id.clone(), node, "OpenAPI external node")?;
        Ok(id)
    }

    fn add_relation(&mut self, input: RelationInput<'_>) -> Result<String> {
        let document = self
            .documents
            .get(input.evidence_locator)
            .with_context(|| {
                format!(
                    "OpenAPI relation references unknown evidence document {}",
                    input.evidence_locator
                )
            })?;
        if !valid_json_pointer(input.pointer) {
            bail!("OpenAPI relation pointer is invalid or unbounded");
        }
        let condition = Condition::All {
            conditions: std::iter::once(("openapi.pointer".to_owned(), input.pointer.to_owned()))
                .chain(
                    input
                        .conditions
                        .into_iter()
                        .map(|(key, value)| (key.to_owned(), value)),
                )
                .map(|(key, value)| Condition::Eq {
                    key,
                    value: Value::String(value),
                })
                .collect(),
        }
        .canonicalize();
        let mut evidence_properties = Properties::from([
            (
                "contract_version".to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            ("format".to_owned(), Value::String("openapi".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(self.profile_id.clone()),
            ),
            (
                "format_version".to_owned(),
                Value::String(document.version.clone()),
            ),
            (
                "contract_digest".to_owned(),
                Value::String(document.digest.clone()),
            ),
            (
                "occurrence_kind".to_owned(),
                serde_json::to_value(input.relation)?,
            ),
            (
                "mapping_kind".to_owned(),
                serde_json::to_value(input.mapping)?,
            ),
        ]);
        evidence_properties.insert(
            "json_pointer".to_owned(),
            Value::String(input.pointer.to_owned()),
        );
        let evidence = vec![Evidence {
            kind: EvidenceKind::Semantic,
            extractor: EXTRACTOR.to_owned(),
            extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
            path: Some(input.evidence_locator.to_owned()),
            start_line: Some(1),
            start_column: Some(1),
            end_line: Some(document.end_line),
            end_column: Some(document.end_column),
            detail: None,
            properties: evidence_properties,
        }];
        let mut site = DependencySite {
            id: String::new(),
            source: input.source.to_owned(),
            kind: input.relation.as_str().to_owned(),
            specifier: format!("#{}", input.pointer),
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
        insert_identical(&mut self.sites, site.id.clone(), site, "OpenAPI site")?;
        insert_identical(&mut self.edges, edge.id.clone(), edge, "OpenAPI edge")?;
        match input.status {
            ResolutionStatus::External => self.external_count += 1,
            ResolutionStatus::Unresolved => {
                self.unresolved_count += 1;
                if let Some(reason) = input.reason {
                    self.reasons.insert(bounded_reason(reason));
                }
            }
            _ => {}
        }
        Ok(site_id)
    }

    fn mark_recursive_schema_sites(&mut self) {
        let mut graph = DiGraphMap::<&str, ()>::new();
        for (_, source, target) in &self.reference_arcs {
            graph.add_edge(source.as_str(), target.as_str(), ());
        }
        let mut cyclic_components = BTreeMap::new();
        for (component_id, component) in kosaraju_scc(&graph).into_iter().enumerate() {
            let self_loop = component
                .first()
                .is_some_and(|node| graph.contains_edge(*node, *node));
            if component.len() > 1 || self_loop {
                for node in component {
                    cyclic_components.insert(node, component_id);
                }
            }
        }
        for (site_id, source, target) in &self.reference_arcs {
            if cyclic_components.get(source.as_str()) == cyclic_components.get(target.as_str())
                && cyclic_components.contains_key(source.as_str())
                && let Some(site) = self.sites.get_mut(site_id)
            {
                site.reason = Some("cyclic-schema-reference".to_owned());
                self.reasons.insert("cyclic-schema-reference".to_owned());
            }
        }
    }
}

struct RelationInput<'a> {
    source: &'a str,
    target: &'a str,
    relation: CrossLanguageRelationKind,
    evidence_locator: &'a str,
    pointer: &'a str,
    status: ResolutionStatus,
    precision: Precision,
    mapping: CrossLanguageMappingKind,
    reason: Option<&'a str>,
    conditions: Vec<(&'a str, String)>,
}

enum ObjectResolution {
    Resolved {
        locator: String,
        pointer: String,
        value: Value,
    },
    External {
        identity: String,
    },
    Unresolved {
        reason: String,
    },
}

enum ReferenceResolution {
    Resolved {
        locator: String,
        pointer: String,
        value: Value,
    },
    External {
        identity: String,
    },
    Unresolved {
        reason: String,
    },
}

const HTTP_METHODS: [&str; 8] = [
    "delete", "get", "head", "options", "patch", "post", "put", "trace",
];

fn operation_conditions<'a>(
    method: &'a str,
    path: &'a str,
    media_type: Option<&'a str>,
    response_status: Option<&'a str>,
) -> Vec<(&'a str, String)> {
    let mut conditions = vec![
        ("openapi.http_method", method.to_owned()),
        ("openapi.path_template", path.to_owned()),
    ];
    if let Some(media_type) = media_type {
        conditions.push(("openapi.media_type", media_type.to_owned()));
    }
    if let Some(status) = response_status {
        conditions.push(("openapi.response_status", status.to_owned()));
    }
    conditions
}

fn insert_identical<T: PartialEq>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> Result<()> {
    if let Some(existing) = map.get(&key) {
        if existing != &value {
            bail!("{label} identity collision");
        }
        return Ok(());
    }
    map.insert(key, value);
    Ok(())
}

fn sorted_object(object: &Map<String, Value>) -> Vec<(String, Value)> {
    let mut entries = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn bounded_contract_text(value: &str) -> bool {
    bounded_text(value, 4_096)
}

fn bounded_reason(reason: &str) -> String {
    if bounded_text(reason, MAX_REASON_BYTES) {
        reason.to_owned()
    } else {
        "openapi-validation-failed".to_owned()
    }
}

fn valid_json_pointer(pointer: &str) -> bool {
    pointer.len() <= 4_096
        && !pointer.chars().any(char::is_control)
        && (pointer.is_empty() || pointer.starts_with('/'))
        && pointer.split('/').skip(1).all(valid_pointer_token)
}

fn valid_pointer_token(token: &str) -> bool {
    let mut chars = token.chars();
    while let Some(character) = chars.next() {
        if character == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

fn pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn normalize_path_template(path: &str) -> Option<String> {
    let path = path.trim();
    if !bounded_contract_text(path)
        || !path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || path.contains('\\')
    {
        return None;
    }
    let mut depth = 0_u32;
    for character in path.chars() {
        match character {
            '{' => {
                depth = depth.checked_add(1)?;
                if depth > 1 {
                    return None;
                }
            }
            '}' => {
                depth = depth.checked_sub(1)?;
            }
            _ => {}
        }
    }
    (depth == 0).then_some(path.to_owned())
}

fn collect_schema_references(
    schema: &Value,
    pointer: &str,
    depth: usize,
    output: &mut Vec<(String, String)>,
) -> Result<()> {
    if depth > MAX_OPENAPI_DEPTH || output.len() > MAX_OPENAPI_REFERENCES {
        bail!("OpenAPI schema reference traversal exceeded its bound");
    }
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        output.push((format!("{pointer}/$ref"), reference.to_owned()));
    }
    for key in [
        "properties",
        "patternProperties",
        "dependentSchemas",
        "$defs",
        "definitions",
    ] {
        if let Some(children) = object.get(key).and_then(Value::as_object) {
            for (name, child) in sorted_object(children) {
                collect_schema_references(
                    &child,
                    &format!("{pointer}/{key}/{}", pointer_escape(&name)),
                    depth + 1,
                    output,
                )?;
            }
        }
    }
    for key in [
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
    ] {
        if let Some(child) = object.get(key)
            && child.is_object()
        {
            collect_schema_references(child, &format!("{pointer}/{key}"), depth + 1, output)?;
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = object.get(key).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                collect_schema_references(
                    child,
                    &format!("{pointer}/{key}/{index}"),
                    depth + 1,
                    output,
                )?;
            }
        }
    }
    Ok(())
}

fn resolve_repository_reference(base_locator: &str, reference: &str) -> Option<String> {
    if reference.is_empty() || reference.starts_with('/') || reference.contains('\\') {
        return None;
    }
    let mut parts = base_locator
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    parts.pop();
    for component in Path::new(reference).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => {
                let value = value.to_str()?;
                if value.is_empty() {
                    return None;
                }
                parts.push(value.to_owned());
            }
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let locator = parts.join("/");
    (!locator.is_empty() && bounded_contract_text(&locator)).then_some(locator)
}

fn percent_decode(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(String::new());
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    bounded_contract_text(&decoded).then_some(decoded)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn remote_reference_identity(reference: &str) -> Option<ReferenceResolution> {
    let Some((scheme, remainder)) = reference.split_once("://") else {
        let scheme = reference.split_once(':')?.0;
        if scheme.starts_with(|character: char| character.is_ascii_alphabetic())
            && scheme.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            })
        {
            return Some(ReferenceResolution::Unresolved {
                reason: "unsupported-reference-scheme".to_owned(),
            });
        }
        return None;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return Some(ReferenceResolution::Unresolved {
            reason: "unsupported-reference-scheme".to_owned(),
        });
    }
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if authority.is_empty()
        || authority.contains('@')
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return Some(ReferenceResolution::Unresolved {
            reason: "remote-reference-authority-is-unsafe".to_owned(),
        });
    }
    Some(ReferenceResolution::External {
        identity: digest_value(&Value::String(authority)),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCompletenessLedger,
        validate_cross_language_adapter_delta,
    };

    use super::*;

    const JSON_API: &str = r#"{
      "openapi": "3.1.1",
      "info": {"title": "Users"},
      "paths": {
        "/users/{id}": {
          "get": {
            "parameters": [
              {"name": "id", "in": "path", "schema": {"$ref": "models.yaml#/components/schemas/UserId"}}
            ],
            "responses": {
              "200": {
                "content": {
                  "application/json": {
                    "schema": {"$ref": "models.yaml#/components/schemas/User"}
                  }
                }
              }
            }
          }
        }
      }
    }"#;

    const YAML_MODELS: &str = r#"
openapi: 3.1.0
info:
  title: Models
paths: {}
components:
  schemas:
    UserId:
      type: string
    User:
      type: object
      properties:
        id:
          $ref: '#/components/schemas/UserId'
"#;

    fn write_pair(root: &Path, reverse: bool) {
        if reverse {
            fs::write(root.join("models.yaml"), YAML_MODELS).unwrap();
            fs::write(root.join("openapi.json"), JSON_API).unwrap();
        } else {
            fs::write(root.join("openapi.json"), JSON_API).unwrap();
            fs::write(root.join("models.yaml"), YAML_MODELS).unwrap();
        }
    }

    fn ledger(delta: &CrossLanguageAdapterDelta) -> CrossLanguageCompletenessLedger {
        serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap()
    }

    fn participating_profiles() -> Vec<Profile> {
        vec![Profile {
            id: "web:production".to_owned(),
            language: "typescript".to_owned(),
            toolchain: None,
            command: None,
            target: None,
            features: Vec::new(),
            environment: BTreeMap::new(),
            source_revision: None,
            properties: BTreeMap::new(),
        }]
    }

    #[test]
    fn json_yaml_local_refs_build_a_valid_checkout_independent_contract_graph() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_pair(first.path(), false);
        write_pair(second.path(), true);

        let first = scan_openapi_repository(first.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let second = scan_openapi_repository(second.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&first).unwrap();
        assert_eq!(first, second);

        let ledger = ledger(&first);
        assert_eq!(ledger.entries[0].input_count, 2);
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Complete
        );
        assert_eq!(ledger.entries[0].unresolved_count, 0);
        assert!(first.nodes.iter().any(|node| node.kind == "operation"
            && node.properties["canonical_identity"]["coordinate"] == "get /users/{id}"));
        let kinds = first
            .sites
            .iter()
            .map(|site| site.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains("provides_operation"));
        assert!(kinds.contains("accepts_message"));
        assert!(kinds.contains("returns_message"));
        assert!(kinds.contains("references_schema"));
        assert!(first.sites.iter().all(|site| {
            site.evidence[0]
                .path
                .as_deref()
                .is_some_and(|path| !path.starts_with('/'))
        }));
    }

    #[test]
    fn remote_missing_unsafe_and_recursive_refs_remain_explicit_without_secret_retention() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("openapi.yaml"),
            r#"
openapi: 3.1.1
info:
  title: hostile refs
paths:
  /refs:
    get:
      responses:
        '200':
          content:
            application/json:
              schema:
                $ref: 'https://schemas.example.test/common.yaml#/Thing'
        '400':
          content:
            application/json:
              schema:
                $ref: 'missing.yaml#/Thing'
        '500':
          content:
            application/json:
              schema:
                $ref: 'https://user:super-secret@example.test/schema'
components:
  schemas:
    A:
      $ref: '#/components/schemas/B'
    B:
      $ref: '#/components/schemas/A'
"#,
        )
        .unwrap();
        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        let ledger = ledger(&delta);
        assert_eq!(ledger.entries[0].external_count, 1);
        assert!(ledger.entries[0].unresolved_count >= 2);
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Incomplete
        );
        assert!(
            delta
                .sites
                .iter()
                .any(|site| site.reason.as_deref() == Some("cyclic-schema-reference"))
        );
        assert!(
            delta
                .sites
                .iter()
                .any(|site| site.resolution_status == ResolutionStatus::External)
        );
        let serialized = serde_json::to_string(&delta).unwrap();
        assert!(!serialized.contains("super-secret"));
        assert!(!serialized.contains("schemas.example.test"));
        assert!(!serialized.contains("missing.yaml"));
    }

    #[test]
    fn duplicate_keys_yaml_graph_features_and_external_symlinks_are_ledgered_as_skipped() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("openapi-duplicate.json"),
            r#"{"openapi":"3.1.1","paths":{},"paths":{}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("openapi-anchor.yaml"),
            "openapi: 3.1.1\npaths: &paths {}\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            let outside = tempfile::NamedTempFile::new().unwrap();
            std::os::unix::fs::symlink(outside.path(), root.path().join("openapi-external.yaml"))
                .unwrap();
        }

        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger = ledger(&delta);
        #[cfg(unix)]
        assert_eq!(ledger.entries[0].skipped_count, 3);
        #[cfg(not(unix))]
        assert_eq!(ledger.entries[0].skipped_count, 2);
        assert!(delta.nodes.is_empty());
        assert!(delta.sites.is_empty());
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Incomplete
        );
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"duplicate-yaml-mapping-key".to_owned())
                || ledger.entries[0]
                    .reasons
                    .contains(&"invalid-or-unbounded-json".to_owned())
        );
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"yaml-tags-anchors-and-aliases-are-not-supported".to_owned())
        );
    }

    #[test]
    fn bounded_yaml_supports_sequences_callbacks_and_block_scalars() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("openapi-callback.yaml"),
            r#"
openapi: 3.1.0
info:
  title: Callback
  description: |
    safe bounded
    description
paths:
  /subscribe:
    post:
      parameters:
        - name: topic
          in: query
          schema:
            type: string
      callbacks:
        update:
          '{$request.body#/callbackUrl}':
            post:
              responses:
                '204':
                  description: done
      responses:
        '202':
          description: accepted
"#,
        )
        .unwrap();
        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(
            delta.nodes.iter().any(|node| {
                node.kind == "operation"
                    && node.properties["canonical_identity"]["coordinate"]
                        .as_str()
                        .is_some_and(|coordinate| coordinate.starts_with("callback "))
            }),
            "callback operation was not represented"
        );
    }

    #[test]
    fn top_level_webhooks_emit_operations_and_message_relations() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("openapi-webhook.yaml"),
            r#"
openapi: 3.1.1
info:
  title: Webhooks
paths: {}
webhooks:
  orderCreated:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Order'
      responses:
        '202':
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Acknowledgement'
components:
  schemas:
    Order:
      type: object
    Acknowledgement:
      type: object
"#,
        )
        .unwrap();

        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        assert_eq!(
            ledger(&delta).entries[0].status,
            CrossLanguageCapabilityStatus::Complete
        );
        assert!(delta.nodes.iter().any(|node| {
            node.kind == "operation"
                && node.properties["canonical_identity"]["coordinate"]
                    == "webhook orderCreated #/webhooks/orderCreated/post post"
        }));
        let kinds = delta
            .sites
            .iter()
            .map(|site| site.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains("provides_operation"));
        assert!(kinds.contains("accepts_message"));
        assert!(kinds.contains("returns_message"));
    }

    #[test]
    fn invalid_pointer_depth_and_empty_inventory_fail_closed() {
        let empty = tempfile::tempdir().unwrap();
        assert!(
            scan_openapi_repository(empty.path(), &participating_profiles())
                .unwrap()
                .is_none()
        );
        assert!(scan_openapi_repository(empty.path(), &[]).is_err());
        assert!(!valid_json_pointer("/bad~2escape"));
        assert!(resolve_repository_reference("api/openapi.yaml", "../../escape.yaml").is_none());

        let mut nested = String::from(r#"{"openapi":"3.1.1","paths":{},"x":"#);
        nested.push_str(&"[".repeat(MAX_OPENAPI_DEPTH + 8));
        nested.push_str(&"]".repeat(MAX_OPENAPI_DEPTH + 8));
        nested.push('}');
        assert!(parse_bounded_json(nested.as_bytes()).is_err());
    }

    #[test]
    fn inventory_entry_and_document_limits_fail_closed_without_growing_records() {
        let mut inventory_entries = MAX_OPENAPI_INVENTORY_ENTRIES - 1;
        record_openapi_inventory_entry(&mut inventory_entries).unwrap();
        assert_eq!(inventory_entries, MAX_OPENAPI_INVENTORY_ENTRIES);
        assert!(record_openapi_inventory_entry(&mut inventory_entries).is_err());

        let mut records = Vec::new();
        for index in 0..MAX_OPENAPI_DOCUMENTS {
            push_openapi_inventory_record(
                &mut records,
                skipped_record(&format!("openapi-{index}.json"), "test-skip"),
            )
            .unwrap();
        }
        assert_eq!(records.len(), MAX_OPENAPI_DOCUMENTS);
        assert!(
            push_openapi_inventory_record(
                &mut records,
                skipped_record("openapi-overflow.json", "test-skip"),
            )
            .is_err()
        );
        assert_eq!(records.len(), MAX_OPENAPI_DOCUMENTS);
    }

    #[test]
    fn oversized_named_input_is_ledgered_with_the_byte_limit_reason() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("openapi-oversized.json"),
            vec![b' '; MAX_OPENAPI_DOCUMENT_BYTES + 1],
        )
        .unwrap();

        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let ledger = ledger(&delta);
        assert_eq!(ledger.entries[0].skipped_count, 1);
        assert!(
            ledger.entries[0]
                .reasons
                .contains(&"input-byte-limit-exceeded".to_owned())
        );
    }
}
