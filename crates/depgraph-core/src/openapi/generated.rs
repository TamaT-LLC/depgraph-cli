use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
    sync::Arc,
};

use crate::bounded_query::read_bounded_repository_file;
use anyhow::{Context, Result};
use depgraph_protocol::{
    CROSS_LANGUAGE_CONTRACT_VERSION, Condition, CrossLanguageMappingKind,
    CrossLanguageRelationKind, Evidence, EvidenceKind, GraphNode, Precision, Properties,
    ResolutionStatus, stable_id_from_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::{
    MAX_OPENAPI_DOCUMENT_BYTES, MAX_OPENAPI_DOCUMENTS, MAX_OPENAPI_REFERENCES,
    MAX_OPENAPI_TOTAL_BYTES, OpenApiGraphBuilder, RelationRecord, bounded_contract_text,
    bounded_text, digest_value, insert_identical, inventory_entry_allowed, parse_bounded_json,
    repository_locator, sha256_prefixed, source_end_position,
};

pub const OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION: &str = "depgraph-openapi-generated-mapping-v1";

const GENERATED_EXTRACTOR: &str = "depgraph-openapi-generated-adapter";
const GENERATED_MANIFEST_SUFFIX: &str = ".depgraph-openapi-generated.json";
const MAX_GENERATED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_GENERATED_TOTAL_OUTPUT_BYTES: usize = 128 * 1024 * 1024;
const MAX_GENERATED_INVENTORY_ENTRIES: usize = 1_000_000;

pub(super) fn is_generated_mapping_locator(locator: &str) -> bool {
    locator.ends_with(GENERATED_MANIFEST_SUFFIX)
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedInventory {
    records: Vec<GeneratedRecord>,
}

impl GeneratedInventory {
    pub(super) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(super) fn input_count(&self) -> u64 {
        self.records.len() as u64
    }

    pub(super) fn skipped_count(&self) -> u64 {
        self.records
            .iter()
            .filter(|record| record.manifest.is_none())
            .count() as u64
    }

    pub(super) fn reasons(&self) -> impl Iterator<Item = String> + '_ {
        self.records
            .iter()
            .filter_map(|record| record.reason.clone())
    }

    pub(super) fn identity_value(&self) -> Value {
        json!(
            self.records
                .iter()
                .map(GeneratedRecord::identity_value)
                .collect::<Vec<_>>()
        )
    }
}

#[derive(Clone, Debug)]
struct GeneratedRecord {
    locator: String,
    digest: String,
    manifest: Option<GeneratedManifest>,
    observations: BTreeMap<String, OutputObservation>,
    reason: Option<String>,
    end_line: u32,
    end_column: u32,
}

impl GeneratedRecord {
    fn identity_value(&self) -> Value {
        let observations = self
            .observations
            .iter()
            .map(|(path, observation)| {
                (
                    path.clone(),
                    json!({
                        "digest": observation.digest,
                        "reason": observation.reason,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        json!({
            "locator": self.locator,
            "digest": self.digest,
            "manifest": self.manifest,
            "observations": observations,
            "status": if self.manifest.is_some() { "admitted" } else { "skipped" },
            "reason": self.reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedManifest {
    schema_version: String,
    generator: GeneratorIdentity,
    contract: ContractIdentity,
    mappings: Vec<GeneratedMapping>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratorIdentity {
    name: String,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ContractIdentity {
    path: String,
    digest: String,
    format_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedMapping {
    language: GeneratedLanguage,
    role: GeneratedRole,
    operation: String,
    output: String,
    output_digest: String,
    symbol: String,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GeneratedLanguage {
    Go,
    Rust,
    Web,
}

impl GeneratedLanguage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Web => "web",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GeneratedRole {
    Client,
    Provider,
}

impl GeneratedRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Provider => "provider",
        }
    }
}

#[derive(Clone, Debug)]
struct OutputObservation {
    digest: Option<String>,
    source: Option<Arc<str>>,
    line_starts: Arc<[usize]>,
    line_columns: Arc<[u32]>,
    reason: Option<String>,
}

pub(super) fn inventory_generated_mappings(root: &Path) -> Result<GeneratedInventory> {
    let mut records = Vec::new();
    let mut manifest_bytes = 0_usize;
    let mut output_bytes = 0_usize;
    let mut observed_outputs = BTreeMap::<String, OutputObservation>::new();
    let mut mapping_count = 0_usize;
    let mut inventory_entries = 0_usize;
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        record_generated_inventory_entry(&mut inventory_entries)?;
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
        if !locator.ends_with(GENERATED_MANIFEST_SUFFIX) {
            continue;
        }
        if entry.file_type().is_symlink() {
            push_generated_inventory_record(
                &mut records,
                skipped_record(&locator, "generated-manifest-symlink-not-admitted"),
            )?;
            continue;
        }
        if !entry.file_type().is_file() {
            push_generated_inventory_record(
                &mut records,
                skipped_record(&locator, "generated-manifest-is-not-a-file"),
            )?;
            continue;
        }
        let bytes =
            match read_bounded_repository_file(root, entry.path(), MAX_OPENAPI_DOCUMENT_BYTES) {
                Ok(bytes) => bytes,
                Err(error) => {
                    let reason = if error.code == "query_file_size_or_type_invalid" {
                        "generated-manifest-byte-limit-exceeded"
                    } else {
                        "generated-manifest-read-failed"
                    };
                    push_generated_inventory_record(
                        &mut records,
                        skipped_record(&locator, reason),
                    )?;
                    continue;
                }
            };
        let Some(total_manifest_bytes) = manifest_bytes.checked_add(bytes.len()) else {
            return Err(anyhow::anyhow!(
                "OpenAPI generated manifest byte count overflowed"
            ));
        };
        if total_manifest_bytes > MAX_OPENAPI_TOTAL_BYTES {
            push_generated_inventory_record(
                &mut records,
                skipped_record(&locator, "generated-manifest-total-byte-limit-exceeded"),
            )?;
            continue;
        }
        manifest_bytes = total_manifest_bytes;
        let raw_digest = sha256_prefixed(&bytes);
        let (end_line, end_column) = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|source| source_end_position(source).ok())
            .unwrap_or((1, 1));
        let value = match parse_bounded_json(&bytes) {
            Ok(value) => value,
            Err(reason) => {
                push_generated_inventory_record(
                    &mut records,
                    GeneratedRecord {
                        locator,
                        digest: raw_digest,
                        manifest: None,
                        observations: BTreeMap::new(),
                        reason: Some(reason),
                        end_line,
                        end_column,
                    },
                )?;
                continue;
            }
        };
        let mut manifest: GeneratedManifest = match serde_json::from_value(value) {
            Ok(manifest) => manifest,
            Err(_) => {
                push_generated_inventory_record(
                    &mut records,
                    GeneratedRecord {
                        locator,
                        digest: raw_digest,
                        manifest: None,
                        observations: BTreeMap::new(),
                        reason: Some("generated-manifest-schema-is-invalid".to_owned()),
                        end_line,
                        end_column,
                    },
                )?;
                continue;
            }
        };
        if let Err(reason) = validate_manifest(&mut manifest) {
            push_generated_inventory_record(
                &mut records,
                GeneratedRecord {
                    locator,
                    digest: raw_digest,
                    manifest: None,
                    observations: BTreeMap::new(),
                    reason: Some(reason),
                    end_line,
                    end_column,
                },
            )?;
            continue;
        }
        if mapping_count.saturating_add(manifest.mappings.len()) > MAX_OPENAPI_REFERENCES {
            push_generated_inventory_record(
                &mut records,
                GeneratedRecord {
                    locator,
                    digest: raw_digest,
                    manifest: None,
                    observations: BTreeMap::new(),
                    reason: Some("generated-mapping-count-limit-exceeded".to_owned()),
                    end_line,
                    end_column,
                },
            )?;
            continue;
        }
        mapping_count += manifest.mappings.len();
        let digest = digest_value(&serde_json::to_value(&manifest)?);
        let mut observations = BTreeMap::new();
        for output in manifest
            .mappings
            .iter()
            .map(|mapping| mapping.output.as_str())
            .collect::<BTreeSet<_>>()
        {
            let observation =
                observe_output_once(root, output, &mut output_bytes, &mut observed_outputs);
            observations.insert(output.to_owned(), observation);
        }
        push_generated_inventory_record(
            &mut records,
            GeneratedRecord {
                locator,
                digest,
                manifest: Some(manifest),
                observations,
                reason: None,
                end_line,
                end_column,
            },
        )?;
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));
    Ok(GeneratedInventory { records })
}

fn record_generated_inventory_entry(inventory_entries: &mut usize) -> Result<()> {
    *inventory_entries = inventory_entries
        .checked_add(1)
        .context("OpenAPI generated inventory entry count overflowed")?;
    if *inventory_entries > MAX_GENERATED_INVENTORY_ENTRIES {
        anyhow::bail!("OpenAPI generated inventory exceeds its closed entry limit");
    }
    Ok(())
}

fn push_generated_inventory_record(
    records: &mut Vec<GeneratedRecord>,
    record: GeneratedRecord,
) -> Result<()> {
    if records.len() >= MAX_OPENAPI_DOCUMENTS {
        anyhow::bail!("OpenAPI generated inventory exceeds its closed manifest limit");
    }
    records.push(record);
    Ok(())
}

fn skipped_record(locator: &str, reason: &str) -> GeneratedRecord {
    GeneratedRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        manifest: None,
        observations: BTreeMap::new(),
        reason: Some(reason.to_owned()),
        end_line: 1,
        end_column: 1,
    }
}

fn validate_manifest(manifest: &mut GeneratedManifest) -> std::result::Result<(), String> {
    if manifest.schema_version != OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION {
        return Err("unsupported-generated-mapping-version".to_owned());
    }
    if !bounded_contract_text(&manifest.generator.name)
        || !bounded_contract_text(&manifest.generator.version)
        || !valid_repository_path(&manifest.contract.path)
        || !valid_digest(&manifest.contract.digest)
        || !matches!(manifest.contract.format_version.as_str(), "3.1.0" | "3.1.1")
        || manifest.mappings.is_empty()
        || manifest.mappings.len() > MAX_OPENAPI_REFERENCES
    {
        return Err("generated-manifest-contract-is-invalid".to_owned());
    }
    for mapping in &manifest.mappings {
        if !bounded_contract_text(&mapping.operation)
            || !valid_repository_path(&mapping.output)
            || !valid_digest(&mapping.output_digest)
            || !bounded_contract_text(&mapping.symbol)
            || mapping.start_line == 0
            || mapping.start_column == 0
            || mapping.end_line == 0
            || mapping.end_column == 0
            || (mapping.start_line, mapping.start_column) > (mapping.end_line, mapping.end_column)
        {
            return Err("generated-mapping-entry-is-invalid".to_owned());
        }
    }
    manifest.mappings.sort();
    Ok(())
}

fn observe_output_once(
    root: &Path,
    relative: &str,
    total_bytes: &mut usize,
    observed_outputs: &mut BTreeMap<String, OutputObservation>,
) -> OutputObservation {
    if let Some(observation) = observed_outputs.get(relative) {
        return observation.clone();
    }
    let observation = observe_output(root, relative, total_bytes);
    observed_outputs.insert(relative.to_owned(), observation.clone());
    observation
}

fn observe_output(root: &Path, relative: &str, total_bytes: &mut usize) -> OutputObservation {
    let path = root.join(relative);
    let bytes = match read_bounded_repository_file(root, &path, MAX_GENERATED_OUTPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            let reason = if error.code == "query_file_size_or_type_invalid" {
                "generated-output-byte-limit-exceeded"
            } else {
                "generated-output-is-missing-or-unsafe"
            };
            return OutputObservation {
                digest: None,
                source: None,
                line_starts: Arc::from(Vec::<usize>::new()),
                line_columns: Arc::from(Vec::<u32>::new()),
                reason: Some(reason.to_owned()),
            };
        }
    };
    let Some(total_output_bytes) = total_bytes.checked_add(bytes.len()) else {
        return OutputObservation {
            digest: None,
            source: None,
            line_starts: Arc::from(Vec::<usize>::new()),
            line_columns: Arc::from(Vec::<u32>::new()),
            reason: Some("generated-output-byte-limit-exceeded".to_owned()),
        };
    };
    if total_output_bytes > MAX_GENERATED_TOTAL_OUTPUT_BYTES {
        return OutputObservation {
            digest: None,
            source: None,
            line_starts: Arc::from(Vec::<usize>::new()),
            line_columns: Arc::from(Vec::<u32>::new()),
            reason: Some("generated-output-byte-limit-exceeded".to_owned()),
        };
    }
    *total_bytes = total_output_bytes;
    let digest = Some(sha256_prefixed(&bytes));
    let source = match std::str::from_utf8(&bytes) {
        Ok(source) => source,
        Err(_) => {
            return OutputObservation {
                digest,
                source: None,
                line_starts: Arc::from(Vec::<usize>::new()),
                line_columns: Arc::from(Vec::<u32>::new()),
                reason: Some("generated-output-is-not-utf8".to_owned()),
            };
        }
    };
    let line_starts = std::iter::once(0)
        .chain(
            source
                .bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        )
        .collect::<Vec<_>>();
    let line_columns = source
        .split('\n')
        .map(|line| u32::try_from(line.chars().count().saturating_add(1)).unwrap_or(u32::MAX))
        .collect::<Vec<_>>();
    OutputObservation {
        digest,
        source: Some(Arc::from(source)),
        line_starts: Arc::from(line_starts),
        line_columns: Arc::from(line_columns),
        reason: None,
    }
}

fn valid_repository_path(value: &str) -> bool {
    if !bounded_text(value, super::MAX_OPENAPI_SCALAR_BYTES)
        || value.starts_with('/')
        || value.contains('\\')
        || value
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return false;
    }
    Path::new(value)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone)]
struct Claim<'a> {
    record: &'a GeneratedRecord,
    manifest: &'a GeneratedManifest,
    mapping: &'a GeneratedMapping,
    ordinal: u64,
}

impl Claim<'_> {
    fn endpoint_key(&self) -> Value {
        json!({
            "output": self.mapping.output,
            "language": self.mapping.language,
            "symbol": self.mapping.symbol,
            "start_line": self.mapping.start_line,
            "start_column": self.mapping.start_column,
            "end_line": self.mapping.end_line,
            "end_column": self.mapping.end_column,
        })
    }

    fn endpoint_digest(&self) -> String {
        digest_value(&self.endpoint_key())
    }

    fn generator_digest(&self) -> String {
        digest_value(&serde_json::to_value(&self.manifest.generator).expect("serializable"))
    }
}

pub(super) fn apply_generated_mappings(
    _root: &Path,
    inventory: &GeneratedInventory,
    builder: &mut OpenApiGraphBuilder,
) -> Result<()> {
    let mut claims = Vec::new();
    for record in &inventory.records {
        let Some(manifest) = &record.manifest else {
            continue;
        };
        for (ordinal, mapping) in manifest.mappings.iter().enumerate() {
            claims.push(Claim {
                record,
                manifest,
                mapping,
                ordinal: u64::try_from(ordinal).context("generated mapping ordinal exceeds u64")?,
            });
        }
    }
    claims.sort_by_key(Claim::endpoint_digest);

    let mut claims_by_endpoint = BTreeMap::<String, Vec<Claim<'_>>>::new();
    let mut generators_by_output = BTreeMap::<String, BTreeSet<String>>::new();
    let mut declared_digests_by_output = BTreeMap::<String, BTreeSet<String>>::new();
    for claim in claims {
        claims_by_endpoint
            .entry(claim.endpoint_digest())
            .or_default()
            .push(claim.clone());
        generators_by_output
            .entry(claim.mapping.output.clone())
            .or_default()
            .insert(claim.generator_digest());
        declared_digests_by_output
            .entry(claim.mapping.output.clone())
            .or_default()
            .insert(claim.mapping.output_digest.clone());
    }

    for endpoint_claims in claims_by_endpoint.into_values() {
        let representative = &endpoint_claims[0];
        let mixed_generator = generators_by_output
            .get(&representative.mapping.output)
            .is_some_and(|generators| generators.len() > 1);
        let conflicting_digest = declared_digests_by_output
            .get(&representative.mapping.output)
            .is_some_and(|digests| digests.len() > 1);
        for claim in &endpoint_claims {
            let reason = mapping_failure_reason(
                claim,
                endpoint_claims.len(),
                mixed_generator,
                conflicting_digest,
                builder,
            );
            emit_claim(builder, claim, reason.as_deref())?;
        }
    }
    Ok(())
}

fn mapping_failure_reason(
    claim: &Claim<'_>,
    endpoint_claim_count: usize,
    mixed_generator: bool,
    conflicting_digest: bool,
    builder: &OpenApiGraphBuilder,
) -> Option<String> {
    if mixed_generator {
        return Some("mixed-generator-output-provenance".to_owned());
    }
    if conflicting_digest {
        return Some("ambiguous-generated-output-digest".to_owned());
    }
    if endpoint_claim_count > 1 {
        return Some("ambiguous-generated-symbol-provenance".to_owned());
    }
    if !supported_generator(&claim.manifest.generator, claim.mapping.language) {
        return Some("unsupported-generated-toolchain".to_owned());
    }
    let Some(observation) = claim.record.observations.get(&claim.mapping.output) else {
        return Some("generated-output-observation-is-missing".to_owned());
    };
    if let Some(reason) = &observation.reason {
        return Some(reason.clone());
    }
    if observation.digest.as_deref() != Some(claim.mapping.output_digest.as_str()) {
        return Some("generated-output-digest-mismatch".to_owned());
    }
    let Some(document) = builder.documents.get(&claim.manifest.contract.path) else {
        return Some("generated-contract-is-not-admitted".to_owned());
    };
    if document.digest != claim.manifest.contract.digest
        || document.version != claim.manifest.contract.format_version
    {
        return Some("generated-contract-digest-mismatch".to_owned());
    }
    if !builder.operation_ids.contains_key(&(
        claim.manifest.contract.path.clone(),
        claim.mapping.operation.clone(),
    )) {
        return Some("generated-operation-is-not-admitted".to_owned());
    }
    if !valid_span(observation, claim.mapping) {
        return Some("generated-source-span-is-invalid".to_owned());
    }
    if !span_contains_symbol(observation, claim.mapping) {
        return Some("generated-source-symbol-mismatch".to_owned());
    }
    None
}

fn supported_generator(generator: &GeneratorIdentity, language: GeneratedLanguage) -> bool {
    let major = generator
        .version
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok());
    match (generator.name.as_str(), language, major) {
        ("openapi-generator", _, Some(7))
        | ("oapi-codegen", GeneratedLanguage::Go, Some(2))
        | ("openapi-typescript", GeneratedLanguage::Web, Some(7)) => generator
            .version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())),
        _ => false,
    }
}

fn valid_span(observation: &OutputObservation, mapping: &GeneratedMapping) -> bool {
    let Some(start_columns) = observation
        .line_columns
        .get(mapping.start_line.saturating_sub(1) as usize)
    else {
        return false;
    };
    let Some(end_columns) = observation
        .line_columns
        .get(mapping.end_line.saturating_sub(1) as usize)
    else {
        return false;
    };
    mapping.start_column <= *start_columns && mapping.end_column <= *end_columns
}

fn span_contains_symbol(observation: &OutputObservation, mapping: &GeneratedMapping) -> bool {
    let Some(source) = observation.source.as_deref() else {
        return false;
    };
    let Some(symbol) = terminal_symbol(&mapping.symbol) else {
        return false;
    };
    let start_line = mapping.start_line.saturating_sub(1) as usize;
    let end_line = mapping.end_line.saturating_sub(1) as usize;
    (start_line..=end_line).any(|line_index| {
        let Some(line) = source_line(source, &observation.line_starts, line_index) else {
            return false;
        };
        let start_column = if line_index == start_line {
            mapping.start_column
        } else {
            1
        };
        let end_column = if line_index == end_line {
            mapping.end_column
        } else {
            line.chars()
                .count()
                .saturating_add(1)
                .try_into()
                .unwrap_or(u32::MAX)
        };
        source_columns(line, start_column, end_column)
            .is_some_and(|span| contains_identifier(span, symbol))
    })
}

fn terminal_symbol(coordinate: &str) -> Option<&str> {
    let symbol = coordinate
        .rsplit([':', '.', '#'])
        .find(|part| !part.is_empty())?;
    (!symbol.is_empty()
        && symbol
            .chars()
            .all(|character| character == '_' || character == '$' || character.is_alphanumeric()))
    .then_some(symbol)
}

fn source_line<'a>(source: &'a str, line_starts: &[usize], index: usize) -> Option<&'a str> {
    let start = *line_starts.get(index)?;
    let end = line_starts
        .get(index + 1)
        .map_or(source.len(), |next| next.saturating_sub(1));
    source.get(start..end)
}

fn source_columns(source: &str, start_column: u32, end_column: u32) -> Option<&str> {
    let start_character = usize::try_from(start_column.checked_sub(1)?).ok()?;
    let end_character = usize::try_from(end_column.checked_sub(1)?).ok()?;
    let start = source.char_indices().nth(start_character).map_or_else(
        || (start_character == source.chars().count()).then_some(source.len()),
        |item| Some(item.0),
    )?;
    let end = source.char_indices().nth(end_character).map_or_else(
        || (end_character == source.chars().count()).then_some(source.len()),
        |item| Some(item.0),
    )?;
    (start <= end).then(|| &source[start..end])
}

fn contains_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(start, matched)| {
        let before = source[..start].chars().next_back();
        let after = source[start + matched.len()..].chars().next();
        !before.is_some_and(identifier_character) && !after.is_some_and(identifier_character)
    })
}

fn identifier_character(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

fn emit_claim(
    builder: &mut OpenApiGraphBuilder,
    claim: &Claim<'_>,
    reason: Option<&str>,
) -> Result<()> {
    let symbol_id = generated_symbol(builder, claim)?;
    let operation_id = builder
        .operation_ids
        .get(&(
            claim.manifest.contract.path.clone(),
            claim.mapping.operation.clone(),
        ))
        .cloned();
    let pointer = format!(
        "/generated/{}",
        claim
            .endpoint_digest()
            .strip_prefix("sha256:")
            .expect("generated endpoint digests use sha256")
    );
    if let Some(reason) = reason {
        let target = builder.unknown_node(&claim.record.locator, &pointer, reason)?;
        match (claim.mapping.role, operation_id.as_deref()) {
            (GeneratedRole::Client, _) => emit_relation(
                builder,
                claim,
                &symbol_id,
                &target,
                CrossLanguageRelationKind::CallsOperation,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
            (GeneratedRole::Provider, Some(operation_id)) => emit_relation(
                builder,
                claim,
                operation_id,
                &target,
                CrossLanguageRelationKind::ImplementedBy,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
            (GeneratedRole::Provider, None) => emit_relation(
                builder,
                claim,
                &symbol_id,
                &target,
                CrossLanguageRelationKind::GeneratedFrom,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
        };
        return Ok(());
    }

    let operation_id = operation_id.context("validated generated operation disappeared")?;
    emit_relation(
        builder,
        claim,
        &symbol_id,
        &operation_id,
        CrossLanguageRelationKind::GeneratedFrom,
        ResolutionStatus::Resolved,
        Precision::Exact,
        CrossLanguageMappingKind::GeneratorManifest,
        None,
    )?;
    match claim.mapping.role {
        GeneratedRole::Client => emit_relation(
            builder,
            claim,
            &symbol_id,
            &operation_id,
            CrossLanguageRelationKind::CallsOperation,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::GeneratorManifest,
            None,
        )?,
        GeneratedRole::Provider => emit_relation(
            builder,
            claim,
            &operation_id,
            &symbol_id,
            CrossLanguageRelationKind::ImplementedBy,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::GeneratorManifest,
            None,
        )?,
    };
    Ok(())
}

fn generated_symbol(builder: &mut OpenApiGraphBuilder, claim: &Claim<'_>) -> Result<String> {
    let id = stable_id_from_value(
        "symbol",
        &json!({
            "identity_version": "openapi-generated-symbol-v1",
            "cross_language_profile_binding": builder.profile_id,
            "language": claim.mapping.language,
            "repository_path": claim.mapping.output,
            "coordinate": claim.mapping.symbol,
        }),
    );
    let node = GraphNode {
        id: id.clone(),
        kind: "symbol".to_owned(),
        locator: format!("generated-openapi:{id}"),
        display_name: Some(claim.mapping.symbol.clone()),
        properties: BTreeMap::from([
            ("generated".to_owned(), Value::Bool(true)),
            (
                "language".to_owned(),
                Value::String(claim.mapping.language.as_str().to_owned()),
            ),
            (
                "repository_path".to_owned(),
                Value::String(claim.mapping.output.clone()),
            ),
        ]),
    };
    insert_identical(
        &mut builder.nodes,
        id.clone(),
        node,
        "OpenAPI generated symbol",
    )?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn emit_relation(
    builder: &mut OpenApiGraphBuilder,
    claim: &Claim<'_>,
    source: &str,
    target: &str,
    relation: CrossLanguageRelationKind,
    status: ResolutionStatus,
    precision: Precision,
    mapping_kind: CrossLanguageMappingKind,
    reason: Option<&str>,
) -> Result<()> {
    let observation = claim.record.observations.get(&claim.mapping.output);
    let use_output_span = observation.is_some_and(|observation| {
        observation.reason.is_none() && valid_span(observation, claim.mapping)
    });
    let (path, start_line, start_column, end_line, end_column) = if use_output_span {
        (
            claim.mapping.output.clone(),
            claim.mapping.start_line,
            claim.mapping.start_column,
            claim.mapping.end_line,
            claim.mapping.end_column,
        )
    } else {
        (
            claim.record.locator.clone(),
            1,
            1,
            claim.record.end_line,
            claim.record.end_column,
        )
    };
    let condition = Condition::All {
        conditions: vec![
            Condition::Eq {
                key: "openapi.generated_language".to_owned(),
                value: Value::String(claim.mapping.language.as_str().to_owned()),
            },
            Condition::Eq {
                key: "openapi.generated_role".to_owned(),
                value: Value::String(claim.mapping.role.as_str().to_owned()),
            },
            Condition::Eq {
                key: "openapi.operation_coordinate".to_owned(),
                value: Value::String(claim.mapping.operation.clone()),
            },
        ],
    }
    .canonicalize();
    let evidence = vec![Evidence {
        kind: EvidenceKind::Semantic,
        extractor: GENERATED_EXTRACTOR.to_owned(),
        extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
        path: Some(path),
        start_line: Some(start_line),
        start_column: Some(start_column),
        end_line: Some(end_line),
        end_column: Some(end_column),
        detail: None,
        properties: Properties::from([
            (
                "contract_version".to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            ("format".to_owned(), Value::String("openapi".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(builder.profile_id.clone()),
            ),
            (
                "format_version".to_owned(),
                Value::String(claim.manifest.contract.format_version.clone()),
            ),
            (
                "contract_digest".to_owned(),
                Value::String(claim.manifest.contract.digest.clone()),
            ),
            (
                "occurrence_kind".to_owned(),
                serde_json::to_value(relation)?,
            ),
            (
                "mapping_kind".to_owned(),
                serde_json::to_value(mapping_kind)?,
            ),
            (
                "artifact_identity".to_owned(),
                Value::String(claim.record.digest.clone()),
            ),
            ("ordinal".to_owned(), Value::from(claim.ordinal)),
            (
                "generator_identity".to_owned(),
                Value::String(claim.generator_digest()),
            ),
            (
                "generated_output_digest".to_owned(),
                Value::String(claim.mapping.output_digest.clone()),
            ),
            (
                "generated_manifest_locator".to_owned(),
                Value::String(claim.record.locator.clone()),
            ),
            (
                "generated_output_path".to_owned(),
                Value::String(claim.mapping.output.clone()),
            ),
            (
                "generated_symbol_coordinate".to_owned(),
                Value::String(claim.mapping.symbol.clone()),
            ),
            (
                "source_contract_locator".to_owned(),
                Value::String(claim.manifest.contract.path.clone()),
            ),
        ]),
    }];
    builder.insert_relation(RelationRecord {
        source,
        target,
        relation,
        specifier: format!(
            "generated:{}:{}",
            claim.mapping.role.as_str(),
            claim.mapping.operation
        ),
        status,
        precision,
        reason,
        condition,
        evidence,
        generated: true,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path};

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCapabilityStatus,
        CrossLanguageCompletenessLedger, CrossLanguageMappingKind, Profile, ResolutionStatus,
        validate_cross_language_adapter_delta,
    };

    use super::*;
    use crate::openapi::scan_openapi_repository;

    const CONTRACT: &str = r#"{
      "openapi": "3.1.1",
      "info": {"title": "Pets"},
      "paths": {
        "/pets/{id}": {
          "get": {
            "responses": {"200": {"description": "ok"}}
          }
        },
        "/pets": {
          "post": {
            "responses": {"201": {"description": "created"}}
          }
        }
      }
    }"#;

    fn mapping(
        language: GeneratedLanguage,
        role: GeneratedRole,
        operation: &str,
        output: &str,
        output_bytes: &[u8],
        symbol: &str,
    ) -> GeneratedMapping {
        GeneratedMapping {
            language,
            role,
            operation: operation.to_owned(),
            output: output.to_owned(),
            output_digest: sha256_prefixed(output_bytes),
            symbol: symbol.to_owned(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: u32::try_from(
                std::str::from_utf8(output_bytes)
                    .unwrap()
                    .chars()
                    .count()
                    .saturating_add(1),
            )
            .unwrap(),
        }
    }

    fn manifest(
        generator: &str,
        version: &str,
        contract_digest: &str,
        mappings: Vec<GeneratedMapping>,
    ) -> GeneratedManifest {
        GeneratedManifest {
            schema_version: OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION.to_owned(),
            generator: GeneratorIdentity {
                name: generator.to_owned(),
                version: version.to_owned(),
            },
            contract: ContractIdentity {
                path: "openapi.json".to_owned(),
                digest: contract_digest.to_owned(),
                format_version: "3.1.1".to_owned(),
            },
            mappings,
        }
    }

    fn write_manifest(root: &Path, name: &str, manifest: &GeneratedManifest) {
        fs::write(
            root.join(format!("{name}{GENERATED_MANIFEST_SUFFIX}")),
            serde_json::to_vec_pretty(manifest).unwrap(),
        )
        .unwrap();
    }

    fn write_positive_fixture(root: &Path, reverse: bool) {
        let rust = b"pub fn get_pet() {}";
        let go = b"func CreatePet() {}";
        let web = b"export const getPet = () => {}";
        let contract_digest = sha256_prefixed(CONTRACT.as_bytes());
        let manifests = [
            (
                "rust",
                manifest(
                    "openapi-generator",
                    "7.10.0",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Rust,
                        GeneratedRole::Client,
                        "get /pets/{id}",
                        "generated/client.rs",
                        rust,
                        "client::get_pet",
                    )],
                ),
            ),
            (
                "go",
                manifest(
                    "oapi-codegen",
                    "2.4.1",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Go,
                        GeneratedRole::Provider,
                        "post /pets",
                        "generated/provider.go",
                        go,
                        "api.CreatePet",
                    )],
                ),
            ),
            (
                "web",
                manifest(
                    "openapi-typescript",
                    "7.6.1",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Web,
                        GeneratedRole::Client,
                        "get /pets/{id}",
                        "generated/client.ts",
                        web,
                        "getPet",
                    )],
                ),
            ),
        ];
        fs::create_dir(root.join("generated")).unwrap();
        if reverse {
            fs::write(root.join("generated/client.ts"), web).unwrap();
            fs::write(root.join("generated/provider.go"), go).unwrap();
            fs::write(root.join("generated/client.rs"), rust).unwrap();
            for (name, manifest) in manifests.iter().rev() {
                write_manifest(root, name, manifest);
            }
            fs::write(root.join("openapi.json"), CONTRACT).unwrap();
        } else {
            fs::write(root.join("openapi.json"), CONTRACT).unwrap();
            for (name, manifest) in &manifests {
                write_manifest(root, name, manifest);
            }
            fs::write(root.join("generated/client.rs"), rust).unwrap();
            fs::write(root.join("generated/provider.go"), go).unwrap();
            fs::write(root.join("generated/client.ts"), web).unwrap();
        }
    }

    fn ledger(
        delta: &depgraph_protocol::CrossLanguageAdapterDelta,
    ) -> CrossLanguageCompletenessLedger {
        serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap()
    }

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

    #[test]
    fn rust_go_and_web_provenance_create_exact_checkout_independent_mappings() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        write_positive_fixture(first.path(), false);
        write_positive_fixture(second.path(), true);

        let first = scan_openapi_repository(first.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let second = scan_openapi_repository(second.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&first).unwrap();
        assert_eq!(first, second);
        let coverage = &ledger(&first).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Complete);
        assert_eq!(coverage.input_count, 4);
        assert_eq!(coverage.unresolved_count, 0);
        assert_eq!(
            first
                .nodes
                .iter()
                .filter(|node| node.kind == "symbol")
                .count(),
            3
        );
        assert_eq!(
            first
                .sites
                .iter()
                .filter(|site| {
                    matches!(
                        site.kind.as_str(),
                        "calls_operation" | "implemented_by" | "generated_from"
                    )
                })
                .count(),
            6
        );
        assert!(
            first
                .sites
                .iter()
                .filter(|site| {
                    matches!(
                        site.kind.as_str(),
                        "calls_operation" | "implemented_by" | "generated_from"
                    )
                })
                .all(|site| {
                    site.resolution_status == ResolutionStatus::Resolved
                        && site.precision == Precision::Exact
                        && site.evidence[0].properties["mapping_kind"]
                            == serde_json::to_value(CrossLanguageMappingKind::GeneratorManifest)
                                .unwrap()
                })
        );
        assert!(
            first
                .sites
                .iter()
                .filter(|site| {
                    matches!(
                        site.kind.as_str(),
                        "calls_operation" | "implemented_by" | "generated_from"
                    )
                })
                .all(|site| {
                    let properties = &site.evidence[0].properties;
                    properties["source_contract_locator"] == "openapi.json"
                        && properties["generated_output_path"]
                            .as_str()
                            .is_some_and(|path| path.starts_with("generated/"))
                        && properties["generated_symbol_coordinate"].is_string()
                        && site.evidence[0].path.as_deref()
                            == properties["generated_output_path"].as_str()
                })
        );
    }

    #[test]
    fn stale_ambiguous_mixed_unsupported_and_partial_provenance_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("generated")).unwrap();
        fs::write(root.path().join("openapi.json"), CONTRACT).unwrap();
        let contract_digest = sha256_prefixed(CONTRACT.as_bytes());

        let expected_stale = b"pub fn expected() {}";
        fs::write(
            root.path().join("generated/stale.rs"),
            b"pub fn changed() {}",
        )
        .unwrap();
        write_manifest(
            root.path(),
            "stale",
            &manifest(
                "openapi-generator",
                "7.10.0",
                &contract_digest,
                vec![mapping(
                    GeneratedLanguage::Rust,
                    GeneratedRole::Client,
                    "get /pets/{id}",
                    "generated/stale.rs",
                    expected_stale,
                    "client::get_pet",
                )],
            ),
        );

        let duplicate = b"func Pet() {}";
        fs::write(root.path().join("generated/duplicate.go"), duplicate).unwrap();
        for (name, operation) in [
            ("duplicate-a", "get /pets/{id}"),
            ("duplicate-b", "post /pets"),
        ] {
            write_manifest(
                root.path(),
                name,
                &manifest(
                    "oapi-codegen",
                    "2.4.1",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Go,
                        GeneratedRole::Provider,
                        operation,
                        "generated/duplicate.go",
                        duplicate,
                        "api.Pet",
                    )],
                ),
            );
        }

        let mixed = b"export const mixed = 1";
        fs::write(root.path().join("generated/mixed.ts"), mixed).unwrap();
        for (name, generator, symbol) in [
            ("mixed-a", "openapi-generator", "mixedA"),
            ("mixed-b", "openapi-typescript", "mixedB"),
        ] {
            write_manifest(
                root.path(),
                name,
                &manifest(
                    generator,
                    "7.6.1",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Web,
                        GeneratedRole::Client,
                        "get /pets/{id}",
                        "generated/mixed.ts",
                        mixed,
                        symbol,
                    )],
                ),
            );
        }

        let unsupported = b"export const unsupported = 1";
        fs::write(root.path().join("generated/unsupported.ts"), unsupported).unwrap();
        write_manifest(
            root.path(),
            "unsupported",
            &manifest(
                "unknown-generator",
                "1.0.0",
                &contract_digest,
                vec![mapping(
                    GeneratedLanguage::Web,
                    GeneratedRole::Client,
                    "get /pets/{id}",
                    "generated/unsupported.ts",
                    unsupported,
                    "unsupported",
                )],
            ),
        );

        let bad_contract = b"pub fn wrong_contract() {}";
        fs::write(
            root.path().join("generated/wrong-contract.rs"),
            bad_contract,
        )
        .unwrap();
        write_manifest(
            root.path(),
            "wrong-contract",
            &manifest(
                "openapi-generator",
                "7.10.0",
                &format!("sha256:{}", "0".repeat(64)),
                vec![mapping(
                    GeneratedLanguage::Rust,
                    GeneratedRole::Client,
                    "get /pets/{id}",
                    "generated/wrong-contract.rs",
                    bad_contract,
                    "client::wrong_contract",
                )],
            ),
        );

        let invalid_span = b"export const invalidSpan = 1";
        fs::write(root.path().join("generated/invalid-span.ts"), invalid_span).unwrap();
        let mut invalid_span_mapping = mapping(
            GeneratedLanguage::Web,
            GeneratedRole::Client,
            "get /pets/{id}",
            "generated/invalid-span.ts",
            invalid_span,
            "invalidSpan",
        );
        invalid_span_mapping.end_column = 999;
        write_manifest(
            root.path(),
            "invalid-span",
            &manifest(
                "openapi-typescript",
                "7.6.1",
                &contract_digest,
                vec![invalid_span_mapping],
            ),
        );

        let wrong_symbol = b"pub fn actual_symbol() {}";
        fs::write(root.path().join("generated/wrong-symbol.rs"), wrong_symbol).unwrap();
        write_manifest(
            root.path(),
            "wrong-symbol",
            &manifest(
                "openapi-generator",
                "7.10.0",
                &contract_digest,
                vec![mapping(
                    GeneratedLanguage::Rust,
                    GeneratedRole::Client,
                    "get /pets/{id}",
                    "generated/wrong-symbol.rs",
                    wrong_symbol,
                    "client::missing_symbol",
                )],
            ),
        );

        #[cfg(unix)]
        let _outside_output = {
            use std::io::Write;

            let mut outside = tempfile::NamedTempFile::new().unwrap();
            outside.write_all(b"pub fn escaped() {}").unwrap();
            std::os::unix::fs::symlink(outside.path(), root.path().join("generated/escaped.rs"))
                .unwrap();
            write_manifest(
                root.path(),
                "escaped",
                &manifest(
                    "openapi-generator",
                    "7.10.0",
                    &contract_digest,
                    vec![mapping(
                        GeneratedLanguage::Rust,
                        GeneratedRole::Client,
                        "get /pets/{id}",
                        "generated/escaped.rs",
                        b"pub fn escaped() {}",
                        "client::escaped",
                    )],
                ),
            );
            outside
        };

        fs::write(
            root.path()
                .join(format!("partial{GENERATED_MANIFEST_SUFFIX}")),
            format!(
                r#"{{"schema_version":"{OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION}","generator":{{"name":"openapi-generator","version":"7.10.0"}},"contract":{{"path":"openapi.json","digest":"{contract_digest}","format_version":"3.1.1"}},"mappings":[]}}"#
            ),
        )
        .unwrap();
        fs::write(
            root.path().join("generated/naming-only.rs"),
            "pub fn get_pet() {}",
        )
        .unwrap();

        let delta = scan_openapi_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        let coverage = &ledger(&delta).entries[0];
        assert_eq!(coverage.status, CrossLanguageCapabilityStatus::Incomplete);
        assert!(coverage.unresolved_count >= 7);
        for reason in [
            "generated-output-digest-mismatch",
            "ambiguous-generated-symbol-provenance",
            "mixed-generator-output-provenance",
            "unsupported-generated-toolchain",
            "generated-contract-digest-mismatch",
            "generated-source-span-is-invalid",
            "generated-source-symbol-mismatch",
            "generated-manifest-contract-is-invalid",
        ] {
            assert!(
                coverage.reasons.contains(&reason.to_owned()),
                "missing reason {reason}: {:?}",
                coverage.reasons
            );
        }
        #[cfg(unix)]
        assert!(
            coverage
                .reasons
                .contains(&"generated-output-is-missing-or-unsafe".to_owned())
        );
        assert!(
            delta
                .sites
                .iter()
                .filter(|site| {
                    matches!(
                        site.kind.as_str(),
                        "calls_operation" | "implemented_by" | "generated_from"
                    )
                })
                .all(|site| site.resolution_status == ResolutionStatus::Unresolved)
        );
        assert_eq!(
            coverage.unresolved_count as usize,
            delta
                .sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::Unresolved)
                .count()
        );
        assert_eq!(
            delta
                .sites
                .iter()
                .filter(|site| {
                    site.evidence[0]
                        .properties
                        .get("generated_output_path")
                        .and_then(Value::as_str)
                        == Some("generated/duplicate.go")
                })
                .count(),
            2,
            "every ambiguous endpoint claim must remain explicit"
        );
        assert!(delta.sites.iter().any(|site| {
            site.evidence[0]
                .properties
                .get("generated_output_path")
                .and_then(Value::as_str)
                == Some("generated/wrong-symbol.rs")
                && site.reason.as_deref() == Some("generated-source-symbol-mismatch")
                && site.resolution_status == ResolutionStatus::Unresolved
        }));
        assert!(!delta.nodes.iter().any(|node| {
            node.properties
                .get("repository_path")
                .and_then(Value::as_str)
                == Some("generated/naming-only.rs")
        }));
    }

    #[test]
    fn generated_inventory_limits_fail_closed_without_growing_records() {
        let mut inventory_entries = MAX_GENERATED_INVENTORY_ENTRIES - 1;
        record_generated_inventory_entry(&mut inventory_entries).unwrap();
        assert_eq!(inventory_entries, MAX_GENERATED_INVENTORY_ENTRIES);
        assert!(record_generated_inventory_entry(&mut inventory_entries).is_err());

        let mut records = Vec::new();
        for index in 0..MAX_OPENAPI_DOCUMENTS {
            push_generated_inventory_record(
                &mut records,
                skipped_record(
                    &format!("mapping-{index}{GENERATED_MANIFEST_SUFFIX}"),
                    "test-skip",
                ),
            )
            .unwrap();
        }
        assert_eq!(records.len(), MAX_OPENAPI_DOCUMENTS);
        assert!(
            push_generated_inventory_record(
                &mut records,
                skipped_record(&format!("overflow{GENERATED_MANIFEST_SUFFIX}"), "test-skip",),
            )
            .is_err()
        );
        assert_eq!(records.len(), MAX_OPENAPI_DOCUMENTS);
    }

    #[test]
    fn shared_generated_outputs_consume_the_total_byte_budget_once() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("generated")).unwrap();
        let shared = b"export const shared = 1";
        fs::write(root.path().join("generated/shared.ts"), shared).unwrap();
        fs::write(root.path().join("generated/other.ts"), b"x").unwrap();

        let mut total_bytes = MAX_GENERATED_TOTAL_OUTPUT_BYTES - shared.len();
        let mut observed_outputs = BTreeMap::new();
        let first = observe_output_once(
            root.path(),
            "generated/shared.ts",
            &mut total_bytes,
            &mut observed_outputs,
        );
        let second = observe_output_once(
            root.path(),
            "generated/shared.ts",
            &mut total_bytes,
            &mut observed_outputs,
        );

        assert_eq!(total_bytes, MAX_GENERATED_TOTAL_OUTPUT_BYTES);
        assert_eq!(first.digest, second.digest);
        assert!(first.reason.is_none());
        assert!(second.reason.is_none());
        assert_eq!(
            observe_output_once(
                root.path(),
                "generated/other.ts",
                &mut total_bytes,
                &mut observed_outputs,
            )
            .reason
            .as_deref(),
            Some("generated-output-byte-limit-exceeded")
        );
    }
}
