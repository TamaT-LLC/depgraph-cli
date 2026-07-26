use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path},
};

use anyhow::{Context, Result};
use depgraph_protocol::{
    CROSS_LANGUAGE_CONTRACT_VERSION, Condition, CrossLanguageMappingKind,
    CrossLanguageRelationKind, DependencySite, Evidence, EvidenceKind, GraphEdge, GraphNode, Phase,
    Precision, Properties, ResolutionStatus, build_cross_language_edge_id,
    build_cross_language_site_id, stable_id_from_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use walkdir::WalkDir;

use super::{
    MAX_PROTOBUF_FILE_BYTES, MAX_PROTOBUF_TOTAL_BYTES, PROTOBUF_DESCRIPTOR_SUFFIX,
    ProtobufGraphBuilder, bounded_reason, bounded_text, digest_value, insert_same,
    inventory_entry_allowed, read_bounded, repository_locator, sha256_prefixed,
    valid_proto_locator,
};

pub const PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION: &str =
    "depgraph-protobuf-generated-mapping-v1";

const GENERATED_EXTRACTOR: &str = "depgraph-protobuf-generated-adapter";
const GENERATED_MANIFEST_SUFFIX: &str = ".depgraph-protobuf-generated.json";
const MAX_GENERATED_MANIFESTS: usize = 256;
const MAX_GENERATED_MAPPINGS: usize = 10_000;
const MAX_GENERATED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_GENERATED_TOTAL_OUTPUT_BYTES: usize = 128 * 1024 * 1024;

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

    pub(super) fn reasons(&self) -> impl Iterator<Item = &str> {
        self.records
            .iter()
            .filter_map(|record| record.reason.as_deref())
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
    source: SourceIdentity,
    descriptor: DescriptorIdentity,
    complete: bool,
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
struct SourceIdentity {
    path: String,
    digest: String,
    format_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DescriptorIdentity {
    path: String,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct GeneratedMapping {
    language: GeneratedLanguage,
    target_kind: GeneratedTargetKind,
    role: GeneratedRole,
    coordinate: String,
    output: String,
    output_digest: String,
    endpoint: String,
    proof: GeneratedProof,
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
enum GeneratedTargetKind {
    Message,
    Method,
    Service,
}

impl GeneratedTargetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Method => "method",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GeneratedRole {
    Client,
    Provider,
    Type,
}

impl GeneratedRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Provider => "provider",
            Self::Type => "type",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum GeneratedProof {
    GeneratorSourceMap,
    NamingOnly,
}

#[derive(Clone, Debug, Serialize)]
struct OutputObservation {
    digest: Option<String>,
    line_columns: Vec<u32>,
    reason: Option<String>,
}

pub(super) fn inventory_generated_mappings(root: &Path) -> Result<GeneratedInventory> {
    let mut records = Vec::new();
    let mut manifest_bytes = 0_usize;
    let mut output_bytes = 0_usize;
    let mut mapping_count = 0_usize;
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
        if !locator.ends_with(GENERATED_MANIFEST_SUFFIX) {
            continue;
        }
        if records.len() >= MAX_GENERATED_MANIFESTS {
            records.push(skipped_record(
                &locator,
                "protobuf-generated-manifest-count-limit-exceeded",
            ));
            break;
        }
        if entry.file_type().is_symlink() {
            records.push(skipped_record(
                &locator,
                "protobuf-generated-manifest-symlink-not-admitted",
            ));
            continue;
        }
        if !entry.file_type().is_file() {
            records.push(skipped_record(
                &locator,
                "protobuf-generated-manifest-is-not-a-file",
            ));
            continue;
        }
        let file_len = match entry.metadata() {
            Ok(metadata) => metadata.len() as usize,
            Err(_) => {
                records.push(skipped_record(
                    &locator,
                    "protobuf-generated-manifest-metadata-unavailable",
                ));
                continue;
            }
        };
        if file_len > MAX_PROTOBUF_FILE_BYTES
            || manifest_bytes.saturating_add(file_len) > MAX_PROTOBUF_TOTAL_BYTES
        {
            records.push(skipped_record(
                &locator,
                "protobuf-generated-manifest-byte-limit-exceeded",
            ));
            continue;
        }
        manifest_bytes += file_len;
        let bytes = match read_bounded(entry.path(), MAX_PROTOBUF_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(_) => {
                records.push(skipped_record(
                    &locator,
                    "protobuf-generated-manifest-read-failed",
                ));
                continue;
            }
        };
        let raw_digest = sha256_prefixed(&bytes);
        let (end_line, end_column) = std::str::from_utf8(&bytes)
            .ok()
            .map(source_end_position)
            .unwrap_or((1, 1));
        let mut manifest: GeneratedManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(_) => {
                records.push(GeneratedRecord {
                    locator,
                    digest: raw_digest,
                    manifest: None,
                    observations: BTreeMap::new(),
                    reason: Some("protobuf-generated-manifest-schema-is-invalid".to_owned()),
                    end_line,
                    end_column,
                });
                continue;
            }
        };
        if let Err(reason) = validate_manifest(&mut manifest) {
            records.push(GeneratedRecord {
                locator,
                digest: raw_digest,
                manifest: None,
                observations: BTreeMap::new(),
                reason: Some(reason),
                end_line,
                end_column,
            });
            continue;
        }
        if mapping_count.saturating_add(manifest.mappings.len()) > MAX_GENERATED_MAPPINGS {
            records.push(GeneratedRecord {
                locator,
                digest: raw_digest,
                manifest: None,
                observations: BTreeMap::new(),
                reason: Some("protobuf-generated-mapping-count-limit-exceeded".to_owned()),
                end_line,
                end_column,
            });
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
            observations.insert(
                output.to_owned(),
                observe_output(root, output, &mut output_bytes),
            );
        }
        records.push(GeneratedRecord {
            locator,
            digest,
            manifest: Some(manifest),
            observations,
            reason: None,
            end_line,
            end_column,
        });
    }
    records.sort_by(|left, right| left.locator.cmp(&right.locator));
    Ok(GeneratedInventory { records })
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
    if manifest.schema_version != PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION {
        return Err("unsupported-protobuf-generated-mapping-version".to_owned());
    }
    if !bounded_text(&manifest.generator.name)
        || !bounded_text(&manifest.generator.version)
        || !valid_proto_locator(&manifest.source.path)
        || !valid_digest(&manifest.source.digest)
        || !matches!(manifest.source.format_version.as_str(), "proto2" | "proto3")
        || !valid_repository_path(&manifest.descriptor.path)
        || !manifest
            .descriptor
            .path
            .ends_with(PROTOBUF_DESCRIPTOR_SUFFIX)
        || !valid_digest(&manifest.descriptor.digest)
        || manifest.mappings.is_empty()
        || manifest.mappings.len() > MAX_GENERATED_MAPPINGS
    {
        return Err("protobuf-generated-manifest-contract-is-invalid".to_owned());
    }
    for mapping in &manifest.mappings {
        let valid_role = matches!(
            (mapping.target_kind, mapping.role),
            (
                GeneratedTargetKind::Message | GeneratedTargetKind::Service,
                GeneratedRole::Type
            ) | (
                GeneratedTargetKind::Method,
                GeneratedRole::Client | GeneratedRole::Provider
            )
        );
        if !valid_role
            || !bounded_text(&mapping.coordinate)
            || !valid_repository_path(&mapping.output)
            || !valid_digest(&mapping.output_digest)
            || !bounded_text(&mapping.endpoint)
            || mapping.start_line == 0
            || mapping.start_column == 0
            || mapping.end_line == 0
            || mapping.end_column == 0
            || (mapping.start_line, mapping.start_column) > (mapping.end_line, mapping.end_column)
        {
            return Err("protobuf-generated-mapping-entry-is-invalid".to_owned());
        }
    }
    manifest.mappings.sort();
    Ok(())
}

fn observe_output(root: &Path, relative: &str, total_bytes: &mut usize) -> OutputObservation {
    let path = root.join(relative);
    if !confined_regular_file(root, &path) {
        return OutputObservation {
            digest: None,
            line_columns: Vec::new(),
            reason: Some("protobuf-generated-output-is-missing-or-unsafe".to_owned()),
        };
    }
    let file_len = match fs::metadata(&path) {
        Ok(metadata) => metadata.len() as usize,
        Err(_) => {
            return OutputObservation {
                digest: None,
                line_columns: Vec::new(),
                reason: Some("protobuf-generated-output-metadata-unavailable".to_owned()),
            };
        }
    };
    if file_len > MAX_GENERATED_OUTPUT_BYTES
        || total_bytes.saturating_add(file_len) > MAX_GENERATED_TOTAL_OUTPUT_BYTES
    {
        return OutputObservation {
            digest: None,
            line_columns: Vec::new(),
            reason: Some("protobuf-generated-output-byte-limit-exceeded".to_owned()),
        };
    }
    *total_bytes += file_len;
    let bytes = match read_bounded(&path, MAX_GENERATED_OUTPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => {
            return OutputObservation {
                digest: None,
                line_columns: Vec::new(),
                reason: Some("protobuf-generated-output-read-failed".to_owned()),
            };
        }
    };
    let digest = Some(sha256_prefixed(&bytes));
    let source = match std::str::from_utf8(&bytes) {
        Ok(source) => source,
        Err(_) => {
            return OutputObservation {
                digest,
                line_columns: Vec::new(),
                reason: Some("protobuf-generated-output-is-not-utf8".to_owned()),
            };
        }
    };
    OutputObservation {
        digest,
        line_columns: source
            .split('\n')
            .map(|line| u32::try_from(line.chars().count().saturating_add(1)).unwrap_or(u32::MAX))
            .collect(),
        reason: None,
    }
}

fn confined_regular_file(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return false;
        };
        current.push(component);
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
    }
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

fn valid_repository_path(value: &str) -> bool {
    if !bounded_text(value)
        || value.starts_with('/')
        || value.contains('\\')
        || value.as_bytes().get(1) == Some(&b':')
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

fn source_end_position(source: &str) -> (u32, u32) {
    let mut line = 1_u32;
    let mut column = 1_u32;
    for character in source.chars() {
        if character == '\n' {
            line = line.saturating_add(1);
            column = 1;
        } else {
            column = column.saturating_add(1);
        }
    }
    (line, column)
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
            "endpoint": self.mapping.endpoint,
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
    inventory: &GeneratedInventory,
    builder: &mut ProtobufGraphBuilder,
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
                ordinal: u64::try_from(ordinal)
                    .context("Protobuf generated mapping ordinal exceeds u64")?,
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
        let claim = &endpoint_claims[0];
        let mixed_generator = generators_by_output
            .get(&claim.mapping.output)
            .is_some_and(|generators| generators.len() > 1);
        let conflicting_digest = declared_digests_by_output
            .get(&claim.mapping.output)
            .is_some_and(|digests| digests.len() > 1);
        let reason = mapping_failure_reason(
            claim,
            endpoint_claims.len(),
            mixed_generator,
            conflicting_digest,
            builder,
        );
        emit_claim(builder, claim, reason.as_deref())?;
    }
    Ok(())
}

fn mapping_failure_reason(
    claim: &Claim<'_>,
    endpoint_claim_count: usize,
    mixed_generator: bool,
    conflicting_digest: bool,
    builder: &ProtobufGraphBuilder,
) -> Option<String> {
    if !claim.manifest.complete {
        return Some("protobuf-generated-source-map-is-partial".to_owned());
    }
    if claim.mapping.proof != GeneratedProof::GeneratorSourceMap {
        return Some("protobuf-generated-naming-only-proof".to_owned());
    }
    if mixed_generator {
        return Some("mixed-protobuf-generator-output-provenance".to_owned());
    }
    if conflicting_digest {
        return Some("ambiguous-protobuf-generated-output-digest".to_owned());
    }
    if endpoint_claim_count > 1 {
        return Some("ambiguous-protobuf-generated-endpoint-provenance".to_owned());
    }
    if !supported_generator(
        &claim.manifest.generator,
        claim.mapping.language,
        claim.mapping.target_kind,
    ) {
        return Some("unsupported-protobuf-generated-toolchain".to_owned());
    }
    let Some(observation) = claim.record.observations.get(&claim.mapping.output) else {
        return Some("protobuf-generated-output-observation-is-missing".to_owned());
    };
    if let Some(reason) = &observation.reason {
        return Some(reason.clone());
    }
    if observation.digest.as_deref() != Some(claim.mapping.output_digest.as_str()) {
        return Some("protobuf-generated-output-digest-mismatch".to_owned());
    }
    if !valid_span(observation, claim.mapping) {
        return Some("protobuf-generated-source-span-is-invalid".to_owned());
    }
    let Some(source) = builder.sources.get(&claim.manifest.source.path) else {
        return Some("protobuf-generated-source-is-not-admitted".to_owned());
    };
    if source.digest != claim.manifest.source.digest
        || source.version != claim.manifest.source.format_version
    {
        return Some("protobuf-generated-source-digest-mismatch".to_owned());
    }
    let Some(descriptor) = builder.proofs.get(&claim.manifest.source.path) else {
        return Some("protobuf-generated-descriptor-proof-is-missing".to_owned());
    };
    if descriptor.descriptor_locator != claim.manifest.descriptor.path
        || descriptor.descriptor_digest != claim.manifest.descriptor.digest
    {
        return Some("protobuf-generated-descriptor-digest-mismatch".to_owned());
    }
    if contract_target_id(builder, claim).is_none() {
        return Some("protobuf-generated-contract-target-is-not-admitted".to_owned());
    }
    None
}

fn supported_generator(
    generator: &GeneratorIdentity,
    language: GeneratedLanguage,
    target: GeneratedTargetKind,
) -> bool {
    let parts = generator
        .version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(parts) = parts else {
        return false;
    };
    if !(2..=3).contains(&parts.len()) {
        return false;
    }
    matches!(
        (generator.name.as_str(), language, target, parts.as_slice()),
        (
            "prost-build" | "tonic-build",
            GeneratedLanguage::Rust,
            _,
            [0, 14] | [0, 14, _]
        ) | (
            "protoc-gen-go",
            GeneratedLanguage::Go,
            GeneratedTargetKind::Message,
            [1, _] | [1, _, _],
        ) | (
            "protoc-gen-go-grpc",
            GeneratedLanguage::Go,
            GeneratedTargetKind::Service | GeneratedTargetKind::Method,
            [1, _] | [1, _, _],
        ) | (
            "ts-proto" | "@bufbuild/protoc-gen-es",
            GeneratedLanguage::Web,
            _,
            [2, _] | [2, _, _]
        )
    )
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

fn contract_target_id(builder: &ProtobufGraphBuilder, claim: &Claim<'_>) -> Option<String> {
    let source_path = &claim.manifest.source.path;
    match claim.mapping.target_kind {
        GeneratedTargetKind::Message => {
            builder
                .sources
                .get(source_path)?
                .messages
                .contains_key(&claim.mapping.coordinate)
                .then_some(())?;
            builder
                .message_ids
                .get(&claim.mapping.coordinate)
                .filter(|ids| ids.len() == 1)
                .and_then(|ids| ids.first().cloned())
        }
        GeneratedTargetKind::Service => builder
            .service_ids
            .get(&(source_path.clone(), claim.mapping.coordinate.clone()))
            .cloned(),
        GeneratedTargetKind::Method => builder
            .operation_ids
            .get(&(source_path.clone(), claim.mapping.coordinate.clone()))
            .cloned(),
    }
}

fn emit_claim(
    builder: &mut ProtobufGraphBuilder,
    claim: &Claim<'_>,
    reason: Option<&str>,
) -> Result<()> {
    let endpoint_id = generated_endpoint(builder, claim)?;
    let target_id = contract_target_id(builder, claim);
    let identity = format!(
        "generated:{}",
        claim
            .endpoint_digest()
            .strip_prefix("sha256:")
            .expect("generated endpoint digests use sha256")
    );
    if let Some(reason) = reason {
        let unknown = builder.unknown_node(&claim.record.locator, &identity, reason)?;
        match (claim.mapping.target_kind, claim.mapping.role, target_id) {
            (GeneratedTargetKind::Method, GeneratedRole::Provider, Some(operation_id)) => {
                emit_relation(
                    builder,
                    claim,
                    &operation_id,
                    &unknown,
                    CrossLanguageRelationKind::ImplementedBy,
                    ResolutionStatus::Unresolved,
                    Precision::Heuristic,
                    CrossLanguageMappingKind::Unresolved,
                    Some(reason),
                )?;
            }
            (GeneratedTargetKind::Method, GeneratedRole::Client, _)
            | (
                GeneratedTargetKind::Message | GeneratedTargetKind::Service,
                GeneratedRole::Type,
                _,
            ) => {
                emit_relation(
                    builder,
                    claim,
                    &endpoint_id,
                    &unknown,
                    if claim.mapping.target_kind == GeneratedTargetKind::Method {
                        CrossLanguageRelationKind::CallsOperation
                    } else {
                        CrossLanguageRelationKind::GeneratedFrom
                    },
                    ResolutionStatus::Unresolved,
                    Precision::Heuristic,
                    CrossLanguageMappingKind::Unresolved,
                    Some(reason),
                )?;
            }
            _ => unreachable!("manifest validation closes Protobuf generated role combinations"),
        }
        return Ok(());
    }

    let target_id = target_id.context("validated Protobuf generated target disappeared")?;
    emit_relation(
        builder,
        claim,
        &endpoint_id,
        &target_id,
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
            &endpoint_id,
            &target_id,
            CrossLanguageRelationKind::CallsOperation,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::GeneratorManifest,
            None,
        )?,
        GeneratedRole::Provider => emit_relation(
            builder,
            claim,
            &target_id,
            &endpoint_id,
            CrossLanguageRelationKind::ImplementedBy,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::GeneratorManifest,
            None,
        )?,
        GeneratedRole::Type => {}
    }
    Ok(())
}

fn generated_endpoint(builder: &mut ProtobufGraphBuilder, claim: &Claim<'_>) -> Result<String> {
    let kind = if claim.mapping.role == GeneratedRole::Type {
        "type"
    } else {
        "symbol"
    };
    let id = stable_id_from_value(
        kind,
        &json!({
            "identity_version": "protobuf-generated-endpoint-v1",
            "cross_language_profile_binding": builder.profile_id,
            "language": claim.mapping.language,
            "repository_path": claim.mapping.output,
            "coordinate": claim.mapping.endpoint,
            "endpoint_kind": kind,
        }),
    );
    let node = GraphNode {
        id: id.clone(),
        kind: kind.to_owned(),
        locator: format!("generated-protobuf:{id}"),
        display_name: Some(claim.mapping.endpoint.clone()),
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
            (
                "generator_identity".to_owned(),
                Value::String(claim.generator_digest()),
            ),
            (
                "descriptor_digest".to_owned(),
                Value::String(claim.manifest.descriptor.digest.clone()),
            ),
            (
                "source_map_digest".to_owned(),
                Value::String(claim.record.digest.clone()),
            ),
        ]),
    };
    insert_same(&mut builder.nodes, id.clone(), node)
        .map_err(|_| anyhow::anyhow!("conflicting Protobuf generated endpoint identity"))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn emit_relation(
    builder: &mut ProtobufGraphBuilder,
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
                key: "protobuf.generated_language".to_owned(),
                value: Value::String(claim.mapping.language.as_str().to_owned()),
            },
            Condition::Eq {
                key: "protobuf.generated_role".to_owned(),
                value: Value::String(claim.mapping.role.as_str().to_owned()),
            },
            Condition::Eq {
                key: "protobuf.generated_target_kind".to_owned(),
                value: Value::String(claim.mapping.target_kind.as_str().to_owned()),
            },
            Condition::Eq {
                key: "protobuf.coordinate".to_owned(),
                value: Value::String(claim.mapping.coordinate.clone()),
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
            ("format".to_owned(), Value::String("protobuf".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(builder.profile_id.clone()),
            ),
            (
                "format_version".to_owned(),
                Value::String(claim.manifest.source.format_version.clone()),
            ),
            (
                "contract_digest".to_owned(),
                Value::String(claim.manifest.descriptor.digest.clone()),
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
                "generator_name".to_owned(),
                Value::String(claim.manifest.generator.name.clone()),
            ),
            (
                "generator_version".to_owned(),
                Value::String(claim.manifest.generator.version.clone()),
            ),
            (
                "descriptor_locator".to_owned(),
                Value::String(claim.manifest.descriptor.path.clone()),
            ),
            (
                "descriptor_digest".to_owned(),
                Value::String(claim.manifest.descriptor.digest.clone()),
            ),
            (
                "source_digest".to_owned(),
                Value::String(claim.manifest.source.digest.clone()),
            ),
            (
                "source_map_digest".to_owned(),
                Value::String(claim.record.digest.clone()),
            ),
            (
                "source_map_locator".to_owned(),
                Value::String(claim.record.locator.clone()),
            ),
            (
                "generated_output_digest".to_owned(),
                Value::String(claim.mapping.output_digest.clone()),
            ),
            (
                "generated_output_path".to_owned(),
                Value::String(claim.mapping.output.clone()),
            ),
            (
                "generated_endpoint_coordinate".to_owned(),
                Value::String(claim.mapping.endpoint.clone()),
            ),
            (
                "source_contract_locator".to_owned(),
                Value::String(claim.manifest.source.path.clone()),
            ),
            (
                "protobuf_coordinate".to_owned(),
                Value::String(claim.mapping.coordinate.clone()),
            ),
        ]),
    }];
    let mut site = DependencySite {
        id: String::new(),
        source: source.to_owned(),
        kind: relation.as_str().to_owned(),
        specifier: format!(
            "generated:{}:{}:{}",
            claim.mapping.role.as_str(),
            claim.mapping.target_kind.as_str(),
            claim.mapping.coordinate
        ),
        resolution_status: status,
        target_ids: vec![target.to_owned()],
        profile_id: builder.profile_id.clone(),
        condition: condition.clone(),
        precision,
        reason: reason.map(bounded_reason),
        evidence: evidence.clone(),
    };
    site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
    let mut edge = GraphEdge {
        id: String::new(),
        source: source.to_owned(),
        target: target.to_owned(),
        kind: relation.as_str().to_owned(),
        site_id: Some(site.id.clone()),
        phase: Phase::Semantic,
        environment: None,
        profile_id: builder.profile_id.clone(),
        condition,
        resolution_status: status,
        precision,
        generated: true,
        evidence,
    };
    edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
    insert_same(&mut builder.sites, site.id.clone(), site)
        .map_err(|_| anyhow::anyhow!("conflicting Protobuf generated site identity"))?;
    insert_same(&mut builder.edges, edge.id.clone(), edge)
        .map_err(|_| anyhow::anyhow!("conflicting Protobuf generated edge identity"))?;
    if status == ResolutionStatus::Unresolved {
        builder.unresolved_count += 1;
        if let Some(reason) = reason {
            builder.insert_reason(reason);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCapabilityStatus,
        CrossLanguageCompletenessLedger, CrossLanguageMappingKind, CrossLanguageRelationKind,
        ResolutionStatus, validate_cross_language_adapter_delta,
    };
    use prost::Message as _;
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto, field_descriptor_proto,
    };

    use super::*;
    use crate::protobuf::scan_protobuf_repository;

    const SOURCE: &str = r#"syntax = "proto3";
package demo.v1;
message Request { string name = 1; }
message Response { string value = 1; }
service Greeter {
  rpc SayHello(Request) returns (Response);
}
"#;

    fn descriptor_bytes() -> Vec<u8> {
        let descriptor = FileDescriptorProto {
            name: Some("proto/greeter.proto".to_owned()),
            package: Some("demo.v1".to_owned()),
            dependency: Vec::new(),
            public_dependency: Vec::new(),
            weak_dependency: Vec::new(),
            message_type: vec![
                DescriptorProto {
                    name: Some("Request".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("name".to_owned()),
                        number: Some(1),
                        label: Some(field_descriptor_proto::Label::Optional as i32),
                        r#type: Some(field_descriptor_proto::Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("Response".to_owned()),
                    field: vec![FieldDescriptorProto {
                        name: Some("value".to_owned()),
                        number: Some(1),
                        label: Some(field_descriptor_proto::Label::Optional as i32),
                        r#type: Some(field_descriptor_proto::Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("Greeter".to_owned()),
                method: vec![MethodDescriptorProto {
                    name: Some("SayHello".to_owned()),
                    input_type: Some(".demo.v1.Request".to_owned()),
                    output_type: Some(".demo.v1.Response".to_owned()),
                    client_streaming: Some(false),
                    server_streaming: Some(false),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            syntax: Some("proto3".to_owned()),
            ..Default::default()
        };
        FileDescriptorSet {
            file: vec![descriptor],
        }
        .encode_to_vec()
    }

    fn initialize(root: &Path) -> (String, String, String) {
        fs::create_dir_all(root.join("proto")).unwrap();
        fs::create_dir_all(root.join("generated")).unwrap();
        fs::write(root.join("proto/greeter.proto"), SOURCE).unwrap();
        let descriptor = descriptor_bytes();
        fs::write(
            root.join(format!("api{PROTOBUF_DESCRIPTOR_SUFFIX}")),
            &descriptor,
        )
        .unwrap();
        (
            sha256_prefixed(SOURCE.as_bytes()),
            sha256_prefixed(&descriptor),
            "api.depgraph-protobuf-descriptor.pb".to_owned(),
        )
    }

    #[derive(Clone, Copy)]
    struct MappingFixture<'a> {
        language: &'a str,
        generator: &'a str,
        version: &'a str,
        target_kind: &'a str,
        role: &'a str,
        coordinate: &'a str,
        endpoint: &'a str,
        output: &'a str,
    }

    fn write_manifest(
        root: &Path,
        name: &str,
        fixture: MappingFixture<'_>,
        complete: bool,
        proof: &str,
        source_digest: &str,
        descriptor_digest: &str,
    ) {
        let output = root.join(fixture.output);
        let output_bytes = fs::read(&output).unwrap();
        let manifest = json!({
            "schema_version": PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION,
            "generator": {"name": fixture.generator, "version": fixture.version},
            "source": {
                "path": "proto/greeter.proto",
                "digest": source_digest,
                "format_version": "proto3"
            },
            "descriptor": {
                "path": "api.depgraph-protobuf-descriptor.pb",
                "digest": descriptor_digest
            },
            "complete": complete,
            "mappings": [{
                "language": fixture.language,
                "target_kind": fixture.target_kind,
                "role": fixture.role,
                "coordinate": fixture.coordinate,
                "output": fixture.output,
                "output_digest": sha256_prefixed(&output_bytes),
                "endpoint": fixture.endpoint,
                "proof": proof,
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 8
            }]
        });
        fs::write(
            root.join(format!("{name}{GENERATED_MANIFEST_SUFFIX}")),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn exact_generated_edge_count(delta: &depgraph_protocol::CrossLanguageAdapterDelta) -> usize {
        delta
            .edges
            .iter()
            .filter(|edge| {
                edge.generated
                    && edge.resolution_status == ResolutionStatus::Resolved
                    && edge.precision == Precision::Exact
                    && edge.evidence[0].properties["mapping_kind"]
                        == serde_json::to_value(CrossLanguageMappingKind::GeneratorManifest)
                            .unwrap()
            })
            .count()
    }

    #[test]
    fn rust_go_and_web_provenance_map_message_method_and_service_exactly() {
        let root = tempfile::tempdir().unwrap();
        let (source_digest, descriptor_digest, _) = initialize(root.path());
        fs::write(root.path().join("generated/rust.rs"), "Request type\n").unwrap();
        fs::write(root.path().join("generated/go.go"), "SayHello call\n").unwrap();
        fs::write(root.path().join("generated/web.ts"), "Greeter type\n").unwrap();
        write_manifest(
            root.path(),
            "rust",
            MappingFixture {
                language: "rust",
                generator: "prost-build",
                version: "0.14.4",
                target_kind: "message",
                role: "type",
                coordinate: "demo.v1.Request",
                endpoint: "demo::v1::Request",
                output: "generated/rust.rs",
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        write_manifest(
            root.path(),
            "go",
            MappingFixture {
                language: "go",
                generator: "protoc-gen-go-grpc",
                version: "1.5.1",
                target_kind: "method",
                role: "client",
                coordinate: "demo.v1.Greeter/SayHello",
                endpoint: "demo.GreeterClient.SayHello",
                output: "generated/go.go",
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        write_manifest(
            root.path(),
            "web",
            MappingFixture {
                language: "web",
                generator: "ts-proto",
                version: "2.8.3",
                target_kind: "service",
                role: "type",
                coordinate: "demo.v1.Greeter",
                endpoint: "demo.v1.Greeter",
                output: "generated/web.ts",
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );

        let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        assert_eq!(exact_generated_edge_count(&delta), 4);
        assert!(
            delta
                .edges
                .iter()
                .filter(|edge| edge.generated)
                .all(|edge| {
                    let properties = &edge.evidence[0].properties;
                    properties.contains_key("descriptor_digest")
                        && properties.contains_key("source_map_digest")
                        && properties.contains_key("generator_version")
                        && properties.contains_key("generated_output_digest")
                })
        );
        assert!(delta.edges.iter().any(|edge| {
            edge.generated
                && edge.kind == CrossLanguageRelationKind::CallsOperation.as_str()
                && edge.resolution_status == ResolutionStatus::Resolved
        }));
    }

    #[test]
    fn generated_identity_is_checkout_independent() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        for root in [first.path(), second.path()] {
            let (source_digest, descriptor_digest, _) = initialize(root);
            fs::write(root.join("generated/rust.rs"), "Request type\n").unwrap();
            write_manifest(
                root,
                "rust",
                MappingFixture {
                    language: "rust",
                    generator: "prost-build",
                    version: "0.14.4",
                    target_kind: "message",
                    role: "type",
                    coordinate: "demo.v1.Request",
                    endpoint: "demo::v1::Request",
                    output: "generated/rust.rs",
                },
                true,
                "generator_source_map",
                &source_digest,
                &descriptor_digest,
            );
        }
        let first = scan_protobuf_repository(first.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        let second = scan_protobuf_repository(second.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    #[test]
    fn stale_partial_naming_only_and_tampered_descriptor_claims_stay_unresolved() {
        let cases = [
            ("stale", true, "generator_source_map", "stale-source"),
            ("partial", false, "generator_source_map", "source"),
            ("naming", true, "naming_only", "source"),
            (
                "descriptor",
                true,
                "generator_source_map",
                "descriptor-tamper",
            ),
        ];
        for (name, complete, proof, mutation) in cases {
            let root = tempfile::tempdir().unwrap();
            let (source_digest, descriptor_digest, _) = initialize(root.path());
            fs::write(root.path().join("generated/rust.rs"), "Request type\n").unwrap();
            let claimed_source = if mutation == "stale-source" {
                format!("sha256:{}", "0".repeat(64))
            } else {
                source_digest.clone()
            };
            let claimed_descriptor = if mutation == "descriptor-tamper" {
                format!("sha256:{}", "1".repeat(64))
            } else {
                descriptor_digest.clone()
            };
            write_manifest(
                root.path(),
                name,
                MappingFixture {
                    language: "rust",
                    generator: "prost-build",
                    version: "0.14.4",
                    target_kind: "message",
                    role: "type",
                    coordinate: "demo.v1.Request",
                    endpoint: "demo::v1::Request",
                    output: "generated/rust.rs",
                },
                complete,
                proof,
                &claimed_source,
                &claimed_descriptor,
            );
            let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
                .unwrap()
                .unwrap();
            assert_eq!(exact_generated_edge_count(&delta), 0, "{name}");
            assert!(
                delta.edges.iter().any(|edge| {
                    edge.generated && edge.resolution_status == ResolutionStatus::Unresolved
                }),
                "{name}"
            );
            let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
                delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
            )
            .unwrap();
            assert_eq!(
                ledger.entries[0].status,
                CrossLanguageCapabilityStatus::Incomplete,
                "{name}"
            );
        }
    }

    #[test]
    fn duplicate_endpoint_output_tamper_and_unsupported_generator_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let (source_digest, descriptor_digest, _) = initialize(root.path());
        fs::write(root.path().join("generated/go.go"), "SayHello call\n").unwrap();
        let fixture = MappingFixture {
            language: "go",
            generator: "protoc-gen-go-grpc",
            version: "1.5.1",
            target_kind: "method",
            role: "client",
            coordinate: "demo.v1.Greeter/SayHello",
            endpoint: "demo.GreeterClient.SayHello",
            output: "generated/go.go",
        };
        write_manifest(
            root.path(),
            "one",
            fixture,
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        write_manifest(
            root.path(),
            "two",
            fixture,
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(exact_generated_edge_count(&delta), 0);
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("ambiguous-protobuf-generated-endpoint-provenance")
        }));

        fs::remove_file(root.path().join(format!("two{GENERATED_MANIFEST_SUFFIX}"))).unwrap();
        fs::write(root.path().join("generated/go.go"), "tampered output\n").unwrap();
        let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(exact_generated_edge_count(&delta), 0);
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("protobuf-generated-output-digest-mismatch")
        }));

        fs::write(root.path().join("generated/go.go"), "SayHello call\n").unwrap();
        write_manifest(
            root.path(),
            "one",
            MappingFixture {
                generator: "unknown-generator",
                ..fixture
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(exact_generated_edge_count(&delta), 0);
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("unsupported-protobuf-generated-toolchain")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn generated_manifest_and_output_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (source_digest, descriptor_digest, _) = initialize(root.path());
        fs::write(outside.path().join("output.rs"), "Request type\n").unwrap();
        symlink(
            outside.path().join("output.rs"),
            root.path().join("generated/rust.rs"),
        )
        .unwrap();
        fs::write(root.path().join("generated/local.rs"), "Request type\n").unwrap();
        write_manifest(
            root.path(),
            "local",
            MappingFixture {
                language: "rust",
                generator: "prost-build",
                version: "0.14.4",
                target_kind: "message",
                role: "type",
                coordinate: "demo.v1.Request",
                endpoint: "demo::v1::Request",
                output: "generated/local.rs",
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        symlink(
            root.path()
                .join(format!("local{GENERATED_MANIFEST_SUFFIX}")),
            root.path()
                .join(format!("linked{GENERATED_MANIFEST_SUFFIX}")),
        )
        .unwrap();
        write_manifest(
            root.path(),
            "unsafe-output",
            MappingFixture {
                output: "generated/rust.rs",
                ..MappingFixture {
                    language: "rust",
                    generator: "prost-build",
                    version: "0.14.4",
                    target_kind: "message",
                    role: "type",
                    coordinate: "demo.v1.Response",
                    endpoint: "demo::v1::Response",
                    output: "generated/rust.rs",
                }
            },
            true,
            "generator_source_map",
            &source_digest,
            &descriptor_digest,
        );
        let delta = scan_protobuf_repository(root.path(), &["polyglot:production".to_owned()])
            .unwrap()
            .unwrap();
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("protobuf-generated-output-is-missing-or-unsafe")
        }));
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert!(ledger.entries[0].skipped_count > 0);
    }
}
