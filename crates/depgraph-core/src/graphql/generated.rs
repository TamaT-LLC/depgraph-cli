use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use crate::bounded_query::read_bounded_repository_file;
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
    GRAPHQL_FORMAT_VERSION, GraphQlGraphBuilder, MAX_GRAPHQL_FILE_BYTES, MAX_GRAPHQL_FILES,
    MAX_GRAPHQL_TOTAL_BYTES, bounded_reason, bounded_text, digest_value, insert_same,
    inventory_entry_allowed, is_federation_directive, repository_locator, sha256_prefixed,
};

pub const GRAPHQL_REPOSITORY_MAPPING_CAPABILITY: &str = "graphql-repository-mapping-v1";
pub const GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION: &str =
    "depgraph-graphql-repository-mapping-v1";

const EXTRACTOR: &str = "depgraph-graphql-repository-mapping-adapter";
const MANIFEST_SUFFIX: &str = ".depgraph-graphql-mapping.json";
const MAX_MANIFESTS: usize = 256;
const MAX_MAPPINGS: usize = 10_000;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_OUTPUT_BYTES: usize = 128 * 1024 * 1024;
const MAX_INVENTORY_ENTRIES: usize = 1_000_000;
const MAX_ENDPOINT_EVIDENCE_CHARS: usize = 4_096;

#[derive(Clone, Debug)]
pub(super) struct RepositoryMappingInventory {
    records: Vec<MappingRecord>,
}

impl RepositoryMappingInventory {
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
                .map(MappingRecord::identity_value)
                .collect::<Vec<_>>()
        )
    }
}

#[derive(Clone, Debug)]
struct MappingRecord {
    locator: String,
    digest: String,
    manifest: Option<RepositoryMappingManifest>,
    observations: BTreeMap<String, OutputObservation>,
    reason: Option<String>,
    end_line: u32,
    end_column: u32,
}

impl MappingRecord {
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
struct RepositoryMappingManifest {
    schema_version: String,
    tool: ToolIdentity,
    input: InputIdentity,
    complete: bool,
    mappings: Vec<RepositoryMapping>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolIdentity {
    name: String,
    version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InputIdentity {
    format_version: String,
    digest: String,
    documents: Vec<DocumentIdentity>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct DocumentIdentity {
    path: String,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct RepositoryMapping {
    language: MappingLanguage,
    role: MappingRole,
    contract_path: String,
    coordinate: String,
    output: String,
    output_digest: String,
    endpoint: String,
    proof: MappingProof,
    dynamic: bool,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum MappingLanguage {
    Go,
    Rust,
    Web,
}

impl MappingLanguage {
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
enum MappingRole {
    Client,
    Resolver,
}

impl MappingRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Resolver => "resolver",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum MappingProof {
    CompilerSourceMap,
    FrameworkMap,
    NamingOnly,
}

#[derive(Clone, Debug, Serialize)]
struct OutputObservation {
    digest: Option<String>,
    line_columns: Vec<u32>,
    reason: Option<String>,
    #[serde(skip)]
    source: Option<String>,
    #[serde(skip)]
    line_offsets: Vec<usize>,
}

pub(super) fn inventory_repository_mappings(root: &Path) -> Result<RepositoryMappingInventory> {
    let mut records = Vec::new();
    let mut manifest_bytes = 0_usize;
    let mut output_bytes = 0_usize;
    let mut mapping_count = 0_usize;
    let mut inventory_entries = 0_usize;
    let mut shared_observations = BTreeMap::<String, OutputObservation>::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(inventory_entry_allowed);
    for entry in walker {
        record_inventory_entry(&mut inventory_entries)?;
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
        if !locator.ends_with(MANIFEST_SUFFIX) {
            continue;
        }
        if entry.file_type().is_symlink() {
            push_inventory_record(
                &mut records,
                skipped_record(&locator, "graphql-mapping-manifest-symlink-not-admitted"),
            )?;
            continue;
        }
        if !entry.file_type().is_file() {
            push_inventory_record(
                &mut records,
                skipped_record(&locator, "graphql-mapping-manifest-is-not-a-file"),
            )?;
            continue;
        }
        let bytes = match read_bounded_repository_file(root, entry.path(), MAX_GRAPHQL_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                let reason = if error.code == "query_file_size_or_type_invalid" {
                    "graphql-mapping-manifest-byte-limit-exceeded"
                } else {
                    "graphql-mapping-manifest-read-failed"
                };
                push_inventory_record(&mut records, skipped_record(&locator, reason))?;
                continue;
            }
        };
        let Some(total_manifest_bytes) = manifest_bytes.checked_add(bytes.len()) else {
            anyhow::bail!("GraphQL mapping manifest byte count overflowed");
        };
        if total_manifest_bytes > MAX_GRAPHQL_TOTAL_BYTES {
            push_inventory_record(
                &mut records,
                skipped_record(
                    &locator,
                    "graphql-mapping-manifest-total-byte-limit-exceeded",
                ),
            )?;
            continue;
        }
        manifest_bytes = total_manifest_bytes;
        let raw_digest = sha256_prefixed(&bytes);
        let (end_line, end_column) = end_position(&bytes);
        let mut manifest: RepositoryMappingManifest = match serde_json::from_slice(&bytes) {
            Ok(manifest) => manifest,
            Err(_) => {
                push_inventory_record(
                    &mut records,
                    MappingRecord {
                        locator,
                        digest: raw_digest,
                        manifest: None,
                        observations: BTreeMap::new(),
                        reason: Some("graphql-mapping-manifest-schema-is-invalid".to_owned()),
                        end_line,
                        end_column,
                    },
                )?;
                continue;
            }
        };
        if let Err(reason) = validate_manifest(&mut manifest) {
            push_inventory_record(
                &mut records,
                MappingRecord {
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
        if mapping_count.saturating_add(manifest.mappings.len()) > MAX_MAPPINGS {
            push_inventory_record(
                &mut records,
                MappingRecord {
                    locator,
                    digest: raw_digest,
                    manifest: None,
                    observations: BTreeMap::new(),
                    reason: Some("graphql-repository-mapping-count-limit-exceeded".to_owned()),
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
            observations.insert(
                output.to_owned(),
                observe_output_once(root, output, &mut shared_observations, &mut output_bytes),
            );
        }
        push_inventory_record(
            &mut records,
            MappingRecord {
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
    Ok(RepositoryMappingInventory { records })
}

fn record_inventory_entry(inventory_entries: &mut usize) -> Result<()> {
    *inventory_entries = inventory_entries
        .checked_add(1)
        .context("GraphQL mapping inventory entry count overflowed")?;
    if *inventory_entries > MAX_INVENTORY_ENTRIES {
        anyhow::bail!("GraphQL mapping inventory exceeds its closed entry limit");
    }
    Ok(())
}

fn push_inventory_record(records: &mut Vec<MappingRecord>, record: MappingRecord) -> Result<()> {
    if records.len() >= MAX_MANIFESTS {
        anyhow::bail!("GraphQL mapping inventory exceeds its closed manifest limit");
    }
    records.push(record);
    Ok(())
}

fn skipped_record(locator: &str, reason: &str) -> MappingRecord {
    MappingRecord {
        locator: locator.to_owned(),
        digest: digest_value(&json!({"locator": locator, "reason": reason})),
        manifest: None,
        observations: BTreeMap::new(),
        reason: Some(reason.to_owned()),
        end_line: 1,
        end_column: 1,
    }
}

fn validate_manifest(manifest: &mut RepositoryMappingManifest) -> std::result::Result<(), String> {
    if manifest.schema_version != GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION {
        return Err("unsupported-graphql-repository-mapping-version".to_owned());
    }
    if !bounded_text(&manifest.tool.name)
        || !bounded_text(&manifest.tool.version)
        || manifest.input.format_version != GRAPHQL_FORMAT_VERSION
        || !valid_digest(&manifest.input.digest)
        || manifest.input.documents.is_empty()
        || manifest.input.documents.len() > MAX_GRAPHQL_FILES
        || manifest.mappings.is_empty()
        || manifest.mappings.len() > MAX_MAPPINGS
    {
        return Err("graphql-mapping-manifest-contract-is-invalid".to_owned());
    }
    manifest.input.documents.sort();
    if manifest
        .input
        .documents
        .windows(2)
        .any(|pair| pair[0].path == pair[1].path)
        || manifest
            .input
            .documents
            .iter()
            .any(|document| !valid_graphql_path(&document.path) || !valid_digest(&document.digest))
        || digest_value(&serde_json::to_value(&manifest.input.documents).expect("serializable"))
            != manifest.input.digest
    {
        return Err("graphql-mapping-input-proof-is-invalid".to_owned());
    }
    for mapping in &manifest.mappings {
        let proof_matches_role = matches!(
            (mapping.role, mapping.proof),
            (MappingRole::Client, MappingProof::CompilerSourceMap)
                | (MappingRole::Resolver, MappingProof::FrameworkMap)
                | (_, MappingProof::NamingOnly)
        );
        if !valid_graphql_path(&mapping.contract_path)
            || !bounded_text(&mapping.coordinate)
            || !valid_repository_path(&mapping.output)
            || !valid_digest(&mapping.output_digest)
            || !bounded_text(&mapping.endpoint)
            || !proof_matches_role
            || mapping.start_line == 0
            || mapping.start_column == 0
            || mapping.end_line == 0
            || mapping.end_column == 0
            || (mapping.start_line, mapping.start_column) > (mapping.end_line, mapping.end_column)
        {
            return Err("graphql-repository-mapping-entry-is-invalid".to_owned());
        }
    }
    manifest.mappings.sort();
    Ok(())
}

fn observe_output(root: &Path, relative: &str, total_bytes: &mut usize) -> OutputObservation {
    let path = root.join(relative);
    let bytes = match read_bounded_repository_file(root, &path, MAX_OUTPUT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            let reason = if error.code == "query_file_size_or_type_invalid" {
                "graphql-mapped-output-byte-limit-exceeded"
            } else {
                "graphql-mapped-output-is-missing-or-unsafe"
            };
            return output_failure(reason);
        }
    };
    let Some(total_output_bytes) = total_bytes.checked_add(bytes.len()) else {
        return output_failure("graphql-mapped-output-byte-limit-exceeded");
    };
    if total_output_bytes > MAX_TOTAL_OUTPUT_BYTES {
        return output_failure("graphql-mapped-output-byte-limit-exceeded");
    }
    *total_bytes = total_output_bytes;
    let digest = Some(sha256_prefixed(&bytes));
    let source = match std::str::from_utf8(&bytes) {
        Ok(source) => source,
        Err(_) => {
            return OutputObservation {
                digest,
                line_columns: Vec::new(),
                reason: Some("graphql-mapped-output-is-not-utf8".to_owned()),
                source: None,
                line_offsets: Vec::new(),
            };
        }
    };
    let line_offsets = std::iter::once(0)
        .chain(source.match_indices('\n').map(|(index, _)| index + 1))
        .collect();
    OutputObservation {
        digest,
        line_columns: source
            .split('\n')
            .map(|line| u32::try_from(line.chars().count().saturating_add(1)).unwrap_or(u32::MAX))
            .collect(),
        reason: None,
        source: Some(source.to_owned()),
        line_offsets,
    }
}

fn observe_output_once(
    root: &Path,
    relative: &str,
    observations: &mut BTreeMap<String, OutputObservation>,
    total_bytes: &mut usize,
) -> OutputObservation {
    if let Some(observation) = observations.get(relative) {
        return observation.clone();
    }
    let observation = observe_output(root, relative, total_bytes);
    observations.insert(relative.to_owned(), observation.clone());
    observation
}

fn output_failure(reason: &str) -> OutputObservation {
    OutputObservation {
        digest: None,
        line_columns: Vec::new(),
        reason: Some(reason.to_owned()),
        source: None,
        line_offsets: Vec::new(),
    }
}

fn valid_repository_path(path: &str) -> bool {
    if !bounded_text(path)
        || path.contains('\\')
        || path.contains(':')
        || Path::new(path).is_absolute()
    {
        return false;
    }
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_graphql_path(path: &str) -> bool {
    valid_repository_path(path)
        && path
            .rsplit_once('.')
            .is_some_and(|(_, extension)| matches!(extension, "graphql" | "graphqls" | "gql"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn end_position(bytes: &[u8]) -> (u32, u32) {
    let Ok(source) = std::str::from_utf8(bytes) else {
        return (1, 1);
    };
    let mut lines = source.split('\n');
    let mut line_count = 0_u32;
    let mut column = 1_u32;
    for line in &mut lines {
        line_count = line_count.saturating_add(1);
        column = u32::try_from(line.chars().count().saturating_add(1)).unwrap_or(u32::MAX);
    }
    (line_count.max(1), column)
}

#[derive(Clone)]
struct Claim<'a> {
    record: &'a MappingRecord,
    manifest: &'a RepositoryMappingManifest,
    mapping: &'a RepositoryMapping,
    ordinal: u64,
}

impl Claim<'_> {
    fn endpoint_digest(&self) -> String {
        digest_value(&json!({
            "language": self.mapping.language,
            "output": self.mapping.output,
            "endpoint": self.mapping.endpoint,
        }))
    }

    fn claim_digest(&self) -> String {
        digest_value(&json!({
            "endpoint_identity": self.endpoint_digest(),
            "artifact_identity": self.record.digest,
            "ordinal": self.ordinal,
        }))
    }

    fn tool_digest(&self) -> String {
        digest_value(&serde_json::to_value(&self.manifest.tool).expect("serializable"))
    }
}

pub(super) fn apply_repository_mappings(
    inventory: &RepositoryMappingInventory,
    builder: &mut GraphQlGraphBuilder,
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
                ordinal: u64::try_from(ordinal).context("GraphQL mapping ordinal exceeds u64")?,
            });
        }
    }
    claims.sort_by_key(Claim::endpoint_digest);
    let mut claims_by_endpoint = BTreeMap::<String, Vec<Claim<'_>>>::new();
    let mut tools_by_output = BTreeMap::<String, BTreeSet<String>>::new();
    let mut digests_by_output = BTreeMap::<String, BTreeSet<String>>::new();
    for claim in claims {
        claims_by_endpoint
            .entry(claim.endpoint_digest())
            .or_default()
            .push(claim.clone());
        tools_by_output
            .entry(claim.mapping.output.clone())
            .or_default()
            .insert(claim.tool_digest());
        digests_by_output
            .entry(claim.mapping.output.clone())
            .or_default()
            .insert(claim.mapping.output_digest.clone());
    }
    for endpoint_claims in claims_by_endpoint.into_values() {
        for claim in &endpoint_claims {
            let reason = mapping_failure_reason(
                claim,
                endpoint_claims.len(),
                tools_by_output
                    .get(&claim.mapping.output)
                    .is_some_and(|tools| tools.len() > 1),
                digests_by_output
                    .get(&claim.mapping.output)
                    .is_some_and(|digests| digests.len() > 1),
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
    mixed_tool: bool,
    conflicting_digest: bool,
    builder: &GraphQlGraphBuilder,
) -> Option<String> {
    if mixed_tool {
        return Some("graphql-mixed-tool-output-provenance".to_owned());
    }
    if conflicting_digest {
        return Some("graphql-ambiguous-output-digest".to_owned());
    }
    if endpoint_claim_count > 1 {
        return Some("graphql-ambiguous-endpoint-provenance".to_owned());
    }
    if !claim.manifest.complete {
        return Some("graphql-repository-map-is-partial".to_owned());
    }
    if claim.mapping.proof == MappingProof::NamingOnly {
        return Some("graphql-naming-only-mapping-is-not-proof".to_owned());
    }
    if claim.mapping.dynamic {
        return Some(match claim.mapping.role {
            MappingRole::Client => "graphql-dynamic-client-boundary".to_owned(),
            MappingRole::Resolver => "graphql-dynamic-resolver-boundary".to_owned(),
        });
    }
    if !supported_tool(
        &claim.manifest.tool,
        claim.mapping.language,
        claim.mapping.role,
    ) {
        return Some("unsupported-graphql-mapping-toolchain".to_owned());
    }
    if !input_matches_builder(&claim.manifest.input, builder) {
        return Some("graphql-mapping-input-digest-mismatch".to_owned());
    }
    let Some(observation) = claim.record.observations.get(&claim.mapping.output) else {
        return Some("graphql-mapped-output-observation-is-missing".to_owned());
    };
    if let Some(reason) = &observation.reason {
        return Some(reason.clone());
    }
    if observation.digest.as_deref() != Some(claim.mapping.output_digest.as_str()) {
        return Some("graphql-mapped-output-digest-mismatch".to_owned());
    }
    if !valid_span(observation, claim.mapping) {
        return Some("graphql-mapped-source-span-is-invalid".to_owned());
    }
    if !span_contains_endpoint(observation, claim.mapping) {
        return Some("graphql-mapped-source-span-does-not-contain-endpoint".to_owned());
    }
    match claim.mapping.role {
        MappingRole::Client => {
            if unique_operation_id(
                builder,
                &claim.mapping.contract_path,
                &claim.mapping.coordinate,
            )
            .is_none()
            {
                return Some("graphql-client-operation-is-unresolved".to_owned());
            }
        }
        MappingRole::Resolver => {
            if let Some(reason) = resolver_boundary_reason(builder, &claim.mapping.coordinate) {
                return Some(reason.to_owned());
            }
            if unique_field_id(
                builder,
                &claim.mapping.contract_path,
                &claim.mapping.coordinate,
            )
            .is_none()
            {
                return Some("graphql-resolver-field-is-unresolved".to_owned());
            }
        }
    }
    None
}

fn input_matches_builder(input: &InputIdentity, builder: &GraphQlGraphBuilder) -> bool {
    if input.documents.len() != builder.documents.len() {
        return false;
    }
    input.documents.iter().all(|document| {
        builder
            .documents
            .get(&document.path)
            .is_some_and(|source| source.digest == document.digest)
    })
}

fn unique_operation_id(
    builder: &GraphQlGraphBuilder,
    contract_path: &str,
    coordinate: &str,
) -> Option<String> {
    let count = builder
        .operations
        .iter()
        .filter(|operation| {
            operation.locator == contract_path
                && format!(
                    "{} {}",
                    operation.definition.kind.as_str(),
                    operation.definition.name
                ) == coordinate
        })
        .count();
    (count == 1)
        .then(|| {
            builder
                .operation_ids
                .get(&(contract_path.to_owned(), coordinate.to_owned()))
                .cloned()
        })
        .flatten()
}

fn unique_field_id(
    builder: &GraphQlGraphBuilder,
    contract_path: &str,
    coordinate: &str,
) -> Option<String> {
    let (type_name, field_name) = coordinate.split_once('.')?;
    let definitions = builder.type_groups.get(type_name)?;
    let matches = definitions
        .iter()
        .flat_map(|definition| {
            definition
                .definition
                .fields
                .iter()
                .map(move |field| (&definition.locator, field))
        })
        .filter(|(locator, field)| *locator == contract_path && field.name == field_name)
        .count();
    if matches != 1
        || definitions
            .iter()
            .flat_map(|definition| definition.definition.fields.iter())
            .filter(|field| field.name == field_name)
            .count()
            != 1
    {
        return None;
    }
    builder
        .field_ids
        .get(coordinate)
        .filter(|ids| ids.len() == 1)
        .and_then(|ids| ids.first().cloned())
}

fn resolver_boundary_reason<'a>(
    builder: &'a GraphQlGraphBuilder,
    coordinate: &str,
) -> Option<&'a str> {
    if builder.federated_schema {
        return Some("graphql-federated-resolver-boundary");
    }
    let (type_name, field_name) = coordinate.split_once('.')?;
    let fields = builder
        .type_groups
        .get(type_name)?
        .iter()
        .flat_map(|definition| definition.definition.fields.iter())
        .filter(|field| field.name == field_name)
        .collect::<Vec<_>>();
    if fields.len() != 1 {
        return None;
    }
    let type_is_federated = builder
        .type_groups
        .get(type_name)
        .is_some_and(|definitions| {
            definitions.iter().any(|definition| {
                definition
                    .definition
                    .directives
                    .iter()
                    .any(|directive| is_federation_directive(&directive.name))
            })
        });
    if type_is_federated
        || fields[0]
            .directives
            .iter()
            .any(|directive| is_federation_directive(&directive.name))
    {
        Some("graphql-federated-resolver-boundary")
    } else if fields[0]
        .directives
        .iter()
        .any(|directive| directive.dynamic)
    {
        Some("graphql-dynamic-resolver-boundary")
    } else {
        None
    }
}

fn supported_tool(tool: &ToolIdentity, language: MappingLanguage, role: MappingRole) -> bool {
    let segments = tool.version.split('.').collect::<Vec<_>>();
    if !(2..=3).contains(&segments.len())
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment.bytes().all(|byte| byte.is_ascii_digit())
                || (segment.len() > 1 && segment.starts_with('0'))
        })
    {
        return false;
    }
    let parts = segments
        .iter()
        .copied()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(parts) = parts else {
        return false;
    };
    matches!(
        (tool.name.as_str(), language, role, parts.as_slice()),
        (
            "cynic-codegen",
            MappingLanguage::Rust,
            MappingRole::Client,
            [3, ..]
        ) | (
            "async-graphql",
            MappingLanguage::Rust,
            MappingRole::Resolver,
            [7, ..]
        ) | (
            "@graphql-codegen/client-preset",
            MappingLanguage::Web,
            MappingRole::Client,
            [4, ..]
        ) | (
            "@graphql-codegen/typescript-resolvers",
            MappingLanguage::Web,
            MappingRole::Resolver,
            [4, ..],
        ) | (
            "genqlient",
            MappingLanguage::Go,
            MappingRole::Client,
            [0, 8, ..]
        ) | (
            "gqlgen",
            MappingLanguage::Go,
            MappingRole::Resolver,
            [0, 17, ..]
        )
    )
}

fn valid_span(observation: &OutputObservation, mapping: &RepositoryMapping) -> bool {
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

fn span_contains_endpoint(observation: &OutputObservation, mapping: &RepositoryMapping) -> bool {
    let Some(source) = observation.source.as_deref() else {
        return false;
    };
    let start_line = mapping.start_line.saturating_sub(1) as usize;
    let end_line = mapping.end_line.saturating_sub(1) as usize;
    let mut inspected_chars = 0_usize;
    let mut found = false;
    for absolute_line in start_line..=end_line {
        let Some(line_start) = observation.line_offsets.get(absolute_line).copied() else {
            return false;
        };
        let line_end = observation
            .line_offsets
            .get(absolute_line + 1)
            .map_or(source.len(), |next| next.saturating_sub(1));
        let Some(line) = source.get(line_start..line_end) else {
            return false;
        };
        let start = if absolute_line == start_line {
            mapping.start_column.saturating_sub(1) as usize
        } else {
            0
        };
        let end = if absolute_line == end_line {
            mapping.end_column.saturating_sub(1) as usize
        } else {
            line.chars().count()
        };
        let segment_chars = end.saturating_sub(start);
        let Some(total_chars) = inspected_chars.checked_add(segment_chars) else {
            return false;
        };
        if total_chars > MAX_ENDPOINT_EVIDENCE_CHARS {
            return false;
        }
        inspected_chars = total_chars;
        let selected = line
            .chars()
            .skip(start)
            .take(segment_chars)
            .collect::<String>();
        found |= contains_endpoint_token(&selected, &mapping.endpoint);
    }
    found
}

fn contains_endpoint_token(selected: &str, endpoint: &str) -> bool {
    selected.match_indices(endpoint).any(|(index, endpoint)| {
        let before = selected[..index].chars().next_back();
        let after = selected[index + endpoint.len()..].chars().next();
        before.is_none_or(|character| !is_endpoint_identifier_character(character))
            && after.is_none_or(|character| !is_endpoint_identifier_character(character))
    })
}

fn is_endpoint_identifier_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '$')
}

fn emit_claim(
    builder: &mut GraphQlGraphBuilder,
    claim: &Claim<'_>,
    reason: Option<&str>,
) -> Result<()> {
    let symbol_id = repository_symbol(builder, claim)?;
    let contract_id = match claim.mapping.role {
        MappingRole::Client => unique_operation_id(
            builder,
            &claim.mapping.contract_path,
            &claim.mapping.coordinate,
        ),
        MappingRole::Resolver => unique_field_id(
            builder,
            &claim.mapping.contract_path,
            &claim.mapping.coordinate,
        ),
    };
    if let Some(reason) = reason {
        let unknown = builder.unknown_node(&claim.record.locator, &claim.claim_digest(), reason)?;
        match (claim.mapping.role, contract_id.as_deref()) {
            (MappingRole::Client, _) => emit_relation(
                builder,
                claim,
                &symbol_id,
                &unknown,
                CrossLanguageRelationKind::CallsOperation,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
            (MappingRole::Resolver, Some(field_id)) => emit_relation(
                builder,
                claim,
                field_id,
                &unknown,
                CrossLanguageRelationKind::ImplementedBy,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
            (MappingRole::Resolver, None) => emit_relation(
                builder,
                claim,
                &symbol_id,
                &unknown,
                CrossLanguageRelationKind::GeneratedFrom,
                ResolutionStatus::Unresolved,
                Precision::Heuristic,
                CrossLanguageMappingKind::Unresolved,
                Some(reason),
            )?,
        }
        return Ok(());
    }
    let contract_id = contract_id.context("validated GraphQL contract endpoint disappeared")?;
    emit_relation(
        builder,
        claim,
        &symbol_id,
        &contract_id,
        CrossLanguageRelationKind::GeneratedFrom,
        ResolutionStatus::Resolved,
        Precision::Exact,
        match claim.mapping.role {
            MappingRole::Client => CrossLanguageMappingKind::SourceMap,
            MappingRole::Resolver => CrossLanguageMappingKind::SourceMap,
        },
        None,
    )?;
    match claim.mapping.role {
        MappingRole::Client => emit_relation(
            builder,
            claim,
            &symbol_id,
            &contract_id,
            CrossLanguageRelationKind::CallsOperation,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::SourceMap,
            None,
        )?,
        MappingRole::Resolver => emit_relation(
            builder,
            claim,
            &contract_id,
            &symbol_id,
            CrossLanguageRelationKind::ImplementedBy,
            ResolutionStatus::Resolved,
            Precision::Exact,
            CrossLanguageMappingKind::SourceMap,
            None,
        )?,
    }
    Ok(())
}

fn repository_symbol(builder: &mut GraphQlGraphBuilder, claim: &Claim<'_>) -> Result<String> {
    let id = stable_id_from_value(
        "symbol",
        &json!({
            "identity_version": "graphql-repository-endpoint-v1",
            "cross_language_profile_binding": builder.profile_id,
            "language": claim.mapping.language,
            "repository_path": claim.mapping.output,
            "coordinate": claim.mapping.endpoint,
        }),
    );
    let node = GraphNode {
        id: id.clone(),
        kind: "symbol".to_owned(),
        locator: format!("graphql-repository:{id}"),
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
        ]),
    };
    insert_same(&mut builder.nodes, id.clone(), node)
        .map_err(|_| anyhow::anyhow!("conflicting GraphQL repository symbol identity"))?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn emit_relation(
    builder: &mut GraphQlGraphBuilder,
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
    let contract_digest = claim
        .manifest
        .input
        .documents
        .iter()
        .find(|document| document.path == claim.mapping.contract_path)
        .map(|document| document.digest.clone())
        .unwrap_or_else(|| claim.manifest.input.digest.clone());
    let condition = Condition::All {
        conditions: vec![
            Condition::Eq {
                key: "graphql.mapping_language".to_owned(),
                value: Value::String(claim.mapping.language.as_str().to_owned()),
            },
            Condition::Eq {
                key: "graphql.mapping_role".to_owned(),
                value: Value::String(claim.mapping.role.as_str().to_owned()),
            },
            Condition::Eq {
                key: "graphql.coordinate".to_owned(),
                value: Value::String(claim.mapping.coordinate.clone()),
            },
            Condition::Eq {
                key: "graphql.mapping_claim".to_owned(),
                value: Value::String(claim.claim_digest()),
            },
        ],
    }
    .canonicalize();
    let evidence = vec![Evidence {
        kind: EvidenceKind::Semantic,
        extractor: EXTRACTOR.to_owned(),
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
            ("format".to_owned(), Value::String("graphql".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(builder.profile_id.clone()),
            ),
            (
                "format_version".to_owned(),
                Value::String(claim.manifest.input.format_version.clone()),
            ),
            ("contract_digest".to_owned(), Value::String(contract_digest)),
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
                "tool_identity".to_owned(),
                Value::String(claim.tool_digest()),
            ),
            (
                "tool_name".to_owned(),
                Value::String(claim.manifest.tool.name.clone()),
            ),
            (
                "tool_version".to_owned(),
                Value::String(claim.manifest.tool.version.clone()),
            ),
            (
                "graphql_input_digest".to_owned(),
                Value::String(claim.manifest.input.digest.clone()),
            ),
            (
                "mapped_output_digest".to_owned(),
                Value::String(claim.mapping.output_digest.clone()),
            ),
            (
                "mapping_manifest_locator".to_owned(),
                Value::String(claim.record.locator.clone()),
            ),
            (
                "mapped_output_path".to_owned(),
                Value::String(claim.mapping.output.clone()),
            ),
            (
                "repository_endpoint".to_owned(),
                Value::String(claim.mapping.endpoint.clone()),
            ),
            (
                "source_contract_locator".to_owned(),
                Value::String(claim.mapping.contract_path.clone()),
            ),
        ]),
    }];
    let mut site = DependencySite {
        id: String::new(),
        source: source.to_owned(),
        kind: relation.as_str().to_owned(),
        specifier: format!(
            "graphql-mapping:{}:{}:{}:{}",
            claim.mapping.role.as_str(),
            claim.mapping.coordinate,
            claim.mapping.endpoint,
            claim.claim_digest(),
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
        .map_err(|_| anyhow::anyhow!("conflicting GraphQL repository mapping site"))?;
    insert_same(&mut builder.edges, edge.id.clone(), edge)
        .map_err(|_| anyhow::anyhow!("conflicting GraphQL repository mapping edge"))?;
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
    use std::{collections::BTreeMap, fs, path::Path};

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCompletenessLedger,
        CrossLanguageMappingKind, CrossLanguageRelationKind, Profile, ResolutionStatus,
        validate_cross_language_adapter_delta,
    };
    use serde_json::json;

    use super::*;
    use crate::graphql::scan_graphql_repository;

    const SCHEMA: &str = r#"
directive @policy(name: String!) on FIELD_DEFINITION
type Query {
  product(id: ID!): Product
  local: String @policy(name: "safe")
}
type Product { id: ID!, name: String! }
"#;
    const OPERATIONS: &str = "query GetProduct($id: ID!) { product(id: $id) { id name } }\n";

    fn participating_profiles() -> Vec<Profile> {
        vec![Profile {
            id: "profile:test".to_owned(),
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

    fn write_contract(root: &Path) -> Vec<DocumentIdentity> {
        fs::write(root.join("schema.graphql"), SCHEMA).unwrap();
        fs::write(root.join("operations.graphql"), OPERATIONS).unwrap();
        let mut documents = vec![
            DocumentIdentity {
                path: "schema.graphql".to_owned(),
                digest: sha256_prefixed(SCHEMA.as_bytes()),
            },
            DocumentIdentity {
                path: "operations.graphql".to_owned(),
                digest: sha256_prefixed(OPERATIONS.as_bytes()),
            },
        ];
        documents.sort();
        documents
    }

    fn mapping_manifest(
        tool: (&str, &str),
        documents: &[DocumentIdentity],
        mapping: RepositoryMapping,
    ) -> RepositoryMappingManifest {
        RepositoryMappingManifest {
            schema_version: GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION.to_owned(),
            tool: ToolIdentity {
                name: tool.0.to_owned(),
                version: tool.1.to_owned(),
            },
            input: InputIdentity {
                format_version: GRAPHQL_FORMAT_VERSION.to_owned(),
                digest: digest_value(&serde_json::to_value(documents).unwrap()),
                documents: documents.to_vec(),
            },
            complete: true,
            mappings: vec![mapping],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_mapping(
        root: &Path,
        name: &str,
        tool: (&str, &str),
        documents: &[DocumentIdentity],
        language: MappingLanguage,
        role: MappingRole,
        output: &str,
        endpoint: &str,
    ) {
        let source = format!("fn {endpoint}() {{}}\n");
        fs::write(root.join(output), &source).unwrap();
        let (contract_path, coordinate, proof) = match role {
            MappingRole::Client => (
                "operations.graphql",
                "query GetProduct",
                MappingProof::CompilerSourceMap,
            ),
            MappingRole::Resolver => (
                "schema.graphql",
                "Query.product",
                MappingProof::FrameworkMap,
            ),
        };
        let manifest = mapping_manifest(
            tool,
            documents,
            RepositoryMapping {
                language,
                role,
                contract_path: contract_path.to_owned(),
                coordinate: coordinate.to_owned(),
                output: output.to_owned(),
                output_digest: sha256_prefixed(source.as_bytes()),
                endpoint: endpoint.to_owned(),
                proof,
                dynamic: false,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
            },
        );
        fs::write(
            root.join(format!("{name}{MANIFEST_SUFFIX}")),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn rust_go_and_web_clients_and_resolvers_have_exact_reconstructable_provenance() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let tools = [
            (
                "rust-client",
                ("cynic-codegen", "3.12.0"),
                MappingLanguage::Rust,
                MappingRole::Client,
                "generated/rust_client.rs",
                "get_product",
            ),
            (
                "rust-resolver",
                ("async-graphql", "7.0.0"),
                MappingLanguage::Rust,
                MappingRole::Resolver,
                "generated/rust_resolver.rs",
                "resolve_product",
            ),
            (
                "go-client",
                ("genqlient", "0.8.1"),
                MappingLanguage::Go,
                MappingRole::Client,
                "generated/go_client.go",
                "GetProduct",
            ),
            (
                "go-resolver",
                ("gqlgen", "0.17.0"),
                MappingLanguage::Go,
                MappingRole::Resolver,
                "generated/go_resolver.go",
                "Product",
            ),
            (
                "web-client",
                ("@graphql-codegen/client-preset", "4.0.0"),
                MappingLanguage::Web,
                MappingRole::Client,
                "generated/web_client.ts",
                "getProduct",
            ),
            (
                "web-resolver",
                ("@graphql-codegen/typescript-resolvers", "4.0.0"),
                MappingLanguage::Web,
                MappingRole::Resolver,
                "generated/web_resolver.ts",
                "product",
            ),
        ];
        for (index, root) in [first.path(), second.path()].into_iter().enumerate() {
            fs::create_dir_all(root.join("generated")).unwrap();
            let documents = write_contract(root);
            let iterator: Box<dyn Iterator<Item = _>> = if index == 0 {
                Box::new(tools.iter())
            } else {
                Box::new(tools.iter().rev())
            };
            for (name, tool, language, role, output, endpoint) in iterator {
                write_mapping(
                    root, name, *tool, &documents, *language, *role, output, endpoint,
                );
            }
        }
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
        let exact_calls = first
            .edges
            .iter()
            .filter(|edge| {
                edge.kind == CrossLanguageRelationKind::CallsOperation.as_str()
                    && edge.generated
                    && edge.resolution_status == ResolutionStatus::Resolved
            })
            .count();
        let exact_resolvers = first
            .edges
            .iter()
            .filter(|edge| {
                edge.kind == CrossLanguageRelationKind::ImplementedBy.as_str()
                    && edge.generated
                    && edge.resolution_status == ResolutionStatus::Resolved
            })
            .count();
        assert_eq!(exact_calls, 3);
        assert_eq!(exact_resolvers, 3);
        for edge in first.edges.iter().filter(|edge| edge.generated) {
            let properties = &edge.evidence[0].properties;
            assert!(properties.contains_key("graphql_input_digest"));
            assert!(properties.contains_key("tool_name"));
            assert!(properties.contains_key("mapped_output_digest"));
            assert!(properties.contains_key("source_contract_locator"));
            let mapping_kind: CrossLanguageMappingKind =
                serde_json::from_value(properties["mapping_kind"].clone()).unwrap();
            assert!(matches!(mapping_kind, CrossLanguageMappingKind::SourceMap));
        }
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            first.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert!(ledger.entries[0].reasons.is_empty());
    }

    #[test]
    fn one_repository_endpoint_cannot_map_multiple_contract_coordinates_exactly() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("generated")).unwrap();
        fs::write(root.path().join("schema.graphql"), SCHEMA).unwrap();
        let operations =
            "query GetProduct($id: ID!) { product(id: $id) { id } }\nquery GetLocal { local }\n";
        fs::write(root.path().join("operations.graphql"), operations).unwrap();
        let mut documents = vec![
            DocumentIdentity {
                path: "schema.graphql".to_owned(),
                digest: sha256_prefixed(SCHEMA.as_bytes()),
            },
            DocumentIdentity {
                path: "operations.graphql".to_owned(),
                digest: sha256_prefixed(operations.as_bytes()),
            },
        ];
        documents.sort();

        let output = "generated/shared.rs";
        let endpoint = "shared_call";
        let source = format!("fn {endpoint}() {{}}\n");
        fs::write(root.path().join(output), &source).unwrap();
        let mapping = RepositoryMapping {
            language: MappingLanguage::Rust,
            role: MappingRole::Client,
            contract_path: "operations.graphql".to_owned(),
            coordinate: "query GetProduct".to_owned(),
            output: output.to_owned(),
            output_digest: sha256_prefixed(source.as_bytes()),
            endpoint: endpoint.to_owned(),
            proof: MappingProof::CompilerSourceMap,
            dynamic: false,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
        };
        let mut manifest =
            mapping_manifest(("cynic-codegen", "3.12.0"), &documents, mapping.clone());
        manifest.mappings.push(RepositoryMapping {
            coordinate: "query GetLocal".to_owned(),
            ..mapping
        });
        fs::write(
            root.path().join(format!("ambiguous{MANIFEST_SUFFIX}")),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let endpoint_sites = delta
            .sites
            .iter()
            .filter(|site| {
                site.evidence[0]
                    .properties
                    .get("repository_endpoint")
                    .is_some_and(|value| value == endpoint)
                    && site.kind == CrossLanguageRelationKind::CallsOperation.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(endpoint_sites.len(), 2);
        assert!(endpoint_sites.iter().all(|site| {
            site.resolution_status == ResolutionStatus::Unresolved
                && site.reason.as_deref() == Some("graphql-ambiguous-endpoint-provenance")
        }));
        assert!(!delta.edges.iter().any(|edge| {
            edge.generated
                && edge.resolution_status == ResolutionStatus::Resolved
                && edge.evidence[0].properties["repository_endpoint"] == endpoint
        }));
    }

    #[test]
    fn mapped_span_must_contain_the_declared_repository_endpoint() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("generated")).unwrap();
        let documents = write_contract(root.path());
        let output = "generated/client.rs";
        let source = "fn claimed_endpoint_suffix() {}\n";
        fs::write(root.path().join(output), source).unwrap();
        let manifest = mapping_manifest(
            ("cynic-codegen", "3.12.0"),
            &documents,
            RepositoryMapping {
                language: MappingLanguage::Rust,
                role: MappingRole::Client,
                contract_path: "operations.graphql".to_owned(),
                coordinate: "query GetProduct".to_owned(),
                output: output.to_owned(),
                output_digest: sha256_prefixed(source.as_bytes()),
                endpoint: "claimed_endpoint".to_owned(),
                proof: MappingProof::CompilerSourceMap,
                dynamic: false,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
            },
        );
        fs::write(
            root.path().join(format!("span{MANIFEST_SUFFIX}")),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("graphql-mapped-source-span-does-not-contain-endpoint")
                && site.resolution_status == ResolutionStatus::Unresolved
        }));
        assert!(!delta.edges.iter().any(|edge| {
            edge.generated && edge.resolution_status == ResolutionStatus::Resolved
        }));
    }

    #[test]
    fn mixed_tool_claims_for_one_symbol_remain_reasoned_and_atomic() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("generated")).unwrap();
        let documents = write_contract(root.path());
        let output = "generated/client.rs";
        let endpoint = "get_product";
        let source = format!("fn {endpoint}() {{}}\n");
        fs::write(root.path().join(output), &source).unwrap();
        let mapping = RepositoryMapping {
            language: MappingLanguage::Rust,
            role: MappingRole::Client,
            contract_path: "operations.graphql".to_owned(),
            coordinate: "query GetProduct".to_owned(),
            output: output.to_owned(),
            output_digest: sha256_prefixed(source.as_bytes()),
            endpoint: endpoint.to_owned(),
            proof: MappingProof::CompilerSourceMap,
            dynamic: false,
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
        };
        for (name, tool) in [
            ("supported", ("cynic-codegen", "3.12.0")),
            ("unsupported", ("other-codegen", "3.12.0")),
        ] {
            let manifest = mapping_manifest(tool, &documents, mapping.clone());
            fs::write(
                root.path().join(format!("{name}{MANIFEST_SUFFIX}")),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        }

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let sites = delta
            .sites
            .iter()
            .filter(|site| site.reason.as_deref() == Some("graphql-mixed-tool-output-provenance"))
            .collect::<Vec<_>>();
        assert_eq!(sites.len(), 2);
        assert!(
            sites
                .iter()
                .all(|site| site.resolution_status == ResolutionStatus::Unresolved)
        );
    }

    #[test]
    fn naming_dynamic_federated_stale_ambiguous_and_unsupported_claims_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("generated")).unwrap();
        let schema = r#"
directive @key(fields: String!) on OBJECT | FIELD_DEFINITION
directive @dynamic(value: String!) on FIELD_DEFINITION
type Query @key(fields: "id") {
  product: String
  duplicate: String
  duplicate: String
  dynamic: String @dynamic(value: "$runtime")
}
"#;
        fs::write(root.path().join("schema.graphql"), schema).unwrap();
        fs::write(root.path().join("operations.graphql"), OPERATIONS).unwrap();
        let mut documents = vec![
            DocumentIdentity {
                path: "schema.graphql".to_owned(),
                digest: sha256_prefixed(schema.as_bytes()),
            },
            DocumentIdentity {
                path: "operations.graphql".to_owned(),
                digest: sha256_prefixed(OPERATIONS.as_bytes()),
            },
        ];
        documents.sort();
        let cases = [
            (
                "naming",
                ("cynic-codegen", "3.0.0"),
                MappingRole::Client,
                "query GetProduct",
                MappingProof::NamingOnly,
                false,
                false,
            ),
            (
                "stale",
                ("genqlient", "0.8.0"),
                MappingRole::Client,
                "query GetProduct",
                MappingProof::CompilerSourceMap,
                true,
                false,
            ),
            (
                "ambiguous",
                ("gqlgen", "0.17.0"),
                MappingRole::Resolver,
                "Query.duplicate",
                MappingProof::FrameworkMap,
                false,
                false,
            ),
            (
                "dynamic",
                ("async-graphql", "7.0.0"),
                MappingRole::Resolver,
                "Query.dynamic",
                MappingProof::FrameworkMap,
                false,
                true,
            ),
            (
                "federated",
                ("gqlgen", "0.17.0"),
                MappingRole::Resolver,
                "Query.product",
                MappingProof::FrameworkMap,
                false,
                false,
            ),
            (
                "unsupported",
                ("unknown-tool", "1.0.0"),
                MappingRole::Resolver,
                "Query.product",
                MappingProof::FrameworkMap,
                false,
                false,
            ),
            (
                "noncanonical-version",
                ("cynic-codegen", "03.0.0"),
                MappingRole::Client,
                "query GetProduct",
                MappingProof::CompilerSourceMap,
                false,
                false,
            ),
        ];
        for (name, tool, role, coordinate, proof, stale, dynamic) in &cases {
            let output = format!("generated/{name}.rs");
            let source = format!("fn {name}() {{}}\n");
            fs::write(root.path().join(&output), &source).unwrap();
            let manifest = mapping_manifest(
                *tool,
                &documents,
                RepositoryMapping {
                    language: match tool.0 {
                        "genqlient" | "gqlgen" => MappingLanguage::Go,
                        name if name.starts_with("@graphql-codegen/") => MappingLanguage::Web,
                        _ => MappingLanguage::Rust,
                    },
                    role: *role,
                    contract_path: if *role == MappingRole::Client {
                        "operations.graphql".to_owned()
                    } else {
                        "schema.graphql".to_owned()
                    },
                    coordinate: (*coordinate).to_owned(),
                    output: output.clone(),
                    output_digest: if *stale {
                        sha256_prefixed(b"stale")
                    } else {
                        sha256_prefixed(source.as_bytes())
                    },
                    endpoint: (*name).to_owned(),
                    proof: *proof,
                    dynamic: *dynamic,
                    start_line: 1,
                    start_column: 1,
                    end_line: 1,
                    end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
                },
            );
            fs::write(
                root.path().join(format!("{name}{MANIFEST_SUFFIX}")),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        }
        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        let exact_generated = delta
            .edges
            .iter()
            .filter(|edge| edge.generated && edge.resolution_status == ResolutionStatus::Resolved)
            .map(|edge| {
                edge.evidence[0]
                    .properties
                    .get("repository_endpoint")
                    .cloned()
            })
            .collect::<Vec<_>>();
        assert!(
            exact_generated.is_empty(),
            "negative mappings became exact: {exact_generated:?}"
        );
        let serialized = serde_json::to_string(&delta).unwrap();
        for reason in [
            "graphql-naming-only-mapping-is-not-proof",
            "graphql-mapped-output-digest-mismatch",
            "graphql-resolver-field-is-unresolved",
            "graphql-dynamic-resolver-boundary",
            "graphql-federated-resolver-boundary",
            "unsupported-graphql-mapping-toolchain",
        ] {
            assert!(serialized.contains(reason), "{reason}");
        }
    }

    #[test]
    fn schema_link_directive_marks_every_resolver_mapping_as_federated() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("generated")).unwrap();
        let schema = r#"
extend schema @link(url: "https://specs.apollo.dev/federation/v2.3")
type Query { product: String }
"#;
        fs::write(root.path().join("schema.graphql"), schema).unwrap();
        let documents = vec![DocumentIdentity {
            path: "schema.graphql".to_owned(),
            digest: sha256_prefixed(schema.as_bytes()),
        }];
        let output = "generated/resolver.rs";
        let endpoint = "resolve_product";
        let source = format!("fn {endpoint}() {{}}\n");
        fs::write(root.path().join(output), &source).unwrap();
        let manifest = mapping_manifest(
            ("async-graphql", "7.0.0"),
            &documents,
            RepositoryMapping {
                language: MappingLanguage::Rust,
                role: MappingRole::Resolver,
                contract_path: "schema.graphql".to_owned(),
                coordinate: "Query.product".to_owned(),
                output: output.to_owned(),
                output_digest: sha256_prefixed(source.as_bytes()),
                endpoint: endpoint.to_owned(),
                proof: MappingProof::FrameworkMap,
                dynamic: false,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: u32::try_from(source.trim_end().chars().count() + 1).unwrap(),
            },
        );
        fs::write(
            root.path().join(format!("federated{MANIFEST_SUFFIX}")),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        assert!(delta.sites.iter().any(|site| {
            site.reason.as_deref() == Some("graphql-federated-resolver-boundary")
                && site.resolution_status == ResolutionStatus::Unresolved
        }));
        assert!(!delta.edges.iter().any(|edge| {
            edge.kind == CrossLanguageRelationKind::ImplementedBy.as_str()
                && edge.generated
                && edge.resolution_status == ResolutionStatus::Resolved
        }));
    }

    #[cfg(unix)]
    #[test]
    fn mapping_and_output_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.rs"), "secret").unwrap();
        symlink(
            outside.path().join("secret.rs"),
            root.path().join("generated.rs"),
        )
        .unwrap();
        symlink(
            outside.path().join("secret.rs"),
            root.path().join(format!("unsafe{MANIFEST_SUFFIX}")),
        )
        .unwrap();
        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_string(&delta).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(serialized.contains("graphql-mapping-manifest-symlink-not-admitted"));
    }

    #[test]
    fn manifest_contract_rejects_unknown_partial_and_invalid_input_proof() {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join(format!("invalid{MANIFEST_SUFFIX}")),
            serde_json::to_vec(&json!({
                "schema_version": GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION,
                "tool": {"name": "cynic-codegen", "version": "3.0.0"},
                "input": {
                    "format_version": GRAPHQL_FORMAT_VERSION,
                    "digest": sha256_prefixed(b"wrong"),
                    "documents": [{"path": "../schema.graphql", "digest": sha256_prefixed(b"x")}]
                },
                "complete": true,
                "mappings": [],
                "unknown": true
            }))
            .unwrap(),
        )
        .unwrap();
        let delta = scan_graphql_repository(root.path(), &participating_profiles())
            .unwrap()
            .unwrap();
        let value = serde_json::to_value(delta).unwrap();
        assert!(
            value
                .to_string()
                .contains("graphql-mapping-manifest-schema-is-invalid")
        );
        assert!(
            value["profile"]["properties"]["graphql_repository_provenance"]
                .as_array()
                .is_some_and(|records| records.len() == 1)
        );
    }

    #[test]
    fn mapping_inventory_limits_fail_closed_without_growing_records() {
        let mut inventory_entries = MAX_INVENTORY_ENTRIES - 1;
        record_inventory_entry(&mut inventory_entries).unwrap();
        assert_eq!(inventory_entries, MAX_INVENTORY_ENTRIES);
        assert!(record_inventory_entry(&mut inventory_entries).is_err());

        let mut records = Vec::new();
        for index in 0..MAX_MANIFESTS {
            push_inventory_record(
                &mut records,
                skipped_record(&format!("mapping-{index}{MANIFEST_SUFFIX}"), "test-skip"),
            )
            .unwrap();
        }
        assert!(
            push_inventory_record(
                &mut records,
                skipped_record(&format!("overflow{MANIFEST_SUFFIX}"), "test-skip"),
            )
            .is_err()
        );
        assert_eq!(records.len(), MAX_MANIFESTS);
    }

    #[test]
    fn shared_outputs_consume_the_total_byte_budget_once() {
        let root = tempfile::tempdir().unwrap();
        let source = b"fn shared_endpoint() {}\n";
        fs::write(root.path().join("shared.rs"), source).unwrap();
        fs::write(root.path().join("other.rs"), source).unwrap();
        let mut observations = BTreeMap::new();
        let mut total_bytes = MAX_TOTAL_OUTPUT_BYTES - source.len();

        let first = observe_output_once(
            root.path(),
            "shared.rs",
            &mut observations,
            &mut total_bytes,
        );
        let second = observe_output_once(
            root.path(),
            "shared.rs",
            &mut observations,
            &mut total_bytes,
        );
        let overflow =
            observe_output_once(root.path(), "other.rs", &mut observations, &mut total_bytes);

        assert_eq!(first.digest, second.digest);
        assert_eq!(total_bytes, MAX_TOTAL_OUTPUT_BYTES);
        assert_eq!(
            overflow.reason.as_deref(),
            Some("graphql-mapped-output-byte-limit-exceeded")
        );
    }
}
