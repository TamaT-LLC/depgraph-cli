use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_CONTRACT_VERSION,
    CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, Condition, CrossLanguageAdapterDelta,
    CrossLanguageCapabilityStatus, CrossLanguageCompletenessLedger, CrossLanguageFormat,
    CrossLanguageMappingKind, CrossLanguageProfileIdentity, CrossLanguageRelationKind,
    DependencySite, Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Properties,
    ResolutionStatus, build_cross_language_edge_id, build_cross_language_site_id, canonical_json,
    stable_id_from_value, validate_cross_language_adapter_delta,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    BuildExecutionOutcome,
    build::BuildOutcomeKind,
    ffi::{FFI_CAPABILITY, FFI_FORMAT_VERSION},
};

pub const FFI_LINK_OBSERVATION_SCHEMA_VERSION: &str = "ffi-link-observation-v1";
pub const FFI_LINK_OBSERVATION_SCHEMA_PATH: &str =
    "schemas/depgraph-ffi-link-observation-v1.schema.json";
pub const FFI_LINK_OBSERVATION_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-ffi-link-observation-v1.schema.json"
));
pub const FFI_LINK_OBSERVER: &str = "depgraph-supervised-ffi-link-observer";
pub const FFI_LINK_OBSERVER_VERSION: &str = "1.0.0";
pub const FFI_LINK_CAPABILITY: &str = "ffi-supervised-link-export-v1";
pub const MAX_FFI_LINK_ENTRIES: usize = 100_000;

const MAX_TEXT: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FfiLinkObservation {
    pub schema_version: String,
    pub observer: String,
    pub observer_version: String,
    pub capability: String,
    pub build_run_id: String,
    pub profile_id: String,
    pub target_triple: String,
    pub architecture: String,
    pub link_mode: String,
    pub source_root_digest: String,
    pub toolchain_digest: String,
    pub link_input_digest: String,
    pub entries: Vec<FfiObservedLink>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FfiObservedLink {
    pub declaration_site_id: String,
    pub abi: String,
    pub direction: String,
    pub library: String,
    pub symbol: String,
    pub library_artifact_digest: String,
}

/// Converts already-sanitized linker/export records from a completed,
/// explicitly consented supervisor outcome into the closed observation DTO.
///
/// This function never runs a command or opens a native artifact. The
/// supervisor-specific collector is responsible for producing the records
/// while the build is staged; this boundary binds them to its immutable audit.
pub fn collect_supervised_ffi_link_observation(
    outcome: &BuildExecutionOutcome,
    architecture: &str,
    link_mode: &str,
    mut entries: Vec<FfiObservedLink>,
) -> Result<FfiLinkObservation> {
    let audit = &outcome.audit;
    if !outcome.project_code_executed
        || audit.outcome != BuildOutcomeKind::Completed
        || audit.exit_code != Some(0)
        || audit.stdout_truncated
        || audit.stderr_truncated
    {
        bail!("FFI link observation requires one complete consented supervisor build");
    }
    let link_input_digest = audit
        .validated_output_digest
        .as_deref()
        .context("FFI link observation requires validated supervisor output")?;
    let target_triple = audit
        .target
        .as_deref()
        .context("FFI link observation requires an explicit target triple")?;
    entries.sort();
    let observation = FfiLinkObservation {
        schema_version: FFI_LINK_OBSERVATION_SCHEMA_VERSION.to_owned(),
        observer: FFI_LINK_OBSERVER.to_owned(),
        observer_version: FFI_LINK_OBSERVER_VERSION.to_owned(),
        capability: FFI_LINK_CAPABILITY.to_owned(),
        build_run_id: audit.run_id.clone(),
        profile_id: audit.profile_id.clone(),
        target_triple: target_triple.to_owned(),
        architecture: architecture.to_owned(),
        link_mode: link_mode.to_owned(),
        source_root_digest: prefixed_digest(&audit.source_root_digest)?,
        toolchain_digest: prefixed_digest(&audit.toolchain_executable_digest)?,
        link_input_digest: prefixed_digest(link_input_digest)?,
        entries,
    };
    validate_ffi_link_observation(&observation)?;
    Ok(observation)
}

pub fn validate_ffi_link_observation(observation: &FfiLinkObservation) -> Result<String> {
    if observation.schema_version != FFI_LINK_OBSERVATION_SCHEMA_VERSION
        || observation.observer != FFI_LINK_OBSERVER
        || observation.observer_version != FFI_LINK_OBSERVER_VERSION
        || observation.capability != FFI_LINK_CAPABILITY
        || !bounded_atom(&observation.build_run_id)
        || !bounded_atom(&observation.profile_id)
        || !bounded_atom(&observation.target_triple)
        || !bounded_atom(&observation.architecture)
        || !matches!(
            observation.link_mode.as_str(),
            "dynamic" | "framework" | "static"
        )
        || !prefixed_sha256(&observation.source_root_digest)
        || !prefixed_sha256(&observation.toolchain_digest)
        || !prefixed_sha256(&observation.link_input_digest)
        || observation.entries.is_empty()
        || observation.entries.len() > MAX_FFI_LINK_ENTRIES
        || observation
            .entries
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        bail!("FFI link observation violates its bounded identity contract");
    }
    let mut declaration_site_ids = BTreeSet::new();
    for entry in &observation.entries {
        if !bounded_atom(&entry.declaration_site_id)
            || !bounded_atom(&entry.abi)
            || !matches!(entry.direction.as_str(), "export" | "import")
            || !safe_symbol(&entry.library)
            || !safe_symbol(&entry.symbol)
            || !prefixed_sha256(&entry.library_artifact_digest)
        {
            bail!("FFI link observation contains an invalid entry");
        }
        if !declaration_site_ids.insert(&entry.declaration_site_id) {
            bail!("FFI link observation contains a duplicate declaration");
        }
    }
    Ok(digest_value(observation))
}

/// Atomically correlates one complete same-profile link observation to a
/// static FFI inventory delta. Any missing, duplicate, profile-mismatched, or
/// tampered item rejects the whole result before a caller can stage it.
pub fn correlate_ffi_link_observation(
    static_delta: &CrossLanguageAdapterDelta,
    observation: &FfiLinkObservation,
) -> Result<CrossLanguageAdapterDelta> {
    validate_cross_language_adapter_delta(static_delta).map_err(anyhow::Error::from)?;
    let observation_digest = validate_ffi_link_observation(observation)?;
    let profile_identity: CrossLanguageProfileIdentity = serde_json::from_value(
        static_delta
            .profile
            .properties
            .get(CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY)
            .cloned()
            .context("FFI delta has no cross-language profile identity")?,
    )?;
    if !profile_identity
        .adapter_capability_versions
        .iter()
        .any(|capability| capability == FFI_CAPABILITY)
        || !profile_identity
            .participating_profile_ids
            .iter()
            .any(|profile_id| profile_id == &observation.profile_id)
    {
        bail!("FFI link observation does not match the static profile identity");
    }

    let mut eligible = static_delta
        .sites
        .iter()
        .filter_map(|site| StaticFfiSite::parse(site, &observation.profile_id).transpose())
        .collect::<Result<Vec<_>>>()?;
    if eligible.is_empty() {
        bail!("FFI link observation has no eligible static declaration");
    }
    eligible.sort_by(|left, right| left.site.id.as_bytes().cmp(right.site.id.as_bytes()));
    let eligible_ids = eligible
        .iter()
        .map(|site| site.site.id.clone())
        .collect::<Vec<_>>();
    let observed_ids = observation
        .entries
        .iter()
        .map(|entry| entry.declaration_site_id.clone())
        .collect::<Vec<_>>();
    if eligible_ids != observed_ids {
        bail!("FFI link observation is partial or references an unknown declaration");
    }

    let entries = observation
        .entries
        .iter()
        .map(|entry| (entry.declaration_site_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut result = static_delta.clone();
    let mut nodes = result
        .nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let mut sites = result
        .sites
        .iter()
        .cloned()
        .map(|site| (site.id.clone(), site))
        .collect::<BTreeMap<_, _>>();
    let mut edges = result
        .edges
        .iter()
        .cloned()
        .map(|edge| (edge.id.clone(), edge))
        .collect::<BTreeMap<_, _>>();

    for (ordinal, static_site) in eligible.iter().enumerate() {
        let entry = entries
            .get(static_site.site.id.as_str())
            .context("eligible FFI declaration disappeared from the validated observation")?;
        static_site.validate_entry(entry)?;
        let native_symbol = static_site
            .site
            .target_ids
            .first()
            .context("static FFI declaration has no native symbol candidate")?;
        let library = observed_library_node(observation, entry);
        let library_id = library.id.clone();
        insert_same(
            &mut nodes,
            library_id.clone(),
            library,
            "observed native library node",
        )?;
        let observed_binding = observed_relation(ObservedRelationInput {
            observation,
            observation_digest: &observation_digest,
            graph_profile_id: &static_delta.profile.id,
            declaration_site_id: &static_site.site.id,
            entry,
            ordinal: ordinal as u64,
            source: &static_site.site.source,
            target: native_symbol,
            relation: CrossLanguageRelationKind::BindsNativeSymbol,
            condition: observed_condition(&static_site.site.condition, observation, entry),
        })?;
        insert_same(
            &mut sites,
            observed_binding.0.id.clone(),
            observed_binding.0,
            "observed FFI binding site",
        )?;
        insert_same(
            &mut edges,
            observed_binding.1.id.clone(),
            observed_binding.1,
            "observed FFI binding edge",
        )?;
        let provider = observed_relation(ObservedRelationInput {
            observation,
            observation_digest: &observation_digest,
            graph_profile_id: &static_delta.profile.id,
            declaration_site_id: &static_site.site.id,
            entry,
            ordinal: ordinal as u64,
            source: native_symbol,
            target: &library_id,
            relation: CrossLanguageRelationKind::ProvidedByLibrary,
            condition: observed_condition(&static_site.site.condition, observation, entry),
        })?;
        insert_same(
            &mut sites,
            provider.0.id.clone(),
            provider.0,
            "observed FFI provider site",
        )?;
        insert_same(
            &mut edges,
            provider.1.id.clone(),
            provider.1,
            "observed FFI provider edge",
        )?;
    }
    result.nodes = nodes.into_values().collect();
    result.sites = sites.into_values().collect();
    result.edges = edges.into_values().collect();
    refresh_ffi_ledger(&mut result)?;
    validate_cross_language_adapter_delta(&result).map_err(anyhow::Error::from)?;
    Ok(result)
}

struct StaticFfiSite<'a> {
    site: &'a DependencySite,
    abi: &'a str,
    direction: &'a str,
    library: Option<&'a str>,
    symbol: &'a str,
}

impl<'a> StaticFfiSite<'a> {
    fn parse(site: &'a DependencySite, profile_id: &str) -> Result<Option<Self>> {
        if site.kind != CrossLanguageRelationKind::BindsNativeSymbol.as_str()
            || !matches!(
                site.resolution_status,
                ResolutionStatus::Candidates | ResolutionStatus::Resolved
            )
            || site.precision == Precision::Observed
        {
            return Ok(None);
        }
        let Some(evidence) = site.evidence.first() else {
            return Ok(None);
        };
        if evidence.properties.get("format").and_then(Value::as_str) != Some("ffi")
            || evidence
                .properties
                .get("target_profile_id")
                .and_then(Value::as_str)
                != Some(profile_id)
        {
            return Ok(None);
        }
        let mapping: CrossLanguageMappingKind = serde_json::from_value(
            evidence
                .properties
                .get("mapping_kind")
                .cloned()
                .context("static FFI declaration has no mapping kind")?,
        )?;
        if !matches!(
            mapping,
            CrossLanguageMappingKind::ClosedCandidates
                | CrossLanguageMappingKind::ManualDeclaration
        ) {
            return Ok(None);
        }
        let abi = property_string(evidence, "ffi_abi")?;
        let direction = property_string(evidence, "ffi_direction")?;
        let library = optional_property_string(evidence, "library_request")?;
        let symbol = optional_property_string(evidence, "symbol_request")?
            .context("eligible static FFI declaration has no symbol request")?;
        Ok(Some(Self {
            site,
            abi,
            direction,
            library,
            symbol,
        }))
    }

    fn validate_entry(&self, entry: &FfiObservedLink) -> Result<()> {
        if entry.abi != self.abi
            || entry.direction != self.direction
            || entry.symbol != self.symbol
            || self.library.is_some_and(|library| entry.library != library)
        {
            bail!("FFI link observation does not match its declared ABI/library/symbol");
        }
        Ok(())
    }
}

struct ObservedRelationInput<'a> {
    observation: &'a FfiLinkObservation,
    observation_digest: &'a str,
    graph_profile_id: &'a str,
    declaration_site_id: &'a str,
    entry: &'a FfiObservedLink,
    ordinal: u64,
    source: &'a str,
    target: &'a str,
    relation: CrossLanguageRelationKind,
    condition: Condition,
}

fn observed_relation(input: ObservedRelationInput<'_>) -> Result<(DependencySite, GraphEdge)> {
    let artifact_identity = stable_id_from_value(
        "ffi-link-observation",
        &json!({
            "build_run_id": input.observation.build_run_id,
            "declaration_site_id": input.entry.declaration_site_id,
            "library_artifact_digest": input.entry.library_artifact_digest,
            "observation_digest": input.observation_digest,
            "relation": input.relation,
        }),
    );
    let evidence = vec![Evidence {
        kind: EvidenceKind::Build,
        extractor: FFI_LINK_OBSERVER.to_owned(),
        extractor_version: FFI_LINK_OBSERVER_VERSION.to_owned(),
        path: None,
        start_line: None,
        start_column: None,
        end_line: None,
        end_column: None,
        detail: None,
        properties: Properties::from([
            (
                "contract_version".to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            ("format".to_owned(), Value::String("ffi".to_owned())),
            (
                "profile_id".to_owned(),
                Value::String(input.graph_profile_id.to_owned()),
            ),
            (
                "format_version".to_owned(),
                Value::String(FFI_FORMAT_VERSION.to_owned()),
            ),
            (
                "contract_digest".to_owned(),
                Value::String(input.observation.link_input_digest.clone()),
            ),
            (
                "occurrence_kind".to_owned(),
                serde_json::to_value(input.relation)?,
            ),
            (
                "mapping_kind".to_owned(),
                serde_json::to_value(CrossLanguageMappingKind::BuildObservation)?,
            ),
            (
                "artifact_identity".to_owned(),
                Value::String(artifact_identity),
            ),
            ("ordinal".to_owned(), Value::from(input.ordinal)),
            (
                "build_run_id".to_owned(),
                Value::String(input.observation.build_run_id.clone()),
            ),
            (
                "declaration_site_id".to_owned(),
                Value::String(input.declaration_site_id.to_owned()),
            ),
            (
                "target_profile_id".to_owned(),
                Value::String(input.observation.profile_id.clone()),
            ),
            (
                "target_triple".to_owned(),
                Value::String(input.observation.target_triple.clone()),
            ),
            (
                "architecture".to_owned(),
                Value::String(input.observation.architecture.clone()),
            ),
            (
                "link_mode".to_owned(),
                Value::String(input.observation.link_mode.clone()),
            ),
            ("ffi_abi".to_owned(), Value::String(input.entry.abi.clone())),
            (
                "library".to_owned(),
                Value::String(input.entry.library.clone()),
            ),
            (
                "symbol".to_owned(),
                Value::String(input.entry.symbol.clone()),
            ),
            (
                "library_artifact_digest".to_owned(),
                Value::String(input.entry.library_artifact_digest.clone()),
            ),
            (
                "toolchain_digest".to_owned(),
                Value::String(input.observation.toolchain_digest.clone()),
            ),
            (
                "link_input_digest".to_owned(),
                Value::String(input.observation.link_input_digest.clone()),
            ),
            (
                "observation_digest".to_owned(),
                Value::String(input.observation_digest.to_owned()),
            ),
        ]),
    }];
    let mut site = DependencySite {
        id: String::new(),
        source: input.source.to_owned(),
        kind: input.relation.as_str().to_owned(),
        specifier: format!(
            "{}:{}:{}",
            input.entry.abi, input.entry.library, input.entry.symbol
        ),
        resolution_status: ResolutionStatus::Resolved,
        target_ids: vec![input.target.to_owned()],
        profile_id: input.graph_profile_id.to_owned(),
        condition: input.condition.clone(),
        precision: Precision::Observed,
        reason: None,
        evidence: evidence.clone(),
    };
    site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
    let mut edge = GraphEdge {
        id: String::new(),
        source: input.source.to_owned(),
        target: input.target.to_owned(),
        kind: input.relation.as_str().to_owned(),
        site_id: Some(site.id.clone()),
        phase: Phase::Build,
        environment: None,
        profile_id: input.graph_profile_id.to_owned(),
        condition: input.condition,
        resolution_status: ResolutionStatus::Resolved,
        precision: Precision::Observed,
        generated: false,
        evidence,
    };
    edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
    Ok((site, edge))
}

fn observed_library_node(observation: &FfiLinkObservation, entry: &FfiObservedLink) -> GraphNode {
    let id = stable_id_from_value(
        "native_library",
        &json!({
            "ffi_link_observation_version": FFI_LINK_OBSERVATION_SCHEMA_VERSION,
            "profile_id": observation.profile_id,
            "target_triple": observation.target_triple,
            "architecture": observation.architecture,
            "link_mode": observation.link_mode,
            "library": entry.library,
            "artifact_digest": entry.library_artifact_digest,
        }),
    );
    GraphNode {
        id: id.clone(),
        kind: "native_library".to_owned(),
        locator: format!("native-library:{id}"),
        display_name: None,
        properties: BTreeMap::from([
            (
                "profile_id".to_owned(),
                Value::String(observation.profile_id.clone()),
            ),
            (
                "target_triple".to_owned(),
                Value::String(observation.target_triple.clone()),
            ),
            (
                "architecture".to_owned(),
                Value::String(observation.architecture.clone()),
            ),
            (
                "link_mode".to_owned(),
                Value::String(observation.link_mode.clone()),
            ),
            ("library".to_owned(), Value::String(entry.library.clone())),
            (
                "artifact_digest".to_owned(),
                Value::String(entry.library_artifact_digest.clone()),
            ),
        ]),
    }
}

fn observed_condition(
    static_condition: &Condition,
    observation: &FfiLinkObservation,
    entry: &FfiObservedLink,
) -> Condition {
    Condition::All {
        conditions: vec![
            static_condition.clone(),
            Condition::Eq {
                key: "ffi.architecture".to_owned(),
                value: Value::String(observation.architecture.clone()),
            },
            Condition::Eq {
                key: "ffi.build_run_id".to_owned(),
                value: Value::String(observation.build_run_id.clone()),
            },
            Condition::Eq {
                key: "ffi.link_mode".to_owned(),
                value: Value::String(observation.link_mode.clone()),
            },
            Condition::Eq {
                key: "ffi.library".to_owned(),
                value: Value::String(entry.library.clone()),
            },
            Condition::Eq {
                key: "ffi.symbol".to_owned(),
                value: Value::String(entry.symbol.clone()),
            },
            Condition::Eq {
                key: "ffi.target_triple".to_owned(),
                value: Value::String(observation.target_triple.clone()),
            },
        ],
    }
    .canonicalize()
}

fn refresh_ffi_ledger(delta: &mut CrossLanguageAdapterDelta) -> Result<()> {
    let mut ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
        delta
            .profile
            .properties
            .get(CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
            .cloned()
            .context("FFI delta has no completeness ledger")?,
    )?;
    let entry = ledger
        .entries
        .iter_mut()
        .find(|entry| entry.format == CrossLanguageFormat::Ffi)
        .context("FFI delta has no FFI completeness entry")?;
    let cross_nodes = delta
        .nodes
        .iter()
        .filter(|node| {
            node.properties
                .get("canonical_identity")
                .and_then(Value::as_object)
                .and_then(|identity| identity.get("format"))
                .and_then(Value::as_str)
                == Some("ffi")
        })
        .count() as u64;
    let ffi_sites = delta
        .sites
        .iter()
        .filter(|site| {
            site.evidence
                .first()
                .and_then(|evidence| evidence.properties.get("format"))
                .and_then(Value::as_str)
                == Some("ffi")
        })
        .collect::<Vec<_>>();
    entry.node_count = cross_nodes;
    entry.site_count = ffi_sites.len() as u64;
    entry.edge_count = delta
        .edges
        .iter()
        .filter(|edge| {
            edge.evidence
                .first()
                .and_then(|evidence| evidence.properties.get("format"))
                .and_then(Value::as_str)
                == Some("ffi")
        })
        .count() as u64;
    entry.external_count = ffi_sites
        .iter()
        .filter(|site| site.resolution_status == ResolutionStatus::External)
        .count() as u64;
    entry.unresolved_count = ffi_sites
        .iter()
        .filter(|site| site.resolution_status == ResolutionStatus::Unresolved)
        .count() as u64;
    let static_site_ids = ffi_sites
        .iter()
        .filter(|site| {
            matches!(
                site.resolution_status,
                ResolutionStatus::Candidates | ResolutionStatus::Resolved
            ) && site.precision != Precision::Observed
        })
        .map(|site| site.id.as_str())
        .collect::<BTreeSet<_>>();
    let observed_site_ids = ffi_sites
        .iter()
        .filter(|site| site.precision == Precision::Observed)
        .filter_map(|site| {
            site.evidence
                .first()
                .and_then(|evidence| evidence.properties.get("declaration_site_id"))
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    if static_site_ids.is_subset(&observed_site_ids) {
        entry
            .reasons
            .retain(|reason| reason != "ffi-link-evidence-pending");
    }
    entry.status =
        if entry.unresolved_count > 0 || entry.skipped_count > 0 || !entry.reasons.is_empty() {
            CrossLanguageCapabilityStatus::Incomplete
        } else {
            CrossLanguageCapabilityStatus::Complete
        };
    delta.profile.properties.insert(
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY.to_owned(),
        serde_json::to_value(ledger)?,
    );
    Ok(())
}

fn property_string<'a>(evidence: &'a Evidence, key: &str) -> Result<&'a str> {
    evidence
        .properties
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("static FFI declaration has no {key}"))
}

fn optional_property_string<'a>(evidence: &'a Evidence, key: &str) -> Result<Option<&'a str>> {
    match evidence.properties.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => bail!("static FFI declaration {key} has an invalid value"),
    }
}

fn insert_same<T: PartialEq>(
    values: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> Result<()> {
    if let Some(existing) = values.get(&key)
        && existing != &value
    {
        bail!("{label} identity collides");
    }
    values.insert(key, value);
    Ok(())
}

fn prefixed_digest(value: &str) -> Result<String> {
    if prefixed_sha256(value) {
        return Ok(value.to_owned());
    }
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(format!("sha256:{value}"));
    }
    bail!("FFI link observation digest is invalid");
}

fn prefixed_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'+' | b'-')
        })
}

fn safe_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.$@-".contains(character))
}

fn digest_value(value: &impl Serialize) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(
            canonical_json(&serde_json::to_value(value).expect("serializable")).as_bytes()
        )
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, time::Duration};

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCompletenessLedger, Profile,
        validate_cross_language_adapter_delta,
    };
    use tempfile::tempdir;

    use crate::{BuildAudit, BuildExecutionOutcome, NetworkIsolation, ffi::scan_ffi_repository};

    use super::*;

    fn profile(id: &str) -> Profile {
        Profile {
            id: id.to_owned(),
            language: "polyglot".to_owned(),
            toolchain: None,
            command: None,
            target: None,
            features: Vec::new(),
            environment: BTreeMap::new(),
            source_revision: None,
            properties: BTreeMap::new(),
        }
    }

    #[test]
    fn linux_macos_and_windows_observations_require_same_profile_and_become_observed() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("native.rs"),
            "#[link(name = \"crypto\")]\nextern \"C\" {\nfn digest();\n}\n",
        )
        .unwrap();
        let platforms = [
            ("linux-x86_64", "x86_64-unknown-linux-gnu", "x86_64"),
            ("macos-aarch64", "aarch64-apple-darwin", "aarch64"),
            ("windows-x86_64", "x86_64-pc-windows-msvc", "x86_64"),
        ];
        let profiles = platforms
            .iter()
            .map(|(profile_id, _, _)| profile(profile_id))
            .collect::<Vec<_>>();
        let mut delta = scan_ffi_repository(root.path(), &profiles)
            .unwrap()
            .unwrap();

        for (ordinal, (profile_id, target, architecture)) in platforms.iter().enumerate() {
            let static_site = static_site_for_profile(&delta, profile_id);
            let outcome = completed_outcome(profile_id, target, true);
            let observation = collect_supervised_ffi_link_observation(
                &outcome,
                architecture,
                if profile_id.starts_with("windows") {
                    "static"
                } else {
                    "dynamic"
                },
                vec![entry_for(
                    static_site,
                    "c",
                    "import",
                    "crypto",
                    "digest",
                    (b'a' + ordinal as u8) as char,
                )],
            )
            .unwrap();
            delta = correlate_ffi_link_observation(&delta, &observation).unwrap();
        }

        validate_cross_language_adapter_delta(&delta).unwrap();
        assert_eq!(
            delta
                .edges
                .iter()
                .filter(|edge| {
                    edge.phase == Phase::Build
                        && edge.precision == Precision::Observed
                        && edge.resolution_status == ResolutionStatus::Resolved
                })
                .count(),
            6
        );
        assert_eq!(
            delta
                .nodes
                .iter()
                .filter(|node| node.kind == "native_library")
                .count(),
            3
        );
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        assert_eq!(
            ledger.entries[0].status,
            CrossLanguageCapabilityStatus::Complete
        );
        assert!(
            !ledger.entries[0]
                .reasons
                .contains(&"ffi-link-evidence-pending".to_owned())
        );
    }

    #[test]
    fn partial_mismatch_and_tamper_reject_the_whole_delta() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("native.rs"),
            "#[link(name = \"crypto\")]\nextern \"C\" {\nfn one();\nfn two();\n}\n",
        )
        .unwrap();
        let delta = scan_ffi_repository(root.path(), &[profile("linux")])
            .unwrap()
            .unwrap();
        let sites = static_sites_for_profile(&delta, "linux");
        let partial = observation(
            "linux",
            vec![entry_for(
                sites[0],
                "c",
                "import",
                "crypto",
                site_symbol(sites[0]),
                'a',
            )],
        );
        assert!(correlate_ffi_link_observation(&delta, &partial).is_err());

        let mut mismatch_entries = sites
            .iter()
            .enumerate()
            .map(|(index, site)| {
                entry_for(
                    site,
                    "c",
                    "import",
                    "crypto",
                    site_symbol(site),
                    (b'a' + index as u8) as char,
                )
            })
            .collect::<Vec<_>>();
        mismatch_entries.sort();
        mismatch_entries[0].abi = "system".to_owned();
        let mismatch = observation("linux", mismatch_entries);
        assert!(correlate_ffi_link_observation(&delta, &mismatch).is_err());

        let mut tampered = observation(
            "linux",
            sites
                .iter()
                .enumerate()
                .map(|(index, site)| {
                    entry_for(
                        site,
                        "c",
                        "import",
                        "crypto",
                        site_symbol(site),
                        (b'a' + index as u8) as char,
                    )
                })
                .collect(),
        );
        tampered.entries[0].library_artifact_digest = "sha256:tampered".to_owned();
        assert!(correlate_ffi_link_observation(&delta, &tampered).is_err());

        let complete = observation(
            "linux",
            sites
                .iter()
                .enumerate()
                .map(|(index, site)| {
                    entry_for(
                        site,
                        "c",
                        "import",
                        "crypto",
                        site_symbol(site),
                        (b'a' + index as u8) as char,
                    )
                })
                .collect(),
        );
        let expected = correlate_ffi_link_observation(&delta, &complete).unwrap();
        let mut reordered = delta.clone();
        reordered.sites.reverse();
        validate_cross_language_adapter_delta(&reordered).unwrap();
        assert_eq!(
            correlate_ffi_link_observation(&reordered, &complete).unwrap(),
            expected
        );
        assert_eq!(
            delta
                .edges
                .iter()
                .filter(|edge| edge.phase == Phase::Build)
                .count(),
            0
        );
    }

    #[test]
    fn consent_failure_and_secret_shaped_records_never_form_an_observation() {
        let entry = FfiObservedLink {
            declaration_site_id: "site".to_owned(),
            abi: "c".to_owned(),
            direction: "import".to_owned(),
            library: "crypto".to_owned(),
            symbol: "digest".to_owned(),
            library_artifact_digest: digest('a'),
        };
        let denied = completed_outcome("linux", "x86_64-unknown-linux-gnu", false);
        assert!(
            collect_supervised_ffi_link_observation(
                &denied,
                "x86_64",
                "dynamic",
                vec![entry.clone()]
            )
            .is_err()
        );
        let allowed = completed_outcome("linux", "x86_64-unknown-linux-gnu", true);
        let valid = collect_supervised_ffi_link_observation(
            &allowed,
            "x86_64",
            "dynamic",
            vec![entry.clone()],
        )
        .unwrap();
        let schema: Value = serde_json::from_str(FFI_LINK_OBSERVATION_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&serde_json::to_value(&valid).unwrap()));
        let mut secret = entry;
        secret.library = "crypto?token=hidden".to_owned();
        let error =
            collect_supervised_ffi_link_observation(&allowed, "x86_64", "dynamic", vec![secret])
                .unwrap_err()
                .to_string();
        assert!(!error.contains("hidden"));
        let error = collect_supervised_ffi_link_observation(
            &allowed,
            "x86_64?token=hidden",
            "dynamic",
            vec![FfiObservedLink {
                declaration_site_id: "site".to_owned(),
                abi: "c".to_owned(),
                direction: "import".to_owned(),
                library: "crypto".to_owned(),
                symbol: "digest".to_owned(),
                library_artifact_digest: digest('a'),
            }],
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("hidden"));
        let mut unknown = serde_json::to_value(valid).unwrap();
        unknown["raw_linker_output"] = Value::String("forbidden".to_owned());
        assert!(!validator.is_valid(&unknown));
    }

    #[test]
    fn reimport_is_byte_identical_and_checkout_independent() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        for root in [first.path(), second.path()] {
            fs::write(
                root.join("native.rs"),
                "#[link(name = \"z\")]\nextern \"C\" {\nfn zed();\n}\n",
            )
            .unwrap();
        }
        let first = scan_ffi_repository(first.path(), &[profile("linux")])
            .unwrap()
            .unwrap();
        let second = scan_ffi_repository(second.path(), &[profile("linux")])
            .unwrap()
            .unwrap();
        let observation = observation(
            "linux",
            vec![entry_for(
                static_site_for_profile(&first, "linux"),
                "c",
                "import",
                "z",
                "zed",
                'a',
            )],
        );
        let once = correlate_ffi_link_observation(&first, &observation).unwrap();
        let twice = correlate_ffi_link_observation(&once, &observation).unwrap();
        let other = correlate_ffi_link_observation(&second, &observation).unwrap();
        assert_eq!(
            canonical_json(&serde_json::to_value(&once).unwrap()),
            canonical_json(&serde_json::to_value(&twice).unwrap())
        );
        assert_eq!(
            canonical_json(&serde_json::to_value(&twice).unwrap()),
            canonical_json(&serde_json::to_value(&other).unwrap())
        );
    }

    fn completed_outcome(
        profile_id: &str,
        target: &str,
        project_code_executed: bool,
    ) -> BuildExecutionOutcome {
        BuildExecutionOutcome {
            audit: BuildAudit {
                schema_version: "build-audit-v1".to_owned(),
                run_id: "run-1".to_owned(),
                adapter: FFI_LINK_OBSERVER.to_owned(),
                adapter_version: FFI_LINK_OBSERVER_VERSION.to_owned(),
                profile_id: profile_id.to_owned(),
                command_program: "tool".to_owned(),
                command_arguments: Vec::new(),
                command_plan_digest: "plan".to_owned(),
                logical_cwd: ".".to_owned(),
                source_root_digest: "a".repeat(64),
                toolchain_executable_digest: "b".repeat(64),
                toolchain_version: Some("1".to_owned()),
                target: Some(target.to_owned()),
                environment_keys: Vec::new(),
                environment_key_set_digest: "environment".to_owned(),
                redacted_secret_key_count: 0,
                timeout_seconds: Duration::from_secs(60).as_secs(),
                stdout_limit_bytes: 1024,
                stderr_limit_bytes: 1024,
                network_policy: "deny".to_owned(),
                network_isolation: NetworkIsolation::Enforced,
                isolation_diagnostic: None,
                started_at: "2026-01-01T00:00:00Z".to_owned(),
                finished_at: "2026-01-01T00:00:01Z".to_owned(),
                duration_millis: 1,
                outcome: BuildOutcomeKind::Completed,
                exit_code: Some(0),
                stdout_truncated: false,
                stderr_truncated: false,
                validated_output_digest: Some("c".repeat(64)),
                diagnostic_code: None,
            },
            project_code_executed,
            rust_observation: None,
            web_observation: None,
        }
    }

    fn observation(profile_id: &str, mut entries: Vec<FfiObservedLink>) -> FfiLinkObservation {
        entries.sort();
        FfiLinkObservation {
            schema_version: FFI_LINK_OBSERVATION_SCHEMA_VERSION.to_owned(),
            observer: FFI_LINK_OBSERVER.to_owned(),
            observer_version: FFI_LINK_OBSERVER_VERSION.to_owned(),
            capability: FFI_LINK_CAPABILITY.to_owned(),
            build_run_id: "run-1".to_owned(),
            profile_id: profile_id.to_owned(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            architecture: "x86_64".to_owned(),
            link_mode: "dynamic".to_owned(),
            source_root_digest: digest('a'),
            toolchain_digest: digest('b'),
            link_input_digest: digest('c'),
            entries,
        }
    }

    fn entry_for(
        site: &DependencySite,
        abi: &str,
        direction: &str,
        library: &str,
        symbol: &str,
        artifact: char,
    ) -> FfiObservedLink {
        FfiObservedLink {
            declaration_site_id: site.id.clone(),
            abi: abi.to_owned(),
            direction: direction.to_owned(),
            library: library.to_owned(),
            symbol: symbol.to_owned(),
            library_artifact_digest: digest(artifact),
        }
    }

    fn static_site_for_profile<'a>(
        delta: &'a CrossLanguageAdapterDelta,
        profile_id: &str,
    ) -> &'a DependencySite {
        static_sites_for_profile(delta, profile_id)[0]
    }

    fn static_sites_for_profile<'a>(
        delta: &'a CrossLanguageAdapterDelta,
        profile_id: &str,
    ) -> Vec<&'a DependencySite> {
        delta
            .sites
            .iter()
            .filter(|site| {
                site.evidence[0]
                    .properties
                    .get("target_profile_id")
                    .and_then(Value::as_str)
                    == Some(profile_id)
                    && site.precision != Precision::Observed
            })
            .collect()
    }

    fn site_symbol(site: &DependencySite) -> &str {
        site.evidence[0]
            .properties
            .get("symbol_request")
            .and_then(Value::as_str)
            .unwrap()
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }
}
