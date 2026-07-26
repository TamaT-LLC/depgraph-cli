use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    DependencySite, Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile,
    ProtocolError, ResolutionStatus, ValidatedProtocol, canonical_json, stable_id_from_value,
};

pub const CROSS_LANGUAGE_CONTRACT_VERSION: &str = "cross-language-contract-v1";
pub const CROSS_LANGUAGE_COMPLETENESS_VERSION: &str = "cross-language-completeness-v1";
pub const CROSS_LANGUAGE_SCHEMA_PATH: &str = "schemas/depgraph-cross-language-v1.schema.json";
pub const CROSS_LANGUAGE_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-cross-language-v1.schema.json"
));
pub const CROSS_LANGUAGE_CONTRACT_PROPERTY: &str = "cross_language_contract_version";
pub const CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY: &str = "cross_language_profile_identity";
pub const CROSS_LANGUAGE_COMPLETENESS_PROPERTY: &str = "cross_language_completeness";

const MAX_IDENTITY_CHARS: usize = 4_096;
const MAX_REASON_CHARS: usize = 256;
const MAX_LEDGER_ENTRIES: usize = 4;
const MAX_REASONS_PER_ENTRY: usize = 64;
const MAX_ARTIFACT_ORDINAL: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageFormat {
    Ffi,
    Graphql,
    Openapi,
    Protobuf,
}

impl CrossLanguageFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ffi => "ffi",
            Self::Graphql => "graphql",
            Self::Openapi => "openapi",
            Self::Protobuf => "protobuf",
        }
    }

    pub const fn capability(self) -> &'static str {
        match self {
            Self::Ffi => "ffi-contract-v1",
            Self::Graphql => "graphql-contract-v1",
            Self::Openapi => "openapi-contract-v1",
            Self::Protobuf => "protobuf-contract-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageNodeKind {
    Service,
    Schema,
    Operation,
    Message,
    NativeSymbol,
}

impl CrossLanguageNodeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Schema => "schema",
            Self::Operation => "operation",
            Self::Message => "message",
            Self::NativeSymbol => "native_symbol",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "service" => Some(Self::Service),
            "schema" => Some(Self::Schema),
            "operation" => Some(Self::Operation),
            "message" => Some(Self::Message),
            "native_symbol" => Some(Self::NativeSymbol),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageRelationKind {
    ProvidesOperation,
    AcceptsMessage,
    ReturnsMessage,
    ReferencesSchema,
    CallsOperation,
    ImplementedBy,
    GeneratedFrom,
    BindsNativeSymbol,
    ProvidedByLibrary,
}

impl CrossLanguageRelationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProvidesOperation => "provides_operation",
            Self::AcceptsMessage => "accepts_message",
            Self::ReturnsMessage => "returns_message",
            Self::ReferencesSchema => "references_schema",
            Self::CallsOperation => "calls_operation",
            Self::ImplementedBy => "implemented_by",
            Self::GeneratedFrom => "generated_from",
            Self::BindsNativeSymbol => "binds_native_symbol",
            Self::ProvidedByLibrary => "provided_by_library",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "provides_operation" => Some(Self::ProvidesOperation),
            "accepts_message" => Some(Self::AcceptsMessage),
            "returns_message" => Some(Self::ReturnsMessage),
            "references_schema" => Some(Self::ReferencesSchema),
            "calls_operation" => Some(Self::CallsOperation),
            "implemented_by" => Some(Self::ImplementedBy),
            "generated_from" => Some(Self::GeneratedFrom),
            "binds_native_symbol" => Some(Self::BindsNativeSymbol),
            "provided_by_library" => Some(Self::ProvidedByLibrary),
            _ => None,
        }
    }

    fn is_contract_internal(self) -> bool {
        matches!(
            self,
            Self::ProvidesOperation
                | Self::AcceptsMessage
                | Self::ReturnsMessage
                | Self::ReferencesSchema
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageCapabilityStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageCanonicalIdentity {
    pub contract_version: String,
    pub format: CrossLanguageFormat,
    pub repository_contract_locator: String,
    pub format_version: String,
    pub coordinate: String,
    pub profile_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageProfileIdentity {
    pub contract_version: String,
    pub completeness_version: String,
    pub contract_input_digest: String,
    pub adapter_capability_versions: Vec<String>,
    pub participating_profile_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageFormatCoverage {
    pub format: CrossLanguageFormat,
    pub capability: String,
    pub status: CrossLanguageCapabilityStatus,
    pub input_count: u64,
    pub node_count: u64,
    pub site_count: u64,
    pub edge_count: u64,
    pub external_count: u64,
    pub unresolved_count: u64,
    pub skipped_count: u64,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageCompletenessLedger {
    pub schema_version: String,
    pub entries: Vec<CrossLanguageFormatCoverage>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossLanguageMappingKind {
    ContractInternal,
    Descriptor,
    GeneratorManifest,
    SourceMap,
    BuildObservation,
    RuntimeObservation,
    RepositoryMapping,
    ManualDeclaration,
    ClosedCandidates,
    ExternalReference,
    Unresolved,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CrossLanguageEvidenceProperties {
    pub contract_version: String,
    pub format: CrossLanguageFormat,
    pub profile_id: String,
    pub format_version: String,
    pub contract_digest: String,
    pub occurrence_kind: CrossLanguageRelationKind,
    pub mapping_kind: CrossLanguageMappingKind,
    #[serde(default)]
    pub artifact_identity: Option<String>,
    #[serde(default)]
    pub ordinal: Option<u64>,
}

/// One adapter's complete, atomically promotable cross-language graph closure.
///
/// Callers validate the whole envelope before staging any member. The envelope
/// intentionally contains the selected profile and every referenced node so
/// identity, proof, edge/site closure, and coverage conservation are checked as
/// one unit rather than record by record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageAdapterDelta {
    pub contract_version: String,
    pub profile: Profile,
    pub nodes: Vec<GraphNode>,
    pub sites: Vec<DependencySite>,
    pub edges: Vec<GraphEdge>,
}

#[must_use]
pub fn cross_language_node_id(
    kind: CrossLanguageNodeKind,
    identity: &CrossLanguageCanonicalIdentity,
) -> String {
    stable_id_from_value(
        kind.as_str(),
        &serde_json::to_value(identity).expect("cross-language identity is serializable"),
    )
}

#[must_use]
pub fn cross_language_profile_id(identity: &CrossLanguageProfileIdentity) -> String {
    stable_id_from_value(
        "profile",
        &serde_json::to_value(identity).expect("cross-language profile identity is serializable"),
    )
}

pub fn build_cross_language_site_id(site: &DependencySite) -> Result<String, ProtocolError> {
    let primary = cross_language_primary_evidence(site)?;
    let properties = parse_evidence_properties(primary)?;
    let anchor = evidence_anchor(primary, &properties)?;
    Ok(stable_id_from_value(
        "site",
        &json!({
            "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
            "kind": site.kind,
            "source": site.source,
            "profile_id": site.profile_id,
            "condition": site.condition.canonicalized(),
            "extractor": primary.extractor,
            "extractor_version": primary.extractor_version,
            "format": properties.format,
            "format_version": properties.format_version,
            "occurrence_kind": properties.occurrence_kind,
            "mapping_kind": properties.mapping_kind,
            "anchor": anchor,
        }),
    ))
}

pub fn build_cross_language_edge_id(edge: &GraphEdge) -> Result<String, ProtocolError> {
    let site_id = edge.site_id.as_deref().ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "cross-language edge {} must reference a dependency site",
            edge.id
        ))
    })?;
    Ok(stable_id_from_value(
        "edge",
        &json!({
            "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
            "site_id": site_id,
            "kind": edge.kind,
            "target": edge.target,
        }),
    ))
}

#[must_use]
pub fn has_cross_language_claim(protocol: &ValidatedProtocol) -> bool {
    protocol
        .profiles
        .values()
        .any(profile_claims_cross_language)
        || protocol.nodes.values().any(is_cross_language_node)
        || protocol
            .sites
            .values()
            .any(|site| site.evidence.iter().any(evidence_claims_cross_language))
        || protocol
            .edges
            .values()
            .any(|edge| edge.evidence.iter().any(evidence_claims_cross_language))
}

pub fn validate_cross_language_contract(protocol: &ValidatedProtocol) -> Result<(), ProtocolError> {
    validate_cross_language_maps(
        &protocol.profiles,
        &protocol.nodes,
        &protocol.edges,
        &protocol.sites,
    )
}

pub fn validate_cross_language_graph(
    profiles: &[Profile],
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    sites: &[DependencySite],
) -> Result<(), ProtocolError> {
    let profiles = unique_map(profiles, |profile| &profile.id, "profile")?;
    let nodes = unique_map(nodes, |node| &node.id, "node")?;
    let edges = unique_map(edges, |edge| &edge.id, "edge")?;
    let sites = unique_map(sites, |site| &site.id, "dependency site")?;
    validate_cross_language_maps(&profiles, &nodes, &edges, &sites)
}

/// Validates one complete adapter closure and returns its canonical digest.
///
/// Returning the digest only after the final-state validator succeeds gives
/// stores a single boundary for staging and atomic promotion.
pub fn validate_cross_language_adapter_delta(
    delta: &CrossLanguageAdapterDelta,
) -> Result<String, ProtocolError> {
    if delta.contract_version != CROSS_LANGUAGE_CONTRACT_VERSION {
        return invariant("cross-language adapter delta has an incompatible contract version");
    }
    cross_language_graph_digest(
        std::slice::from_ref(&delta.profile),
        &delta.nodes,
        &delta.edges,
        &delta.sites,
    )
}

pub fn cross_language_graph_digest(
    profiles: &[Profile],
    nodes: &[GraphNode],
    edges: &[GraphEdge],
    sites: &[DependencySite],
) -> Result<String, ProtocolError> {
    validate_cross_language_graph(profiles, nodes, edges, sites)?;
    let profiles = unique_map(profiles, |profile| &profile.id, "profile")?;
    let nodes = unique_map(nodes, |node| &node.id, "node")?;
    let edges = unique_map(edges, |edge| &edge.id, "edge")?;
    let sites = unique_map(sites, |site| &site.id, "dependency site")?;
    Ok(stable_id_from_value(
        "cross-language-graph",
        &json!({
            "contract_version": CROSS_LANGUAGE_CONTRACT_VERSION,
            "profiles": profiles.into_values().collect::<Vec<_>>(),
            "nodes": nodes.into_values().collect::<Vec<_>>(),
            "sites": sites.into_values().collect::<Vec<_>>(),
            "edges": edges.into_values().collect::<Vec<_>>(),
        }),
    ))
}

pub(crate) fn validate_cross_language_maps(
    profiles: &BTreeMap<String, Profile>,
    nodes: &BTreeMap<String, GraphNode>,
    edges: &BTreeMap<String, GraphEdge>,
    sites: &BTreeMap<String, DependencySite>,
) -> Result<(), ProtocolError> {
    let claimed_profiles = profiles
        .values()
        .filter(|profile| profile_claims_cross_language(profile))
        .map(|profile| {
            validate_cross_language_profile(profile)?;
            Ok((profile.id.clone(), profile))
        })
        .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
    let cross_nodes = nodes
        .values()
        .filter(|node| {
            is_cross_language_node(node)
                || node
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .is_some_and(|profile_id| claimed_profiles.contains_key(profile_id))
        })
        .map(|node| {
            let identity = validate_cross_language_node(node, &claimed_profiles)?;
            Ok((node.id.clone(), (node, identity)))
        })
        .collect::<Result<BTreeMap<_, _>, ProtocolError>>()?;
    let has_cross_evidence = sites
        .values()
        .any(|site| site.evidence.iter().any(evidence_claims_cross_language))
        || edges
            .values()
            .any(|edge| edge.evidence.iter().any(evidence_claims_cross_language));

    if claimed_profiles.is_empty() {
        if cross_nodes.is_empty() && !has_cross_evidence {
            return Ok(());
        }
        return invariant(
            "cross-language nodes or evidence require a claimed cross-language profile",
        );
    }

    let mut cross_sites = BTreeMap::new();
    for site in sites.values() {
        let touches_cross_node = cross_nodes.contains_key(&site.source)
            || site
                .target_ids
                .iter()
                .any(|target| cross_nodes.contains_key(target));
        let claims_cross_language = site.evidence.iter().any(evidence_claims_cross_language);
        if !claimed_profiles.contains_key(&site.profile_id)
            && !touches_cross_node
            && !claims_cross_language
        {
            continue;
        }
        if !claimed_profiles.contains_key(&site.profile_id) {
            return invariant(format!(
                "cross-language dependency site {} uses undeclared profile {}",
                site.id, site.profile_id
            ));
        }
        let relation = CrossLanguageRelationKind::parse(&site.kind).ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "cross-language dependency site {} uses unknown relation kind {}",
                site.id, site.kind
            ))
        })?;
        validate_cross_language_site(site, relation, nodes, &cross_nodes)?;
        cross_sites.insert(site.id.clone(), (site, relation));
    }

    let mut cross_edges = BTreeMap::new();
    for edge in edges.values() {
        let touches_cross_node =
            cross_nodes.contains_key(&edge.source) || cross_nodes.contains_key(&edge.target);
        let claims_cross_language = edge.evidence.iter().any(evidence_claims_cross_language);
        if !claimed_profiles.contains_key(&edge.profile_id)
            && !touches_cross_node
            && !claims_cross_language
        {
            continue;
        }
        if !claimed_profiles.contains_key(&edge.profile_id) {
            return invariant(format!(
                "cross-language edge {} uses undeclared profile {}",
                edge.id, edge.profile_id
            ));
        }
        let relation = CrossLanguageRelationKind::parse(&edge.kind).ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "cross-language edge {} uses unknown relation kind {}",
                edge.id, edge.kind
            ))
        })?;
        validate_cross_language_edge(edge, relation)?;
        cross_edges.insert(edge.id.clone(), (edge, relation));
    }

    validate_cross_language_site_edge_closure(&cross_sites, &cross_edges)?;
    validate_cross_language_ledgers(&claimed_profiles, &cross_nodes, &cross_sites, &cross_edges)
}

fn validate_cross_language_profile(profile: &Profile) -> Result<(), ProtocolError> {
    if profile.language != "cross-language" {
        return invariant(format!(
            "cross-language profile {} must use language=cross-language",
            profile.id
        ));
    }
    if profile
        .properties
        .get(CROSS_LANGUAGE_CONTRACT_PROPERTY)
        .and_then(Value::as_str)
        != Some(CROSS_LANGUAGE_CONTRACT_VERSION)
    {
        return invariant(format!(
            "cross-language profile {} has an incompatible contract version",
            profile.id
        ));
    }
    let identity: CrossLanguageProfileIdentity = parse_property(
        profile,
        CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY,
        "profile identity",
    )?;
    if identity.contract_version != CROSS_LANGUAGE_CONTRACT_VERSION
        || identity.completeness_version != CROSS_LANGUAGE_COMPLETENESS_VERSION
        || !is_prefixed_sha256(&identity.contract_input_digest)
    {
        return invariant(format!(
            "cross-language profile {} has an incompatible profile identity",
            profile.id
        ));
    }
    validate_sorted_unique(
        "cross-language adapter capability versions",
        &identity.adapter_capability_versions,
        false,
    )?;
    validate_sorted_unique(
        "cross-language participating profile IDs",
        &identity.participating_profile_ids,
        false,
    )?;
    if identity
        .adapter_capability_versions
        .iter()
        .any(|value| !is_bounded_text(value, MAX_IDENTITY_CHARS))
        || identity
            .participating_profile_ids
            .iter()
            .any(|value| !is_bounded_text(value, MAX_IDENTITY_CHARS))
    {
        return invariant(format!(
            "cross-language profile {} identity contains an invalid bounded value",
            profile.id
        ));
    }
    let expected = cross_language_profile_id(&identity);
    if profile.id != expected {
        return invariant(format!(
            "cross-language profile {} does not match its canonical identity; expected {expected}",
            profile.id
        ));
    }

    let ledger: CrossLanguageCompletenessLedger = parse_property(
        profile,
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY,
        "completeness ledger",
    )?;
    validate_ledger_shape(profile, &identity, &ledger)
}

fn validate_ledger_shape(
    profile: &Profile,
    identity: &CrossLanguageProfileIdentity,
    ledger: &CrossLanguageCompletenessLedger,
) -> Result<(), ProtocolError> {
    if ledger.schema_version != CROSS_LANGUAGE_COMPLETENESS_VERSION
        || ledger.entries.len() > MAX_LEDGER_ENTRIES
    {
        return invariant(format!(
            "cross-language profile {} has an incompatible completeness ledger",
            profile.id
        ));
    }
    let formats = ledger
        .entries
        .iter()
        .map(|entry| entry.format)
        .collect::<Vec<_>>();
    validate_sorted_unique("cross-language ledger formats", &formats, true)?;
    for entry in &ledger.entries {
        if entry.capability != entry.format.capability() {
            return invariant(format!(
                "cross-language profile {} declares unknown capability {} for {}",
                profile.id,
                entry.capability,
                entry.format.as_str()
            ));
        }
        validate_sorted_unique("cross-language ledger reasons", &entry.reasons, true)?;
        if entry.reasons.len() > MAX_REASONS_PER_ENTRY
            || entry
                .reasons
                .iter()
                .any(|reason| !is_bounded_text(reason, MAX_REASON_CHARS))
        {
            return invariant(format!(
                "cross-language profile {} has an invalid bounded reason ledger",
                profile.id
            ));
        }
        let must_be_incomplete =
            entry.unresolved_count > 0 || entry.skipped_count > 0 || !entry.reasons.is_empty();
        if (entry.status == CrossLanguageCapabilityStatus::Complete && must_be_incomplete)
            || (entry.status == CrossLanguageCapabilityStatus::Incomplete && !must_be_incomplete)
        {
            return invariant(format!(
                "cross-language profile {} capability {} status contradicts its ledger",
                profile.id, entry.capability
            ));
        }
    }
    let capabilities = ledger
        .entries
        .iter()
        .map(|entry| entry.capability.clone())
        .collect::<Vec<_>>();
    if capabilities != identity.adapter_capability_versions {
        return invariant(format!(
            "cross-language profile {} capability identity differs from its ledger",
            profile.id
        ));
    }
    Ok(())
}

fn validate_cross_language_node<'a>(
    node: &'a GraphNode,
    claimed_profiles: &BTreeMap<String, &'a Profile>,
) -> Result<CrossLanguageCanonicalIdentity, ProtocolError> {
    let kind = CrossLanguageNodeKind::parse(&node.kind).ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "cross-language node {} uses unknown kind {}",
            node.id, node.kind
        ))
    })?;
    let value = node
        .properties
        .get("canonical_identity")
        .cloned()
        .ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "cross-language node {} has no canonical identity",
                node.id
            ))
        })?;
    let identity: CrossLanguageCanonicalIdentity =
        serde_json::from_value(value).map_err(|error| {
            ProtocolError::Invariant(format!(
                "cross-language node {} identity is invalid: {error}",
                node.id
            ))
        })?;
    if identity.contract_version != CROSS_LANGUAGE_CONTRACT_VERSION
        || !claimed_profiles.contains_key(&identity.profile_id)
        || !is_safe_contract_locator(&identity.repository_contract_locator)
        || !is_bounded_text(&identity.format_version, MAX_IDENTITY_CHARS)
        || !is_bounded_text(&identity.coordinate, MAX_IDENTITY_CHARS)
    {
        return invariant(format!(
            "cross-language node {} has an incompatible canonical identity",
            node.id
        ));
    }
    if node.properties.get("profile_id").and_then(Value::as_str)
        != Some(identity.profile_id.as_str())
        || node.properties.get("format").and_then(Value::as_str) != Some(identity.format.as_str())
    {
        return invariant(format!(
            "cross-language node {} duplicates an inconsistent format or profile",
            node.id
        ));
    }
    let expected = cross_language_node_id(kind, &identity);
    if node.id != expected || node.locator != format!("cross-language:{}", node.id) {
        return invariant(format!(
            "cross-language node {} does not match its canonical identity or locator",
            node.id
        ));
    }
    Ok(identity)
}

fn validate_cross_language_site(
    site: &DependencySite,
    relation: CrossLanguageRelationKind,
    nodes: &BTreeMap<String, GraphNode>,
    cross_nodes: &BTreeMap<String, (&GraphNode, CrossLanguageCanonicalIdentity)>,
) -> Result<(), ProtocolError> {
    let primary = cross_language_primary_evidence(site)?;
    let properties = validate_cross_language_evidence(
        &format!("cross-language dependency site {}", site.id),
        &site.profile_id,
        relation,
        &site.evidence,
    )?;
    validate_resolution_contract(
        &format!("cross-language dependency site {}", site.id),
        site.resolution_status,
        site.precision,
        relation,
        primary.kind,
        properties.mapping_kind,
    )?;
    if site.target_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invariant(format!(
            "cross-language dependency site {} targets must be sorted and unique",
            site.id
        ));
    }
    if site
        .reason
        .as_deref()
        .is_some_and(|reason| !is_bounded_text(reason, MAX_REASON_CHARS))
    {
        return invariant(format!(
            "cross-language dependency site {} has an invalid bounded reason",
            site.id
        ));
    }
    validate_relation_endpoints(
        relation,
        site.resolution_status,
        &site.source,
        &site.target_ids,
        nodes,
    )?;
    validate_format_ownership(
        relation,
        properties.format,
        &site.profile_id,
        &site.source,
        &site.target_ids,
        cross_nodes,
    )?;
    let expected = build_cross_language_site_id(site)?;
    if site.id != expected {
        return invariant(format!(
            "cross-language dependency site {} does not match its canonical identity; expected {expected}",
            site.id
        ));
    }
    Ok(())
}

fn validate_cross_language_edge(
    edge: &GraphEdge,
    relation: CrossLanguageRelationKind,
) -> Result<(), ProtocolError> {
    let primary = edge.evidence.first().ok_or_else(|| {
        ProtocolError::Invariant(format!("cross-language edge {} has no evidence", edge.id))
    })?;
    let properties = validate_cross_language_evidence(
        &format!("cross-language edge {}", edge.id),
        &edge.profile_id,
        relation,
        &edge.evidence,
    )?;
    validate_resolution_contract(
        &format!("cross-language edge {}", edge.id),
        edge.resolution_status,
        edge.precision,
        relation,
        primary.kind,
        properties.mapping_kind,
    )?;
    let expected_phase = match primary.kind {
        EvidenceKind::Source => Phase::Source,
        EvidenceKind::Semantic => Phase::Semantic,
        EvidenceKind::Build => Phase::Build,
        EvidenceKind::Runtime => Phase::Runtime,
    };
    if edge.phase != expected_phase {
        return invariant(format!(
            "cross-language edge {} phase does not match its primary evidence",
            edge.id
        ));
    }
    let expected = build_cross_language_edge_id(edge)?;
    if edge.id != expected {
        return invariant(format!(
            "cross-language edge {} does not match its canonical identity; expected {expected}",
            edge.id
        ));
    }
    Ok(())
}

fn validate_cross_language_site_edge_closure(
    sites: &BTreeMap<String, (&DependencySite, CrossLanguageRelationKind)>,
    edges: &BTreeMap<String, (&GraphEdge, CrossLanguageRelationKind)>,
) -> Result<(), ProtocolError> {
    let mut edges_by_site = BTreeMap::<&str, Vec<&GraphEdge>>::new();
    for (edge, _) in edges.values() {
        let site_id = edge.site_id.as_deref().ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "cross-language edge {} does not reference a site",
                edge.id
            ))
        })?;
        if !sites.contains_key(site_id) {
            return invariant(format!(
                "cross-language edge {} references a non-cross-language site",
                edge.id
            ));
        }
        edges_by_site.entry(site_id).or_default().push(edge);
    }
    for (site, relation) in sites.values() {
        let site_edges = edges_by_site
            .get(site.id.as_str())
            .cloned()
            .unwrap_or_default();
        if site_edges.len() != site.target_ids.len() {
            return invariant(format!(
                "cross-language dependency site {} edge closure is incomplete",
                site.id
            ));
        }
        for edge in site_edges {
            if edge.kind != relation.as_str()
                || edge.source != site.source
                || edge.profile_id != site.profile_id
                || edge.condition != site.condition
                || edge.resolution_status != site.resolution_status
                || edge.precision != site.precision
                || edge.evidence != site.evidence
            {
                return invariant(format!(
                    "cross-language edge {} differs from dependency site {}",
                    edge.id, site.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_cross_language_ledgers(
    profiles: &BTreeMap<String, &Profile>,
    nodes: &BTreeMap<String, (&GraphNode, CrossLanguageCanonicalIdentity)>,
    sites: &BTreeMap<String, (&DependencySite, CrossLanguageRelationKind)>,
    edges: &BTreeMap<String, (&GraphEdge, CrossLanguageRelationKind)>,
) -> Result<(), ProtocolError> {
    for profile in profiles.values() {
        let ledger: CrossLanguageCompletenessLedger = parse_property(
            profile,
            CROSS_LANGUAGE_COMPLETENESS_PROPERTY,
            "completeness ledger",
        )?;
        for entry in &ledger.entries {
            let node_count = nodes
                .values()
                .filter(|(_, identity)| {
                    identity.profile_id == profile.id && identity.format == entry.format
                })
                .count() as u64;
            let format_sites = sites
                .values()
                .filter(|(site, _)| {
                    site.profile_id == profile.id
                        && parse_evidence_properties(&site.evidence[0])
                            .is_ok_and(|properties| properties.format == entry.format)
                })
                .map(|(site, _)| *site)
                .collect::<Vec<_>>();
            let edge_count = edges
                .values()
                .filter(|(edge, _)| {
                    edge.profile_id == profile.id
                        && parse_evidence_properties(&edge.evidence[0])
                            .is_ok_and(|properties| properties.format == entry.format)
                })
                .count() as u64;
            let external_count = format_sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::External)
                .count() as u64;
            let unresolved_count = format_sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::Unresolved)
                .count() as u64;
            if entry.input_count == 0
                || entry.node_count != node_count
                || entry.site_count != format_sites.len() as u64
                || entry.edge_count != edge_count
                || entry.external_count != external_count
                || entry.unresolved_count != unresolved_count
            {
                return invariant(format!(
                    "cross-language profile {} capability {} count ledger does not match its emitted closure",
                    profile.id, entry.capability
                ));
            }
        }
        for (_, identity) in nodes
            .values()
            .filter(|(_, identity)| identity.profile_id == profile.id)
        {
            if !ledger
                .entries
                .iter()
                .any(|entry| entry.format == identity.format)
            {
                return invariant(format!(
                    "cross-language profile {} has an unledgered {} node",
                    profile.id,
                    identity.format.as_str()
                ));
            }
        }
        for (site, _) in sites
            .values()
            .filter(|(site, _)| site.profile_id == profile.id)
        {
            let format = parse_evidence_properties(&site.evidence[0])?.format;
            if !ledger.entries.iter().any(|entry| entry.format == format) {
                return invariant(format!(
                    "cross-language profile {} has an unledgered {} site",
                    profile.id,
                    format.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn validate_cross_language_evidence(
    owner: &str,
    profile_id: &str,
    relation: CrossLanguageRelationKind,
    evidence: &[Evidence],
) -> Result<CrossLanguageEvidenceProperties, ProtocolError> {
    let primary = evidence
        .first()
        .ok_or_else(|| ProtocolError::Invariant(format!("{owner} has no primary evidence")))?;
    let properties = parse_evidence_properties(primary)?;
    if primary.detail.is_some()
        || properties.contract_version != CROSS_LANGUAGE_CONTRACT_VERSION
        || properties.profile_id != profile_id
        || properties.occurrence_kind != relation
        || !is_bounded_text(&properties.format_version, MAX_IDENTITY_CHARS)
        || !is_prefixed_sha256(&properties.contract_digest)
    {
        return invariant(format!("{owner} has invalid common primary evidence"));
    }
    evidence_anchor(primary, &properties)?;
    for item in evidence {
        if item.detail.is_some() {
            return invariant(format!("{owner} must not retain raw evidence detail"));
        }
        reject_secret_properties(owner, &item.properties)?;
    }
    let supporting = evidence
        .iter()
        .skip(1)
        .map(|item| canonical_json(&serde_json::to_value(item).expect("evidence is serializable")))
        .collect::<Vec<_>>();
    if supporting.windows(2).any(|pair| pair[0] > pair[1]) {
        return invariant(format!(
            "{owner} supporting evidence is not canonical-JSON sorted"
        ));
    }
    Ok(properties)
}

fn validate_resolution_contract(
    owner: &str,
    status: ResolutionStatus,
    precision: Precision,
    relation: CrossLanguageRelationKind,
    evidence_kind: EvidenceKind,
    mapping_kind: CrossLanguageMappingKind,
) -> Result<(), ProtocolError> {
    let valid = match (status, precision) {
        (ResolutionStatus::Resolved, Precision::Exact) => {
            evidence_kind == EvidenceKind::Semantic
                && if relation.is_contract_internal() {
                    matches!(
                        mapping_kind,
                        CrossLanguageMappingKind::ContractInternal
                            | CrossLanguageMappingKind::Descriptor
                    )
                } else {
                    matches!(
                        mapping_kind,
                        CrossLanguageMappingKind::GeneratorManifest
                            | CrossLanguageMappingKind::SourceMap
                    )
                }
        }
        (ResolutionStatus::Resolved, Precision::Heuristic) => matches!(
            mapping_kind,
            CrossLanguageMappingKind::RepositoryMapping
                | CrossLanguageMappingKind::ManualDeclaration
        ),
        (ResolutionStatus::Resolved, Precision::Observed) => matches!(
            (evidence_kind, mapping_kind),
            (
                EvidenceKind::Build,
                CrossLanguageMappingKind::BuildObservation
            ) | (
                EvidenceKind::Runtime,
                CrossLanguageMappingKind::RuntimeObservation
            )
        ),
        (ResolutionStatus::Candidates, Precision::Overapprox) => {
            mapping_kind == CrossLanguageMappingKind::ClosedCandidates
        }
        (ResolutionStatus::External, Precision::Exact | Precision::Heuristic) => {
            mapping_kind == CrossLanguageMappingKind::ExternalReference
        }
        (ResolutionStatus::Unresolved, Precision::Heuristic) => {
            mapping_kind == CrossLanguageMappingKind::Unresolved
        }
        _ => false,
    };
    if !valid
        || (relation == CrossLanguageRelationKind::ProvidedByLibrary
            && status == ResolutionStatus::Resolved
            && precision != Precision::Observed)
    {
        return invariant(format!(
            "{owner} has an invalid status/precision/phase/mapping proof"
        ));
    }
    Ok(())
}

fn validate_relation_endpoints(
    relation: CrossLanguageRelationKind,
    status: ResolutionStatus,
    source: &str,
    targets: &[String],
    nodes: &BTreeMap<String, GraphNode>,
) -> Result<(), ProtocolError> {
    let source_kind = nodes
        .get(source)
        .map(|node| node.kind.as_str())
        .ok_or_else(|| {
            ProtocolError::Invariant(format!(
                "cross-language relation {} references missing source {source}",
                relation.as_str()
            ))
        })?;
    let source_valid = match relation {
        CrossLanguageRelationKind::ProvidesOperation => source_kind == "service",
        CrossLanguageRelationKind::AcceptsMessage
        | CrossLanguageRelationKind::ReturnsMessage
        | CrossLanguageRelationKind::ImplementedBy => source_kind == "operation",
        CrossLanguageRelationKind::ReferencesSchema => {
            matches!(source_kind, "schema" | "message")
        }
        CrossLanguageRelationKind::CallsOperation => {
            matches!(
                source_kind,
                "symbol" | "component" | "server_function" | "operation"
            )
        }
        CrossLanguageRelationKind::GeneratedFrom => {
            matches!(source_kind, "file" | "symbol" | "type")
        }
        CrossLanguageRelationKind::BindsNativeSymbol => {
            matches!(source_kind, "symbol" | "build_unit")
        }
        CrossLanguageRelationKind::ProvidedByLibrary => source_kind == "native_symbol",
    };
    if !source_valid {
        return invariant(format!(
            "cross-language relation {} has invalid source kind {source_kind}",
            relation.as_str()
        ));
    }
    if matches!(
        status,
        ResolutionStatus::External | ResolutionStatus::Unresolved
    ) {
        return Ok(());
    }
    for target in targets {
        let target_kind = nodes
            .get(target)
            .map(|node| node.kind.as_str())
            .ok_or_else(|| {
                ProtocolError::Invariant(format!(
                    "cross-language relation {} references missing target {target}",
                    relation.as_str()
                ))
            })?;
        let valid = match relation {
            CrossLanguageRelationKind::ProvidesOperation
            | CrossLanguageRelationKind::CallsOperation => target_kind == "operation",
            CrossLanguageRelationKind::AcceptsMessage
            | CrossLanguageRelationKind::ReturnsMessage => target_kind == "message",
            CrossLanguageRelationKind::ReferencesSchema => {
                matches!(target_kind, "schema" | "message")
            }
            CrossLanguageRelationKind::ImplementedBy => {
                matches!(target_kind, "symbol" | "server_function")
            }
            CrossLanguageRelationKind::GeneratedFrom => {
                matches!(target_kind, "schema" | "service" | "operation" | "message")
            }
            CrossLanguageRelationKind::BindsNativeSymbol => target_kind == "native_symbol",
            CrossLanguageRelationKind::ProvidedByLibrary => target_kind == "native_library",
        };
        if !valid {
            return invariant(format!(
                "cross-language relation {} has invalid target kind {target_kind}",
                relation.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_format_ownership(
    relation: CrossLanguageRelationKind,
    format: CrossLanguageFormat,
    profile_id: &str,
    source: &str,
    targets: &[String],
    cross_nodes: &BTreeMap<String, (&GraphNode, CrossLanguageCanonicalIdentity)>,
) -> Result<(), ProtocolError> {
    let mut identities = Vec::new();
    if let Some((_, identity)) = cross_nodes.get(source) {
        identities.push(identity);
    }
    for target in targets {
        if let Some((_, identity)) = cross_nodes.get(target) {
            identities.push(identity);
        }
    }
    if identities
        .iter()
        .any(|identity| identity.format != format || identity.profile_id != profile_id)
    {
        return invariant(format!(
            "cross-language relation {} mixes incompatible format or profile identities",
            relation.as_str()
        ));
    }
    Ok(())
}

fn cross_language_primary_evidence(site: &DependencySite) -> Result<&Evidence, ProtocolError> {
    site.evidence.first().ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "cross-language dependency site {} has no primary evidence",
            site.id
        ))
    })
}

fn parse_evidence_properties(
    evidence: &Evidence,
) -> Result<CrossLanguageEvidenceProperties, ProtocolError> {
    serde_json::from_value(Value::Object(
        evidence.properties.clone().into_iter().collect(),
    ))
    .map_err(|error| {
        ProtocolError::Invariant(format!(
            "cross-language primary evidence properties are invalid: {error}"
        ))
    })
}

fn evidence_anchor(
    evidence: &Evidence,
    properties: &CrossLanguageEvidenceProperties,
) -> Result<Value, ProtocolError> {
    let coordinates = [
        evidence.start_line,
        evidence.start_column,
        evidence.end_line,
        evidence.end_column,
    ];
    if let Some(path) = evidence.path.as_deref() {
        if coordinates.iter().any(Option::is_none) || !is_safe_contract_locator(path) {
            return invariant("cross-language source evidence has an incomplete span");
        }
        return Ok(json!({
            "path": path,
            "start_line": evidence.start_line,
            "start_column": evidence.start_column,
            "end_line": evidence.end_line,
            "end_column": evidence.end_column,
        }));
    }
    if coordinates.iter().any(Option::is_some) {
        return invariant("cross-language artifact evidence has partial source coordinates");
    }
    let artifact_identity = properties
        .artifact_identity
        .as_deref()
        .filter(|value| is_bounded_text(value, MAX_IDENTITY_CHARS))
        .ok_or_else(|| {
            ProtocolError::Invariant(
                "cross-language unspanned evidence requires artifact_identity".into(),
            )
        })?;
    let ordinal = properties
        .ordinal
        .filter(|ordinal| *ordinal <= MAX_ARTIFACT_ORDINAL)
        .ok_or_else(|| {
            ProtocolError::Invariant(
                "cross-language unspanned evidence requires a bounded ordinal".into(),
            )
        })?;
    Ok(json!({
        "artifact_identity": artifact_identity,
        "ordinal": ordinal,
    }))
}

pub(crate) fn is_cross_language_artifact_evidence(evidence: &Evidence) -> bool {
    evidence.path.is_none()
        && evidence
            .properties
            .get("contract_version")
            .and_then(Value::as_str)
            == Some(CROSS_LANGUAGE_CONTRACT_VERSION)
        && evidence
            .properties
            .get("artifact_identity")
            .and_then(Value::as_str)
            .is_some()
        && evidence
            .properties
            .get("ordinal")
            .and_then(Value::as_u64)
            .is_some()
}

fn profile_claims_cross_language(profile: &Profile) -> bool {
    profile.language == "cross-language"
        || profile
            .properties
            .contains_key(CROSS_LANGUAGE_CONTRACT_PROPERTY)
        || profile
            .properties
            .contains_key(CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY)
        || profile
            .properties
            .contains_key(CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
}

fn is_cross_language_node(node: &GraphNode) -> bool {
    node.properties
        .get("canonical_identity")
        .and_then(Value::as_object)
        .and_then(|identity| identity.get("contract_version"))
        .and_then(Value::as_str)
        == Some(CROSS_LANGUAGE_CONTRACT_VERSION)
}

fn evidence_claims_cross_language(evidence: &Evidence) -> bool {
    evidence
        .properties
        .get("contract_version")
        .and_then(Value::as_str)
        == Some(CROSS_LANGUAGE_CONTRACT_VERSION)
}

fn parse_property<T: for<'de> Deserialize<'de>>(
    profile: &Profile,
    property: &str,
    label: &str,
) -> Result<T, ProtocolError> {
    let value = profile.properties.get(property).cloned().ok_or_else(|| {
        ProtocolError::Invariant(format!(
            "cross-language profile {} has no {label}",
            profile.id
        ))
    })?;
    serde_json::from_value(value).map_err(|error| {
        ProtocolError::Invariant(format!(
            "cross-language profile {} {label} is invalid: {error}",
            profile.id
        ))
    })
}

fn unique_map<'a, T>(
    values: &'a [T],
    key: impl Fn(&'a T) -> &'a str,
    label: &str,
) -> Result<BTreeMap<String, T>, ProtocolError>
where
    T: Clone,
{
    let mut result = BTreeMap::new();
    for value in values {
        let key = key(value).to_owned();
        if result.insert(key.clone(), value.clone()).is_some() {
            return invariant(format!(
                "cross-language graph contains duplicate {label} {key}"
            ));
        }
    }
    Ok(result)
}

fn validate_sorted_unique<T: Ord>(
    label: &str,
    values: &[T],
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    if (!allow_empty && values.is_empty()) || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invariant(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn is_safe_contract_locator(value: &str) -> bool {
    is_bounded_text(value, MAX_IDENTITY_CHARS)
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains("://")
        && !value.contains('?')
        && !value.contains('#')
        && !value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
}

fn is_bounded_text(value: &str, max_chars: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max_chars && !value.chars().any(char::is_control)
}

fn is_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn reject_secret_properties(
    owner: &str,
    properties: &BTreeMap<String, Value>,
) -> Result<(), ProtocolError> {
    fn visit(owner: &str, key: Option<&str>, value: &Value) -> Result<(), ProtocolError> {
        if let Some(key) = key {
            let normalized = key.to_ascii_lowercase();
            if [
                "authorization",
                "cookie",
                "password",
                "secret",
                "token",
                "api_key",
                "query",
                "headers",
                "body",
            ]
            .iter()
            .any(|forbidden| normalized == *forbidden || normalized.ends_with(forbidden))
            {
                return invariant(format!("{owner} contains forbidden secret-shaped property"));
            }
        }
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    visit(owner, Some(key), value)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    visit(owner, None, value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for (key, value) in properties {
        visit(owner, Some(key), value)?;
    }
    Ok(())
}

fn invariant<T>(message: impl Into<String>) -> Result<T, ProtocolError> {
    Err(ProtocolError::Invariant(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_node_ids_are_canonical_and_format_scoped() {
        let profile = CrossLanguageProfileIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            completeness_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
            contract_input_digest: format!("sha256:{}", "1".repeat(64)),
            adapter_capability_versions: vec!["openapi-contract-v1".to_owned()],
            participating_profile_ids: vec!["web:production".to_owned()],
        };
        let profile_id = cross_language_profile_id(&profile);
        let identity = CrossLanguageCanonicalIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            format: CrossLanguageFormat::Openapi,
            repository_contract_locator: "contracts/api.json".to_owned(),
            format_version: "3.1.1".to_owned(),
            coordinate: "get /users/{id}".to_owned(),
            profile_id: profile_id.clone(),
        };
        assert_ne!(
            cross_language_node_id(CrossLanguageNodeKind::Operation, &identity),
            cross_language_node_id(
                CrossLanguageNodeKind::Operation,
                &CrossLanguageCanonicalIdentity {
                    format: CrossLanguageFormat::Graphql,
                    ..identity
                }
            )
        );
        assert!(profile_id.starts_with("profile:sha256:"));
    }

    #[test]
    fn generated_type_may_bind_to_a_contract_service() {
        let nodes = BTreeMap::from([
            (
                "type".to_owned(),
                GraphNode {
                    id: "type".to_owned(),
                    kind: "type".to_owned(),
                    locator: "generated:type".to_owned(),
                    display_name: None,
                    properties: BTreeMap::new(),
                },
            ),
            (
                "service".to_owned(),
                GraphNode {
                    id: "service".to_owned(),
                    kind: "service".to_owned(),
                    locator: "cross-language:service".to_owned(),
                    display_name: None,
                    properties: BTreeMap::new(),
                },
            ),
        ]);
        assert!(
            validate_relation_endpoints(
                CrossLanguageRelationKind::GeneratedFrom,
                ResolutionStatus::Resolved,
                "type",
                &["service".to_owned()],
                &nodes,
            )
            .is_ok()
        );
    }
}
