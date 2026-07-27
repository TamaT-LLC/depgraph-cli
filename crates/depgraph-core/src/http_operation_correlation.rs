use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_CONTRACT_VERSION,
    CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, Condition, CrossLanguageAdapterDelta,
    CrossLanguageCanonicalIdentity, CrossLanguageCompletenessLedger,
    CrossLanguageEvidenceProperties, CrossLanguageFormat, CrossLanguageMappingKind,
    CrossLanguageProfileIdentity, CrossLanguageRelationKind, DependencySite, Evidence,
    EvidenceKind, GraphEdge, Phase, Precision, Properties, ResolutionStatus,
    build_cross_language_edge_id, build_cross_language_site_id, stable_id_from_value,
    validate_cross_language_adapter_delta,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    RuntimeHttpObservation, RuntimeHttpOperationFormat, RuntimeTraceLocator,
    RuntimeTraceMatchStatus, ValidatedRuntimeTrace, ValidatedRuntimeTraceEvent,
    runtime_trace::validate_http_correlation_trace,
};

pub const HTTP_OPERATION_CORRELATION_VERSION: &str = "http-operation-correlation-v1";
const EXTRACTOR: &str = "depgraph-http-operation-correlator";
const MAX_CORRELATION_CONTRACTS: usize = 256;
const MAX_CORRELATION_OPERATIONS: usize = 100_000;
const MAX_CORRELATION_CANDIDATES_PER_EVENT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOperationCorrelationOutcome {
    pub id: String,
    pub event_id: String,
    pub status: ResolutionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<CrossLanguageFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub operation_ids: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOperationCorrelationResult {
    pub contract_version: String,
    pub trace_digest: String,
    pub outcomes: Vec<HttpOperationCorrelationOutcome>,
    pub deltas: Vec<CrossLanguageAdapterDelta>,
}

#[derive(Clone)]
struct OperationCandidate {
    delta_index: usize,
    node_id: String,
    profile_id: String,
    format: CrossLanguageFormat,
    format_version: String,
    contract_digest: String,
}

#[derive(Clone)]
struct IndexedOperation {
    candidate: OperationCandidate,
    identity: CrossLanguageCanonicalIdentity,
    proof: Option<(String, String)>,
}

/// Correlates validated and redacted runtime HTTP observations to existing
/// static contract operations. The input deltas are cloned and augmented only
/// for unique, same-profile matches; static exact relations are never changed.
pub fn correlate_http_operations(
    trace: &ValidatedRuntimeTrace,
    contracts: &[CrossLanguageAdapterDelta],
) -> Result<HttpOperationCorrelationResult> {
    validate_http_correlation_trace(trace)?;
    if contracts.len() > MAX_CORRELATION_CONTRACTS {
        bail!("HTTP correlation exceeds its closed contract limit");
    }
    for contract in contracts {
        validate_cross_language_adapter_delta(contract)
            .map_err(anyhow::Error::from)
            .context("HTTP correlation received an invalid static contract delta")?;
    }
    let operation_index = build_operation_index(trace, contracts)?;
    let trace_digest = stable_id_from_value(
        "http-operation-trace",
        &serde_json::to_value(trace).context("serializing validated runtime trace")?,
    );
    let mut deltas = contracts.to_vec();
    let mut dirty = BTreeSet::new();
    let mut outcomes = Vec::new();

    for event in trace.events.iter().filter(|event| event.http.is_some()) {
        let http = event.http.as_ref().context("filtered HTTP observation")?;
        let mut candidates = Vec::new();
        let mut version_drift = false;
        if trace.profile_match.status == RuntimeTraceMatchStatus::Resolved {
            let coordinate = http.operation.clone().unwrap_or_else(|| {
                format!(
                    "{} {}",
                    http.method.to_ascii_lowercase(),
                    http.route_template
                )
            });
            for indexed in operation_index.get(&coordinate).into_iter().flatten() {
                let match_kind = operation_match(http, &indexed.identity);
                if match_kind == OperationMatch::VersionDrift {
                    version_drift = true;
                    continue;
                }
                if match_kind != OperationMatch::Match {
                    continue;
                }
                let Some((format_version, contract_digest)) = &indexed.proof else {
                    continue;
                };
                if candidates.len() >= MAX_CORRELATION_CANDIDATES_PER_EVENT {
                    bail!("HTTP correlation exceeds its closed per-event candidate limit");
                }
                let mut candidate = indexed.candidate.clone();
                candidate.format_version = format_version.clone();
                candidate.contract_digest = contract_digest.clone();
                candidates.push(candidate);
            }
        }
        candidates.sort_by(|left, right| {
            (
                left.format,
                left.profile_id.as_bytes(),
                left.node_id.as_bytes(),
            )
                .cmp(&(
                    right.format,
                    right.profile_id.as_bytes(),
                    right.node_id.as_bytes(),
                ))
        });
        candidates.dedup_by(|left, right| {
            left.delta_index == right.delta_index && left.node_id == right.node_id
        });

        let mut outcome = if trace.profile_match.status != RuntimeTraceMatchStatus::Resolved {
            outcome(
                &trace_digest,
                event,
                ResolutionStatus::Unresolved,
                None,
                None,
                Vec::new(),
                "runtime-profile-unmatched",
            )
        } else if candidates.len() > 1 {
            let formats = candidates
                .iter()
                .map(|candidate| candidate.format)
                .collect::<BTreeSet<_>>();
            let profiles = candidates
                .iter()
                .map(|candidate| candidate.profile_id.as_str())
                .collect::<BTreeSet<_>>();
            outcome(
                &trace_digest,
                event,
                ResolutionStatus::Candidates,
                (formats.len() == 1).then(|| candidates[0].format),
                (profiles.len() == 1).then(|| candidates[0].profile_id.clone()),
                candidates
                    .iter()
                    .map(|candidate| candidate.node_id.clone())
                    .collect(),
                "http-operation-ambiguous",
            )
        } else if let Some(candidate) = candidates.first() {
            let source_id = event.source.node_id.as_deref();
            if event.source.status != RuntimeTraceMatchStatus::Resolved
                || !source_id.is_some_and(|source| {
                    deltas[candidate.delta_index]
                        .nodes
                        .iter()
                        .any(|node| node.id == source && valid_runtime_call_source(&node.kind))
                })
            {
                outcome(
                    &trace_digest,
                    event,
                    ResolutionStatus::Unresolved,
                    Some(candidate.format),
                    Some(candidate.profile_id.clone()),
                    vec![candidate.node_id.clone()],
                    "runtime-source-not-in-contract-graph",
                )
            } else {
                append_runtime_relation(
                    &mut deltas[candidate.delta_index],
                    trace,
                    event,
                    http,
                    candidate,
                    source_id.context("checked resolved runtime source")?,
                )?;
                dirty.insert(candidate.delta_index);
                outcome(
                    &trace_digest,
                    event,
                    ResolutionStatus::Resolved,
                    Some(candidate.format),
                    Some(candidate.profile_id.clone()),
                    vec![candidate.node_id.clone()],
                    "unique-compatible-operation",
                )
            }
        } else if version_drift {
            outcome(
                &trace_digest,
                event,
                ResolutionStatus::Unresolved,
                http.format.map(runtime_format),
                None,
                Vec::new(),
                "contract-version-drift",
            )
        } else {
            outcome(
                &trace_digest,
                event,
                ResolutionStatus::External,
                http.format.map(runtime_format),
                None,
                Vec::new(),
                "http-operation-not-declared",
            )
        };
        outcome.operation_ids.sort();
        outcome.operation_ids.dedup();
        outcomes.push(outcome);
    }

    for index in dirty {
        canonicalize_and_validate_delta(&mut deltas[index])?;
    }
    deltas.sort_by(|left, right| left.profile.id.as_bytes().cmp(right.profile.id.as_bytes()));
    outcomes.sort_by(|left, right| {
        (left.event_id.as_bytes(), left.id.as_bytes())
            .cmp(&(right.event_id.as_bytes(), right.id.as_bytes()))
    });
    Ok(HttpOperationCorrelationResult {
        contract_version: HTTP_OPERATION_CORRELATION_VERSION.to_owned(),
        trace_digest,
        outcomes,
        deltas,
    })
}

fn build_operation_index(
    trace: &ValidatedRuntimeTrace,
    contracts: &[CrossLanguageAdapterDelta],
) -> Result<BTreeMap<String, Vec<IndexedOperation>>> {
    let mut operation_count = 0_usize;
    let mut index = BTreeMap::<String, Vec<IndexedOperation>>::new();
    if trace.profile_match.status != RuntimeTraceMatchStatus::Resolved {
        return Ok(index);
    }
    let parent_profile_id = trace
        .profile_match
        .parent_profile_id
        .as_deref()
        .context("resolved runtime profile has no parent profile ID")?;
    for (delta_index, delta) in contracts.iter().enumerate() {
        let profile_identity = profile_identity(delta)?;
        if !profile_identity
            .participating_profile_ids
            .iter()
            .any(|profile| profile == parent_profile_id)
        {
            continue;
        }
        for node in delta.nodes.iter().filter(|node| node.kind == "operation") {
            operation_count = operation_count
                .checked_add(1)
                .context("HTTP correlation operation count overflowed")?;
            if operation_count > MAX_CORRELATION_OPERATIONS {
                bail!("HTTP correlation exceeds its closed operation limit");
            }
            let identity = operation_identity(node)?;
            let proof = operation_contract_proof(delta, &node.id, &identity)?;
            index
                .entry(identity.coordinate.clone())
                .or_default()
                .push(IndexedOperation {
                    candidate: OperationCandidate {
                        delta_index,
                        node_id: node.id.clone(),
                        profile_id: delta.profile.id.clone(),
                        format: identity.format,
                        format_version: String::new(),
                        contract_digest: String::new(),
                    },
                    identity,
                    proof,
                });
        }
    }
    for operations in index.values_mut() {
        operations.sort_by(|left, right| {
            (
                left.candidate.format,
                left.candidate.profile_id.as_bytes(),
                left.candidate.node_id.as_bytes(),
            )
                .cmp(&(
                    right.candidate.format,
                    right.candidate.profile_id.as_bytes(),
                    right.candidate.node_id.as_bytes(),
                ))
        });
    }
    Ok(index)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationMatch {
    Match,
    NoMatch,
    VersionDrift,
}

fn operation_match(
    observation: &RuntimeHttpObservation,
    identity: &CrossLanguageCanonicalIdentity,
) -> OperationMatch {
    if observation
        .format
        .is_some_and(|format| runtime_format(format) != identity.format)
        || observation
            .contract_locator
            .as_deref()
            .is_some_and(|locator| locator != identity.repository_contract_locator)
    {
        return OperationMatch::NoMatch;
    }
    let coordinate_matches = match observation.operation.as_deref() {
        Some(operation) => operation == identity.coordinate,
        None if identity.format == CrossLanguageFormat::Openapi => {
            let expected = format!(
                "{} {}",
                observation.method.to_ascii_lowercase(),
                observation.route_template
            );
            identity.coordinate == expected
        }
        None => false,
    };
    if !coordinate_matches || !format_route_matches(observation, identity) {
        return OperationMatch::NoMatch;
    }
    if observation
        .format_version
        .as_deref()
        .is_some_and(|version| version != identity.format_version)
    {
        return OperationMatch::VersionDrift;
    }
    OperationMatch::Match
}

fn format_route_matches(
    observation: &RuntimeHttpObservation,
    identity: &CrossLanguageCanonicalIdentity,
) -> bool {
    if identity.format != CrossLanguageFormat::Openapi {
        return observation.operation.is_some();
    }
    identity
        .coordinate
        .split_once(' ')
        .is_some_and(|(method, route)| {
            method.eq_ignore_ascii_case(&observation.method) && route == observation.route_template
        })
}

fn runtime_format(format: RuntimeHttpOperationFormat) -> CrossLanguageFormat {
    match format {
        RuntimeHttpOperationFormat::Openapi => CrossLanguageFormat::Openapi,
        RuntimeHttpOperationFormat::Protobuf => CrossLanguageFormat::Protobuf,
        RuntimeHttpOperationFormat::Graphql => CrossLanguageFormat::Graphql,
    }
}

fn profile_identity(delta: &CrossLanguageAdapterDelta) -> Result<CrossLanguageProfileIdentity> {
    serde_json::from_value(
        delta
            .profile
            .properties
            .get(CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY)
            .cloned()
            .context("cross-language profile has no identity")?,
    )
    .context("cross-language profile identity is invalid")
}

fn operation_identity(
    node: &depgraph_protocol::GraphNode,
) -> Result<CrossLanguageCanonicalIdentity> {
    serde_json::from_value(
        node.properties
            .get("canonical_identity")
            .cloned()
            .context("operation has no canonical identity")?,
    )
    .context("operation canonical identity is invalid")
}

fn operation_contract_proof(
    delta: &CrossLanguageAdapterDelta,
    operation_id: &str,
    identity: &CrossLanguageCanonicalIdentity,
) -> Result<Option<(String, String)>> {
    let mut proofs = BTreeSet::new();
    for site in &delta.sites {
        if site.source != operation_id
            && !site.target_ids.iter().any(|target| target == operation_id)
        {
            continue;
        }
        let Some(primary) = site.evidence.first() else {
            continue;
        };
        let Ok(properties) = serde_json::from_value::<CrossLanguageEvidenceProperties>(
            Value::Object(primary.properties.clone().into_iter().collect()),
        ) else {
            continue;
        };
        if primary.path.as_deref() == Some(identity.repository_contract_locator.as_str())
            && properties.format == identity.format
            && properties.profile_id == delta.profile.id
            && properties.contract_version == CROSS_LANGUAGE_CONTRACT_VERSION
            && matches!(
                properties.mapping_kind,
                CrossLanguageMappingKind::ContractInternal | CrossLanguageMappingKind::Descriptor
            )
        {
            proofs.insert((properties.format_version, properties.contract_digest));
        }
    }
    if proofs.len() > 1 {
        bail!("operation has ambiguous static contract proof");
    }
    Ok(proofs.into_iter().next())
}

fn valid_runtime_call_source(kind: &str) -> bool {
    matches!(
        kind,
        "symbol" | "component" | "server_function" | "operation"
    )
}

fn append_runtime_relation(
    delta: &mut CrossLanguageAdapterDelta,
    trace: &ValidatedRuntimeTrace,
    event: &ValidatedRuntimeTraceEvent,
    observation: &RuntimeHttpObservation,
    candidate: &OperationCandidate,
    source_id: &str,
) -> Result<()> {
    let (scheme, authority) = match &event.target.input {
        RuntimeTraceLocator::External { namespace, name } => (namespace.as_str(), name.as_str()),
        _ => bail!("validated HTTP observation lost its redacted external target"),
    };
    let condition = runtime_condition(trace, observation, scheme, authority);
    let artifact_identity = stable_id_from_value(
        "http-operation-observation",
        &json!({
            "contract_version": HTTP_OPERATION_CORRELATION_VERSION,
            "event_id": event.id,
            "profile_id": candidate.profile_id,
            "operation_id": candidate.node_id,
            "environment": trace.session.environment,
        }),
    );
    let properties = Properties::from([
        (
            "contract_version".to_owned(),
            Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
        ),
        ("format".to_owned(), serde_json::to_value(candidate.format)?),
        (
            "profile_id".to_owned(),
            Value::String(candidate.profile_id.clone()),
        ),
        (
            "format_version".to_owned(),
            Value::String(candidate.format_version.clone()),
        ),
        (
            "contract_digest".to_owned(),
            Value::String(candidate.contract_digest.clone()),
        ),
        (
            "occurrence_kind".to_owned(),
            serde_json::to_value(CrossLanguageRelationKind::CallsOperation)?,
        ),
        (
            "mapping_kind".to_owned(),
            serde_json::to_value(CrossLanguageMappingKind::RuntimeObservation)?,
        ),
        (
            "artifact_identity".to_owned(),
            Value::String(artifact_identity),
        ),
        ("ordinal".to_owned(), Value::from(event.sequence)),
        (
            "runtime_event_id".to_owned(),
            Value::String(event.id.clone()),
        ),
        (
            "runtime_session_id".to_owned(),
            Value::String(trace.session.id.clone()),
        ),
        (
            "runtime_environment".to_owned(),
            serde_json::to_value(&trace.session.environment)?,
        ),
        ("http_scheme".to_owned(), Value::String(scheme.to_owned())),
        (
            "http_authority".to_owned(),
            Value::String(authority.to_owned()),
        ),
        (
            "http_method".to_owned(),
            Value::String(observation.method.clone()),
        ),
        (
            "http_route_template".to_owned(),
            Value::String(observation.route_template.clone()),
        ),
        (
            "operation_coordinate".to_owned(),
            Value::String(observation.operation.clone().unwrap_or_else(|| {
                format!("{} {}", observation.method, observation.route_template)
            })),
        ),
    ]);
    let evidence = vec![Evidence {
        kind: EvidenceKind::Runtime,
        extractor: EXTRACTOR.to_owned(),
        extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
        path: None,
        start_line: None,
        start_column: None,
        end_line: None,
        end_column: None,
        detail: None,
        properties,
    }];
    let mut site = DependencySite {
        id: String::new(),
        source: source_id.to_owned(),
        kind: CrossLanguageRelationKind::CallsOperation
            .as_str()
            .to_owned(),
        specifier: format!("{} {}", observation.method, observation.route_template),
        resolution_status: ResolutionStatus::Resolved,
        target_ids: vec![candidate.node_id.clone()],
        profile_id: candidate.profile_id.clone(),
        condition: condition.clone(),
        precision: Precision::Observed,
        reason: None,
        evidence: evidence.clone(),
    };
    site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
    let mut edge = GraphEdge {
        id: String::new(),
        source: source_id.to_owned(),
        target: candidate.node_id.clone(),
        kind: CrossLanguageRelationKind::CallsOperation
            .as_str()
            .to_owned(),
        site_id: Some(site.id.clone()),
        phase: Phase::Runtime,
        environment: Some(trace.session.environment.name.clone()),
        profile_id: candidate.profile_id.clone(),
        condition,
        resolution_status: ResolutionStatus::Resolved,
        precision: Precision::Observed,
        generated: false,
        evidence,
    };
    edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
    insert_identical(
        &mut delta.sites,
        site,
        |item| &item.id,
        "runtime correlation site",
    )?;
    insert_identical(
        &mut delta.edges,
        edge,
        |item| &item.id,
        "runtime correlation edge",
    )
}

fn runtime_condition(
    trace: &ValidatedRuntimeTrace,
    observation: &RuntimeHttpObservation,
    scheme: &str,
    authority: &str,
) -> Condition {
    let mut values = vec![
        ("http.authority", authority.to_owned()),
        ("http.method", observation.method.clone()),
        ("http.route_template", observation.route_template.clone()),
        ("http.scheme", scheme.to_owned()),
        (
            "runtime.environment.name",
            trace.session.environment.name.clone(),
        ),
        ("runtime.session.id", trace.session.id.clone()),
    ];
    if let Some(runtime) = &trace.session.environment.runtime {
        values.push(("runtime.environment.runtime", runtime.clone()));
    }
    if let Some(region) = &trace.session.environment.region {
        values.push(("runtime.environment.region", region.clone()));
    }
    Condition::All {
        conditions: values
            .into_iter()
            .map(|(key, value)| Condition::Eq {
                key: key.to_owned(),
                value: Value::String(value),
            })
            .collect(),
    }
    .canonicalize()
}

fn insert_identical<T: PartialEq>(
    values: &mut Vec<T>,
    value: T,
    id: impl Fn(&T) -> &str,
    label: &str,
) -> Result<()> {
    let value_id = id(&value).to_owned();
    if let Some(existing) = values.iter().find(|item| id(item) == value_id) {
        if existing != &value {
            bail!("{label} identity collision");
        }
        return Ok(());
    }
    values.push(value);
    Ok(())
}

fn canonicalize_and_validate_delta(delta: &mut CrossLanguageAdapterDelta) -> Result<()> {
    delta
        .sites
        .sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    delta
        .edges
        .sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    let mut ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
        delta
            .profile
            .properties
            .get(CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
            .cloned()
            .context("cross-language profile has no completeness ledger")?,
    )
    .context("cross-language completeness ledger is invalid")?;
    for entry in &mut ledger.entries {
        entry.node_count = delta
            .nodes
            .iter()
            .filter_map(|node| node.properties.get("canonical_identity"))
            .filter_map(|value| {
                serde_json::from_value::<CrossLanguageCanonicalIdentity>(value.clone()).ok()
            })
            .filter(|identity| identity.format == entry.format)
            .count() as u64;
        let site_properties = delta.sites.iter().filter_map(|site| {
            site.evidence.first().and_then(|evidence| {
                serde_json::from_value::<CrossLanguageEvidenceProperties>(Value::Object(
                    evidence.properties.clone().into_iter().collect(),
                ))
                .ok()
                .map(|properties| (site, properties))
            })
        });
        let site_properties = site_properties.collect::<Vec<_>>();
        entry.site_count = site_properties
            .iter()
            .filter(|(_, properties)| properties.format == entry.format)
            .count() as u64;
        entry.external_count = site_properties
            .iter()
            .filter(|(site, properties)| {
                properties.format == entry.format
                    && site.resolution_status == ResolutionStatus::External
            })
            .count() as u64;
        entry.unresolved_count = site_properties
            .iter()
            .filter(|(site, properties)| {
                properties.format == entry.format
                    && site.resolution_status == ResolutionStatus::Unresolved
            })
            .count() as u64;
        entry.edge_count = delta
            .edges
            .iter()
            .filter_map(|edge| edge.evidence.first())
            .filter_map(|evidence| {
                serde_json::from_value::<CrossLanguageEvidenceProperties>(Value::Object(
                    evidence.properties.clone().into_iter().collect(),
                ))
                .ok()
            })
            .filter(|properties| properties.format == entry.format)
            .count() as u64;
    }
    delta.profile.properties.insert(
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY.to_owned(),
        serde_json::to_value(ledger)?,
    );
    validate_cross_language_adapter_delta(delta)
        .map_err(anyhow::Error::from)
        .context("HTTP correlation produced an invalid observed contract delta")?;
    Ok(())
}

fn outcome(
    trace_digest: &str,
    event: &ValidatedRuntimeTraceEvent,
    status: ResolutionStatus,
    format: Option<CrossLanguageFormat>,
    profile_id: Option<String>,
    operation_ids: Vec<String>,
    reason: &str,
) -> HttpOperationCorrelationOutcome {
    let id = stable_id_from_value(
        "http-operation-correlation",
        &json!({
            "contract_version": HTTP_OPERATION_CORRELATION_VERSION,
            "trace_digest": trace_digest,
            "event_id": event.id,
            "status": status,
            "format": format,
            "profile_id": profile_id,
            "operation_ids": operation_ids,
            "reason": reason,
        }),
    );
    HttpOperationCorrelationOutcome {
        id,
        event_id: event.id.clone(),
        status,
        format,
        profile_id,
        operation_ids,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use depgraph_protocol::{CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, GraphNode};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        RuntimeHttpObservation, RuntimeHttpOperationFormat, RuntimeTraceEnvironment,
        RuntimeTraceProfile, RuntimeTraceProfileMatch, RuntimeTraceRedaction,
        RuntimeTraceRepository, RuntimeTraceSession, RuntimeTraceSummary, scan_graphql_repository,
        scan_openapi_repository, scan_protobuf_repository,
    };

    const PARENT_PROFILE: &str =
        "profile:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn uniquely_correlates_openapi_protobuf_and_graphql_operations_as_observed() -> Result<()> {
        let root = tempdir()?;
        fs::write(
            root.path().join("api.json"),
            r#"{"openapi":"3.1.0","info":{"title":"api","version":"1"},"paths":{"/pets/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        )?;
        fs::write(
            root.path().join("service.proto"),
            "syntax = \"proto3\"; package shop.v1; service Pets { rpc GetPet (GetPetRequest) returns (GetPetResponse); } message GetPetRequest {} message GetPetResponse {}",
        )?;
        fs::write(
            root.path().join("schema.graphql"),
            "type Query { pet(id: ID!): Pet } type Pet { id: ID! } query GetPet { pet(id: \"redacted\") { id } }",
        )?;
        let contracts = vec![
            scan_openapi_repository(root.path(), &[PARENT_PROFILE.to_owned()])?
                .context("OpenAPI fixture delta")?,
            scan_protobuf_repository(root.path(), &[PARENT_PROFILE.to_owned()])?
                .context("Protobuf fixture delta")?,
            scan_graphql_repository(root.path(), &[PARENT_PROFILE.to_owned()])?
                .context("GraphQL fixture delta")?,
        ];
        let cases = [
            (
                RuntimeHttpOperationFormat::Openapi,
                "get /pets/{id}",
                "GET",
                "/pets/{id}",
            ),
            (
                RuntimeHttpOperationFormat::Protobuf,
                "shop.v1.Pets/GetPet",
                "POST",
                "/rpc/{service}/{method}",
            ),
            (
                RuntimeHttpOperationFormat::Graphql,
                "query GetPet",
                "POST",
                "/graphql",
            ),
        ];
        for (format, coordinate, method, route_template) in cases {
            let (_, source) = operation(&contracts, runtime_format(format), coordinate)?;
            let trace = trace(
                source.id.clone(),
                RuntimeHttpObservation {
                    method: method.to_owned(),
                    route_template: route_template.to_owned(),
                    format: Some(format),
                    operation: Some(coordinate.to_owned()),
                    contract_locator: None,
                    format_version: None,
                },
                "session-a",
            );
            let first = correlate_http_operations(&trace, &contracts)?;
            let second = correlate_http_operations(&trace, &contracts)?;
            assert_eq!(first, second);
            assert_eq!(first.outcomes.len(), 1);
            assert_eq!(first.outcomes[0].status, ResolutionStatus::Resolved);
            let delta = first
                .deltas
                .iter()
                .find(|delta| {
                    Some(delta.profile.id.as_str()) == first.outcomes[0].profile_id.as_deref()
                })
                .context("correlated delta")?;
            let observed = &delta
                .edges
                .iter()
                .find(|edge| edge.phase == Phase::Runtime)
                .context("observed correlation edge")?;
            assert_eq!(observed.precision, Precision::Observed);
            assert_eq!(observed.target, source.id);
            assert!(
                contracts
                    .iter()
                    .find(|contract| contract.profile.id == delta.profile.id)
                    .context("static delta")?
                    .edges
                    .iter()
                    .all(|edge| edge.phase != Phase::Runtime)
            );
        }
        Ok(())
    }

    #[test]
    fn ambiguous_version_drift_and_profile_mismatch_remain_reasoned_without_edges() -> Result<()> {
        let root = tempdir()?;
        fs::write(
            root.path().join("a.json"),
            r#"{"openapi":"3.1.0","info":{"title":"a","version":"1"},"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        )?;
        fs::write(
            root.path().join("b.json"),
            r#"{"openapi":"3.1.0","info":{"title":"b","version":"1"},"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        )?;
        let contract =
            scan_openapi_repository(root.path(), &[PARENT_PROFILE.to_owned()])?.context("delta")?;
        let source = contract
            .nodes
            .iter()
            .find(|node| node.kind == "operation")
            .context("operation")?;
        let mut runtime = trace(
            source.id.clone(),
            RuntimeHttpObservation {
                method: "GET".to_owned(),
                route_template: "/pets".to_owned(),
                format: Some(RuntimeHttpOperationFormat::Openapi),
                operation: None,
                contract_locator: None,
                format_version: None,
            },
            "session-a",
        );
        let ambiguous = correlate_http_operations(&runtime, std::slice::from_ref(&contract))?;
        assert_eq!(ambiguous.outcomes[0].status, ResolutionStatus::Candidates);
        assert_eq!(ambiguous.outcomes[0].operation_ids.len(), 2);
        assert!(
            ambiguous.deltas[0]
                .edges
                .iter()
                .all(|edge| edge.phase != Phase::Runtime)
        );

        runtime.events[0]
            .http
            .as_mut()
            .context("http")?
            .contract_locator = Some("a.json".to_owned());
        runtime.events[0]
            .http
            .as_mut()
            .context("http")?
            .format_version = Some("3.2.0".to_owned());
        runtime.events[0].id = crate::runtime_trace::expected_validated_runtime_event_id(
            &runtime.repository,
            &runtime.session,
            &runtime.events[0],
        );
        let drift = correlate_http_operations(&runtime, std::slice::from_ref(&contract))?;
        assert_eq!(drift.outcomes[0].status, ResolutionStatus::Unresolved);
        assert_eq!(drift.outcomes[0].reason, "contract-version-drift");

        runtime.profile_match = RuntimeTraceProfileMatch {
            status: RuntimeTraceMatchStatus::Unresolved,
            parent_profile_id: None,
            reason: Some("profile_not_found".to_owned()),
        };
        let unmatched = correlate_http_operations(&runtime, &[contract])?;
        assert_eq!(unmatched.outcomes[0].reason, "runtime-profile-unmatched");
        Ok(())
    }

    #[test]
    fn session_environment_and_checkout_are_canonical_and_reimport_is_idempotent() -> Result<()> {
        let first_root = tempdir()?;
        let second_root = tempdir()?;
        let document = r#"{"openapi":"3.1.0","info":{"title":"api","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#;
        fs::write(first_root.path().join("api.json"), document)?;
        fs::write(second_root.path().join("api.json"), document)?;
        let first_contract =
            scan_openapi_repository(first_root.path(), &[PARENT_PROFILE.to_owned()])?
                .context("first delta")?;
        let second_contract =
            scan_openapi_repository(second_root.path(), &[PARENT_PROFILE.to_owned()])?
                .context("second delta")?;
        assert_eq!(first_contract, second_contract);
        let source = operation(
            std::slice::from_ref(&first_contract),
            CrossLanguageFormat::Openapi,
            "get /health",
        )?
        .1;
        let first_trace = trace(
            source.id.clone(),
            RuntimeHttpObservation {
                method: "GET".to_owned(),
                route_template: "/health".to_owned(),
                format: Some(RuntimeHttpOperationFormat::Openapi),
                operation: None,
                contract_locator: Some("api.json".to_owned()),
                format_version: Some("3.1.0".to_owned()),
            },
            "session-a",
        );
        let first = correlate_http_operations(&first_trace, std::slice::from_ref(&first_contract))?;
        let second =
            correlate_http_operations(&first_trace, std::slice::from_ref(&second_contract))?;
        assert_eq!(first, second);
        let reimport = correlate_http_operations(&first_trace, &first.deltas)?;
        assert_eq!(reimport.deltas, first.deltas);

        let another = correlate_http_operations(
            &trace(
                source.id.clone(),
                first_trace.events[0].http.clone().context("http")?,
                "session-b",
            ),
            &[first_contract],
        )?;
        assert_ne!(
            first.deltas[0]
                .edges
                .iter()
                .find(|edge| edge.phase == Phase::Runtime)
                .map(|edge| &edge.id),
            another.deltas[0]
                .edges
                .iter()
                .find(|edge| edge.phase == Phase::Runtime)
                .map(|edge| &edge.id)
        );
        Ok(())
    }

    fn operation<'a>(
        contracts: &'a [CrossLanguageAdapterDelta],
        format: CrossLanguageFormat,
        coordinate: &str,
    ) -> Result<(usize, &'a GraphNode)> {
        contracts
            .iter()
            .enumerate()
            .find_map(|(index, delta)| {
                delta
                    .nodes
                    .iter()
                    .find(|node| {
                        node.kind == "operation"
                            && operation_identity(node).is_ok_and(|identity| {
                                identity.format == format && identity.coordinate == coordinate
                            })
                    })
                    .map(|node| (index, node))
            })
            .context("fixture operation")
    }

    fn trace(
        source_id: String,
        http: RuntimeHttpObservation,
        session_id: &str,
    ) -> ValidatedRuntimeTrace {
        let target_input = RuntimeTraceLocator::External {
            namespace: "https".to_owned(),
            name: "api.example.test".to_owned(),
        };
        let mut trace = ValidatedRuntimeTrace {
            schema_version: crate::RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
            repository: RuntimeTraceRepository {
                identity: "repository".to_owned(),
                revision: Some("revision".to_owned()),
            },
            session: RuntimeTraceSession {
                id: session_id.to_owned(),
                started_at: "2026-07-26T00:00:00Z".to_owned(),
                ended_at: Some("2026-07-26T00:00:01Z".to_owned()),
                collector_contract_version: Some(
                    crate::RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
                ),
                profile: RuntimeTraceProfile {
                    language: "web".to_owned(),
                    target: None,
                    features: Vec::new(),
                    parent_profile_id: Some(PARENT_PROFILE.to_owned()),
                },
                environment: RuntimeTraceEnvironment {
                    name: "production".to_owned(),
                    runtime: Some("node-24".to_owned()),
                    region: Some("global".to_owned()),
                    environment_keys: Vec::new(),
                },
                redaction: RuntimeTraceRedaction::default(),
            },
            profile_match: RuntimeTraceProfileMatch {
                status: RuntimeTraceMatchStatus::Resolved,
                parent_profile_id: Some(PARENT_PROFILE.to_owned()),
                reason: None,
            },
            events: vec![ValidatedRuntimeTraceEvent {
                id: String::new(),
                sequence: 1,
                timestamp: "2026-07-26T00:00:00Z".to_owned(),
                dependency_kind: "requests".to_owned(),
                source: crate::MatchedRuntimeTraceLocator {
                    status: RuntimeTraceMatchStatus::Resolved,
                    node_id: Some(source_id.clone()),
                    reason: None,
                    input: RuntimeTraceLocator::Node { node_id: source_id },
                },
                target: crate::MatchedRuntimeTraceLocator {
                    status: RuntimeTraceMatchStatus::External,
                    node_id: None,
                    reason: Some("collector_external".to_owned()),
                    input: target_input,
                },
                http: Some(http),
                count: 1,
                duration_ns: Some(1),
                redaction: RuntimeTraceRedaction::default(),
            }],
            summary: RuntimeTraceSummary {
                events: 1,
                resolved_targets: 0,
                external_targets: 1,
                unresolved_targets: 0,
                redacted_values: 0,
            },
        };
        trace.events[0].id = crate::runtime_trace::expected_validated_runtime_event_id(
            &trace.repository,
            &trace.session,
            &trace.events[0],
        );
        trace
    }

    #[test]
    fn forged_validated_traces_and_unbounded_contract_sets_fail_closed() -> Result<()> {
        let root = tempdir()?;
        fs::write(
            root.path().join("api.json"),
            r#"{"openapi":"3.1.0","info":{"title":"api","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}"#,
        )?;
        let contract =
            scan_openapi_repository(root.path(), &[PARENT_PROFILE.to_owned()])?.context("delta")?;
        let source = operation(
            std::slice::from_ref(&contract),
            CrossLanguageFormat::Openapi,
            "get /health",
        )?
        .1;
        let source_id = source.id.clone();
        let mut forged = trace(
            source_id.clone(),
            RuntimeHttpObservation {
                method: "GET".to_owned(),
                route_template: "/health".to_owned(),
                format: Some(RuntimeHttpOperationFormat::Openapi),
                operation: None,
                contract_locator: Some("api.json".to_owned()),
                format_version: Some("3.1.0".to_owned()),
            },
            "session-a",
        );
        let secret = "fixture-secret-value";
        forged.events[0].target.input = RuntimeTraceLocator::External {
            namespace: "https".to_owned(),
            name: format!("user:{secret}@api.example.test"),
        };
        forged.events[0].id = crate::runtime_trace::expected_validated_runtime_event_id(
            &forged.repository,
            &forged.session,
            &forged.events[0],
        );
        let error = correlate_http_operations(&forged, std::slice::from_ref(&contract))
            .expect_err("forged validated trace must be rejected");
        assert!(!format!("{error:#}").contains(secret));

        let contracts = vec![contract; MAX_CORRELATION_CONTRACTS + 1];
        assert!(
            correlate_http_operations(
                &trace(
                    source_id,
                    RuntimeHttpObservation {
                        method: "GET".to_owned(),
                        route_template: "/health".to_owned(),
                        format: Some(RuntimeHttpOperationFormat::Openapi),
                        operation: None,
                        contract_locator: Some("api.json".to_owned()),
                        format_version: Some("3.1.0".to_owned()),
                    },
                    "session-a",
                ),
                &contracts
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn fixture_profiles_retain_the_parent_identity() -> Result<()> {
        let root = tempdir()?;
        fs::write(
            root.path().join("api.json"),
            r#"{"openapi":"3.1.0","info":{"title":"api","version":"1"},"paths":{}}"#,
        )?;
        let delta =
            scan_openapi_repository(root.path(), &[PARENT_PROFILE.to_owned()])?.context("delta")?;
        let identity: CrossLanguageProfileIdentity = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY].clone(),
        )?;
        assert_eq!(identity.participating_profile_ids, [PARENT_PROFILE]);
        Ok(())
    }
}
