use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_CONTRACT_PROPERTY,
    CROSS_LANGUAGE_CONTRACT_VERSION, CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY,
    CrossLanguageCanonicalIdentity, CrossLanguageCompletenessLedger,
    CrossLanguageEvidenceProperties, CrossLanguageFormat, CrossLanguageProfileIdentity,
    CrossLanguageRelationKind, ValidatedProtocol, build_cross_language_edge_id,
    build_cross_language_site_id, cross_language_node_id, cross_language_profile_id,
    has_cross_language_claim,
};
use serde_json::Value;

#[derive(Clone, Default)]
struct ObservedFormatCounts {
    nodes: u64,
    sites: u64,
    edges: u64,
    external: u64,
    unresolved: u64,
}

/// Independently rechecks a worker's claimed cross-language closure after the
/// protocol state machine has accepted the stream. The protocol crate owns the
/// normative contract; core intentionally repeats identity, closure, and count
/// checks before any worker output can reach the store.
pub fn validate_cross_language_worker_protocol(protocol: &ValidatedProtocol) -> Result<()> {
    if !has_cross_language_claim(protocol) {
        return Ok(());
    }

    let mut claimed_profiles = BTreeMap::new();
    for profile in protocol.profiles.values() {
        let claims = profile.language == "cross-language"
            || profile
                .properties
                .contains_key(CROSS_LANGUAGE_CONTRACT_PROPERTY);
        if !claims {
            continue;
        }
        if profile.language != "cross-language"
            || profile
                .properties
                .get(CROSS_LANGUAGE_CONTRACT_PROPERTY)
                .and_then(Value::as_str)
                != Some(CROSS_LANGUAGE_CONTRACT_VERSION)
        {
            bail!(
                "cross-language profile {} has an incompatible core claim",
                profile.id
            );
        }
        let identity: CrossLanguageProfileIdentity = property(
            &profile.properties,
            CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY,
        )
        .with_context(|| format!("cross-language profile {} identity", profile.id))?;
        if cross_language_profile_id(&identity) != profile.id {
            bail!(
                "cross-language profile {} fails the core identity check",
                profile.id
            );
        }
        for participant_id in &identity.participating_profile_ids {
            let participant = protocol.profiles.get(participant_id).with_context(|| {
                format!(
                    "cross-language profile {} references undeclared participating profile {}",
                    profile.id, participant_id
                )
            })?;
            if participant.language == "cross-language"
                || participant
                    .properties
                    .contains_key(CROSS_LANGUAGE_CONTRACT_PROPERTY)
            {
                bail!(
                    "cross-language profile {} uses cross-language profile {} as a participant",
                    profile.id,
                    participant_id
                );
            }
        }
        let ledger: CrossLanguageCompletenessLedger =
            property(&profile.properties, CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
                .with_context(|| format!("cross-language profile {} ledger", profile.id))?;
        let ledger_capabilities = ledger
            .entries
            .iter()
            .map(|entry| entry.capability.as_str())
            .collect::<Vec<_>>();
        if ledger_capabilities
            != identity
                .adapter_capability_versions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            bail!(
                "cross-language profile {} capability identity differs from its ledger",
                profile.id
            );
        }
        claimed_profiles.insert(profile.id.clone(), ledger);
    }
    if claimed_profiles.is_empty() {
        bail!("cross-language graph has no core-authorized profile");
    }

    let mut counts = BTreeMap::<(String, CrossLanguageFormat), ObservedFormatCounts>::new();
    let mut cross_node_ids = BTreeSet::new();
    for node in protocol.nodes.values() {
        let claims_by_profile = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .is_some_and(|profile_id| claimed_profiles.contains_key(profile_id));
        let claims_by_identity = node
            .properties
            .get("canonical_identity")
            .and_then(|identity| identity.get("contract_version"))
            .and_then(Value::as_str)
            == Some(CROSS_LANGUAGE_CONTRACT_VERSION);
        if !claims_by_profile && !claims_by_identity {
            continue;
        }
        let identity_value = node
            .properties
            .get("canonical_identity")
            .with_context(|| format!("cross-language node {} has no core identity", node.id))?;
        if identity_value
            .get("contract_version")
            .and_then(Value::as_str)
            != Some(CROSS_LANGUAGE_CONTRACT_VERSION)
        {
            bail!(
                "cross-language node {} has an incompatible core identity",
                node.id
            );
        }
        let identity: CrossLanguageCanonicalIdentity =
            serde_json::from_value(identity_value.clone())
                .with_context(|| format!("cross-language node {} identity", node.id))?;
        let kind = serde_json::from_value(Value::String(node.kind.clone()))
            .with_context(|| format!("cross-language node {} kind", node.id))?;
        if !claimed_profiles.contains_key(identity.profile_id.as_str())
            || cross_language_node_id(kind, &identity) != node.id
            || node.locator != format!("cross-language:{}", node.id)
        {
            bail!(
                "cross-language node {} fails the core identity/profile check",
                node.id
            );
        }
        cross_node_ids.insert(node.id.clone());
        counts
            .entry((identity.profile_id.clone(), identity.format))
            .or_default()
            .nodes += 1;
    }

    let mut cross_sites = BTreeMap::new();
    for site in protocol.sites.values() {
        if !claimed_profiles.contains_key(site.profile_id.as_str())
            && !cross_node_ids.contains(site.source.as_str())
            && !site
                .target_ids
                .iter()
                .any(|target| cross_node_ids.contains(target.as_str()))
        {
            continue;
        }
        let relation: CrossLanguageRelationKind =
            serde_json::from_value(Value::String(site.kind.clone()))
                .with_context(|| format!("cross-language site {} relation", site.id))?;
        let primary_evidence = site
            .evidence
            .first()
            .with_context(|| format!("cross-language site {} has no evidence", site.id))?;
        let evidence: CrossLanguageEvidenceProperties = serde_json::from_value(Value::Object(
            primary_evidence.properties.clone().into_iter().collect(),
        ))
        .with_context(|| format!("cross-language site {} evidence", site.id))?;
        if relation != evidence.occurrence_kind
            || evidence.profile_id != site.profile_id
            || build_cross_language_site_id(site).map_err(anyhow::Error::from)? != site.id
        {
            bail!(
                "cross-language dependency site {} fails the core identity/evidence check",
                site.id
            );
        }
        let entry = counts
            .entry((site.profile_id.clone(), evidence.format))
            .or_default();
        entry.sites += 1;
        match site.resolution_status {
            depgraph_protocol::ResolutionStatus::External => entry.external += 1,
            depgraph_protocol::ResolutionStatus::Unresolved => entry.unresolved += 1,
            _ => {}
        }
        cross_sites.insert(site.id.clone(), site);
    }

    let mut edge_targets_by_site = BTreeMap::<String, BTreeSet<String>>::new();
    for edge in protocol.edges.values() {
        if !claimed_profiles.contains_key(edge.profile_id.as_str())
            && !cross_node_ids.contains(edge.source.as_str())
            && !cross_node_ids.contains(edge.target.as_str())
        {
            continue;
        }
        let relation: CrossLanguageRelationKind =
            serde_json::from_value(Value::String(edge.kind.clone()))
                .with_context(|| format!("cross-language edge {} relation", edge.id))?;
        let site_id = edge
            .site_id
            .as_deref()
            .context("cross-language edge has no site")?;
        let site = cross_sites.get(site_id).with_context(|| {
            format!(
                "cross-language edge {} references an unauthorized site",
                edge.id
            )
        })?;
        let primary_evidence = edge
            .evidence
            .first()
            .with_context(|| format!("cross-language edge {} has no evidence", edge.id))?;
        let evidence: CrossLanguageEvidenceProperties = serde_json::from_value(Value::Object(
            primary_evidence.properties.clone().into_iter().collect(),
        ))
        .with_context(|| format!("cross-language edge {} evidence", edge.id))?;
        if relation != evidence.occurrence_kind
            || edge.kind != site.kind
            || edge.profile_id != site.profile_id
            || edge.condition != site.condition
            || edge.resolution_status != site.resolution_status
            || edge.precision != site.precision
            || edge.evidence != site.evidence
            || build_cross_language_edge_id(edge).map_err(anyhow::Error::from)? != edge.id
        {
            bail!(
                "cross-language edge {} fails the independent core closure check",
                edge.id
            );
        }
        edge_targets_by_site
            .entry(site_id.to_owned())
            .or_default()
            .insert(edge.target.clone());
        counts
            .entry((edge.profile_id.clone(), evidence.format))
            .or_default()
            .edges += 1;
    }
    for (site_id, site) in &cross_sites {
        let edge_targets = edge_targets_by_site
            .get(site_id)
            .cloned()
            .unwrap_or_default();
        let site_targets = site.target_ids.iter().cloned().collect::<BTreeSet<_>>();
        if edge_targets != site_targets {
            bail!(
                "cross-language dependency site {} has a mismatched core edge closure",
                site.id
            );
        }
    }

    for (profile_id, ledger) in claimed_profiles {
        for entry in ledger.entries {
            let observed = counts
                .get(&(profile_id.clone(), entry.format))
                .cloned()
                .unwrap_or_default();
            if entry.capability != entry.format.capability()
                || entry.node_count != observed.nodes
                || entry.site_count != observed.sites
                || entry.edge_count != observed.edges
                || entry.external_count != observed.external
                || entry.unresolved_count != observed.unresolved
            {
                bail!(
                    "cross-language profile {profile_id} capability {} fails the independent core count check",
                    entry.capability
                );
            }
        }
    }
    Ok(())
}

fn property<T: for<'de> serde::Deserialize<'de>>(
    properties: &depgraph_protocol::Properties,
    key: &str,
) -> Result<T> {
    serde_json::from_value(
        properties
            .get(key)
            .cloned()
            .with_context(|| format!("missing property {key}"))?,
    )
    .with_context(|| format!("invalid property {key}"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use depgraph_protocol::validate_safe_ndjson;

    use super::*;

    const GOLDEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../depgraph-protocol/tests/fixtures/protocol-v1.cross-language.golden.ndjson"
    ));

    #[test]
    fn core_independently_accepts_the_cross_format_golden_and_rejects_count_drift() {
        let protocol = validate_safe_ndjson(Cursor::new(GOLDEN)).unwrap();
        validate_cross_language_worker_protocol(&protocol).unwrap();

        let mut missing_identity = protocol.clone();
        missing_identity
            .nodes
            .values_mut()
            .next()
            .unwrap()
            .properties
            .remove("canonical_identity");
        assert!(validate_cross_language_worker_protocol(&missing_identity).is_err());

        let mut missing_site_evidence = protocol.clone();
        missing_site_evidence
            .sites
            .values_mut()
            .next()
            .unwrap()
            .evidence
            .clear();
        assert!(validate_cross_language_worker_protocol(&missing_site_evidence).is_err());

        let mut missing_edge_evidence = protocol.clone();
        missing_edge_evidence
            .edges
            .values_mut()
            .next()
            .unwrap()
            .evidence
            .clear();
        assert!(validate_cross_language_worker_protocol(&missing_edge_evidence).is_err());

        let mut missing_participant = protocol.clone();
        missing_participant.profiles.remove("web:production");
        assert!(validate_cross_language_worker_protocol(&missing_participant).is_err());

        let mut mismatched_targets = protocol.clone();
        let operation_targets = mismatched_targets
            .nodes
            .values()
            .filter(|node| node.kind == "operation")
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        let edge = mismatched_targets.edges.values_mut().next().unwrap();
        edge.target = operation_targets
            .into_iter()
            .find(|target| target != &edge.target)
            .unwrap();
        edge.id = build_cross_language_edge_id(edge).unwrap();
        assert!(validate_cross_language_worker_protocol(&mismatched_targets).is_err());

        let mut drifted = protocol;
        let profile = drifted.profiles.values_mut().next().unwrap();
        profile
            .properties
            .get_mut(CROSS_LANGUAGE_COMPLETENESS_PROPERTY)
            .unwrap()["entries"][0]["edge_count"] = Value::from(2);
        assert!(validate_cross_language_worker_protocol(&drifted).is_err());
    }
}
