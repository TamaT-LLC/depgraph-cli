use std::{io::BufRead, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    Evidence, EvidenceKind, Phase, Precision, ResolutionStatus, ValidatedProtocol,
    validate_build_ndjson,
};
use depgraph_store::{GraphSnapshot, Store, canonical_effective_input_id};
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

use crate::{
    BuildAudit, BuildOutcomeKind, WebBuildObservation,
    worker::{
        copy_safe_environment, locate_web_build_runtime, process_argument_path,
        resolve_safe_executable,
    },
};

const BUILD_EVIDENCE_CONVERTER: &str = "depgraph-web-build-evidence.mjs";
const MAX_CONVERTER_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONVERTER_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const FRAMEWORK_BUILD_NODE_KINDS: &[&str] = &[
    "route",
    "component",
    "server_function",
    "middleware",
    "module",
    "symbol",
    "file",
    "unknown_target",
];
const FRAMEWORK_BUILD_RELATION_KINDS: &[&str] = &[
    "renders",
    "hydrates",
    "emits",
    "loads",
    "imports",
    "dynamic_imports",
    "routes_in_phase",
    "route_entry",
    "parent_route",
    "before_load",
    "navigates_to",
    "masks_to",
    "observes_definition",
    "client_stub_for",
    "handled_by",
    "uses_middleware",
];
const FRAMEWORK_BUILD_UNRESOLVED_REASONS: &[&str] = &[
    "framework_build_incomplete",
    "framework_build_version_unsupported",
    "framework_build_manifest_missing",
    "framework_build_hook_missing",
    "framework_build_dynamic_target_unmatched",
    "framework_build_generated_identity_conflict",
];

/// Applies the core trust boundary to untrusted observer NDJSON. The caller can
/// inspect the validated value, but no store mutation occurs during validation.
pub fn validate_build_evidence(reader: impl BufRead) -> Result<ValidatedProtocol> {
    validate_build_ndjson(reader).context("build evidence rejected by protocol/core validation")
}

/// Validates the complete observer output and stages it atomically in an
/// already-created build attempt. Store-level audit matching and base-graph
/// overwrite checks run before any delta bytes are committed.
pub fn stage_build_evidence(
    store: &mut Store,
    attempt_id: &str,
    reader: impl BufRead,
) -> Result<()> {
    let protocol = validate_build_evidence(reader)?;
    store
        .save_build_delta(attempt_id, &protocol)
        .context("build evidence rejected by store union validation")
}

fn required_string_property<'a>(
    properties: &'a std::collections::BTreeMap<String, Value>,
    field: &str,
    owner: &str,
) -> Result<&'a str> {
    properties
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{owner} has no non-empty {field}"))
}

fn validate_framework_build_evidence(
    evidence: &[Evidence],
    profile_id: &str,
    framework: &str,
    observer: &str,
    observer_version: &str,
    capability: &str,
    owner: &str,
) -> Result<()> {
    let primary = evidence
        .first()
        .with_context(|| format!("{owner} has no primary evidence"))?;
    if primary.kind != EvidenceKind::Build
        || primary.extractor != observer
        || primary.extractor_version != observer_version
        || primary.properties.get("framework").and_then(Value::as_str) != Some(framework)
        || primary.properties.get("capability").and_then(Value::as_str) != Some(capability)
        || primary
            .properties
            .get("contract_version")
            .and_then(Value::as_str)
            != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
        || primary.properties.get("profile_id").and_then(Value::as_str) != Some(profile_id)
    {
        bail!("{owner} has incompatible framework build evidence provenance");
    }
    Ok(())
}

/// Enforces the shared dynamic framework graph contract on trusted Web
/// converter output after protocol validation and before any store mutation.
pub fn validate_framework_build_evidence_contract(protocol: &ValidatedProtocol) -> Result<()> {
    let (profile_id, profile) = protocol
        .profiles
        .iter()
        .next()
        .context("framework build graph declares no profile")?;
    if protocol.profiles.len() != 1 {
        bail!("framework build graph must declare exactly one profile");
    }
    let framework =
        required_string_property(&profile.properties, "framework", "framework build profile")?;
    let observer =
        required_string_property(&profile.properties, "observer", "framework build profile")?;
    let observer_version = required_string_property(
        &profile.properties,
        "observer_version",
        "framework build profile",
    )?;
    let capability = required_string_property(
        &profile.properties,
        "framework_build_capability",
        "framework build profile",
    )?;
    let expected = crate::framework_build_capability_contract()
        .into_iter()
        .find(|entry| entry.framework == framework)
        .context("framework build profile declares an unsupported framework")?;
    if observer != expected.observer
        || observer_version != expected.observer_version
        || capability != expected.capability
        || profile
            .features
            .iter()
            .filter(|feature| feature.as_str() == crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
            .count()
            != 1
        || profile
            .features
            .iter()
            .filter(|feature| feature.as_str() == capability)
            .count()
            != 1
        || profile
            .properties
            .get("framework_build_graph_contract_version")
            .and_then(Value::as_str)
            != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
    {
        bail!("framework build profile has an incompatible versioned contract");
    }
    for (property, actual) in [
        ("framework_build_node_count", protocol.nodes.len()),
        ("framework_build_site_count", protocol.sites.len()),
        ("framework_build_edge_count", protocol.edges.len()),
        (
            "framework_build_diagnostic_count",
            protocol.diagnostics.len(),
        ),
    ] {
        let declared = profile
            .properties
            .get(property)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok())
            .with_context(|| format!("framework build profile has invalid {property}"))?;
        if declared != actual {
            bail!("framework build profile {property}={declared} but emitted {actual}");
        }
    }

    for node in protocol.nodes.values().filter(|node| {
        node.properties
            .get("build_generated")
            .and_then(Value::as_bool)
            == Some(true)
    }) {
        if !FRAMEWORK_BUILD_NODE_KINDS.contains(&node.kind.as_str())
            || node.properties.get("framework").and_then(Value::as_str) != Some(framework)
            || node
                .properties
                .get("framework_build_contract_version")
                .and_then(Value::as_str)
                != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
        {
            bail!(
                "framework build generated node {} has an incompatible contract",
                node.id
            );
        }
        let identity = node
            .properties
            .get("build_identity")
            .and_then(Value::as_object)
            .with_context(|| {
                format!(
                    "framework build generated node {} has no build identity",
                    node.id
                )
            })?;
        let provenance = node
            .properties
            .get("build_provenance")
            .and_then(Value::as_object)
            .with_context(|| {
                format!(
                    "framework build generated node {} has no build provenance",
                    node.id
                )
            })?;
        if identity.get("contract_version").and_then(Value::as_str)
            != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
            || identity.get("framework").and_then(Value::as_str) != Some(framework)
            || provenance.get("framework").and_then(Value::as_str) != Some(framework)
            || provenance.get("observer").and_then(Value::as_str) != Some(observer)
            || provenance.get("observer_version").and_then(Value::as_str) != Some(observer_version)
            || provenance.get("capability").and_then(Value::as_str) != Some(capability)
            || provenance.get("contract_version").and_then(Value::as_str)
                != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
            || provenance.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        {
            bail!(
                "framework build generated node {} has incompatible identity provenance",
                node.id
            );
        }
    }

    for site in protocol.sites.values() {
        if !FRAMEWORK_BUILD_RELATION_KINDS.contains(&site.kind.as_str())
            || site.profile_id != *profile_id
            || site.precision != Precision::Observed
            || !matches!(
                site.resolution_status,
                ResolutionStatus::Resolved | ResolutionStatus::Unresolved
            )
        {
            bail!(
                "framework build dependency site {} has an incompatible graph shape",
                site.id
            );
        }
        validate_framework_build_evidence(
            &site.evidence,
            profile_id,
            framework,
            observer,
            observer_version,
            capability,
            &format!("framework build dependency site {}", site.id),
        )?;
        if site.resolution_status == ResolutionStatus::Unresolved
            && site
                .reason
                .as_deref()
                .is_none_or(|reason| !FRAMEWORK_BUILD_UNRESOLVED_REASONS.contains(&reason))
        {
            bail!(
                "framework build unresolved site {} has an unbounded reason",
                site.id
            );
        }
    }
    for edge in protocol.edges.values() {
        if !FRAMEWORK_BUILD_RELATION_KINDS.contains(&edge.kind.as_str())
            || edge.phase != Phase::Build
            || edge.profile_id != *profile_id
            || edge.precision != Precision::Observed
            || !matches!(
                edge.resolution_status,
                ResolutionStatus::Resolved | ResolutionStatus::Unresolved
            )
        {
            bail!(
                "framework build edge {} has an incompatible graph shape",
                edge.id
            );
        }
        validate_framework_build_evidence(
            &edge.evidence,
            profile_id,
            framework,
            observer,
            observer_version,
            capability,
            &format!("framework build edge {}", edge.id),
        )?;
    }
    for diagnostic in protocol.diagnostics.values() {
        if diagnostic.profile_id.as_deref() != Some(profile_id)
            || diagnostic
                .properties
                .get("framework")
                .and_then(Value::as_str)
                != Some(framework)
            || diagnostic
                .properties
                .get("capability")
                .and_then(Value::as_str)
                != Some(capability)
            || diagnostic
                .properties
                .get("contract_version")
                .and_then(Value::as_str)
                != Some(crate::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
        {
            bail!(
                "framework build diagnostic {} has incompatible provenance",
                diagnostic.id
            );
        }
        if !diagnostic.evidence.is_empty() {
            validate_framework_build_evidence(
                &diagnostic.evidence,
                profile_id,
                framework,
                observer,
                observer_version,
                capability,
                &format!("framework build diagnostic {}", diagnostic.id),
            )?;
        }
    }
    Ok(())
}

/// Converts a validated Web observation with a release-attested runtime. The
/// converter runs after project code has exited and receives only the safe
/// base graph, redacted observation, and supervisor provenance.
pub async fn web_build_protocol_ndjson(
    snapshot: &GraphSnapshot,
    audit: &BuildAudit,
    observation: &WebBuildObservation,
) -> Result<Vec<u8>> {
    if audit.outcome != BuildOutcomeKind::Completed
        || audit.adapter != observation.adapter.observer()
        || audit.adapter_version != observation.adapter.observer_version()
    {
        bail!("Web build observation contract does not match its completed audit");
    }
    let output_digest = audit
        .validated_output_digest
        .as_deref()
        .context("completed Web build has no validated output digest")?;
    let mut parents = snapshot
        .profiles
        .iter()
        .filter(|profile| {
            matches!(
                profile.language.as_str(),
                "web" | "typescript" | "javascript"
            ) && profile
                .properties
                .get("profile_phase")
                .and_then(serde_json::Value::as_str)
                != Some("build")
        })
        .collect::<Vec<_>>();
    parents.sort_by(|left, right| left.id.cmp(&right.id));
    let parent = match parents.as_slice() {
        [parent] => *parent,
        [] => bail!("Web build observation has no compatible safe parent profile"),
        _ => bail!("Web build observation has multiple compatible safe parent profiles"),
    };
    let input = serde_json::to_vec(&json!({
        "adapter": observation.adapter.key(),
        "root": ".",
        "source_revision": snapshot.scan.source_revision.as_deref().unwrap_or("unknown"),
        "observation": observation.observation,
        "provenance": {
            "build_run_id": audit.run_id,
            "profile_id": audit.profile_id,
            "command_plan_digest": audit.command_plan_digest,
            "toolchain_executable_digest": audit.toolchain_executable_digest,
            "environment_key_set_digest": audit.environment_key_set_digest,
            "validated_output_digest": output_digest,
        },
        "base_nodes": snapshot.nodes,
        "base_edges": snapshot.edges,
        "base_diagnostic_ids": snapshot.diagnostics.iter().map(|diagnostic| &diagnostic.id).collect::<Vec<_>>(),
        "profile": {
            "parent_profile_id": parent.id,
            "effective_input_id": canonical_effective_input_id(parent),
            "environment": parent.environment,
        },
    }))?;
    if input.len() > MAX_CONVERTER_INPUT_BYTES {
        bail!("Web build evidence converter input exceeds its byte limit");
    }

    let project_root = Path::new(&snapshot.scan.root);
    let converter = locate_web_build_runtime(BUILD_EVIDENCE_CONVERTER, project_root)?;
    let node = resolve_safe_executable("node", project_root)?;
    let mut command = Command::new(node);
    command
        .arg(process_argument_path(&converter))
        .current_dir(project_root)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    copy_safe_environment(&mut command, project_root)?;
    let mut child = command
        .spawn()
        .context("failed to start Web build evidence converter")?;
    let mut stdin = child
        .stdin
        .take()
        .context("Web build evidence converter stdin is unavailable")?;
    let writer = tokio::spawn(async move {
        stdin.write_all(&input).await?;
        stdin.shutdown().await
    });
    let output = timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .context("Web build evidence converter timed out")??;
    writer
        .await
        .context("Web build evidence converter input task failed")??;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_CONVERTER_OUTPUT_BYTES
    {
        bail!("Web build evidence converter rejected the observation");
    }
    let protocol = validate_build_evidence(std::io::Cursor::new(&output.stdout))?;
    validate_framework_build_evidence_contract(&protocol)
        .context("Web build evidence rejected by the framework graph contract")?;
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_protocol::Profile;
    use serde_json::json;
    use std::{collections::BTreeMap, io::Cursor};

    #[test]
    fn core_rejects_unauthorized_build_stream_before_store_mutation() {
        let coverage = json!({
            "profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,
            "dependency_sites":0,"resolved":0,"candidates":0,"external":0,
            "unresolved":0,"unsupported_syntax":0,"project_code_executed":false,
            "completeness":[],"reasons":[]
        });
        let lines = [
            json!({
                "event":"scan_started","protocol_version":"1.0","scan_id":"build-1",
                "adapter":"observer","adapter_version":"1.0.0","seq":1,
                "root":"/fixture","project_code_executed":false,"safe_mode":true
            }),
            json!({
                "event":"scan_completed","protocol_version":"1.0","scan_id":"build-1",
                "adapter":"observer","adapter_version":"1.0.0","seq":2,
                "coverage":coverage
            }),
        ]
        .into_iter()
        .map(|event| serde_json::to_string(&event).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

        let error = validate_build_evidence(Cursor::new(lines)).unwrap_err();
        assert!(error.to_string().contains("protocol/core"));
    }

    #[test]
    fn core_requires_the_versioned_framework_build_profile_contract() -> Result<()> {
        let profile: Profile = serde_json::from_value(json!({
            "id":"profile:build",
            "language":"typescript",
            "features":[
                "framework-build-graph-v1",
                "next-adapter-api-16.2-v1"
            ],
            "environment":{"mode":"production"},
            "properties":{
                "framework":"next",
                "observer":"next-adapter-observer",
                "observer_version":"0.2.0",
                "framework_build_capability":"next-adapter-api-16.2-v1",
                "framework_build_graph_contract_version":"framework-build-graph-v1",
                "framework_build_node_count":"0",
                "framework_build_site_count":"0",
                "framework_build_edge_count":"0",
                "framework_build_diagnostic_count":"0"
            }
        }))?;
        let protocol = ValidatedProtocol {
            events: Vec::new(),
            profiles: BTreeMap::from([(profile.id.clone(), profile)]),
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            sites: BTreeMap::new(),
            diagnostics: BTreeMap::new(),
        };
        validate_framework_build_evidence_contract(&protocol)?;

        let mut drifted = protocol.clone();
        drifted
            .profiles
            .get_mut("profile:build")
            .context("test profile")?
            .properties
            .insert(
                "framework_build_graph_contract_version".to_owned(),
                json!("framework-build-graph-v2"),
            );
        assert!(
            validate_framework_build_evidence_contract(&drifted)
                .unwrap_err()
                .to_string()
                .contains("versioned contract")
        );

        let mut capability_drifted = protocol;
        capability_drifted
            .profiles
            .get_mut("profile:build")
            .context("test profile")?
            .properties
            .insert(
                "framework_build_capability".to_owned(),
                json!("next-adapter-api-16.2-v9"),
            );
        assert!(
            validate_framework_build_evidence_contract(&capability_drifted)
                .unwrap_err()
                .to_string()
                .contains("versioned contract")
        );
        Ok(())
    }
}
