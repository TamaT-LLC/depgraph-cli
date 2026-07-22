use std::{io::BufRead, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{ValidatedProtocol, validate_build_ndjson};
use depgraph_store::{GraphSnapshot, Store, canonical_effective_input_id};
use serde_json::json;
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
        || audit.adapter_version != crate::build::WEB_BUILD_OBSERVER_VERSION
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
    validate_build_evidence(std::io::Cursor::new(&output.stdout))?;
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

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
}
