use std::io::BufRead;

use anyhow::{Context, Result};
use depgraph_protocol::{ValidatedProtocol, validate_build_ndjson};
use depgraph_store::Store;

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
