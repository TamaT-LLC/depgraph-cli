use crate::{ADAPTER, ADAPTER_VERSION, ScanResult};
use anyhow::{Context, Result};
use depgraph_protocol::{
    CommonFields, DependencySiteEvent, DiagnosticEvent, EdgeUpsert, FileCompleted, NodeUpsert,
    ProfileCompleted, ProfileDeclared, ProtocolEvent, ProtocolValidator, ScanCompleted,
    ScanStarted,
};

/// Build a complete, typed, self-validated v1.0 event stream.
pub fn build_events(scan_id: &str, result: &ScanResult) -> Result<Vec<ProtocolEvent>> {
    let mut seq = 0_u64;
    let mut common = || {
        seq += 1;
        CommonFields {
            protocol_version: depgraph_protocol::PROTOCOL_VERSION.into(),
            scan_id: scan_id.into(),
            adapter: ADAPTER.into(),
            adapter_version: ADAPTER_VERSION.into(),
            seq,
        }
    };

    let mut events = vec![
        ProtocolEvent::ScanStarted(ScanStarted {
            common: common(),
            root: result.root.clone(),
            project_code_executed: false,
            safe_mode: true,
        }),
        ProtocolEvent::ProfileDeclared(ProfileDeclared {
            common: common(),
            profile: result.profile.clone(),
        }),
    ];
    events.extend(result.nodes.iter().cloned().map(|node| {
        ProtocolEvent::NodeUpsert(NodeUpsert {
            common: common(),
            node,
        })
    }));
    events.extend(result.sites.iter().cloned().map(|site| {
        ProtocolEvent::DependencySite(DependencySiteEvent {
            common: common(),
            site,
        })
    }));
    events.extend(result.edges.iter().cloned().map(|edge| {
        ProtocolEvent::EdgeUpsert(EdgeUpsert {
            common: common(),
            edge,
        })
    }));
    events.extend(result.diagnostics.iter().cloned().map(|diagnostic| {
        ProtocolEvent::Diagnostic(DiagnosticEvent {
            common: common(),
            diagnostic,
        })
    }));
    events.extend(result.files.iter().map(|file| {
        ProtocolEvent::FileCompleted(FileCompleted {
            common: common(),
            path: file.path.clone(),
            discovered_sites: file.discovered_sites,
            emitted_sites: file.emitted_sites,
            skipped_sites: file.discovered_sites.saturating_sub(file.emitted_sites),
            skipped: file.skipped,
            reason: file.reason.clone(),
        })
    }));
    events.push(ProtocolEvent::ProfileCompleted(ProfileCompleted {
        common: common(),
        profile_id: result.profile.id.clone(),
        coverage: result.coverage.clone(),
    }));
    events.push(ProtocolEvent::ScanCompleted(ScanCompleted {
        common: common(),
        coverage: result.coverage.clone(),
    }));

    let mut validator = ProtocolValidator::new();
    for event in events.iter().cloned() {
        validator
            .push(event)
            .context("Rust worker generated an invalid protocol event")?;
    }
    validator
        .finish()
        .context("Rust worker generated an incomplete protocol stream")?;
    Ok(events)
}
