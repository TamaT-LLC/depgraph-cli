use crate::{ADAPTER, ADAPTER_VERSION, ScanResult};
#[cfg(debug_assertions)]
use anyhow::Context;
use anyhow::Result;
#[cfg(debug_assertions)]
use depgraph_protocol::ProtocolValidator;
use depgraph_protocol::{
    CommonFields, DependencySiteEvent, DiagnosticEvent, EdgeUpsert, FileCompleted, NodeUpsert,
    ProfileCompleted, ProfileDeclared, ProtocolEvent, ScanCompleted, ScanStarted,
};

/// Stream a complete typed v1.0 event stream into `sink`, one event at a time,
/// and return how many events were emitted.
///
/// The scan result is consumed: each node, site, edge, and diagnostic moves
/// into its event, so the result and the event stream are never both resident.
/// This does not validate; `ProtocolValidator` retains every event it checks,
/// so validating callers wrap the sink themselves (see `build_events` and the
/// debug build of the worker binary). Release builds rely on the core, which
/// always validates the worker stream at its process trust boundary.
pub fn emit_events(
    scan_id: &str,
    result: ScanResult,
    mut sink: impl FnMut(ProtocolEvent) -> Result<()>,
) -> Result<u64> {
    let ScanResult {
        root,
        profile,
        nodes,
        sites,
        edges,
        diagnostics,
        files,
        coverage,
        performance: _,
    } = result;
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

    sink(ProtocolEvent::ScanStarted(ScanStarted {
        common: common(),
        root,
        project_code_executed: false,
        safe_mode: true,
    }))?;
    let profile_id = profile.id.clone();
    sink(ProtocolEvent::ProfileDeclared(ProfileDeclared {
        common: common(),
        profile,
    }))?;
    for node in nodes {
        sink(ProtocolEvent::NodeUpsert(NodeUpsert {
            common: common(),
            node,
        }))?;
    }
    for site in sites {
        sink(ProtocolEvent::DependencySite(DependencySiteEvent {
            common: common(),
            site,
        }))?;
    }
    for edge in edges {
        sink(ProtocolEvent::EdgeUpsert(EdgeUpsert {
            common: common(),
            edge,
        }))?;
    }
    for diagnostic in diagnostics {
        sink(ProtocolEvent::Diagnostic(DiagnosticEvent {
            common: common(),
            diagnostic,
        }))?;
    }
    for file in files {
        sink(ProtocolEvent::FileCompleted(FileCompleted {
            common: common(),
            skipped_sites: file.discovered_sites.saturating_sub(file.emitted_sites),
            path: file.path,
            discovered_sites: file.discovered_sites,
            emitted_sites: file.emitted_sites,
            skipped: file.skipped,
            reason: file.reason,
        }))?;
    }
    sink(ProtocolEvent::ProfileCompleted(ProfileCompleted {
        common: common(),
        profile_id,
        coverage: coverage.clone(),
    }))?;
    sink(ProtocolEvent::ScanCompleted(ScanCompleted {
        common: common(),
        coverage,
    }))?;
    Ok(seq)
}

/// Build a complete typed v1.0 event stream in memory.
///
/// Debug and test builds validate the producer contract here. The worker
/// binary streams with `emit_events` instead so it never holds the stream.
pub fn build_events(scan_id: &str, result: ScanResult) -> Result<Vec<ProtocolEvent>> {
    let mut events = Vec::new();
    #[cfg(debug_assertions)]
    let mut validator = ProtocolValidator::new();
    emit_events(scan_id, result, |event| {
        #[cfg(debug_assertions)]
        validator
            .push(event.clone())
            .context("Rust worker generated an invalid protocol event")?;
        events.push(event);
        Ok(())
    })?;
    #[cfg(debug_assertions)]
    validator
        .finish()
        .context("Rust worker generated an incomplete protocol stream")?;
    Ok(events)
}
