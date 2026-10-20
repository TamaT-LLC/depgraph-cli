use crate::{ADAPTER, ADAPTER_VERSION, ScanResult};
#[cfg(debug_assertions)]
use anyhow::Context;
use anyhow::Result;
#[cfg(debug_assertions)]
use depgraph_protocol::ProtocolValidator;
use depgraph_protocol::{
    CommonFields, DependencySite, DependencySiteEvent, DiagnosticEvent, EdgeUpsert, Evidence,
    FileCompleted, NodeUpsert, ProfileCompleted, ProfileDeclared, ProtocolEvent, ScanCompleted,
    ScanStarted,
};
use std::collections::HashMap;

/// Stream a complete typed v1.0 event stream into `sink`, one event at a time,
/// and return how many events were emitted.
///
/// The scan result is consumed: each node, site, edge, and diagnostic moves
/// into its event, so the result and the event stream are never both resident.
/// A site-linked edge with empty `evidence` shares its site's evidence (see
/// `scan_with_options_for_emit`) and is emitted with a copy of it, so the
/// stream is the same whether or not the result shares site evidence.
/// This does not validate; `ProtocolValidator` retains every event it checks,
/// so validating callers wrap the sink themselves (see `build_events` and the
/// debug build of the worker binary). Release builds rely on the core, which
/// always validates the worker stream at its process trust boundary.
pub fn emit_events(
    scan_id: &str,
    result: ScanResult,
    mut sink: impl FnMut(ProtocolEvent) -> Result<()>,
) -> Result<u64> {
    stream_events(scan_id, result, EventSink::Owned(&mut sink))
}

/// Stream the same event stream as [`emit_events`] to a sink that only
/// borrows each event, such as a serializer.
///
/// Because the sink hands each event back, the evidence of a site whose
/// edges share it moves from the site event to those edges after the site is
/// written, instead of being copied while every site is written (#578).
pub fn write_events(
    scan_id: &str,
    result: ScanResult,
    mut sink: impl FnMut(&ProtocolEvent) -> Result<()>,
) -> Result<u64> {
    stream_events(scan_id, result, EventSink::Borrowed(&mut sink))
}

enum EventSink<'a> {
    Owned(&'a mut dyn FnMut(ProtocolEvent) -> Result<()>),
    Borrowed(&'a mut dyn FnMut(&ProtocolEvent) -> Result<()>),
}

impl EventSink<'_> {
    fn send(&mut self, event: ProtocolEvent) -> Result<()> {
        match self {
            Self::Owned(sink) => sink(event),
            Self::Borrowed(sink) => sink(&event),
        }
    }

    /// Sends a site event and returns the site's evidence for its edges.
    fn send_site_keeping_evidence(
        &mut self,
        common: CommonFields,
        site: DependencySite,
    ) -> Result<Vec<Evidence>> {
        match self {
            Self::Owned(sink) => {
                let evidence = site.evidence.clone();
                sink(ProtocolEvent::DependencySite(DependencySiteEvent {
                    common,
                    site,
                }))?;
                Ok(evidence)
            }
            Self::Borrowed(sink) => {
                let event = DependencySiteEvent { common, site };
                let event = ProtocolEvent::DependencySite(event);
                sink(&event)?;
                let ProtocolEvent::DependencySite(event) = event else {
                    unreachable!("the site event is returned unchanged");
                };
                Ok(event.site.evidence)
            }
        }
    }
}

fn stream_events(scan_id: &str, result: ScanResult, mut sink: EventSink<'_>) -> Result<u64> {
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

    sink.send(ProtocolEvent::ScanStarted(ScanStarted {
        common: common(),
        root,
        project_code_executed: false,
        safe_mode: true,
    }))?;
    let profile_id = profile.id.clone();
    sink.send(ProtocolEvent::ProfileDeclared(ProfileDeclared {
        common: common(),
        profile,
    }))?;
    for node in nodes {
        sink.send(ProtocolEvent::NodeUpsert(NodeUpsert {
            common: common(),
            node,
        }))?;
    }
    // Sites whose edges share their evidence, with the number of such edges.
    let mut shared_edges = HashMap::<String, usize>::new();
    for edge in &edges {
        if edge.evidence.is_empty()
            && let Some(site_id) = &edge.site_id
        {
            *shared_edges.entry(site_id.clone()).or_default() += 1;
        }
    }
    let mut shared_evidence = HashMap::<String, (Vec<Evidence>, usize)>::new();
    for site in sites {
        if let Some(edge_count) = shared_edges.remove(&site.id) {
            let site_id = site.id.clone();
            let evidence = sink.send_site_keeping_evidence(common(), site)?;
            shared_evidence.insert(site_id, (evidence, edge_count));
        } else {
            sink.send(ProtocolEvent::DependencySite(DependencySiteEvent {
                common: common(),
                site,
            }))?;
        }
    }
    for mut edge in edges {
        if edge.evidence.is_empty()
            && let Some(site_id) = &edge.site_id
            && let Some((evidence, remaining)) = shared_evidence.get_mut(site_id)
        {
            *remaining -= 1;
            if *remaining == 0 {
                edge.evidence = shared_evidence
                    .remove(site_id)
                    .map(|(evidence, _)| evidence)
                    .unwrap_or_default();
            } else {
                edge.evidence.clone_from(evidence);
            }
        }
        sink.send(ProtocolEvent::EdgeUpsert(EdgeUpsert {
            common: common(),
            edge,
        }))?;
    }
    for diagnostic in diagnostics {
        sink.send(ProtocolEvent::Diagnostic(DiagnosticEvent {
            common: common(),
            diagnostic,
        }))?;
    }
    for file in files {
        sink.send(ProtocolEvent::FileCompleted(FileCompleted {
            common: common(),
            skipped_sites: file.discovered_sites.saturating_sub(file.emitted_sites),
            path: file.path,
            discovered_sites: file.discovered_sites,
            emitted_sites: file.emitted_sites,
            skipped: file.skipped,
            reason: file.reason,
        }))?;
    }
    sink.send(ProtocolEvent::ProfileCompleted(ProfileCompleted {
        common: common(),
        profile_id,
        coverage: coverage.clone(),
    }))?;
    sink.send(ProtocolEvent::ScanCompleted(ScanCompleted {
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
