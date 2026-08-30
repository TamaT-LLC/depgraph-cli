use std::{collections::BTreeMap, io};

use anyhow::Result;
use depgraph_store::{GraphSnapshot, refresh_profile_matrix_view};

use crate::query::{GraphQueryFilter, render_condition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Dot,
    Mermaid,
    Graphml,
}

pub fn export(snapshot: &GraphSnapshot, format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Json => export_json(snapshot),
        ExportFormat::Dot => Ok(export_dot(snapshot)),
        ExportFormat::Mermaid => Ok(export_mermaid(snapshot)),
        ExportFormat::Graphml => {
            let mut output = Vec::new();
            crate::graphml::write_graphml(snapshot, &mut output)?;
            Ok(String::from_utf8(output)?)
        }
    }
}

pub fn export_filtered(
    snapshot: &GraphSnapshot,
    format: ExportFormat,
    filter: &GraphQueryFilter,
) -> Result<String> {
    if filter.is_empty() {
        return export(snapshot, format);
    }
    let filtered = filter_snapshot(snapshot, filter);
    export(&filtered, format)
}

pub fn export_filtered_to_writer<W: io::Write>(
    snapshot: &GraphSnapshot,
    format: ExportFormat,
    filter: &GraphQueryFilter,
    writer: &mut W,
) -> Result<()> {
    let filtered;
    let snapshot = if filter.is_empty() {
        snapshot
    } else {
        filtered = filter_snapshot(snapshot, filter);
        &filtered
    };
    match format {
        ExportFormat::Json => write_json(snapshot, writer),
        ExportFormat::Dot => write_dot(snapshot, writer),
        ExportFormat::Mermaid => write_mermaid(snapshot, writer),
        ExportFormat::Graphml => crate::graphml::write_graphml(snapshot, writer),
    }
}

pub fn export_graphml_filtered_to_writer<W: io::Write>(
    snapshot: &GraphSnapshot,
    filter: &GraphQueryFilter,
    writer: &mut W,
) -> Result<()> {
    if filter.is_empty() {
        return crate::graphml::write_graphml(snapshot, writer);
    }
    let filtered = filter_snapshot(snapshot, filter);
    crate::graphml::write_graphml(&filtered, writer)
}

pub fn filter_snapshot(snapshot: &GraphSnapshot, filter: &GraphQueryFilter) -> GraphSnapshot {
    if filter.is_empty() {
        return snapshot.clone();
    }
    let mut filtered = snapshot.clone();
    filtered
        .edges
        .retain(|edge| filter.matches_edge(snapshot, edge));
    let edge_ids = filtered
        .edges
        .iter()
        .map(|edge| edge.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let site_ids = filtered
        .edges
        .iter()
        .filter_map(|edge| edge.site_id.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    let node_ids = filtered
        .edges
        .iter()
        .flat_map(|edge| [edge.source.as_str(), edge.target.as_str()])
        .collect::<std::collections::BTreeSet<_>>();
    let mut profile_ids = filtered
        .edges
        .iter()
        .map(|edge| edge.profile_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    loop {
        let parents = snapshot
            .profiles
            .iter()
            .filter(|profile| profile_ids.contains(&profile.id))
            .filter_map(|profile| {
                profile
                    .properties
                    .get("parent_profile_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        let before = profile_ids.len();
        profile_ids.extend(parents);
        if profile_ids.len() == before {
            break;
        }
    }
    filtered
        .nodes
        .retain(|node| node_ids.contains(node.id.as_str()));
    filtered
        .sites
        .retain(|site| site_ids.contains(site.id.as_str()));
    filtered
        .profiles
        .retain(|profile| profile_ids.contains(&profile.id));
    filtered.evidence.retain(|evidence| {
        ((evidence.owner_type == "edge" && edge_ids.contains(evidence.owner_id.as_str()))
            || (evidence.owner_type == "site" && site_ids.contains(evidence.owner_id.as_str())))
            && filter.matches_evidence(evidence)
    });
    filtered
        .diagnostics
        .retain(|diagnostic| filter.matches_diagnostic(diagnostic));
    filtered.coverage.profiles = filtered.profiles.len() as u64;
    filtered.coverage.dependency_sites = filtered.sites.len() as u64;
    filtered.coverage.resolved = filtered
        .sites
        .iter()
        .filter(|site| site.resolution_status == "resolved")
        .count() as u64;
    filtered.coverage.candidates = filtered
        .sites
        .iter()
        .filter(|site| site.resolution_status == "candidates")
        .count() as u64;
    filtered.coverage.external = filtered
        .sites
        .iter()
        .filter(|site| site.resolution_status == "external")
        .count() as u64;
    filtered.coverage.unresolved = filtered
        .sites
        .iter()
        .filter(|site| site.resolution_status == "unresolved")
        .count() as u64;
    refresh_profile_matrix_view(&mut filtered);
    filtered
}

fn export_json(snapshot: &GraphSnapshot) -> Result<String> {
    let mut output = Vec::new();
    write_json(snapshot, &mut output)?;
    Ok(String::from_utf8(output)?)
}

fn write_json<W: io::Write>(snapshot: &GraphSnapshot, writer: &mut W) -> Result<()> {
    let mut sites = serde_json::to_value(&snapshot.sites)?;
    for site in sites.as_array_mut().into_iter().flatten() {
        if let Some(object) = site.as_object_mut()
            && let Some(condition) = object.get("condition")
        {
            object.insert(
                "condition_text".to_owned(),
                serde_json::Value::String(render_condition(condition)),
            );
        }
    }
    let mut edges = serde_json::to_value(&snapshot.edges)?;
    for edge in edges.as_array_mut().into_iter().flatten() {
        if let Some(object) = edge.as_object_mut()
            && let Some(condition) = object.get("condition")
        {
            object.insert(
                "condition_text".to_owned(),
                serde_json::Value::String(render_condition(condition)),
            );
        }
    }
    // Attempt identity, timestamps, absolute checkout roots, and worker logs
    // deliberately stay in `doctor`/the evidence store. This content envelope
    // is reproducible across scans of the same repository state.
    serde_json::to_writer_pretty(
        writer,
        &serde_json::json!({
            "schema_version":"1.0",
            "command":"export",
            "graph":{
                "profiles":snapshot.profiles,
                "nodes":snapshot.nodes,
                "sites":sites,
                "edges":edges,
                "evidence":snapshot.evidence,
                "diagnostics":snapshot.diagnostics,
                "file_coverage":snapshot.file_coverage,
                "coverage":snapshot.coverage,
                "profile_matrix":snapshot.profile_matrix,
            }
        }),
    )?;
    Ok(())
}

fn export_dot(snapshot: &GraphSnapshot) -> String {
    let mut output = Vec::new();
    write_dot(snapshot, &mut output).expect("writing a graph export to memory cannot fail");
    String::from_utf8(output).expect("DOT export is UTF-8")
}

fn write_dot<W: io::Write>(snapshot: &GraphSnapshot, output: &mut W) -> Result<()> {
    output.write_all(b"digraph depgraph {\n  rankdir=LR;\n")?;
    let observation_status = edge_observation_status(snapshot);
    for node in &snapshot.nodes {
        writeln!(
            output,
            "  \"{}\" [label=\"{}\\n({})\"];",
            dot_escape(&node.id),
            dot_escape(&node.display_name),
            dot_escape(&node.kind)
        )?;
    }
    for edge in &snapshot.edges {
        let observed = observation_status
            .get(edge.id.as_str())
            .map(|status| format!("; observed={status}"))
            .unwrap_or_default();
        let label = format!(
            "{} [{}; {}; {}; {}; {}{}]",
            edge.kind,
            edge.phase,
            edge.resolution_status,
            edge.precision,
            edge.profile_id,
            render_condition(&edge.condition),
            observed,
        );
        writeln!(
            output,
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_escape(&edge.source),
            dot_escape(&edge.target),
            dot_escape(&label)
        )?;
    }
    output.write_all(b"}\n")?;
    Ok(())
}

fn export_mermaid(snapshot: &GraphSnapshot) -> String {
    let mut output = Vec::new();
    write_mermaid(snapshot, &mut output).expect("writing a graph export to memory cannot fail");
    String::from_utf8(output).expect("Mermaid export is UTF-8")
}

fn write_mermaid<W: io::Write>(snapshot: &GraphSnapshot, output: &mut W) -> Result<()> {
    output.write_all(b"flowchart LR\n")?;
    let observation_status = edge_observation_status(snapshot);
    for (index, node) in snapshot.nodes.iter().enumerate() {
        writeln!(
            output,
            "  n{index}[\"{}\\n({})\"]",
            mermaid_escape(&node.display_name),
            mermaid_escape(&node.kind)
        )?;
    }
    let indexes = snapshot
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect::<std::collections::BTreeMap<_, _>>();
    for edge in &snapshot.edges {
        if let (Some(source), Some(target)) = (
            indexes.get(edge.source.as_str()),
            indexes.get(edge.target.as_str()),
        ) {
            let observed = observation_status
                .get(edge.id.as_str())
                .map(|status| format!("; observed={status}"))
                .unwrap_or_default();
            writeln!(
                output,
                "  n{source} -->|\"{} [{}; {}; {}; {}; {}{}]\"| n{target}",
                mermaid_escape(&edge.kind),
                mermaid_escape(&edge.phase),
                mermaid_escape(&edge.resolution_status),
                mermaid_escape(&edge.precision),
                mermaid_escape(&edge.profile_id),
                mermaid_escape(&render_condition(&edge.condition)),
                mermaid_escape(&observed)
            )?;
        }
    }
    Ok(())
}

fn edge_observation_status(snapshot: &GraphSnapshot) -> BTreeMap<&str, &str> {
    snapshot
        .profile_matrix
        .correlations
        .iter()
        .filter(|correlation| correlation.status != "unobserved")
        .flat_map(|correlation| {
            correlation
                .edge_ids_by_phase
                .values()
                .flatten()
                .map(move |edge_id| (edge_id.as_str(), correlation.status.as_str()))
        })
        .collect()
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn mermaid_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('|', "&#124;")
        .replace('`', "&#96;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use depgraph_store::{
        CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, ProfileCorrelationRecord, ScanRecord,
    };
    use serde_json::json;

    #[test]
    fn empty_exports_are_stable() -> Result<()> {
        let snapshot = GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: "/tmp".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "now".to_owned(),
                completed_at: Some("now".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
            },
            profiles: Vec::new(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        };
        assert_eq!(
            export(&snapshot, ExportFormat::Dot)?,
            "digraph depgraph {\n  rankdir=LR;\n}\n"
        );
        assert_eq!(export(&snapshot, ExportFormat::Mermaid)?, "flowchart LR\n");
        let first = export(&snapshot, ExportFormat::Json)?;
        let mut second_snapshot = snapshot.clone();
        second_snapshot.scan.id = "another-scan".to_owned();
        second_snapshot.scan.root = "/different/checkout".to_owned();
        second_snapshot.scan.started_at = "later".to_owned();
        let second = export(&second_snapshot, ExportFormat::Json)?;
        assert_eq!(first, second);
        assert!(!first.contains("another-scan"));
        assert!(!first.contains("/tmp"));
        assert_eq!(mermaid_escape("a|`<b>"), "a&#124;&#96;&lt;b&gt;");

        let mut layered = snapshot;
        layered.nodes = ["a", "b"]
            .into_iter()
            .map(|id| NodeRecord {
                id: id.to_owned(),
                kind: "file".to_owned(),
                locator: id.to_owned(),
                display_name: id.to_owned(),
                properties: json!({}),
            })
            .collect();
        layered.edges = ["build", "source"]
            .into_iter()
            .map(|phase| EdgeRecord {
                id: format!("edge:{phase}"),
                site_id: Some(format!("site:{phase}")),
                source: "a".to_owned(),
                target: "b".to_owned(),
                kind: "imports".to_owned(),
                phase: phase.to_owned(),
                environment: "server".to_owned(),
                profile_id: "web:server".to_owned(),
                resolution_status: "resolved".to_owned(),
                precision: if phase == "build" {
                    "observed"
                } else {
                    "exact"
                }
                .to_owned(),
                condition: json!({"op":"all","conditions":[]}),
                generated: phase == "build",
            })
            .collect();
        let dot = export(&layered, ExportFormat::Dot)?;
        let mermaid = export(&layered, ExportFormat::Mermaid)?;
        assert!(dot.contains("imports [build; resolved; observed; web:server; true]"));
        assert!(dot.contains("imports [source; resolved; exact; web:server; true]"));
        assert!(mermaid.contains("imports [build; resolved; observed; web:server; true]"));
        assert!(mermaid.contains("imports [source; resolved; exact; web:server; true]"));
        layered.profile_matrix.correlations = vec![ProfileCorrelationRecord {
            id: "correlation".to_owned(),
            effective_profile_id: "effective-profile".to_owned(),
            source: "a".to_owned(),
            kind: "import".to_owned(),
            specifier: "./b".to_owned(),
            status: "matched".to_owned(),
            condition_union: json!({"op":"all","conditions":[]}),
            conditions_by_phase: BTreeMap::new(),
            targets_by_phase: BTreeMap::new(),
            resolutions_by_phase: BTreeMap::new(),
            site_ids_by_phase: BTreeMap::new(),
            edge_ids_by_phase: BTreeMap::from([
                ("build".to_owned(), vec!["edge:build".to_owned()]),
                ("static".to_owned(), vec!["edge:source".to_owned()]),
            ]),
            difference_reasons: Vec::new(),
            diagnostic_id: None,
        }];
        let observed_dot = export(&layered, ExportFormat::Dot)?;
        let observed_mermaid = export(&layered, ExportFormat::Mermaid)?;
        assert_eq!(observed_dot.matches("observed=matched").count(), 2);
        assert_eq!(observed_mermaid.matches("observed=matched").count(), 2);

        layered.profile_matrix.correlations[0].status = "unobserved".to_owned();
        assert!(!export(&layered, ExportFormat::Dot)?.contains("observed="));
        assert!(!export(&layered, ExportFormat::Mermaid)?.contains("observed="));
        let first = export(&layered, ExportFormat::Json)?;
        layered.edges.reverse();
        layered.edges.sort_by(|left, right| left.id.cmp(&right.id));
        assert_eq!(first, export(&layered, ExportFormat::Json)?);
        Ok(())
    }
}
