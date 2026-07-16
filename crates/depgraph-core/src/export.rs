use std::fmt::Write;

use anyhow::Result;
use depgraph_store::GraphSnapshot;

use crate::query::render_condition;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Dot,
    Mermaid,
}

pub fn export(snapshot: &GraphSnapshot, format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Json => export_json(snapshot),
        ExportFormat::Dot => Ok(export_dot(snapshot)),
        ExportFormat::Mermaid => Ok(export_mermaid(snapshot)),
    }
}

fn export_json(snapshot: &GraphSnapshot) -> Result<String> {
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
    Ok(serde_json::to_string_pretty(&serde_json::json!({
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
        }
    }))?)
}

fn export_dot(snapshot: &GraphSnapshot) -> String {
    let mut output = String::from("digraph depgraph {\n  rankdir=LR;\n");
    for node in &snapshot.nodes {
        let _ = writeln!(
            output,
            "  \"{}\" [label=\"{}\\n({})\"];",
            dot_escape(&node.id),
            dot_escape(&node.display_name),
            dot_escape(&node.kind)
        );
    }
    for edge in &snapshot.edges {
        let label = format!(
            "{} [{}; {}; {}; {}]",
            edge.kind,
            edge.resolution_status,
            edge.precision,
            edge.profile_id,
            render_condition(&edge.condition)
        );
        let _ = writeln!(
            output,
            "  \"{}\" -> \"{}\" [label=\"{}\"];",
            dot_escape(&edge.source),
            dot_escape(&edge.target),
            dot_escape(&label)
        );
    }
    output.push_str("}\n");
    output
}

fn export_mermaid(snapshot: &GraphSnapshot) -> String {
    let mut output = String::from("flowchart LR\n");
    for (index, node) in snapshot.nodes.iter().enumerate() {
        let _ = writeln!(
            output,
            "  n{index}[\"{}\\n({})\"]",
            mermaid_escape(&node.display_name),
            mermaid_escape(&node.kind)
        );
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
            let _ = writeln!(
                output,
                "  n{source} -->|\"{} [{}; {}; {}; {}]\"| n{target}",
                mermaid_escape(&edge.kind),
                mermaid_escape(&edge.resolution_status),
                mermaid_escape(&edge.precision),
                mermaid_escape(&edge.profile_id),
                mermaid_escape(&render_condition(&edge.condition))
            );
        }
    }
    output
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
    use depgraph_store::{CoverageRecord, GraphSnapshot, ScanRecord};

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
        Ok(())
    }
}
