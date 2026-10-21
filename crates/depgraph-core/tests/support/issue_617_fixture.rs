//! A generated snapshot shaped like a mixed TypeScript / Rust repository of
//! about 250 files, shared by the core, CLI, and MCP regression tests of
//! Issues #617 / #618.
//!
//! The default shape has 25,251 nodes, 23,500 dependency sites (6,750 of them
//! unresolved), 30,000 edges, and 53,500 evidence records. Before the fix,
//! indexing it counted 130,501 work items for unresolved listing and 55,751
//! for file-level cycles against the default `max_traversal` of 50,000.

use std::path::Path;

use anyhow::Result;
use depgraph_store::Store;
use serde_json::json;

/// Shape of a generated snapshot shaped like a mixed TS/Rust repository of
/// about 250 files: most dependency sites resolve to symbols in other files,
/// a fixed share stays unresolved, and files import each other in rings.
#[derive(Clone, Copy)]
pub struct Issue617Shape {
    pub files: usize,
    pub symbols_per_file: usize,
    pub sites_per_file: usize,
    pub unresolved_per_file: usize,
    pub contains_per_file: usize,
    pub ring: usize,
}

impl Issue617Shape {
    pub const MID_SIZED: Self = Self {
        files: 250,
        symbols_per_file: 100,
        sites_per_file: 94,
        unresolved_per_file: 27,
        contains_per_file: 25,
        ring: 10,
    };
}

pub fn seed_issue_617_graph(
    store: &mut Store,
    root: &Path,
    shape: Issue617Shape,
) -> Result<String> {
    let scan_id = "issue-617";
    store.start_scan_with_revision(scan_id, root, false, Some("revision-617"))?;
    let sites = shape.files * shape.sites_per_file;
    let unresolved = shape.files * shape.unresolved_per_file;
    let coverage = json!({
        "profiles": 1,
        "files_discovered": shape.files,
        "files_analyzed": shape.files,
        "files_skipped": 0,
        "dependency_sites": sites,
        "resolved": sites - unresolved,
        "candidates": 0,
        "external": 0,
        "unresolved": unresolved,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let mut seq = 0_u64;
    let mut common = |event: &str| {
        seq += 1;
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let evidence = |path: &str, line: usize| {
        json!([{
            "kind": "semantic",
            "extractor": "fixture",
            "extractor_version": "1.0",
            "path": path,
            "start_line": line + 1,
            "start_column": 1,
            "end_line": line + 1,
            "end_column": 2,
            "properties": {}
        }])
    };
    let mut events = Vec::new();
    let mut started = common("scan_started");
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    events.push(started);
    let mut profile = common("profile_declared");
    profile["profile"] = json!({
        "id": "fixture:mixed",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {}
    });
    events.push(profile);
    let file_id = |file: usize| format!("file:{file:04}");
    let symbol_id = |file: usize, symbol: usize| format!("symbol:{file:04}:{symbol:03}");
    let file_path = |file: usize| format!("src/m{file:04}.ts");
    for file in 0..shape.files {
        let mut node = common("node_upsert");
        node["node"] = json!({
            "id": file_id(file),
            "kind": "file",
            "locator": format!("file:{}", file_path(file)),
            "display_name": file_path(file),
            "properties": {"path": file_path(file)}
        });
        events.push(node);
        for symbol in 0..shape.symbols_per_file {
            let mut node = common("node_upsert");
            node["node"] = json!({
                "id": symbol_id(file, symbol),
                "kind": "symbol",
                "locator": format!("symbol:{}#s{symbol:03}", file_path(file)),
                "display_name": format!("s{symbol:03}"),
                "properties": {}
            });
            events.push(node);
        }
    }
    let mut unknown = common("node_upsert");
    unknown["node"] = json!({
        "id": "unknown:missing",
        "kind": "unknown_target",
        "locator": "id:unknown:missing",
        "display_name": "fixture:missing",
        "properties": {}
    });
    events.push(unknown);
    let edge = |id: String,
                source: String,
                target: String,
                kind: &str,
                site: Option<&str>,
                status: &str,
                evidence: serde_json::Value| {
        let mut edge = json!({
            "id": id,
            "source": source,
            "target": target,
            "kind": kind,
            "phase": "semantic",
            "environment": "host",
            "profile_id": "fixture:mixed",
            "resolution_status": status,
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": evidence
        });
        if let Some(site) = site {
            edge["site_id"] = json!(site);
        }
        edge
    };
    for file in 0..shape.files {
        let path = file_path(file);
        for index in 0..shape.sites_per_file {
            let site_id = format!("site:{file:04}:{index:03}");
            let is_unresolved = index < shape.unresolved_per_file;
            let target = if is_unresolved {
                "unknown:missing".to_owned()
            } else {
                symbol_id(
                    (file + 1 + index) % shape.files,
                    index % shape.symbols_per_file,
                )
            };
            let mut site = common("dependency_site");
            site["site"] = json!({
                "id": site_id,
                "source": file_id(file),
                "kind": "import",
                "specifier": format!("./m{index:03}"),
                "resolution_status": if is_unresolved { "unresolved" } else { "resolved" },
                "target_ids": [target],
                "profile_id": "fixture:mixed",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": evidence(&path, index)
            });
            if is_unresolved {
                site["site"]["reason"] = json!("module_not_found");
            }
            events.push(site);
            let mut site_edge = common("edge_upsert");
            site_edge["edge"] = edge(
                format!("edge:{site_id}"),
                file_id(file),
                target,
                "imports",
                Some(&site_id),
                if is_unresolved {
                    "unresolved"
                } else {
                    "resolved"
                },
                evidence(&path, index),
            );
            events.push(site_edge);
        }
        let ring_start = file - file % shape.ring;
        let next = if (file + 1) % shape.ring == 0 || file + 1 == shape.files {
            ring_start
        } else {
            file + 1
        };
        let mut ring = common("edge_upsert");
        ring["edge"] = edge(
            format!("edge:ring:{file:04}"),
            file_id(file),
            file_id(next),
            "imports",
            None,
            "resolved",
            evidence(&path, shape.sites_per_file),
        );
        events.push(ring);
        for symbol in 0..shape.contains_per_file {
            let mut contains = common("edge_upsert");
            contains["edge"] = edge(
                format!("edge:contains:{file:04}:{symbol:03}"),
                file_id(file),
                symbol_id(file, symbol),
                "contains",
                None,
                "resolved",
                evidence(&path, shape.sites_per_file + 1 + symbol),
            );
            events.push(contains);
        }
        let mut completed = common("file_completed");
        completed["path"] = json!(path);
        completed["discovered_sites"] = json!(shape.sites_per_file);
        completed["emitted_sites"] = json!(shape.sites_per_file);
        completed["skipped_sites"] = json!(0);
        completed["skipped"] = json!(false);
        events.push(completed);
    }
    let mut profile_completed = common("profile_completed");
    profile_completed["profile_id"] = json!("fixture:mixed");
    profile_completed["coverage"] = coverage.clone();
    events.push(profile_completed);
    let mut completed = common("scan_completed");
    completed["coverage"] = coverage;
    events.push(completed);
    for chunk in events.chunks(4_096) {
        store.ingest_events(&chunk.iter().collect::<Vec<_>>())?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed graph snapshot is promoted"))
}
