//! Issue #566: import groups of agent_edges_list detail=imports and the
//! graph_fan_in_list ranking.

use std::path::Path;

use anyhow::Result;
use depgraph_core::service::{
    DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig, DepgraphServiceLimits,
    EdgeDirection, MAX_IMPORT_GROUP_NAMES, ResolvedSnapshotId, SnapshotLocator,
};
use depgraph_core::{CancellationToken, EdgeKindFilter};
use depgraph_store::Store;
use serde_json::{Value, json};

const SCAN_ID: &str = "issue-566-groups";

fn evidence(path: &str, line: u64, kind: &str, properties: Value) -> Value {
    json!({
        "kind": kind,
        "extractor": "fixture",
        "extractor_version": "1.0",
        "path": path,
        "start_line": line,
        "start_column": 1,
        "end_line": line,
        "end_column": 20,
        "properties": properties
    })
}

fn named(specifier: &str, name: &str) -> Value {
    evidence(
        "src/app.ts",
        1,
        "semantic",
        json!({
            "occurrence_kind": "named_import",
            "module_specifier": specifier,
            "imported_name": name,
            "local_name": name
        }),
    )
}

struct Seed {
    store: Store,
    seq: u64,
}

impl Seed {
    fn event(&mut self, event: &str) -> Value {
        self.seq += 1;
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": SCAN_ID,
            "adapter": "fixture",
            "adapter_version": "1.0",
            "seq": self.seq
        })
    }

    fn node(&mut self, id: &str, kind: &str, path: Option<&str>) -> Result<()> {
        let mut node = self.event("node_upsert");
        let properties = path.map_or_else(|| json!({}), |path| json!({"path": path}));
        node["node"] = json!({
            "id": id,
            "kind": kind,
            "locator": format!("repo://{id}"),
            "display_name": id,
            "properties": properties
        });
        self.store.ingest_event(&node)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn edge(
        &mut self,
        site_id: &str,
        source: &str,
        target: &str,
        site_kind: &str,
        specifier: Option<&str>,
        edge_kind: &str,
        phase: &str,
        site_evidence: Vec<Value>,
    ) -> Result<()> {
        // External declarations and packages are classified as external.
        let resolution = if target.starts_with("node:") {
            "resolved"
        } else {
            "external"
        };
        let mut site = self.event("dependency_site");
        site["site"] = json!({
            "id": site_id,
            "source": source,
            "kind": site_kind,
            "specifier": specifier,
            "resolution_status": resolution,
            "target_ids": [target],
            "profile_id": "fixture:safe",
            "condition": {"op": "all", "conditions": []},
            "precision": "exact",
            "evidence": site_evidence
        });
        self.store.ingest_event(&site)?;
        let mut edge = self.event("edge_upsert");
        edge["edge"] = json!({
            "id": format!("edge:{site_id}"),
            "site_id": site_id,
            "source": source,
            "target": target,
            "kind": edge_kind,
            "phase": phase,
            "environment": "host",
            "profile_id": "fixture:safe",
            "resolution_status": resolution,
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": []
        });
        self.store.ingest_event(&edge)?;
        Ok(())
    }
}

fn seed(store_path: &Path, root: &Path) -> Result<()> {
    let mut store = Store::open(store_path)?;
    store.start_scan_with_revision(SCAN_ID, root, false, Some("revision-566"))?;
    let mut seed = Seed { store, seq: 0 };
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 9,
        "resolved": 6,
        "candidates": 0,
        "external": 3,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let mut started = seed.event("scan_started");
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    seed.store.ingest_event(&started)?;
    let mut profile = seed.event("profile_declared");
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "fixture",
        "features": [],
        "environment": {},
        "properties": {}
    });
    seed.store.ingest_event(&profile)?;
    seed.node("node:app", "file", Some("src/app.ts"))?;
    seed.node("node:big", "file", Some("src/big.ts"))?;
    seed.node("node:other", "file", Some("src/other.ts"))?;
    seed.node("package:react", "external_system", None)?;
    seed.node("external:react-useState", "external_system", None)?;
    seed.node("external:react-useMemo", "external_system", None)?;

    // An external import: the statement edge reaches the package and the binding
    // edges reach external declarations, with the same specifier and node kind.
    seed.edge(
        "site:react",
        "node:app",
        "package:react",
        "import",
        Some("react"),
        "imports",
        "source",
        vec![evidence("src/app.ts", 1, "source", json!({}))],
    )?;
    for name in ["useState", "useMemo"] {
        seed.edge(
            &format!("site:react-{name}"),
            "node:app",
            &format!("external:react-{name}"),
            "web_import",
            Some("react"),
            "imports",
            "semantic",
            vec![named("react", name)],
        )?;
    }
    // A file import whose statement records more names than one group lists.
    seed.edge(
        "site:big",
        "node:app",
        "node:big",
        "import",
        Some("./big"),
        "imports",
        "source",
        vec![evidence("src/app.ts", 2, "source", json!({}))],
    )?;
    let mut big = Vec::new();
    for index in 0..300 {
        big.push(named("./big", &format!("name{index:03}")));
    }
    seed.edge(
        "site:big-names",
        "node:app",
        "node:big",
        "web_import",
        Some("./big"),
        "imports",
        "semantic",
        big,
    )?;
    // Dependents for the fan-in ranking: two sources, a self-loop and a
    // structural edge that is not counted by default.
    seed.edge(
        "site:other-big",
        "node:other",
        "node:big",
        "import",
        Some("./big"),
        "imports",
        "source",
        vec![],
    )?;
    seed.edge(
        "site:other-big-type",
        "node:other",
        "node:big",
        "type_import",
        Some("./big"),
        "type_uses",
        "source",
        vec![],
    )?;
    seed.edge(
        "site:big-self",
        "node:big",
        "node:big",
        "import",
        Some("./big"),
        "imports",
        "source",
        vec![],
    )?;
    seed.edge(
        "site:other-contains",
        "node:other",
        "node:app",
        "contains",
        None,
        "contains",
        "source",
        vec![],
    )?;
    let mut completed_profile = seed.event("profile_completed");
    completed_profile["profile_id"] = json!("fixture:safe");
    completed_profile["coverage"] = coverage.clone();
    seed.store.ingest_event(&completed_profile)?;
    let mut completed = seed.event("scan_completed");
    completed["coverage"] = coverage;
    seed.store.ingest_event(&completed)?;
    seed.store.finish_scan(SCAN_ID, "completed", None, true)?;
    Ok(())
}

fn kinds(kinds: &[&str]) -> EdgeKindFilter {
    EdgeKindFilter::try_new(kinds.iter().map(|kind| (*kind).to_owned()).collect(), None)
        .expect("valid edge kinds")
}

fn open() -> Result<(tempfile::TempDir, DepgraphService, ResolvedSnapshotId)> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root)?;
    let store_path = temp.path().join("store.sqlite");
    seed(&store_path, &root)?;
    let service = DepgraphService::new(DepgraphServiceConfig::new(
        &root,
        &store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?);
    let snapshot = service.resolve_snapshot_id_cancellable(
        &SnapshotLocator::parse("current")?,
        &CancellationToken::new(),
    )?;
    Ok((temp, service, snapshot))
}

#[test]
fn import_groups_anchor_statements_and_bound_their_names() -> Result<()> {
    let (_temp, service, snapshot) = open()?;
    let cancellation = CancellationToken::new();
    let groups = service.list_import_groups_page(
        &snapshot,
        "node:app",
        EdgeDirection::Outgoing,
        &EdgeKindFilter::unrestricted(),
        0,
        10,
        &cancellation,
    )?;
    assert_eq!(groups.total_items(), 2);
    let targets = groups
        .items()
        .iter()
        .map(|group| group.target().id())
        .collect::<Vec<_>>();
    // The package anchors the external import: its edge is outside the semantic
    // phase, while the binding edges reach external declarations of the same kind.
    assert_eq!(targets, ["node:big", "package:react"]);

    let react = &groups.items()[1];
    assert_eq!(react.edge_count(), 3);
    assert_eq!(react.edge_kinds(), ["imports"]);
    let names = react
        .imports()
        .iter()
        .map(|import| import.local_name().unwrap())
        .collect::<Vec<_>>();
    // The statement evidence without names is dropped once names are known.
    assert_eq!(names, ["useMemo", "useState"]);
    assert_eq!(react.import_count(), 2);

    let big = &groups.items()[0];
    assert_eq!(big.imports().len(), MAX_IMPORT_GROUP_NAMES);
    assert_eq!(big.import_count(), 300);
    assert_eq!(big.imports()[0].local_name(), Some("name000"));

    // Paging counts groups and keeps the order.
    let second = service.list_import_groups_page(
        &snapshot,
        "node:app",
        EdgeDirection::Outgoing,
        &EdgeKindFilter::unrestricted(),
        1,
        1,
        &cancellation,
    )?;
    assert_eq!(second.total_items(), 2);
    assert_eq!(second.items()[0].target().id(), "package:react");

    // Incoming: each importer once, with the names of its statement.
    let importers = service.list_import_groups_page(
        &snapshot,
        "node:big",
        EdgeDirection::Incoming,
        &EdgeKindFilter::unrestricted(),
        0,
        10,
        &cancellation,
    )?;
    let sources = importers
        .items()
        .iter()
        .map(|group| group.source().id())
        .collect::<Vec<_>>();
    assert_eq!(sources, ["node:app", "node:big", "node:other"]);
    assert_eq!(importers.items()[0].import_count(), 300);

    // An explicit allowlist replaces the default import kinds.
    let typed = service.list_import_groups_page(
        &snapshot,
        "node:big",
        EdgeDirection::Incoming,
        &kinds(&["type_uses"]),
        0,
        10,
        &cancellation,
    )?;
    assert_eq!(typed.total_items(), 1);
    assert_eq!(typed.items()[0].edge_kinds(), ["type_uses"]);
    Ok(())
}

#[test]
fn fan_in_counts_distinct_dependents_over_dependency_edges() -> Result<()> {
    let (_temp, service, snapshot) = open()?;
    let cancellation = CancellationToken::new();
    let default_kinds = kinds(&[]);
    let files = service.rank_fan_in(
        &snapshot,
        &["file".to_owned()],
        &default_kinds,
        &cancellation,
    )?;
    let ranked = files
        .entries()
        .iter()
        .map(|entry| (entry.node().id(), entry.fan_in(), entry.edge_count()))
        .collect::<Vec<_>>();
    // big: app (two edges) and other (two kinds); the self-loop is ignored and
    // the structural contains edge to app is not a dependency.
    assert_eq!(ranked, [("node:big", 2, 4)]);

    let structural = service.rank_fan_in(
        &snapshot,
        &["file".to_owned()],
        &kinds(&["contains"]),
        &cancellation,
    )?;
    assert_eq!(structural.entries().len(), 1);
    assert_eq!(structural.entries()[0].node().id(), "node:app");

    let every_kind = service.rank_fan_in(&snapshot, &[], &default_kinds, &cancellation)?;
    let ids = every_kind
        .entries()
        .iter()
        .map(|entry| entry.node().id())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "node:big",
            "external:react-useMemo",
            "external:react-useState",
            "package:react"
        ]
    );
    Ok(())
}
