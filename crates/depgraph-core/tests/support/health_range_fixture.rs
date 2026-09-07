//! Deterministic, public, synthetic Go-shaped health fixtures.
//!
//! The generator emits a worker protocol stream (adapter `go`, protocol 1.0)
//! for `packages × files × symbols` subjects under `profiles` equivalent stage
//! profiles and ingests it through the public Store API. Shapes are chosen so
//! the *whole* graph exceeds the previous single-budget work limit while every
//! planned range stays inside the unchanged per-range budget, and so callers
//! can sort after or before their callees to exercise cross-range usage.
//!
//! Nothing here is derived from a private repository.

#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Result;
use depgraph_store::Store;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MODULE_PATH: &str = "example.test/health-range";
pub const SCAN_ID: &str = "health-range-fixture";

/// One synthetic fixture shape.
#[derive(Clone, Debug)]
pub struct HealthRangeFixtureShape {
    pub packages: usize,
    pub files: usize,
    pub symbols: usize,
    /// Equivalent Go stage profiles (`analysis_stage=stage-k`).
    pub profiles: usize,
    /// Percentage of symbols per file that are called from the previous
    /// package (`0..=100`).
    pub cross_percent: usize,
    /// When `true`, symbol ids of callers sort *after* the ids of their
    /// callees (package `p` calls into `p + 1`, so ids decrease with `p`).
    /// When `false`, callers sort before callees.
    pub caller_after_callee: bool,
    /// File 0 of the last package also imports package 0 (import cycle).
    pub mutual_import_cycle: bool,
    /// A second module node shares package 1's `package_path` and a
    /// `candidates` site targets both modules (ambiguous ownership).
    pub same_path_two_modules: bool,
    /// File 0 of package 0 reaches the last symbol of file 0 of package 1
    /// through a heuristic `dynamic_import` site (dynamic-import evidence).
    pub dynamic_import_site: bool,
    /// Mark the scan's coverage with an unanalysed analysis unit.
    pub incomplete_unit: bool,
    /// Every symbol additionally calls symbol 0 of file 0 of package 0, so
    /// that one subject's inbound side dwarfs every other range (used to
    /// force a range that cannot complete even after re-splitting).
    pub hub_symbol: bool,
}

impl HealthRangeFixtureShape {
    /// Small shape for unit tests: 4 packages × 2 files × 4 symbols, 2 stage
    /// profiles, half of the symbols called from the previous package.
    #[must_use]
    pub const fn small() -> Self {
        Self {
            packages: 4,
            files: 2,
            symbols: 4,
            profiles: 2,
            cross_percent: 50,
            caller_after_callee: false,
            mutual_import_cycle: false,
            same_path_two_modules: false,
            dynamic_import_site: false,
            incomplete_unit: false,
            hub_symbol: false,
        }
    }

    /// The public acceptance fixture (plan fixture B): 64 × 8 × 8 subjects
    /// under 24 stage profiles with every symbol called across packages.
    /// The whole graph needs about 1.75 M analysis steps (previous limit:
    /// 1 M) and yields 72 findings, 8 of them confirmed.
    #[must_use]
    pub const fn over_limit() -> Self {
        Self {
            packages: 64,
            files: 8,
            symbols: 8,
            profiles: 24,
            cross_percent: 100,
            caller_after_callee: true,
            mutual_import_cycle: false,
            same_path_two_modules: false,
            dynamic_import_site: false,
            incomplete_unit: false,
            hub_symbol: false,
        }
    }

    #[must_use]
    pub const fn with_hub_symbol(mut self, value: bool) -> Self {
        self.hub_symbol = value;
        self
    }

    #[must_use]
    pub const fn with_caller_after_callee(mut self, value: bool) -> Self {
        self.caller_after_callee = value;
        self
    }

    #[must_use]
    pub const fn with_mutual_import_cycle(mut self, value: bool) -> Self {
        self.mutual_import_cycle = value;
        self
    }

    #[must_use]
    pub const fn with_same_path_two_modules(mut self, value: bool) -> Self {
        self.same_path_two_modules = value;
        self
    }

    #[must_use]
    pub const fn with_dynamic_import_site(mut self, value: bool) -> Self {
        self.dynamic_import_site = value;
        self
    }

    #[must_use]
    pub const fn with_incomplete_unit(mut self, value: bool) -> Self {
        self.incomplete_unit = value;
        self
    }

    #[must_use]
    pub const fn with_profiles(mut self, value: usize) -> Self {
        self.profiles = value;
        self
    }
}

/// A generated fixture: repository root, store, and the promoted snapshot.
#[derive(Clone, Debug)]
pub struct HealthRangeFixture {
    pub root: PathBuf,
    pub store_path: PathBuf,
    pub scan_id: String,
    pub snapshot_id: String,
    pub events: u64,
    pub edges: u64,
    pub sites: u64,
    pub shape: HealthRangeFixtureShape,
}

/// `kind:sha256:<64 hex>` with a controlled first byte so tests can pin the
/// sort order of subject ids without depending on hash luck.
pub fn ordered_id(kind: &str, order: u8, label: &str) -> String {
    let digest = hex::encode(Sha256::digest(label.as_bytes()));
    format!("{kind}:sha256:{order:02x}{}", &digest[2..])
}

pub fn id(kind: &str, label: &str) -> String {
    format!(
        "{kind}:sha256:{}",
        hex::encode(Sha256::digest(label.as_bytes()))
    )
}

pub fn package_path(p: usize) -> String {
    format!("{MODULE_PATH}/pkg{p:04}")
}

pub fn module_id(p: usize) -> String {
    id("module", &format!("module:{}", package_path(p)))
}

pub fn shadow_module_id() -> String {
    id("module", "module:shadow:pkg0001")
}

pub fn file_path(p: usize, f: usize) -> String {
    format!("pkg{p:04}/file{f:03}.go")
}

pub fn file_id(shape: &HealthRangeFixtureShape, p: usize, f: usize) -> String {
    ordered_id(
        "file",
        package_order(shape, p),
        &format!("file:{}", file_path(p, f)),
    )
}

pub fn symbol_id(shape: &HealthRangeFixtureShape, p: usize, f: usize, s: usize) -> String {
    ordered_id(
        "symbol",
        package_order(shape, p),
        &format!("symbol:{}.Sym{f:03}_{s:03}", package_path(p)),
    )
}

fn package_order(shape: &HealthRangeFixtureShape, p: usize) -> u8 {
    let position = if shape.caller_after_callee {
        shape.packages.saturating_sub(1).saturating_sub(p)
    } else {
        p
    };
    u8::try_from(position.min(255)).unwrap_or(u8::MAX)
}

/// Symbol `s` of any file in package `p` is called from package `p - 1`.
pub fn symbol_is_called(shape: &HealthRangeFixtureShape, p: usize, s: usize) -> bool {
    p > 0 && s * 100 < shape.symbols * shape.cross_percent
}

/// Expected unused findings of a shape without the optional twists: every
/// file of package 0 (never imported) and every uncalled symbol.
pub fn expected_unused_counts(shape: &HealthRangeFixtureShape) -> (usize, usize) {
    let unused_files = if shape.mutual_import_cycle {
        0
    } else {
        shape.files
    };
    let mut unused_symbols = 0;
    for p in 0..shape.packages {
        for f in 0..shape.files {
            for s in 0..shape.symbols {
                let hub = shape.hub_symbol && (p, f, s) == (0, 0, 0);
                if !symbol_is_called(shape, p, s) && !hub {
                    unused_symbols += 1;
                }
            }
        }
    }
    (unused_files, unused_symbols)
}

/// Events per flushed chunk; the generator never holds more than one chunk.
pub const EVENT_CHUNK: usize = 4096;

/// Sequenced event stream; chunks are handed to `consume` as they fill so the
/// over-limit shape (hundreds of thousands of events) never sits in memory.
struct EventSink<'a> {
    scan_id: &'a str,
    seq: u64,
    pending: Vec<Value>,
    consume: &'a mut dyn FnMut(Vec<Value>) -> Result<()>,
    error: Option<anyhow::Error>,
    edges: u64,
    sites: u64,
    candidate_sites: u64,
    unresolved_sites: u64,
}

impl EventSink<'_> {
    fn push(&mut self, mut event: Value) {
        // Once ingest has failed the run is over; buffering the rest of the
        // stream would only grow `pending` until the error is reported.
        if self.error.is_some() {
            return;
        }
        self.seq += 1;
        event["seq"] = json!(self.seq);
        event["scan_id"] = json!(self.scan_id);
        event["protocol_version"] = json!("1.0");
        event["adapter"] = json!("go");
        event["adapter_version"] = json!("0.5.4");
        self.pending.push(event);
        if self.pending.len() >= EVENT_CHUNK {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.error.is_some() || self.pending.is_empty() {
            return;
        }
        let chunk = std::mem::take(&mut self.pending);
        if let Err(error) = (self.consume)(chunk) {
            self.error = Some(error);
        }
    }
}

fn condition() -> Value {
    json!({"op": "all", "conditions": []})
}

fn evidence(path: &str, detail: &str) -> Value {
    json!([{
        "kind": "semantic", "extractor": "go-types", "extractor_version": "0.5.4", "path": path,
        "start_line": 1, "start_column": 1, "end_line": 1, "end_column": 8, "detail": detail,
        "properties": {}
    }])
}

fn module_node(p: usize, module_path: &str, module_id: &str) -> Value {
    json!({"event": "node_upsert", "node": {
        "id": module_id, "kind": "module",
        "locator": format!("go-package:{}", package_path(p)),
        "display_name": package_path(p),
        "properties": {
            "language": "go", "manifest_path": "go.mod", "module_path": module_path,
            "package_name": format!("pkg{p:04}"), "package_path": package_path(p),
            "relative_dir": format!("pkg{p:04}"), "vendor": false}}})
}

/// `import:<tag>:<profile index>:<package>:<file>` → module of `target`.
fn push_import(
    sink: &mut EventSink<'_>,
    shape: &HealthRangeFixtureShape,
    profile_id: &str,
    source: (usize, usize, usize),
    target: usize,
    tag: &str,
) {
    let (k, p, f) = source;
    sink.sites += 1;
    sink.edges += 1;
    let site = id("site", &format!("import:{tag}:{k}:{p}:{f}"));
    let path = file_path(p, f);
    sink.push(json!({"event": "dependency_site", "site": {
        "id": site, "source": file_id(shape, p, f), "kind": "import",
        "specifier": package_path(target), "resolution_status": "resolved",
        "target_ids": [module_id(target)], "profile_id": profile_id,
        "condition": condition(), "precision": "exact",
        "evidence": evidence(&path, "import")}}));
    sink.push(json!({"event": "edge_upsert", "edge": {
        "id": id("edge", &format!("imports:{tag}:{k}:{p}:{f}")),
        "source": file_id(shape, p, f), "target": module_id(target), "kind": "imports",
        "phase": "semantic", "site_id": site, "environment": "any",
        "resolution_status": "resolved", "profile_id": profile_id,
        "condition": condition(), "precision": "exact", "generated": false,
        "evidence": evidence(&path, "import")}}));
}

fn push_call(
    sink: &mut EventSink<'_>,
    shape: &HealthRangeFixtureShape,
    profile_id: &str,
    label: &str,
    source: (usize, usize, usize),
    target: (usize, usize, usize),
) {
    sink.sites += 1;
    sink.edges += 1;
    let site = id("site", label);
    let source_id = symbol_id(shape, source.0, source.1, source.2);
    let target_id = symbol_id(shape, target.0, target.1, target.2);
    let path = file_path(source.0, source.1);
    sink.push(json!({"event": "dependency_site", "site": {
        "id": site, "source": source_id, "kind": "call",
        "specifier": format!("{}.Sym{:03}_{:03}", package_path(target.0), target.1, target.2),
        "resolution_status": "resolved", "target_ids": [target_id],
        "profile_id": profile_id, "condition": condition(),
        "precision": "exact", "evidence": evidence(&path, "call")}}));
    sink.push(json!({"event": "edge_upsert", "edge": {
        "id": id("edge", &label.replacen("call:", "calls:", 1).replacen("hub:", "hub-calls:", 1)),
        "source": source_id, "target": target_id,
        "kind": "calls", "phase": "semantic", "site_id": site,
        "environment": "any", "resolution_status": "resolved",
        "profile_id": profile_id, "condition": condition(),
        "precision": "exact", "generated": false,
        "evidence": evidence(&path, "call")}}));
}

/// Counts of one emitted stream.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EmittedCounts {
    pub events: u64,
    pub edges: u64,
    pub sites: u64,
}

/// Stream the worker protocol events of `shape` to `consume` in chunks of
/// [`EVENT_CHUNK`] and return the event, edge, and site counts.
pub fn emit(
    shape: &HealthRangeFixtureShape,
    scan_id: &str,
    root: &Path,
    consume: &mut dyn FnMut(Vec<Value>) -> Result<()>,
) -> Result<EmittedCounts> {
    let profile_ids = (0..shape.profiles)
        .map(|k| id("profile", &format!("go-stage-{k}")))
        .collect::<Vec<_>>();
    let mut sink = EventSink {
        scan_id,
        seq: 0,
        pending: Vec::new(),
        consume,
        error: None,
        edges: 0,
        sites: 0,
        candidate_sites: 0,
        unresolved_sites: 0,
    };
    sink.push(json!({
        "event": "scan_started",
        "profile_ids": profile_ids,
        "project_code_executed": false,
        "root": root,
        "safe_mode": true
    }));
    for (k, profile_id) in profile_ids.iter().enumerate() {
        sink.push(json!({"event": "profile_declared", "profile": {
            "id": profile_id, "language": "go", "toolchain": "go1.26.1", "command": "scan",
            "target": "linux-amd64", "features": [],
            "environment": {"CGO_ENABLED": "0", "GOARCH": "amd64", "GOOS": "linux", "GO_TAGS": ""},
            "properties": {"analysis_stage": format!("stage-{k}"), "safe_scan": "true"}}}));
    }

    let mut file_count = 0_u64;
    for p in 0..shape.packages {
        sink.push(module_node(p, MODULE_PATH, &module_id(p)));
        for f in 0..shape.files {
            file_count += 1;
            let path = file_path(p, f);
            sink.push(json!({"event": "node_upsert", "node": {
                "id": file_id(shape, p, f), "kind": "file",
                "locator": format!("file:{path}"), "display_name": path,
                "properties": {
                    "build_constraint": "", "content_hash": id("sha", &path),
                    "generated": false, "language": "go", "manifest_path": "go.mod",
                    "package_name": format!("pkg{p:04}"), "package_path": package_path(p),
                    "path": path, "test": false}}}));
            for s in 0..shape.symbols {
                sink.push(json!({"event": "node_upsert", "node": {
                    "id": symbol_id(shape, p, f, s), "kind": "symbol",
                    "locator": format!("go-symbol:{}.Sym{f:03}_{s:03}", package_path(p)),
                    "display_name": format!("Sym{f:03}_{s:03}"),
                    "properties": {
                        "language": "go", "exported": true, "symbol_kind": "function",
                        "path": path, "package_path": package_path(p)}}}));
            }
        }
    }
    if shape.same_path_two_modules {
        let mut node = module_node(1, "example.test/shadow", &shadow_module_id());
        node["node"]["locator"] = json!("go-package:example.test/shadow/pkg0001");
        node["node"]["properties"]["manifest_path"] = json!("shadow/go.mod");
        sink.push(node);
    }

    for (k, profile_id) in profile_ids.iter().enumerate() {
        for p in 0..shape.packages {
            for f in 0..shape.files {
                let path = file_path(p, f);
                sink.edges += 1;
                sink.push(json!({"event": "edge_upsert", "edge": {
                    "id": id("edge", &format!("contains:{k}:{p}:{f}")),
                    "source": module_id(p), "target": file_id(shape, p, f), "kind": "contains",
                    "phase": "source", "environment": "any", "resolution_status": "resolved",
                    "profile_id": profile_id, "condition": condition(), "precision": "exact",
                    "generated": false, "evidence": evidence(&path, "contains")}}));
                for s in 0..shape.symbols {
                    sink.edges += 1;
                    sink.push(json!({"event": "edge_upsert", "edge": {
                        "id": id("edge", &format!("declares:{k}:{p}:{f}:{s}")),
                        "source": module_id(p), "target": symbol_id(shape, p, f, s),
                        "kind": "declares", "phase": "semantic", "environment": "any",
                        "resolution_status": "resolved", "profile_id": profile_id,
                        "condition": condition(), "precision": "exact", "generated": false,
                        "evidence": evidence(&path, "declares")}}));
                }
                if p + 1 < shape.packages {
                    push_import(&mut sink, shape, profile_id, (k, p, f), p + 1, "chain");
                }
                if shape.mutual_import_cycle && p + 1 == shape.packages && f == 0 {
                    push_import(&mut sink, shape, profile_id, (k, p, f), 0, "cycle");
                }
                for s in 0..shape.symbols {
                    if p + 1 < shape.packages && symbol_is_called(shape, p + 1, s) {
                        push_call(
                            &mut sink,
                            shape,
                            profile_id,
                            &format!("call:{k}:{p}:{f}:{s}"),
                            (p, f, s),
                            (p + 1, f, s),
                        );
                    }
                    if shape.hub_symbol && (p, f, s) != (0, 0, 0) {
                        push_call(
                            &mut sink,
                            shape,
                            profile_id,
                            &format!("hub:{k}:{p}:{f}:{s}"),
                            (p, f, s),
                            (0, 0, 0),
                        );
                    }
                }
            }
        }
        if shape.same_path_two_modules {
            // Package 0's first file also refers to pkg0001 ambiguously: one
            // `candidates` site with one edge per candidate module.
            sink.sites += 1;
            sink.candidate_sites += 1;
            let site = id("site", &format!("candidates:{k}"));
            let path = file_path(0, 0);
            sink.push(json!({"event": "dependency_site", "site": {
                "id": site, "source": file_id(shape, 0, 0),
                "kind": "import", "specifier": package_path(1),
                "resolution_status": "candidates",
                "target_ids": [module_id(1), shadow_module_id()], "profile_id": profile_id,
                "condition": condition(), "precision": "heuristic",
                "evidence": evidence(&path, "candidates")}}));
            for (tag, target) in [("primary", module_id(1)), ("shadow", shadow_module_id())] {
                sink.edges += 1;
                sink.push(json!({"event": "edge_upsert", "edge": {
                    "id": id("edge", &format!("candidate-imports:{tag}:{k}")),
                    "source": file_id(shape, 0, 0), "target": target, "kind": "imports",
                    "phase": "semantic", "site_id": site, "environment": "any",
                    "resolution_status": "candidates", "profile_id": profile_id,
                    "condition": condition(), "precision": "heuristic", "generated": false,
                    "evidence": evidence(&path, "candidates")}}));
            }
        }
        if shape.dynamic_import_site && shape.packages > 1 && shape.symbols > 0 {
            // Package 0 reaches an otherwise uncalled symbol of package 1
            // through a heuristic dynamic import: a usage that cannot clear
            // the finding but must attach the same blockers in every range
            // layout.
            sink.sites += 1;
            sink.edges += 1;
            let site = id("site", &format!("dynamic:{k}"));
            let target = (1, 0, shape.symbols - 1);
            let target_id = symbol_id(shape, target.0, target.1, target.2);
            let path = file_path(0, 0);
            let dynamic_evidence = json!([{
                "kind": "semantic", "extractor": "go-types", "extractor_version": "0.5.4",
                "path": path, "start_line": 2, "start_column": 1, "end_line": 2,
                "end_column": 8, "detail": "dynamic import",
                "properties": {"occurrence_kind": "dynamic_import"}}]);
            sink.push(json!({"event": "dependency_site", "site": {
                "id": site, "source": file_id(shape, 0, 0),
                "kind": "dynamic_import", "specifier": "plugin://runtime",
                "resolution_status": "resolved", "target_ids": [target_id],
                "profile_id": profile_id, "condition": condition(), "precision": "heuristic",
                "evidence": dynamic_evidence}}));
            sink.push(json!({"event": "edge_upsert", "edge": {
                "id": id("edge", &format!("dynamic-imports:{k}")),
                "source": file_id(shape, 0, 0), "target": target_id, "kind": "imports",
                "phase": "semantic", "site_id": site, "environment": "any",
                "resolution_status": "resolved", "profile_id": profile_id,
                "condition": condition(), "precision": "heuristic", "generated": false,
                "evidence": dynamic_evidence}}));
        }
    }
    for p in 0..shape.packages {
        for f in 0..shape.files {
            sink.push(json!({"event": "file_completed", "path": file_path(p, f),
                "discovered_sites": 1, "emitted_sites": 1, "skipped": false, "skipped_sites": 0}));
        }
    }
    let site_count = sink.sites;
    // An unanalysed analysis unit surfaces to health through the coverage
    // ledger reasons; the levels stay consistent with the profile intersection
    // so the scan still validates and promotes.
    let reasons = if shape.incomplete_unit {
        json!(["analysis-unit-unanalysed"])
    } else {
        json!([])
    };
    let (candidate_sites, unresolved_sites) = (sink.candidate_sites, sink.unresolved_sites);
    let coverage_for = |profile_count: usize, sites: u64, candidates: u64, unresolved: u64| {
        json!({
            "profiles": profile_count, "files_discovered": file_count, "files_analyzed": file_count,
            "files_skipped": 0, "dependency_sites": sites,
            "resolved": sites - candidates - unresolved, "candidates": candidates,
            "external": 0, "unresolved": unresolved, "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete", "semantic-complete"], "reasons": reasons
        })
    };
    let profiles = shape.profiles.max(1) as u64;
    for profile_id in &profile_ids {
        sink.push(
            json!({"event": "profile_completed", "profile_id": profile_id,
            "coverage": coverage_for(
                1,
                site_count / profiles,
                candidate_sites / profiles,
                unresolved_sites / profiles
            )}),
        );
    }
    sink.push(json!({"event": "scan_completed", "coverage": coverage_for(
        shape.profiles, site_count, candidate_sites, unresolved_sites)}));
    sink.flush();
    if let Some(error) = sink.error {
        return Err(error);
    }
    Ok(EmittedCounts {
        events: sink.seq,
        edges: sink.edges,
        sites: sink.sites,
    })
}

/// Collect the whole stream of `shape` in memory (small shapes only).
pub fn events(shape: &HealthRangeFixtureShape, scan_id: &str, root: &Path) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    emit(shape, scan_id, root, &mut |chunk| {
        all.extend(chunk);
        Ok(())
    })?;
    Ok(all)
}

/// Generate the protocol stream of `shape` and ingest it into a fresh store
/// under `dir` (`repo/` root with a `go.mod`, `depgraph.sqlite` store).
pub fn generate(dir: &Path, shape: &HealthRangeFixtureShape) -> Result<HealthRangeFixture> {
    fs::create_dir_all(dir)?;
    let root = dir.join("repo");
    fs::create_dir_all(&root)?;
    fs::write(
        root.join("go.mod"),
        format!("module {MODULE_PATH}\n\ngo 1.26\n"),
    )?;
    let store_path = dir.join("depgraph.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(dir.join(format!("depgraph.sqlite{suffix}")));
    }
    let mut store = Store::open(&store_path)?;
    store.start_scan_with_revision(SCAN_ID, &root, false, Some("health-range-fixture"))?;
    let counts = emit(shape, SCAN_ID, &root, &mut |chunk| {
        let refs = chunk.iter().collect::<Vec<_>>();
        store.ingest_events(&refs)
    })?;
    store.finish_scan(SCAN_ID, "completed", None, true)?;
    let snapshot_id = store
        .current_snapshot_id()?
        .expect("the fixture scan promotes a completed snapshot");
    drop(store);
    Ok(HealthRangeFixture {
        root,
        store_path,
        scan_id: SCAN_ID.to_owned(),
        snapshot_id,
        events: counts.events,
        edges: counts.edges,
        sites: counts.sites,
        shape: shape.clone(),
    })
}
