use crate::{
    ADAPTER_VERSION, EXTRACTOR,
    manifest::{
        Dependency, ManifestDocument, Package, expanded_features, normalize_path, parse_packages,
        select_static_documents, slash_path, workspace_identity,
    },
    metadata::{LockIndex, apply_lock_versions, run_cargo_metadata},
    source::{Occurrence, SourceSpan, collect_occurrences},
};
use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CompletenessLevel, Condition, Coverage, DependencySite, Diagnostic, DiagnosticSeverity,
    Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile, Properties,
    ResolutionStatus, StableIdInput, stable_id, stable_id_from_value,
    validate_site_edge_invariants,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCoverage {
    pub path: String,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub root: String,
    pub profile: Profile,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub sites: Vec<DependencySite>,
    pub diagnostics: Vec<Diagnostic>,
    pub files: Vec<FileCoverage>,
    pub coverage: Coverage,
}

struct SourceUnit {
    rel_path: String,
    package_index: Option<usize>,
    syntax: Option<syn::File>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleContext {
    scope: String,
    path: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleKey {
    package_index: usize,
    scope: String,
    path: Vec<String>,
}

#[derive(Clone, Debug)]
struct TargetResolution {
    target_ids: Vec<String>,
    status: ResolutionStatus,
    precision: Precision,
    reason: Option<String>,
}

#[derive(Debug)]
struct State {
    root: PathBuf,
    repository_identity: String,
    profile: Profile,
    nodes: BTreeMap<String, GraphNode>,
    edges: BTreeMap<String, GraphEdge>,
    sites: BTreeMap<String, DependencySite>,
    diagnostics: BTreeMap<String, Diagnostic>,
    files: BTreeMap<String, FileCoverage>,
    package_nodes: BTreeMap<usize, String>,
    file_nodes: BTreeMap<String, String>,
    module_nodes: BTreeMap<ModuleKey, BTreeSet<String>>,
    source_module_contexts: BTreeMap<(usize, String), BTreeSet<ModuleContext>>,
    dependency_resolutions: BTreeMap<(usize, String), TargetResolution>,
    unsupported_syntax: u64,
    reasons: BTreeSet<String>,
}

pub fn scan(root: &Path) -> Result<ScanResult> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize scan root {}", root.display()))?;
    if !root.is_dir() {
        bail!("scan root is not a directory: {}", root.display());
    }

    let (documents, discovery_failures) = discover_manifests(&root)?;
    let metadata_manifest = documents
        .iter()
        .find(|document| document.rel_path == "Cargo.toml")
        .or_else(|| documents.first())
        .cloned();
    let metadata_lock_preflight = metadata_manifest
        .as_ref()
        .map(|document| LockIndex::read(&root, &document.dir));
    let metadata_result = metadata_manifest.as_ref().and_then(|document| {
        if metadata_lock_preflight
            .as_ref()
            .is_some_and(|lock| lock.failure.is_some())
        {
            return None;
        }
        run_cargo_metadata(&root, &document.abs_path)
            .and_then(|metadata| {
                let workspace_root = normalize_path(metadata.workspace_root());
                if !workspace_root.starts_with(&root) {
                    bail!("cargo metadata workspace root is outside the scan root");
                }
                let lock = LockIndex::read(&root, &workspace_root);
                metadata
                    .into_packages(&root, &lock, &documents)
                    .map(|(packages, active_documents)| (packages, active_documents, lock))
            })
            .ok()
    });
    let metadata_succeeded = metadata_result.is_some();
    let (packages, active_documents, lock) = metadata_result.unwrap_or_else(|| {
        let active_documents = select_static_documents(&documents);
        let workspace_root = active_documents
            .iter()
            .find(|document| document.value.get("workspace").is_some())
            .map(|document| document.dir.as_path())
            .unwrap_or(root.as_path());
        let lock = LockIndex::read(&root, workspace_root);
        let mut packages = parse_packages(&active_documents);
        apply_lock_versions(&mut packages, &lock);
        (packages, active_documents, lock)
    });
    let repository_identity = workspace_identity(&packages, &active_documents);
    let profile = rust_profile(&packages);
    let mut state = State::new(root.clone(), repository_identity, profile);

    if let Some((path, declared)) = declared_rust_toolchain(&root)
        && declared != "1.93.1"
    {
        state.add_diagnostic(
            DiagnosticSeverity::Info,
            "RUST_TOOLCHAIN_BEST_EFFORT",
            &format!(
                "repository declares Rust {declared} rather than the verified 1.93.1 baseline; static analysis continues on a best-effort basis"
            ),
            Some(&path),
            None,
            &format!("toolchain:{declared}"),
        );
    }

    for document in &active_documents {
        state.ensure_file_coverage(&document.rel_path);
    }
    if let Some(lock_path) = &lock.path {
        state.ensure_file_coverage(lock_path);
    }
    if let Some(failure) = &lock.failure {
        state.mark_file_skipped(&failure.path, &failure.reason);
        state.unsupported_syntax += 1;
        state.add_diagnostic(
            DiagnosticSeverity::Error,
            failure.code,
            &failure.reason,
            Some(&failure.path),
            None,
            &failure.path,
        );
    }
    for failure in discovery_failures {
        state.mark_file_skipped(&failure.path, &failure.reason);
        state.unsupported_syntax += 1;
        state.add_diagnostic(
            DiagnosticSeverity::Error,
            "RUST_MANIFEST_PARSE",
            &failure.reason,
            Some(&failure.path),
            None,
            &failure.path,
        );
    }

    state.add_diagnostic(
        DiagnosticSeverity::Info,
        "SAFE_SCAN",
        "Rust source, build scripts, and procedural macros were not executed",
        None,
        None,
        "safe-scan",
    );
    match metadata_manifest.as_ref() {
        Some(document) if metadata_succeeded => {
            state.add_diagnostic(
                DiagnosticSeverity::Info,
                "CARGO_METADATA_FROZEN",
                "cargo metadata completed with frozen, offline, no-deps settings",
                Some(&document.rel_path),
                None,
                "cargo-metadata-success",
            );
        }
        Some(document) => {
            state.reasons.insert("cargo-metadata-fallback".into());
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "CARGO_METADATA_FALLBACK",
                "cargo metadata --frozen --offline was unavailable; static manifest parsing was used",
                Some(&document.rel_path),
                None,
                "cargo-metadata-fallback",
            );
        }
        None => {
            state.reasons.insert("manifest-not-found".into());
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "CARGO_MANIFEST_NOT_FOUND",
                "No Cargo.toml was found; standalone Rust files were scanned",
                None,
                None,
                "manifest-not-found",
            );
        }
    }

    let workspace_node = state.add_workspace_node()?;
    state.add_packages(&packages, &workspace_node)?;
    let inactive_manifest_dirs: Vec<_> = documents
        .iter()
        .filter(|document| {
            !active_documents
                .iter()
                .any(|active| active.rel_path == document.rel_path)
        })
        .map(|document| document.dir.clone())
        .collect();
    let sources = state.discover_sources(&packages, &inactive_manifest_dirs)?;
    state.add_targets(&packages)?;
    state.add_manifest_dependencies(&packages, lock.path.as_deref())?;
    state.add_unexecuted_build_capabilities(&packages)?;
    state.index_modules(&packages, &sources)?;
    state.extract_source_dependencies(&packages, &sources)?;
    state.finish()
}

impl State {
    fn new(root: PathBuf, repository_identity: String, profile: Profile) -> Self {
        Self {
            root,
            repository_identity,
            profile,
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            sites: BTreeMap::new(),
            diagnostics: BTreeMap::new(),
            files: BTreeMap::new(),
            package_nodes: BTreeMap::new(),
            file_nodes: BTreeMap::new(),
            module_nodes: BTreeMap::new(),
            source_module_contexts: BTreeMap::new(),
            dependency_resolutions: BTreeMap::new(),
            unsupported_syntax: 0,
            reasons: BTreeSet::new(),
        }
    }

    fn finish(self) -> Result<ScanResult> {
        let nodes: Vec<_> = self.nodes.into_values().collect();
        let edges: Vec<_> = self.edges.into_values().collect();
        let sites: Vec<_> = self.sites.into_values().collect();
        validate_site_edge_invariants(&nodes, &edges, &sites)
            .context("Rust worker graph invariants failed")?;

        let files: Vec<_> = self.files.into_values().collect();
        let files_skipped = files.iter().filter(|file| file.skipped).count() as u64;
        let completeness = if files_skipped == 0 && self.unsupported_syntax == 0 {
            vec![CompletenessLevel::SyntaxComplete]
        } else {
            Vec::new()
        };
        let mut coverage = Coverage {
            profiles: 1,
            files_discovered: files.len() as u64,
            files_analyzed: files.len() as u64 - files_skipped,
            files_skipped,
            dependency_sites: sites.len() as u64,
            unsupported_syntax: self.unsupported_syntax,
            project_code_executed: false,
            completeness,
            reasons: self.reasons.into_iter().collect(),
            ..Coverage::default()
        };
        for site in &sites {
            match site.resolution_status {
                ResolutionStatus::Resolved => coverage.resolved += 1,
                ResolutionStatus::Candidates => coverage.candidates += 1,
                ResolutionStatus::External => coverage.external += 1,
                ResolutionStatus::Unresolved => coverage.unresolved += 1,
            }
        }
        Ok(ScanResult {
            root: slash_path(&self.root),
            profile: self.profile,
            nodes,
            edges,
            sites,
            diagnostics: self.diagnostics.into_values().collect(),
            files,
            coverage,
        })
    }

    fn add_workspace_node(&mut self) -> Result<String> {
        let id = self.id("workspace", None, None, None, "cargo-workspace");
        self.insert_node(GraphNode {
            id: id.clone(),
            kind: "workspace".into(),
            locator: format!("cargo-workspace:{}", self.repository_identity),
            display_name: Some("Cargo workspace".into()),
            properties: properties(json!({
                "ecosystem": "cargo",
                "root": ".",
                "safe_scan": true
            })),
        })?;
        Ok(id)
    }

    fn add_packages(&mut self, packages: &[Package], workspace_node: &str) -> Result<()> {
        for (index, package) in packages.iter().enumerate() {
            let locator = format!(
                "cargo:{}@{}#{}",
                package.name, package.version, package.rel_dir
            );
            let id = self.id(
                "package_instance",
                Some(&locator),
                Some(&package.manifest_path),
                None,
                "cargo-package",
            );
            self.insert_node(GraphNode {
                id: id.clone(),
                kind: "package_instance".into(),
                locator,
                display_name: Some(package.name.clone()),
                properties: properties(json!({
                    "ecosystem": "cargo",
                    "name": package.name,
                    "version": package.version,
                    "edition": package.edition,
                    "manifest_path": package.manifest_path,
                    "workspace_member": true,
                    "proc_macro": package.proc_macro,
                    "cargo_model": if package.from_metadata { "metadata" } else { "static-fallback" }
                })),
            })?;
            self.package_nodes.insert(index, id.clone());
            self.add_structural_edge(
                workspace_node,
                &id,
                "contains",
                Condition::default(),
                source_evidence(&package.manifest_path, default_span(), "workspace package"),
            )?;
        }
        Ok(())
    }

    fn discover_sources(
        &mut self,
        packages: &[Package],
        inactive_manifest_dirs: &[PathBuf],
    ) -> Result<Vec<SourceUnit>> {
        let mut paths = Vec::new();
        let root = self.root.clone();
        for entry in WalkDir::new(&root)
            .follow_links(false)
            .into_iter()
            .filter_entry(scannable_entry)
        {
            let entry = entry.context("walk Rust source tree")?;
            if entry.path().extension() != Some(OsStr::new("rs"))
                || inactive_manifest_dirs
                    .iter()
                    .any(|directory| entry.path().starts_with(directory))
            {
                continue;
            }
            if entry.file_type().is_symlink() {
                let original = relative_path(&root, entry.path());
                let ledger_path = confined_skipped_ledger_path(&root, entry.path(), &original);
                let reason =
                    format!("Rust source symlink {original} was not followed in safe mode");
                self.mark_file_skipped(&ledger_path, &reason);
                self.add_diagnostic(
                    DiagnosticSeverity::Warning,
                    "RUST_SOURCE_PATH_CONFINEMENT",
                    &reason,
                    Some(&ledger_path),
                    None,
                    &original,
                );
            } else if entry.file_type().is_file() {
                paths.push(entry.into_path());
            }
        }
        paths.sort();

        let mut sources = Vec::with_capacity(paths.len());
        for abs_path in paths {
            let original_rel_path = relative_path(&self.root, &abs_path);
            let source_result =
                canonical_file_within(&self.root, &abs_path).and_then(|canonical| {
                    fs::read_to_string(&canonical)
                        .with_context(|| format!("read {original_rel_path}"))
                });
            let rel_path = if source_result.is_ok() {
                original_rel_path.clone()
            } else {
                skipped_ledger_path(&original_rel_path)
            };
            self.ensure_file_coverage(&rel_path);
            let package_index = package_for_path(packages, &abs_path);
            let package_locator = package_index.map(|index| package_locator(&packages[index]));
            let file_id = self.id(
                "file",
                package_locator.as_deref(),
                Some(&rel_path),
                None,
                "rust-source",
            );
            let source = match source_result {
                Ok(source) => source,
                Err(error) => {
                    let reason = format!(
                        "Rust source {original_rel_path} could not be safely read: {error:#}"
                    );
                    self.mark_file_skipped(&rel_path, &reason);
                    self.unsupported_syntax += 1;
                    self.add_diagnostic(
                        DiagnosticSeverity::Error,
                        "RUST_SOURCE_READ",
                        &reason,
                        Some(&rel_path),
                        None,
                        &original_rel_path,
                    );
                    String::new()
                }
            };
            let generated = source
                .lines()
                .take(8)
                .any(|line| line.contains("@generated") || line.contains("DO NOT EDIT"));
            self.insert_node(GraphNode {
                id: file_id.clone(),
                kind: "file".into(),
                locator: format!("file:{rel_path}"),
                display_name: Some(rel_path.clone()),
                properties: properties(json!({
                    "language": "rust",
                    "generated": generated,
                    "package": package_index.map(|index| packages[index].name.clone())
                })),
            })?;
            self.file_nodes.insert(rel_path.clone(), file_id);

            let syntax = if source.is_empty() && self.files[&rel_path].skipped {
                None
            } else {
                match syn::parse_file(&source) {
                    Ok(file) => Some(file),
                    Err(error) => {
                        self.mark_file_skipped(&rel_path, "Rust syntax could not be parsed");
                        self.unsupported_syntax += 1;
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            "RUST_PARSE_ERROR",
                            &error.to_string(),
                            Some(&rel_path),
                            None,
                            &rel_path,
                        );
                        None
                    }
                }
            };
            sources.push(SourceUnit {
                rel_path,
                package_index,
                syntax,
            });
        }
        Ok(sources)
    }

    fn add_targets(&mut self, packages: &[Package]) -> Result<()> {
        for (package_index, package) in packages.iter().enumerate() {
            let Some(package_node) = self.package_nodes.get(&package_index).cloned() else {
                continue;
            };
            for target in &package.targets {
                let locator = format!(
                    "cargo-target:{}@{}#{}:{}:{}",
                    package.name, package.version, package.rel_dir, target.kind, target.name
                );
                let target_id = self.id(
                    "build_unit",
                    Some(&package_locator(package)),
                    Some(&target.src_path),
                    Some(&self.profile.id),
                    &format!("{}:{}", target.kind, target.name),
                );
                self.insert_node(GraphNode {
                    id: target_id.clone(),
                    kind: "build_unit".into(),
                    locator,
                    display_name: Some(format!("{} ({})", target.name, target.kind)),
                    properties: properties(json!({
                        "language": "rust",
                        "package": package.name,
                        "target_name": target.name,
                        "target_kind": target.kind,
                        "src_path": target.src_path,
                        "proc_macro": target.proc_macro,
                        "profile_id": self.profile.id,
                        "cargo_model": if package.from_metadata { "metadata" } else { "static-fallback" }
                    })),
                })?;
                let evidence = source_evidence(
                    &package.manifest_path,
                    default_span(),
                    "Cargo target declaration",
                );
                self.add_structural_edge(
                    &package_node,
                    &target_id,
                    "contains",
                    Condition::default(),
                    evidence.clone(),
                )?;
                if let Some(file_id) = self.file_nodes.get(&target.src_path).cloned() {
                    self.add_structural_edge(
                        &target_id,
                        &file_id,
                        "contains",
                        Condition::default(),
                        evidence.clone(),
                    )?;
                    let module_id = self.id(
                        "module",
                        Some(&package_locator(package)),
                        Some(&target.src_path),
                        Some(&self.profile.id),
                        &format!("crate-root:{}:{}", target.kind, target.name),
                    );
                    let scope = target_scope(target);
                    self.insert_node(GraphNode {
                        id: module_id.clone(),
                        kind: "module".into(),
                        locator: format!("rust-module:{}:{scope}::", package.name),
                        display_name: Some(target.name.clone()),
                        properties: properties(json!({
                            "language": "rust",
                            "crate_root": true,
                            "target_kind": target.kind,
                            "crate_scope": scope,
                            "canonical_module_path": "",
                            "profile_id": self.profile.id
                        })),
                    })?;
                    let root_context = ModuleContext {
                        scope: scope.clone(),
                        path: Vec::new(),
                    };
                    self.source_module_contexts
                        .entry((package_index, target.src_path.clone()))
                        .or_default()
                        .insert(root_context);
                    self.module_nodes
                        .entry(ModuleKey {
                            package_index,
                            scope,
                            path: Vec::new(),
                        })
                        .or_default()
                        .insert(module_id.clone());
                    self.add_structural_edge(
                        &target_id,
                        &module_id,
                        "contains",
                        Condition::default(),
                        evidence.clone(),
                    )?;
                    self.add_structural_edge(
                        &module_id,
                        &file_id,
                        "declares",
                        Condition::default(),
                        evidence,
                    )?;
                } else {
                    self.add_diagnostic(
                        DiagnosticSeverity::Warning,
                        "CARGO_TARGET_SOURCE_MISSING",
                        &format!("Cargo target source {} was not found", target.src_path),
                        Some(&package.manifest_path),
                        None,
                        &format!("{}:{}", target.kind, target.name),
                    );
                }
            }
        }
        Ok(())
    }

    fn add_manifest_dependencies(
        &mut self,
        packages: &[Package],
        lock_path: Option<&str>,
    ) -> Result<()> {
        let package_by_dir: BTreeMap<_, _> = packages
            .iter()
            .enumerate()
            .map(|(index, package)| (normalize_path(&package.dir), index))
            .collect();
        for (package_index, package) in packages.iter().enumerate() {
            let Some(source) = self.package_nodes.get(&package_index).cloned() else {
                continue;
            };
            for dependency in &package.dependencies {
                let resolution =
                    self.resolve_manifest_dependency(package, &package_by_dir, dependency)?;
                self.dependency_resolutions
                    .entry((package_index, dependency.alias.replace('-', "_")))
                    .or_insert_with(|| resolution.clone());
                let mut evidence = source_evidence(
                    &package.manifest_path,
                    default_span(),
                    &format!("Cargo {} dependency", dependency.kind.as_str()),
                );
                if dependency.locked {
                    evidence
                        .properties
                        .insert("lock_resolved".into(), Value::Bool(true));
                    if let Some(lock_path) = lock_path {
                        evidence
                            .properties
                            .insert("lock_path".into(), Value::String(lock_path.to_owned()));
                    }
                }
                self.add_site(
                    &source,
                    "cargo_dependency",
                    &dependency.alias,
                    dependency.kind.edge_kind(),
                    dependency.condition.clone(),
                    resolution,
                    evidence,
                )?;
                self.increment_file_site(&package.manifest_path);
            }
        }
        Ok(())
    }

    fn resolve_manifest_dependency(
        &mut self,
        source_package: &Package,
        package_by_dir: &BTreeMap<PathBuf, usize>,
        dependency: &Dependency,
    ) -> Result<TargetResolution> {
        if let Some(path) = &dependency.path
            && let Some(index) = package_by_dir.get(&normalize_path(path))
            && let Some(target) = self.package_nodes.get(index)
        {
            return Ok(resolved(target.clone()));
        }
        if let Some(path) = &dependency.path
            && !path.starts_with(&self.root)
        {
            let identity = stable_id_from_value(
                "outside_path",
                &json!({
                    "source_package": package_locator(source_package),
                    "dependency_alias": dependency.alias,
                    "dependency_package": dependency.package,
                    "version": dependency.version,
                }),
            );
            let digest = identity.rsplit(':').next().expect("stable ID has a digest");
            let locator = format!(
                "cargo-path:{}@{}#outside-{}",
                dependency.package,
                dependency.version.as_deref().unwrap_or("*"),
                &digest[..16]
            );
            let target =
                self.external_node(&locator, &dependency.package, dependency.version.as_deref())?;
            self.add_diagnostic(
                DiagnosticSeverity::Info,
                "EXTERNAL_PATH_DEPENDENCY",
                &format!(
                    "Path dependency {} is outside the scan root and was not traversed",
                    dependency.alias
                ),
                Some(&source_package.manifest_path),
                None,
                &format!("{}:{}", source_package.name, dependency.alias),
            );
            return Ok(external(target));
        }
        // Name-only dependencies are registry/external dependencies. A local
        // workspace package is only selected when Cargo's path form identified it.
        let mut locator = format!(
            "cargo:{}@{}",
            dependency.package,
            dependency.version.as_deref().unwrap_or("*")
        );
        if let Some(source) = &dependency.source
            && !source.starts_with("registry+")
        {
            let identity = stable_id_from_value("cargo_source", &json!({"source": source}));
            let digest = identity.rsplit(':').next().expect("stable ID has a digest");
            locator.push_str(&format!("#source-{}", &digest[..16]));
        }
        let target =
            self.external_node(&locator, &dependency.package, dependency.version.as_deref())?;
        if dependency.locked {
            Ok(external(target))
        } else {
            Ok(TargetResolution {
                target_ids: vec![target],
                status: ResolutionStatus::External,
                precision: Precision::Heuristic,
                reason: Some(
                    "dependency version is a manifest requirement and was not lock-resolved".into(),
                ),
            })
        }
    }

    fn add_unexecuted_build_capabilities(&mut self, packages: &[Package]) -> Result<()> {
        for (index, package) in packages.iter().enumerate() {
            if let Some(build_script) = &package.build_script {
                let source = self
                    .file_nodes
                    .get(build_script)
                    .cloned()
                    .or_else(|| self.package_nodes.get(&index).cloned())
                    .expect("package node exists");
                let span = default_span();
                let evidence = source_evidence(build_script, span, "build script not executed");
                let unknown = self.unknown_node(
                    "build_script_output",
                    build_script,
                    build_script,
                    span,
                    "safe scan does not execute build scripts",
                )?;
                self.add_site(
                    &source,
                    "build_script_execution",
                    build_script,
                    "generates",
                    Condition::default(),
                    unresolved(unknown, "safe scan does not execute build scripts"),
                    evidence.clone(),
                )?;
                self.increment_file_site(build_script);
                self.reasons.insert("build-script-not-executed".into());
                self.add_diagnostic(
                    DiagnosticSeverity::Warning,
                    "BUILD_SCRIPT_NOT_EXECUTED",
                    "Build script was discovered but not executed in safe scan mode",
                    Some(build_script),
                    Some(evidence),
                    &package.name,
                );
            }
            if package.proc_macro {
                let source = self.package_nodes[&index].clone();
                let evidence = source_evidence(
                    &package.manifest_path,
                    default_span(),
                    "procedural macro crate not executed",
                );
                let unknown = self.unknown_node(
                    "proc_macro_expansion",
                    &package.name,
                    &package.manifest_path,
                    default_span(),
                    "safe scan does not execute procedural macros",
                )?;
                self.add_site(
                    &source,
                    "proc_macro_execution",
                    &package.name,
                    "expands",
                    Condition::default(),
                    unresolved(unknown, "safe scan does not execute procedural macros"),
                    evidence.clone(),
                )?;
                self.increment_file_site(&package.manifest_path);
                self.reasons.insert("proc-macro-not-executed".into());
                self.add_diagnostic(
                    DiagnosticSeverity::Warning,
                    "PROC_MACRO_NOT_EXECUTED",
                    "Procedural macro crate was discovered but not executed in safe scan mode",
                    Some(&package.manifest_path),
                    Some(evidence),
                    &package.name,
                );
            }
        }
        Ok(())
    }

    fn prepare_module_contexts(&mut self, packages: &[Package], sources: &[SourceUnit]) {
        self.propagate_module_contexts(sources);

        // Files that are not reachable from a statically visible `mod`
        // declaration are still inventoried. Give them a deterministic
        // filesystem-derived context, but prefer declaration-derived contexts
        // (including `#[path]`) whenever one is available.
        for source in sources {
            let Some(package_index) = source.package_index else {
                continue;
            };
            let key = (package_index, source.rel_path.clone());
            if self
                .source_module_contexts
                .get(&key)
                .is_some_and(|contexts| !contexts.is_empty())
            {
                continue;
            }
            self.source_module_contexts
                .entry(key)
                .or_default()
                .extend(inferred_module_contexts(
                    &packages[package_index],
                    &source.rel_path,
                ));
        }
        self.propagate_module_contexts(sources);
    }

    fn propagate_module_contexts(&mut self, sources: &[SourceUnit]) {
        loop {
            let mut additions = Vec::new();
            for source in sources {
                let (Some(package_index), Some(syntax)) =
                    (source.package_index, source.syntax.as_ref())
                else {
                    continue;
                };
                let Some(contexts) = self
                    .source_module_contexts
                    .get(&(package_index, source.rel_path.clone()))
                    .cloned()
                else {
                    continue;
                };
                for occurrence in collect_occurrences(syntax) {
                    let Occurrence::Module {
                        name,
                        inline: false,
                        inline_ancestors,
                        path_override,
                        ..
                    } = occurrence
                    else {
                        continue;
                    };
                    let (_, candidates) = module_file_candidates(
                        &source.rel_path,
                        &name,
                        &inline_ancestors,
                        path_override.as_deref(),
                    );
                    for candidate in candidates {
                        let candidate = slash_path(&normalize_path(&candidate));
                        if !self.file_nodes.contains_key(&candidate) {
                            continue;
                        }
                        for context in &contexts {
                            let mut path = context.path.clone();
                            path.extend(inline_ancestors.iter().cloned());
                            path.push(name.clone());
                            additions.push((
                                (package_index, candidate.clone()),
                                ModuleContext {
                                    scope: context.scope.clone(),
                                    path,
                                },
                            ));
                        }
                    }
                }
            }
            let mut changed = false;
            for (key, context) in additions {
                changed |= self
                    .source_module_contexts
                    .entry(key)
                    .or_default()
                    .insert(context);
            }
            if !changed {
                break;
            }
        }
    }

    fn index_modules(&mut self, packages: &[Package], sources: &[SourceUnit]) -> Result<()> {
        self.prepare_module_contexts(packages, sources);
        for source in sources {
            let (Some(package_index), Some(syntax)) =
                (source.package_index, source.syntax.as_ref())
            else {
                continue;
            };
            let package = &packages[package_index];
            let source_node = self.file_nodes[&source.rel_path].clone();
            for occurrence in collect_occurrences(syntax) {
                let Occurrence::Module {
                    name,
                    inline,
                    inline_ancestors,
                    path_override: _,
                    condition,
                    span,
                } = occurrence
                else {
                    continue;
                };
                let contexts = self
                    .source_module_contexts
                    .get(&(package_index, source.rel_path.clone()))
                    .cloned()
                    .unwrap_or_default();
                for context in contexts {
                    let mut module_path = context.path.clone();
                    module_path.extend(inline_ancestors.iter().cloned());
                    module_path.push(name.clone());
                    let canonical_name = module_path.join("::");
                    let module_id = self.id(
                        "module",
                        Some(&package_locator(package)),
                        Some(&source.rel_path),
                        Some(&self.profile.id),
                        &format!("module:{}:{canonical_name}", context.scope),
                    );
                    self.insert_node(GraphNode {
                        id: module_id.clone(),
                        kind: "module".into(),
                        locator: format!(
                            "rust-module:{}:{}::{canonical_name}",
                            package.name, context.scope
                        ),
                        display_name: Some(canonical_name.clone()),
                        properties: properties(json!({
                            "language": "rust",
                            "inline": inline,
                            "source_path": source.rel_path,
                            "profile_id": self.profile.id,
                            "crate_scope": context.scope,
                            "canonical_module_path": canonical_name
                        })),
                    })?;
                    self.module_nodes
                        .entry(ModuleKey {
                            package_index,
                            scope: context.scope,
                            path: module_path,
                        })
                        .or_default()
                        .insert(module_id.clone());
                    self.add_structural_edge(
                        &source_node,
                        &module_id,
                        "declares",
                        condition.clone(),
                        source_evidence(&source.rel_path, span, "module declaration"),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn extract_source_dependencies(
        &mut self,
        packages: &[Package],
        sources: &[SourceUnit],
    ) -> Result<()> {
        for source in sources {
            let Some(syntax) = source.syntax.as_ref() else {
                continue;
            };
            let source_node = self.file_nodes[&source.rel_path].clone();
            for occurrence in collect_occurrences(syntax) {
                match occurrence {
                    Occurrence::Use {
                        specifier,
                        reexport,
                        inline_ancestors,
                        condition,
                        span,
                    } => {
                        let resolution = self.resolve_rust_path(
                            packages,
                            source.package_index,
                            &specifier,
                            &source.rel_path,
                            &inline_ancestors,
                            span,
                        )?;
                        let (site_kind, edge_kind) = if reexport {
                            ("rust_reexport", "reexports")
                        } else {
                            ("rust_use", "imports")
                        };
                        self.add_site(
                            &source_node,
                            site_kind,
                            &specifier,
                            edge_kind,
                            condition,
                            resolution,
                            source_evidence(&source.rel_path, span, site_kind),
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::ExternCrate {
                        specifier,
                        inline_ancestors,
                        condition,
                        span,
                    } => {
                        let resolution = self.resolve_rust_path(
                            packages,
                            source.package_index,
                            &specifier,
                            &source.rel_path,
                            &inline_ancestors,
                            span,
                        )?;
                        self.add_site(
                            &source_node,
                            "extern_crate",
                            &specifier,
                            "imports",
                            condition,
                            resolution,
                            source_evidence(&source.rel_path, span, "extern crate"),
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::Module {
                        name,
                        inline: false,
                        inline_ancestors,
                        path_override,
                        condition,
                        span,
                    } => {
                        let (specifier, resolution) = self.resolve_module_file(
                            source,
                            &name,
                            &inline_ancestors,
                            path_override.as_deref(),
                            span,
                        )?;
                        self.add_site(
                            &source_node,
                            "module_declaration",
                            &specifier,
                            "imports",
                            condition,
                            resolution,
                            source_evidence(&source.rel_path, span, "external module declaration"),
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::Include {
                        macro_name,
                        argument,
                        raw_argument,
                        condition,
                        span,
                    } => {
                        let (specifier, resolution) = self.resolve_include(
                            &source.rel_path,
                            &macro_name,
                            argument,
                            &raw_argument,
                            span,
                        )?;
                        let edge_kind = if macro_name == "include" {
                            "imports"
                        } else {
                            "consumes_asset"
                        };
                        self.add_site(
                            &source_node,
                            &macro_name,
                            &specifier,
                            edge_kind,
                            condition,
                            resolution,
                            source_evidence(&source.rel_path, span, &format!("{macro_name}!")),
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::Module { inline: true, .. } => {}
                }
            }
        }
        Ok(())
    }

    fn resolve_rust_path(
        &mut self,
        packages: &[Package],
        package_index: Option<usize>,
        specifier: &str,
        path: &str,
        inline_ancestors: &[String],
        span: SourceSpan,
    ) -> Result<TargetResolution> {
        let parts: Vec<String> = specifier
            .split("::")
            .filter(|part| !part.is_empty() && *part != "*")
            .map(|part| part.trim_start_matches("r#").to_owned())
            .collect();
        let first = parts
            .first()
            .map(String::as_str)
            .unwrap_or(specifier.trim_start_matches("r#"));
        if matches!(first, "std" | "core" | "alloc" | "proc_macro") {
            let target = self.external_node(&format!("rust-sysroot:{first}"), first, None)?;
            return Ok(external(target));
        }
        if let Some(package_index) = package_index {
            let package = &packages[package_index];
            if first == package.name.replace('-', "_") {
                return Ok(resolved(self.package_nodes[&package_index].clone()));
            }
            if !matches!(first, "crate" | "self" | "super")
                && let Some(resolution) = self
                    .dependency_resolutions
                    .get(&(package_index, first.to_owned()))
            {
                return Ok(resolution.clone());
            }

            let contexts = self
                .source_module_contexts
                .get(&(package_index, path.to_owned()))
                .cloned()
                .unwrap_or_default();
            let mut targets = BTreeSet::new();
            for context in contexts {
                let mut module_path;
                let mut cursor;
                match first {
                    "crate" => {
                        module_path = Vec::new();
                        cursor = 1;
                    }
                    "self" => {
                        module_path = context.path.clone();
                        module_path.extend(inline_ancestors.iter().cloned());
                        cursor = 1;
                    }
                    "super" => {
                        module_path = context.path.clone();
                        module_path.extend(inline_ancestors.iter().cloned());
                        cursor = 0;
                        while parts.get(cursor).is_some_and(|part| part == "super") {
                            module_path.pop();
                            cursor += 1;
                        }
                    }
                    _ => {
                        // Rust 2018+ `use foo::bar` paths are rooted in the
                        // crate/external prelude. Dependency aliases were
                        // checked above, so the remaining path starts at this
                        // crate root.
                        module_path = Vec::new();
                        cursor = 0;
                    }
                }
                module_path.extend(parts[cursor..].iter().cloned());
                for prefix_len in (0..=module_path.len()).rev() {
                    let key = ModuleKey {
                        package_index,
                        scope: context.scope.clone(),
                        path: module_path[..prefix_len].to_vec(),
                    };
                    if let Some(nodes) = self.module_nodes.get(&key) {
                        targets.extend(nodes.iter().cloned());
                        break;
                    }
                }
            }
            if !targets.is_empty() {
                let target_ids: Vec<_> = targets.into_iter().collect();
                return Ok(if target_ids.len() == 1 {
                    resolved(target_ids[0].clone())
                } else {
                    TargetResolution {
                        target_ids,
                        status: ResolutionStatus::Candidates,
                        precision: Precision::Overapprox,
                        reason: Some(
                            "path is present in multiple Rust crate/module contexts".into(),
                        ),
                    }
                });
            }
        }
        let unknown = self.unknown_node(
            "rust_path",
            specifier,
            path,
            span,
            "path could not be resolved by static syntax analysis",
        )?;
        Ok(unresolved(
            unknown,
            "path could not be resolved by static syntax analysis",
        ))
    }

    fn resolve_module_file(
        &mut self,
        source: &SourceUnit,
        name: &str,
        inline_ancestors: &[String],
        path_override: Option<&str>,
        span: SourceSpan,
    ) -> Result<(String, TargetResolution)> {
        let (specifier, candidates) =
            module_file_candidates(&source.rel_path, name, inline_ancestors, path_override);
        let target_ids: Vec<_> = candidates
            .iter()
            .map(|candidate| slash_path(&normalize_path(candidate)))
            .filter_map(|candidate| self.file_nodes.get(&candidate).cloned())
            .collect();
        let resolution = match target_ids.len() {
            0 => {
                let unknown = self.unknown_node(
                    "module_file",
                    &specifier,
                    &source.rel_path,
                    span,
                    "declared module file was not found",
                )?;
                unresolved(unknown, "declared module file was not found")
            }
            1 => resolved(target_ids[0].clone()),
            _ => TargetResolution {
                target_ids,
                status: ResolutionStatus::Candidates,
                precision: Precision::Overapprox,
                reason: Some("multiple module file candidates exist".into()),
            },
        };
        Ok((specifier, resolution))
    }

    fn resolve_include(
        &mut self,
        source_path: &str,
        macro_name: &str,
        argument: Option<String>,
        raw_argument: &str,
        span: SourceSpan,
    ) -> Result<(String, TargetResolution)> {
        let Some(argument) = argument else {
            self.unsupported_syntax += 1;
            self.reasons.insert("dynamic-include".into());
            self.add_diagnostic(
                DiagnosticSeverity::Warning,
                "DYNAMIC_INCLUDE_UNRESOLVED",
                &format!("{macro_name}! argument is not a string literal"),
                Some(source_path),
                Some(source_evidence(source_path, span, "dynamic include")),
                &format!("{source_path}:{}:{raw_argument}", span.start_line),
            );
            let unknown = self.unknown_node(
                "include",
                raw_argument,
                source_path,
                span,
                "include argument is not a string literal",
            )?;
            return Ok((
                raw_argument.into(),
                unresolved(unknown, "include argument is not a string literal"),
            ));
        };
        let argument_path = Path::new(&argument);
        let relative = if argument_path.is_absolute() {
            None
        } else {
            Some(normalize_path(
                &Path::new(source_path)
                    .parent()
                    .unwrap_or(Path::new(""))
                    .join(argument_path),
            ))
        };
        let safe_relative = relative.filter(|path| {
            !path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        });
        if let Some(relative) = safe_relative {
            let rel = slash_path(&relative);
            let absolute = self.root.join(&relative);
            let confined_file = absolute
                .canonicalize()
                .is_ok_and(|canonical| canonical.starts_with(&self.root) && canonical.is_file());
            if confined_file {
                if let Some(file) = self.file_nodes.get(&rel) {
                    return Ok((argument, resolved(file.clone())));
                }
                let kind = if macro_name == "include" {
                    "file"
                } else {
                    "asset"
                };
                let id = self.id(kind, None, Some(&rel), None, macro_name);
                self.insert_node(GraphNode {
                    id: id.clone(),
                    kind: kind.into(),
                    locator: format!("file:{rel}"),
                    display_name: Some(rel),
                    properties: properties(json!({
                        "language": if macro_name == "include" { "rust" } else { "data" },
                        "included_by_macro": macro_name
                    })),
                })?;
                return Ok((argument, resolved(id)));
            }
        }
        let unknown = self.unknown_node(
            "include",
            &argument,
            source_path,
            span,
            "included path is missing or outside the scan root",
        )?;
        Ok((
            argument,
            unresolved(unknown, "included path is missing or outside the scan root"),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn add_site(
        &mut self,
        source: &str,
        site_kind: &str,
        specifier: &str,
        edge_kind: &str,
        condition: Condition,
        resolution: TargetResolution,
        evidence: Evidence,
    ) -> Result<()> {
        let condition = condition.canonicalize();
        let language_identity = format!(
            "site:{source}:{site_kind}:{specifier}:{}:{}:{}:{}:{}:{}",
            evidence.path.as_deref().unwrap_or(""),
            evidence.start_line.unwrap_or(0),
            evidence.start_column.unwrap_or(0),
            evidence.end_line.unwrap_or(0),
            evidence.end_column.unwrap_or(0),
            condition.render()
        );
        let site_id = self.id(
            "site",
            None,
            evidence.path.as_deref(),
            Some(&self.profile.id),
            &language_identity,
        );
        let site = DependencySite {
            id: site_id.clone(),
            source: source.into(),
            kind: site_kind.into(),
            specifier: specifier.into(),
            resolution_status: resolution.status,
            target_ids: resolution.target_ids.clone(),
            profile_id: self.profile.id.clone(),
            condition: condition.clone(),
            precision: resolution.precision,
            reason: resolution.reason,
            evidence: vec![evidence.clone()],
        };
        match self.sites.get(&site_id) {
            Some(existing) if existing != &site => bail!("conflicting site ID {site_id}"),
            Some(_) => {}
            None => {
                self.sites.insert(site_id.clone(), site);
            }
        }
        for target in resolution.target_ids {
            let edge_id = self.id(
                "edge",
                None,
                evidence.path.as_deref(),
                Some(&self.profile.id),
                &format!("site:{site_id}:{edge_kind}:{target}"),
            );
            self.insert_edge(GraphEdge {
                id: edge_id,
                source: source.into(),
                target,
                kind: edge_kind.into(),
                site_id: Some(site_id.clone()),
                phase: Phase::Source,
                environment: Some("host".into()),
                profile_id: self.profile.id.clone(),
                condition: condition.clone(),
                resolution_status: resolution.status,
                precision: resolution.precision,
                generated: false,
                evidence: vec![evidence.clone()],
            })?;
        }
        Ok(())
    }

    fn add_structural_edge(
        &mut self,
        source: &str,
        target: &str,
        kind: &str,
        condition: Condition,
        evidence: Evidence,
    ) -> Result<()> {
        let condition = condition.canonicalize();
        let id = self.id(
            "edge",
            None,
            evidence.path.as_deref(),
            Some(&self.profile.id),
            &format!("structural:{source}:{kind}:{target}:{}", condition.render()),
        );
        self.insert_edge(GraphEdge {
            id,
            source: source.into(),
            target: target.into(),
            kind: kind.into(),
            site_id: None,
            phase: Phase::Source,
            environment: Some("host".into()),
            profile_id: self.profile.id.clone(),
            condition,
            resolution_status: ResolutionStatus::Resolved,
            precision: Precision::Exact,
            generated: false,
            evidence: vec![evidence],
        })
    }

    fn external_node(
        &mut self,
        locator: &str,
        display_name: &str,
        version: Option<&str>,
    ) -> Result<String> {
        let id = self.id(
            "external_system",
            Some(locator),
            None,
            None,
            "cargo-external",
        );
        self.insert_node(GraphNode {
            id: id.clone(),
            kind: "external_system".into(),
            locator: locator.into(),
            display_name: Some(display_name.into()),
            properties: properties(json!({
                "ecosystem": "cargo",
                "version": version
            })),
        })?;
        Ok(id)
    }

    fn unknown_node(
        &mut self,
        kind: &str,
        specifier: &str,
        path: &str,
        span: SourceSpan,
        reason: &str,
    ) -> Result<String> {
        let id = self.id(
            "unknown_target",
            None,
            Some(path),
            Some(&self.profile.id),
            &format!(
                "{kind}:{specifier}:{}:{}",
                span.start_line, span.start_column
            ),
        );
        self.insert_node(GraphNode {
            id: id.clone(),
            kind: "unknown_target".into(),
            locator: format!("unknown:rust:{kind}:{specifier}"),
            display_name: Some(specifier.into()),
            properties: properties(json!({"reason": reason, "site_kind": kind})),
        })?;
        Ok(id)
    }

    fn insert_node(&mut self, node: GraphNode) -> Result<()> {
        if let Some(existing) = self.nodes.get(&node.id) {
            if existing != &node {
                bail!("conflicting node ID {}", node.id);
            }
        } else {
            self.nodes.insert(node.id.clone(), node);
        }
        Ok(())
    }

    fn insert_edge(&mut self, edge: GraphEdge) -> Result<()> {
        if let Some(existing) = self.edges.get_mut(&edge.id) {
            let mut existing_without_evidence = existing.clone();
            existing_without_evidence.evidence.clear();
            let mut edge_without_evidence = edge.clone();
            edge_without_evidence.evidence.clear();
            if existing_without_evidence != edge_without_evidence {
                bail!("conflicting edge ID {}", edge.id);
            }
            for evidence in edge.evidence {
                if !existing.evidence.contains(&evidence) {
                    existing.evidence.push(evidence);
                }
            }
            existing.evidence.sort_by_key(|evidence| {
                serde_json::to_string(evidence).expect("evidence is serializable")
            });
        } else {
            self.edges.insert(edge.id.clone(), edge);
        }
        Ok(())
    }

    fn id(
        &self,
        namespace: &str,
        package_locator: Option<&str>,
        relative_path: Option<&str>,
        profile_id: Option<&str>,
        language_identity: &str,
    ) -> String {
        stable_id(
            namespace,
            &StableIdInput {
                repository_identity: self.repository_identity.clone(),
                workspace_identity: Some(self.repository_identity.clone()),
                package_locator: package_locator.map(str::to_owned),
                relative_path: relative_path.map(str::to_owned),
                profile_id: profile_id.map(str::to_owned),
                language_identity: Some(language_identity.into()),
            },
        )
    }

    fn ensure_file_coverage(&mut self, path: &str) {
        self.files.entry(path.into()).or_insert(FileCoverage {
            path: path.into(),
            discovered_sites: 0,
            emitted_sites: 0,
            skipped: false,
            reason: None,
        });
    }

    fn increment_file_site(&mut self, path: &str) {
        self.ensure_file_coverage(path);
        let file = self.files.get_mut(path).expect("file was inserted");
        file.discovered_sites += 1;
        file.emitted_sites += 1;
    }

    fn mark_file_skipped(&mut self, path: &str, reason: &str) {
        self.ensure_file_coverage(path);
        let file = self.files.get_mut(path).expect("file was inserted");
        if !file.skipped {
            // Reserve one explicit ledger item for syntax/dependencies that
            // could not be inventoried. Existing emitted sites remain intact,
            // yielding discovered = emitted + skipped in the protocol event.
            file.discovered_sites += 1;
        }
        file.skipped = true;
        file.reason = Some(reason.into());
        self.reasons.insert("file-skipped".into());
    }

    #[allow(clippy::too_many_arguments)]
    fn add_diagnostic(
        &mut self,
        severity: DiagnosticSeverity,
        code: &str,
        message: &str,
        path: Option<&str>,
        evidence: Option<Evidence>,
        identity: &str,
    ) {
        let id = self.id(
            "diagnostic",
            None,
            path,
            Some(&self.profile.id),
            &format!("{code}:{identity}"),
        );
        let (start_line, start_column, end_line, end_column) = evidence
            .as_ref()
            .map(|evidence| {
                (
                    evidence.start_line,
                    evidence.start_column,
                    evidence.end_line,
                    evidence.end_column,
                )
            })
            .unwrap_or((None, None, None, None));
        self.diagnostics.insert(
            id.clone(),
            Diagnostic {
                id,
                severity,
                code: code.into(),
                message: message.into(),
                profile_id: Some(self.profile.id.clone()),
                path: path.map(str::to_owned),
                start_line,
                start_column,
                end_line,
                end_column,
                evidence: evidence.into_iter().collect(),
                properties: Properties::new(),
            },
        );
    }
}

#[derive(Debug)]
struct DiscoveryFailure {
    path: String,
    reason: String,
}

fn skipped_ledger_path(relative: &str) -> String {
    format!("__depgraph_skipped__/{}", relative.trim_start_matches('/'))
}

fn confined_skipped_ledger_path(root: &Path, path: &Path, relative: &str) -> String {
    if path
        .canonicalize()
        .is_ok_and(|target| target.starts_with(root))
    {
        relative.to_owned()
    } else {
        skipped_ledger_path(relative)
    }
}

fn canonical_file_within(root: &Path, path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        bail!(
            "{} resolves outside the canonical scan root or is not a regular file",
            path.display()
        );
    }
    Ok(canonical)
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct RustProfileSelection {
    rust_features: Vec<String>,
    rust_targets: Vec<String>,
}

fn discover_manifests(root: &Path) -> Result<(Vec<ManifestDocument>, Vec<DiscoveryFailure>)> {
    let mut paths = Vec::new();
    let mut failures = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(scannable_entry)
    {
        let entry = entry.context("walk Cargo manifests")?;
        if entry.file_name() != OsStr::new("Cargo.toml") {
            continue;
        }
        if entry.file_type().is_file() {
            paths.push(entry.into_path());
        } else if entry.file_type().is_symlink() {
            let path = entry.into_path();
            let lexical = relative_path(root, &path);
            let confined = path
                .canonicalize()
                .is_ok_and(|target| target.starts_with(root));
            let ledger_path = if confined {
                lexical.clone()
            } else {
                slash_path(&Path::new("__depgraph_skipped__").join(&lexical))
            };
            failures.push(DiscoveryFailure {
                path: ledger_path,
                reason: format!(
                    "Cargo manifest {lexical} is a symbolic link and was not followed in safe mode"
                ),
            });
        }
    }
    paths.sort();
    let mut documents = Vec::new();
    for path in paths {
        let rel_path = relative_path(root, &path);
        let document = canonical_file_within(root, &path).and_then(|safe_path| {
            fs::read_to_string(&safe_path)
                .with_context(|| format!("read {rel_path}"))
                .and_then(|source| {
                    toml::from_str(&source).with_context(|| format!("parse {rel_path}"))
                })
                .map(|value| (safe_path, value))
        });
        match document {
            Ok((safe_path, value)) => {
                let dir = safe_path.parent().unwrap_or(root).to_path_buf();
                documents.push(ManifestDocument {
                    abs_path: safe_path,
                    rel_path,
                    rel_dir: relative_path(root, &dir),
                    dir,
                    value,
                });
            }
            Err(error) => failures.push(DiscoveryFailure {
                path: rel_path,
                reason: format!("{error:#}"),
            }),
        }
    }
    Ok((documents, failures))
}

fn rust_profile(packages: &[Package]) -> Profile {
    let mut selection = std::env::var("DEPGRAPH_PROFILE_CONFIG")
        .ok()
        .and_then(|raw| serde_json::from_str::<RustProfileSelection>(&raw).ok())
        .unwrap_or_default();
    selection.rust_features = selection
        .rust_features
        .into_iter()
        .map(|feature| feature.trim().to_owned())
        .filter(|feature| !feature.is_empty())
        .collect();
    selection.rust_targets = selection
        .rust_targets
        .into_iter()
        .map(|target| target.trim().to_owned())
        .filter(|target| !target.is_empty())
        .collect();
    selection.rust_features.sort();
    selection.rust_features.dedup();
    selection.rust_targets.sort();
    selection.rust_targets.dedup();
    let features: Vec<_> = expanded_features(packages, &selection.rust_features)
        .into_iter()
        .collect();
    let host_target = compiled_host_target();
    let selected_target = if selection.rust_targets.is_empty() {
        host_target.clone()
    } else {
        selection.rust_targets.join(",")
    };
    let id = rust_profile_id(
        &host_target,
        &selected_target,
        &selection.rust_features,
        &features,
        &selection.rust_targets,
    );
    let expanded_profile_features = features.clone();
    Profile {
        id,
        language: "rust".into(),
        toolchain: Some(json!({
            "metadata_command": "cargo metadata --format-version 1 --no-deps --frozen --offline",
            "adapter_version": ADAPTER_VERSION
        })),
        command: Some("check".into()),
        target: Some(selected_target.clone()),
        features,
        environment: BTreeMap::from([
            ("cargo.frozen".into(), Value::Bool(true)),
            ("cargo.offline".into(), Value::Bool(true)),
            (
                "rust.host_target".into(),
                Value::String(host_target.clone()),
            ),
            ("safe_mode".into(), Value::Bool(true)),
        ]),
        source_revision: None,
        properties: properties(json!({
            "analysis": "syntax",
            "effective_target": selected_target,
            "host_target": host_target,
            "requested_features": selection.rust_features,
            "expanded_features": expanded_profile_features,
            "configured_targets": selection.rust_targets,
            "build_scripts_executed": false,
            "proc_macros_executed": false
        })),
    }
}

fn rust_profile_id(
    host_target: &str,
    effective_target: &str,
    requested_features: &[String],
    expanded_features: &[String],
    configured_targets: &[String],
) -> String {
    stable_id_from_value(
        "profile",
        &json!({
            "language": "rust",
            "analysis": "syntax",
            "command": "check",
            "safe_mode": true,
            "host_target": host_target,
            "effective_target": effective_target,
            "requested_features": requested_features,
            "expanded_features": expanded_features,
            "configured_targets": configured_targets,
        }),
    )
}

fn compiled_host_target() -> String {
    let architecture = std::env::consts::ARCH;
    let operating_system = std::env::consts::OS;
    match operating_system {
        "macos" => format!("{architecture}-apple-darwin"),
        "ios" => format!("{architecture}-apple-ios"),
        "android" => format!("{architecture}-linux-android"),
        "windows" => {
            let environment = if cfg!(target_env = "msvc") {
                "msvc"
            } else if cfg!(target_env = "gnu") {
                "gnu"
            } else {
                "unknown"
            };
            format!("{architecture}-pc-windows-{environment}")
        }
        "linux" => {
            let environment = if cfg!(target_env = "musl") {
                "musl"
            } else if cfg!(target_env = "gnu") {
                "gnu"
            } else if cfg!(target_env = "uclibc") {
                "uclibc"
            } else {
                "unknown"
            };
            format!("{architecture}-unknown-linux-{environment}")
        }
        "freebsd" | "netbsd" | "openbsd" | "dragonfly" | "solaris" | "illumos" => {
            format!("{architecture}-unknown-{operating_system}")
        }
        _ => format!("{architecture}-unknown-{operating_system}"),
    }
}

fn target_scope(target: &crate::manifest::Target) -> String {
    format!("{}:{}", target.kind, target.name)
}

fn module_file_candidates(
    source_rel_path: &str,
    name: &str,
    inline_ancestors: &[String],
    path_override: Option<&str>,
) -> (String, Vec<PathBuf>) {
    let source_path = Path::new(source_rel_path);
    let parent = source_path.parent().unwrap_or(Path::new(""));
    if let Some(path_override) = path_override {
        return (
            path_override.to_owned(),
            vec![normalize_path(&parent.join(path_override))],
        );
    }
    let file_name = source_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("");
    let mut base = if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs") {
        parent.to_path_buf()
    } else {
        parent.join(source_path.file_stem().unwrap_or_default())
    };
    for inline in inline_ancestors {
        base.push(inline);
    }
    (
        name.to_owned(),
        vec![
            base.join(format!("{name}.rs")),
            base.join(name).join("mod.rs"),
        ],
    )
}

fn inferred_module_contexts(package: &Package, source_rel_path: &str) -> BTreeSet<ModuleContext> {
    let source = Path::new(source_rel_path);
    let mut contexts = BTreeSet::new();
    for target in &package.targets {
        let target_path = Path::new(&target.src_path);
        if source == target_path {
            contexts.insert(ModuleContext {
                scope: target_scope(target),
                path: Vec::new(),
            });
            continue;
        }
        let Some(root) = target_path.parent() else {
            continue;
        };
        let Ok(relative) = source.strip_prefix(root) else {
            continue;
        };
        let mut path: Vec<String> = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        let Some(file_name) = path.pop() else {
            continue;
        };
        if file_name != "mod.rs" {
            let stem = Path::new(&file_name)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if stem.is_empty() {
                continue;
            }
            path.push(stem);
        }
        contexts.insert(ModuleContext {
            scope: target_scope(target),
            path,
        });
    }
    if contexts.is_empty() {
        let package_root = Path::new(&package.rel_dir);
        let relative = source.strip_prefix(package_root).unwrap_or(source);
        let mut path: Vec<String> = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect();
        if let Some(file_name) = path.pop()
            && file_name != "mod.rs"
        {
            path.push(
                Path::new(&file_name)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        contexts.insert(ModuleContext {
            scope: format!("package:{}", package.name),
            path,
        });
    }
    contexts
}

fn package_for_path(packages: &[Package], path: &Path) -> Option<usize> {
    packages
        .iter()
        .enumerate()
        .filter(|(_, package)| path.starts_with(&package.dir))
        .max_by_key(|(_, package)| package.dir.components().count())
        .map(|(index, _)| index)
}

fn package_locator(package: &Package) -> String {
    format!(
        "cargo:{}@{}#{}",
        package.name, package.version, package.rel_dir
    )
}

fn resolved(target: String) -> TargetResolution {
    TargetResolution {
        target_ids: vec![target],
        status: ResolutionStatus::Resolved,
        precision: Precision::Exact,
        reason: None,
    }
}

fn external(target: String) -> TargetResolution {
    TargetResolution {
        target_ids: vec![target],
        status: ResolutionStatus::External,
        precision: Precision::Exact,
        reason: None,
    }
}

fn unresolved(target: String, reason: &str) -> TargetResolution {
    TargetResolution {
        target_ids: vec![target],
        status: ResolutionStatus::Unresolved,
        precision: Precision::Heuristic,
        reason: Some(reason.into()),
    }
}

fn source_evidence(path: &str, span: SourceSpan, detail: &str) -> Evidence {
    Evidence {
        kind: EvidenceKind::Source,
        extractor: EXTRACTOR.into(),
        extractor_version: ADAPTER_VERSION.into(),
        path: Some(path.into()),
        start_line: Some(span.start_line),
        start_column: Some(span.start_column),
        end_line: Some(span.end_line),
        end_column: Some(span.end_column),
        detail: (!detail.is_empty()).then(|| detail.into()),
        properties: Properties::new(),
    }
}

fn default_span() -> SourceSpan {
    SourceSpan {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
    }
}

fn properties(value: Value) -> Properties {
    serde_json::from_value(value).expect("properties are always a JSON object")
}

fn declared_rust_toolchain(root: &Path) -> Option<(String, String)> {
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        let candidate = root.join(name);
        let Ok(canonical) = candidate.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(root) || !canonical.is_file() {
            continue;
        }
        let Ok(source) = fs::read_to_string(canonical) else {
            continue;
        };
        let declared = if name.ends_with(".toml") {
            toml::from_str::<toml::Value>(&source)
                .ok()?
                .get("toolchain")?
                .get("channel")?
                .as_str()?
                .trim()
                .to_owned()
        } else {
            source.trim().to_owned()
        };
        if !declared.is_empty() {
            return Some((name.to_owned(), declared));
        }
    }
    None
}

fn relative_path(root: &Path, path: &Path) -> String {
    slash_path(path.strip_prefix(root).unwrap_or(path))
}

fn scannable_entry(entry: &DirEntry) -> bool {
    if entry.file_type().is_symlink() {
        // Manifest and Rust source links still need to reach discovery so the
        // coverage ledger can report that safe mode deliberately refused to
        // follow them.
        return entry.file_name() == OsStr::new("Cargo.toml")
            || entry.path().extension() == Some(OsStr::new("rs"));
    }
    if !entry.file_type().is_dir() {
        return true;
    }
    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git" | ".hg" | ".svn" | "target" | "node_modules" | ".next" | "dist" | "build" | ".cache"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_result_satisfies_site_edge_invariants() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workspace");
        let result = scan(&fixture).unwrap();
        validate_site_edge_invariants(&result.nodes, &result.edges, &result.sites).unwrap();
        assert!(result.sites.iter().all(|site| !site.evidence.is_empty()));
        assert!(result.edges.iter().all(|edge| edge.phase == Phase::Source));
    }

    #[test]
    fn broken_source_is_not_reported_as_syntax_complete() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='broken'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "fn broken( {").unwrap();
        let result = scan(temp.path()).unwrap();
        assert_eq!(result.coverage.files_skipped, 1);
        assert!(result.coverage.unsupported_syntax > 0);
        assert!(result.coverage.completeness.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_is_ledgered_without_reading_an_external_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            outside.join("Cargo.toml"),
            "[package]\nname='outside-secret'\nversion='0.1.0'\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub struct Local;\n").unwrap();
        symlink(outside.join("Cargo.toml"), root.join("Cargo.toml")).unwrap();

        let result = scan(&root).unwrap();
        assert!(result.coverage.files_skipped >= 1);
        assert!(result.coverage.unsupported_syntax >= 1);
        assert!(result.files.iter().any(|file| {
            file.path == "__depgraph_skipped__/Cargo.toml"
                && file.skipped
                && file.discovered_sites == 1
                && file.emitted_sites == 0
        }));
        assert!(result.coverage.completeness.is_empty());
        let serialized = serde_json::to_string(&(&result.nodes, &result.diagnostics)).unwrap();
        assert!(!serialized.contains("outside-secret"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_is_ledgered_without_reading_an_external_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside-secret.rs");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub struct Local;\n").unwrap();
        fs::write(
            &outside,
            "pub const OUTSIDE_SECRET: &str = \"do-not-read\";\n",
        )
        .unwrap();
        symlink(&outside, root.join("src/linked.rs")).unwrap();

        let result = scan(&root).unwrap();
        assert!(result.files.iter().any(|file| {
            file.path == "__depgraph_skipped__/src/linked.rs"
                && file.skipped
                && file.discovered_sites == 1
                && file.emitted_sites == 0
        }));
        assert!(result.coverage.completeness.is_empty());
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "RUST_SOURCE_PATH_CONFINEMENT"
                && diagnostic.path.as_deref() == Some("__depgraph_skipped__/src/linked.rs")
        }));
        let serialized = serde_json::to_string(&(&result.nodes, &result.diagnostics)).unwrap();
        assert!(!serialized.contains("OUTSIDE_SECRET"));
        assert!(!serialized.contains("do-not-read"));
    }

    #[test]
    fn malformed_lockfile_is_an_explicit_incomplete_ledger_entry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "this is not valid TOML = [\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub struct Local;\n").unwrap();

        let result = scan(&root).unwrap();
        assert!(result.files.iter().any(|file| {
            file.path == "Cargo.lock"
                && file.skipped
                && file.discovered_sites == 1
                && file.emitted_sites == 0
        }));
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "RUST_LOCKFILE_PARSE"
                && diagnostic.path.as_deref() == Some("Cargo.lock")
        }));
        assert!(result.coverage.unsupported_syntax >= 1);
        assert!(result.coverage.completeness.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn external_lockfile_symlink_is_not_followed_and_uses_a_confined_ledger_path() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside-secret.lock");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='local'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub struct Local;\n").unwrap();
        fs::write(
            &outside,
            "version = 4\n\n[[package]]\nname = 'outside-secret'\nversion = '9.9.9'\n",
        )
        .unwrap();
        symlink(&outside, root.join("Cargo.lock")).unwrap();

        let result = scan(&root).unwrap();
        assert!(result.files.iter().any(|file| {
            file.path == "__depgraph_skipped__/Cargo.lock"
                && file.skipped
                && file.discovered_sites == 1
                && file.emitted_sites == 0
        }));
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "RUST_LOCKFILE_PATH_CONFINEMENT"
                && diagnostic.path.as_deref() == Some("__depgraph_skipped__/Cargo.lock")
        }));
        assert!(result.coverage.completeness.is_empty());
        let serialized = serde_json::to_string(&(&result.nodes, &result.diagnostics)).unwrap();
        assert!(!serialized.contains("outside-secret"));
        assert!(!serialized.contains("9.9.9"));
    }

    #[test]
    fn non_baseline_declared_toolchain_is_reported_as_best_effort() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='older'\nversion='0.1.0'\nedition='2021'\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        std::fs::write(
            temp.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel='1.80.0'\n",
        )
        .unwrap();
        let result = scan(temp.path()).unwrap();
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUST_TOOLCHAIN_BEST_EFFORT")
        );
    }

    #[test]
    fn profile_identity_includes_effective_target_and_configuration() {
        let default_features = vec!["default".to_owned()];
        let no_values: Vec<String> = Vec::new();
        let linux = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &no_values,
            &default_features,
            &no_values,
        );
        let same_linux = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &no_values,
            &default_features,
            &no_values,
        );
        let macos = rust_profile_id(
            "aarch64-apple-darwin",
            "aarch64-apple-darwin",
            &no_values,
            &default_features,
            &no_values,
        );
        let requested = vec!["full".to_owned()];
        let expanded = vec!["default".to_owned(), "full".to_owned()];
        let with_feature = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &requested,
            &expanded,
            &no_values,
        );

        assert_eq!(linux, same_linux);
        assert_ne!(linux, macos);
        assert_ne!(linux, with_feature);
        assert!(linux.starts_with("profile:sha256:"));
    }
}
