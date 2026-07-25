use crate::{
    ADAPTER_VERSION, EXTRACTOR, RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION,
    RUST_ANALYZER_SALSA_VERSION, RUST_HIR_INTEGRATION_POLICY, RUST_SYSROOT_COMPONENT_VERSION,
    RUST_SYSROOT_CONTRACT_VERSION, RUST_SYSROOT_SOURCE_LAYOUT, RUST_TOOLCHAIN_BASELINE,
    hir_project::{
        HirProjectMode, HirProjectProfile, InventorySource, ProjectModelErrorKind,
        SafeProjectModel, build_safe_project_model_with_sysroot,
    },
    hir_semantic::{SemanticCrateContext, SemanticDelta, extract_semantic_delta},
    hir_sysroot::{RUST_SYSROOT_ROOT_ENV, load_attested_sysroot},
    manifest::{
        Dependency, ManifestDocument, Package, expanded_features, normalize_path, parse_packages,
        select_static_documents, slash_path, workspace_identity,
    },
    metadata::{LockIndex, apply_lock_versions, run_cargo_metadata},
    source::{
        CallOccurrenceKey, Occurrence, SourceSpan, TypeUseOccurrenceKey, UseOccurrenceKey,
        collect_occurrences,
    },
    toolchain::{RustToolchainProbe, ToolchainProbeStatus, probe_rust_toolchain},
};
use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CompletenessLevel, Condition, Coverage, DependencySite, Diagnostic, DiagnosticSeverity,
    Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile, Properties,
    ResolutionStatus, StableIdInput, stable_id, stable_id_from_value, validate_semantic_graph,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    text: Option<String>,
    syntax: Option<syn::File>,
}

fn source_content_hash(source: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(source.as_bytes());
    let mut output = String::from("sha256:");
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing a digest to String cannot fail");
    }
    output
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

type SemanticExtractor = fn(
    &SafeProjectModel,
    &BTreeMap<String, SemanticCrateContext>,
    &BTreeMap<String, Vec<Occurrence>>,
    &str,
) -> Result<SemanticDelta>;

const RUST_RELEASE_GATE_ENV: &str = "DEPGRAPH_RUST_RELEASE_GATE";
const RELEASE_GATE_PENDING: &str = "release-gate-pending";
const RELEASE_GATE_VERIFIED: &str = "release-gate-verified";

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
    semantic_use_occurrences: BTreeSet<UseOccurrenceKey>,
    semantic_type_use_occurrences: BTreeSet<TypeUseOccurrenceKey>,
    semantic_call_occurrences: BTreeSet<CallOccurrenceKey>,
    unsupported_syntax: u64,
    reasons: BTreeSet<String>,
    rust_release_gate: &'static str,
}

pub fn scan(root: &Path) -> Result<ScanResult> {
    scan_with_semantic_extractor(root, extract_semantic_delta)
}

fn scan_with_semantic_extractor(
    root: &Path,
    semantic_extractor: SemanticExtractor,
) -> Result<ScanResult> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize scan root {}", root.display()))?;
    if !root.is_dir() {
        bail!("scan root is not a directory: {}", root.display());
    }
    let toolchain_probe = probe_rust_toolchain(&root);
    let declared_toolchain = declared_rust_toolchain(&root);
    let hir_toolchain_status = match &declared_toolchain {
        RustToolchainDeclaration::Valid { channel, .. } if channel != RUST_TOOLCHAIN_BASELINE => {
            ToolchainProbeStatus::Unsupported
        }
        RustToolchainDeclaration::Invalid { .. } => ToolchainProbeStatus::Unsupported,
        RustToolchainDeclaration::Absent | RustToolchainDeclaration::Valid { .. } => {
            toolchain_probe.status()
        }
    };

    let (documents, discovery_failures) = discover_manifests(&root)?;
    let metadata_manifest = documents
        .iter()
        .find(|document| document.rel_path == "Cargo.toml")
        .or_else(|| documents.first())
        .cloned();
    let metadata_result = metadata_manifest.as_ref().and_then(|document| {
        if cargo_ancestor_manifest_failed(&root, document, &discovery_failures) {
            return None;
        }
        run_cargo_metadata(&root, &document.abs_path, &documents)
            .and_then(|(metadata, lock)| {
                let workspace_root = normalize_path(metadata.workspace_root());
                if !workspace_root.starts_with(&root) {
                    bail!("cargo metadata workspace root is outside the scan root");
                }
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
    let profile = rust_profile(
        &packages,
        &toolchain_probe,
        hir_toolchain_status,
        declared_toolchain.channel(),
        declared_toolchain.status(),
    );
    let mut state = State::new(root.clone(), repository_identity, profile);

    match &declared_toolchain {
        RustToolchainDeclaration::Valid { path, channel } if channel != RUST_TOOLCHAIN_BASELINE => {
            state.add_diagnostic(
                DiagnosticSeverity::Info,
                "RUST_TOOLCHAIN_BEST_EFFORT",
                &format!(
                    "repository declares Rust {channel} rather than the verified {RUST_TOOLCHAIN_BASELINE} baseline; static analysis continues on a best-effort basis"
                ),
                Some(path),
                None,
                &format!("toolchain:{channel}"),
            );
        }
        RustToolchainDeclaration::Invalid { path, reason } => {
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "RUST_TOOLCHAIN_INVALID",
                &format!(
                    "repository toolchain declaration is not safely usable: {reason}; static analysis continues without HIR"
                ),
                Some(path),
                None,
                "toolchain:invalid",
            );
        }
        RustToolchainDeclaration::Absent | RustToolchainDeclaration::Valid { .. } => {}
    }
    match hir_toolchain_status {
        ToolchainProbeStatus::Compatible => state.add_diagnostic(
            DiagnosticSeverity::Info,
            "RUST_HIR_SCAFFOLD_READY",
            &format!(
                "rust-analyzer {RUST_ANALYZER_CRATE_VERSION} ({RUST_ANALYZER_REVISION}) is pinned and the Rust {RUST_TOOLCHAIN_BASELINE} probe passed; inventory-only HIR definition graph extraction is available"
            ),
            None,
            None,
            "rust-hir-scaffold-ready",
        ),
        ToolchainProbeStatus::Unsupported | ToolchainProbeStatus::Unavailable => {
            state.reasons.insert("rust-hir-unsupported".into());
            let reason = declared_toolchain
                .rejection_reason()
                .or_else(|| toolchain_probe.reason().map(str::to_owned))
                .unwrap_or_else(|| "the verified Rust toolchain pair is unavailable".into());
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "RUST_HIR_TOOLCHAIN_UNSUPPORTED",
                &format!("{reason}; HIR remains disabled and syntax analysis continues"),
                declared_toolchain.path(),
                None,
                &format!("rust-hir-toolchain:{}", hir_toolchain_status.as_str()),
            );
        }
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
                "cargo metadata completed against a confined input mirror with frozen, offline, no-deps settings",
                Some(&document.rel_path),
                None,
                "cargo-metadata-success",
            );
        }
        Some(document) => {
            state.reasons.insert("cargo-metadata-fallback".into());
            state
                .reasons
                .insert("rust-hir-crate-graph-unavailable".into());
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "CARGO_METADATA_FALLBACK",
                "confined cargo metadata --frozen --offline was unavailable; static manifest parsing was used",
                Some(&document.rel_path),
                None,
                "cargo-metadata-fallback",
            );
            state.add_diagnostic(
                DiagnosticSeverity::Warning,
                "RUST_HIR_CRATE_GRAPH_UNAVAILABLE",
                "a confined Cargo crate graph was unavailable; HIR remains disabled and syntax analysis continues",
                Some(&document.rel_path),
                None,
                "rust-hir-crate-graph-unavailable",
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
    let hir_model = state.build_hir_project_model(
        &packages,
        &sources,
        metadata_succeeded,
        metadata_manifest.is_some(),
        hir_toolchain_status,
    );
    if let Some(model) = hir_model {
        state.extract_hir_semantics(&packages, &sources, &model, semantic_extractor);
    }
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
            semantic_use_occurrences: BTreeSet::new(),
            semantic_type_use_occurrences: BTreeSet::new(),
            semantic_call_occurrences: BTreeSet::new(),
            unsupported_syntax: 0,
            reasons: BTreeSet::new(),
            rust_release_gate: configured_rust_release_gate(),
        }
    }

    fn finish(self) -> Result<ScanResult> {
        let nodes: Vec<_> = self.nodes.into_values().collect();
        let edges: Vec<_> = self.edges.into_values().collect();
        let sites: Vec<_> = self.sites.into_values().collect();
        validate_semantic_graph(&nodes, &edges, &sites)
            .context("Rust worker semantic graph invariants failed")?;

        let files: Vec<_> = self.files.into_values().collect();
        let files_skipped = files.iter().filter(|file| file.skipped).count() as u64;
        let mut coverage = Coverage {
            profiles: 1,
            files_discovered: files.len() as u64,
            files_analyzed: files.len() as u64 - files_skipped,
            files_skipped,
            dependency_sites: sites.len() as u64,
            unsupported_syntax: self.unsupported_syntax,
            project_code_executed: false,
            completeness: Vec::new(),
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
        if coverage.files_skipped != 0 {
            coverage.reasons.push("files-skipped".into());
        }
        if coverage.unsupported_syntax != 0 {
            coverage.reasons.push("unsupported-syntax".into());
        }
        if coverage.unresolved != 0 {
            coverage.reasons.push("unresolved-sites".into());
        }
        coverage.reasons.sort();
        coverage.reasons.dedup();

        let syntax_complete = coverage.files_skipped == 0 && coverage.unsupported_syntax == 0;
        if syntax_complete {
            coverage
                .completeness
                .push(CompletenessLevel::SyntaxComplete);
        }
        if syntax_complete
            && coverage.unresolved == 0
            && rust_semantic_complete_eligible(&self.profile, &coverage)
        {
            coverage
                .completeness
                .push(CompletenessLevel::SemanticComplete);
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
                    "feature_resolver": package.feature_resolver,
                    "manifest_path": package.manifest_path,
                    "workspace_member": package.workspace_member,
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
                Ok(source) => Some(source),
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
                    None
                }
            };
            let generated = source
                .as_deref()
                .unwrap_or_default()
                .lines()
                .take(8)
                .any(|line| line.contains("@generated") || line.contains("DO NOT EDIT"));
            let content_hash = source.as_deref().map(source_content_hash);
            self.insert_node(GraphNode {
                id: file_id.clone(),
                kind: "file".into(),
                locator: format!("file:{rel_path}"),
                display_name: Some(rel_path.clone()),
                properties: properties(json!({
                    "language": "rust",
                    "generated": generated,
                    "package": package_index.map(|index| packages[index].name.clone()),
                    "package_locator": package_locator,
                    "content_hash": content_hash
                })),
            })?;
            self.file_nodes.insert(rel_path.clone(), file_id);

            let syntax = match source.as_deref() {
                None => None,
                Some(source) => match syn::parse_file(source) {
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
                },
            };
            sources.push(SourceUnit {
                rel_path,
                package_index,
                text: source,
                syntax,
            });
        }
        Ok(sources)
    }

    fn build_hir_project_model(
        &mut self,
        packages: &[Package],
        sources: &[SourceUnit],
        metadata_succeeded: bool,
        manifest_found: bool,
        hir_toolchain_status: ToolchainProbeStatus,
    ) -> Option<SafeProjectModel> {
        let crate_graph_source = if metadata_succeeded {
            "confined-cargo-metadata"
        } else if manifest_found {
            "static-manifest-fallback"
        } else {
            "none"
        };
        self.profile.properties.insert(
            "crate_graph_source".into(),
            Value::String(crate_graph_source.into()),
        );

        if hir_toolchain_status != ToolchainProbeStatus::Compatible {
            self.profile.properties.insert(
                "rust_hir_project_model".into(),
                Value::String("not-invoked".into()),
            );
            self.profile.properties.insert(
                "rust_hir_enable_gate".into(),
                Value::String("toolchain-unsupported".into()),
            );
            return None;
        }
        if let Some((path, edition)) = packages.iter().find_map(|package| {
            package
                .targets
                .iter()
                .find(|target| !supported_rust_edition(&target.edition))
                .map(|target| (target.src_path.as_str(), target.edition.as_str()))
                .or_else(|| {
                    (!supported_rust_edition(&package.edition))
                        .then_some((package.manifest_path.as_str(), package.edition.as_str()))
                })
        }) {
            self.profile.properties.insert(
                "rust_hir_project_model".into(),
                Value::String("unsupported".into()),
            );
            self.profile.properties.insert(
                "rust_hir_enable_gate".into(),
                Value::String("input-unsupported".into()),
            );
            self.reasons.insert("rust-hir-unsupported".into());
            self.add_diagnostic(
                DiagnosticSeverity::Warning,
                "RUST_HIR_INPUT_UNSUPPORTED",
                &format!("Rust edition {edition} is outside the verified HIR compatibility matrix; syntax analysis continues"),
                Some(path),
                None,
                &format!("unsupported-edition:{edition}"),
            );
            return None;
        }
        if !metadata_succeeded {
            self.profile.properties.insert(
                "rust_hir_project_model".into(),
                Value::String("unavailable".into()),
            );
            self.profile.properties.insert(
                "rust_hir_enable_gate".into(),
                Value::String("crate-graph-unavailable".into()),
            );
            return None;
        }

        let inventory: Vec<_> = sources
            .iter()
            .filter_map(|source| {
                source.text.as_ref().map(|text| InventorySource {
                    rel_path: source.rel_path.clone(),
                    package_index: source.package_index,
                    text: text.clone(),
                })
            })
            .collect();
        let requested_features = self
            .profile
            .properties
            .get("requested_features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let mode = match self.profile.command.as_deref() {
            Some("test") => HirProjectMode::Test,
            Some("build") => HirProjectMode::Build,
            Some("check") | None | Some(_) => HirProjectMode::Check,
        };
        let project_profile = HirProjectProfile {
            target_triple: self.profile.target.clone().unwrap_or_default(),
            mode,
            requested_features,
        };
        let sysroot = match load_attested_sysroot(
            self.rust_release_gate == RELEASE_GATE_VERIFIED,
            std::env::var_os(RUST_SYSROOT_ROOT_ENV).as_deref(),
        ) {
            Ok(sysroot) => {
                self.profile.properties.insert(
                    "rust_hir_sysroot_status".into(),
                    Value::String("attested".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_sysroot_file_count".into(),
                    Value::from(sysroot.files.len() as u64),
                );
                Some(sysroot)
            }
            Err(reason) => {
                self.profile.properties.insert(
                    "rust_hir_sysroot_status".into(),
                    Value::String("unavailable".into()),
                );
                self.reasons.insert("rust-hir-sysroot-unavailable".into());
                self.add_diagnostic(
                    DiagnosticSeverity::Warning,
                    "RUST_HIR_SYSROOT_UNAVAILABLE",
                    &format!(
                        "the pinned bundled Rust sysroot is unavailable; syntax and local HIR analysis continue without semantic completeness: {reason}"
                    ),
                    None,
                    None,
                    "rust-hir-sysroot-unavailable",
                );
                None
            }
        };
        match build_safe_project_model_with_sysroot(
            packages,
            &inventory,
            sysroot.as_ref(),
            &project_profile,
            Path::new(""),
        ) {
            Ok(model) => {
                let _ = model.database();
                let snapshot = model.snapshot();
                let file_count = snapshot
                    .files
                    .iter()
                    .filter(|file| !file.path.starts_with("rust-sysroot/"))
                    .count() as u64;
                let crate_count = snapshot.crates.len() as u64;
                let sysroot_crate_count = snapshot.sysroot_crates.len() as u64;
                let external_count = snapshot.externals.len() as u64;
                self.profile.properties.insert(
                    "rust_hir_project_model".into(),
                    Value::String("ready".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_enable_gate".into(),
                    Value::String("semantic-emission-pending".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_project_file_count".into(),
                    Value::from(file_count),
                );
                self.profile.properties.insert(
                    "rust_hir_project_crate_count".into(),
                    Value::from(crate_count),
                );
                self.profile.properties.insert(
                    "rust_hir_sysroot_crate_count".into(),
                    Value::from(sysroot_crate_count),
                );
                self.profile.properties.insert(
                    "rust_hir_project_external_count".into(),
                    Value::from(external_count),
                );
                self.add_diagnostic(
                    DiagnosticSeverity::Info,
                    "RUST_HIR_PROJECT_MODEL_READY",
                    &format!(
                        "safe Rust project model admitted {file_count} inventory files, {crate_count} local crates, and {sysroot_crate_count} attested sysroot crates"
                    ),
                    None,
                    None,
                    "rust-hir-project-model-ready",
                );
                if external_count != 0 {
                    self.reasons
                        .insert("rust-hir-external-definition-unavailable".into());
                    let unavailable = if sysroot_crate_count == 0 {
                        "external dependency and sysroot crate definitions"
                    } else {
                        "external dependency definitions"
                    };
                    self.add_diagnostic(
                        DiagnosticSeverity::Warning,
                        "RUST_HIR_EXTERNAL_DEFINITION_UNAVAILABLE",
                        &format!(
                            "{external_count} {unavailable} were recorded as sentinels and were not loaded"
                        ),
                        None,
                        None,
                        "rust-hir-external-definition-unavailable",
                    );
                }
                Some(model)
            }
            Err(error) => {
                match error.kind {
                    ProjectModelErrorKind::UnsupportedInput => {
                        self.profile.properties.insert(
                            "rust_hir_project_model".into(),
                            Value::String("unsupported".into()),
                        );
                        self.profile.properties.insert(
                            "rust_hir_enable_gate".into(),
                            Value::String("input-unsupported".into()),
                        );
                        self.reasons.insert("rust-hir-unsupported".into());
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            "RUST_HIR_INPUT_UNSUPPORTED",
                            &error.reason,
                            error.path.as_deref(),
                            None,
                            "rust-hir-input-unsupported",
                        );
                    }
                    ProjectModelErrorKind::Incomplete => {
                        self.record_hir_project_unavailable(error.path.as_deref(), &error.reason);
                    }
                }
                None
            }
        }
    }

    fn extract_hir_semantics(
        &mut self,
        packages: &[Package],
        sources: &[SourceUnit],
        model: &SafeProjectModel,
        semantic_extractor: SemanticExtractor,
    ) {
        let result = (|| -> Result<(SemanticDelta, BTreeMap<String, SemanticCrateContext>)> {
            let contexts = self.semantic_crate_contexts(packages, model)?;
            let occurrences_by_path = sources
                .iter()
                .filter_map(|source| {
                    source
                        .syntax
                        .as_ref()
                        .map(|syntax| (source.rel_path.clone(), collect_occurrences(syntax)))
                })
                .collect();
            let delta =
                semantic_extractor(model, &contexts, &occurrences_by_path, &self.profile.id)?;
            self.merge_semantic_delta(&delta)?;
            Ok((delta, contexts))
        })();

        match result {
            Ok((delta, _contexts)) => {
                let node_count = delta.nodes.len() as u64;
                let relation_count = delta.edges.len() as u64;
                let site_count = delta.sites.len() as u64;
                let call_site_count = delta
                    .sites
                    .iter()
                    .filter(|site| site.kind == "call")
                    .count() as u64;
                let issue_count = delta.issues.len() as u64;
                self.profile.properties.insert(
                    "analysis".into(),
                    Value::String("syntax+hir-imports-types-calls".into()),
                );
                self.profile.properties.insert(
                    "analysis_backend".into(),
                    Value::String("static-syntax+rust-analyzer-hir".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_backend".into(),
                    Value::String("rust-analyzer-hir".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_status".into(),
                    Value::String(
                        if issue_count == 0 {
                            "import-type-call-graph-emitted"
                        } else {
                            "import-type-call-graph-partial"
                        }
                        .into(),
                    ),
                );
                self.profile.properties.insert(
                    "rust_hir_enable_gate".into(),
                    Value::String(self.rust_release_gate.into()),
                );
                self.profile.properties.insert(
                    "rust_hir_semantic_node_count".into(),
                    Value::from(node_count),
                );
                self.profile.properties.insert(
                    "rust_hir_semantic_relation_count".into(),
                    Value::from(relation_count),
                );
                self.profile.properties.insert(
                    "rust_hir_semantic_site_count".into(),
                    Value::from(site_count),
                );
                self.profile.properties.insert(
                    "rust_hir_semantic_call_site_count".into(),
                    Value::from(call_site_count),
                );
                self.profile.properties.insert(
                    "rust_hir_semantic_issue_count".into(),
                    Value::from(issue_count),
                );
                self.add_diagnostic(
                    DiagnosticSeverity::Info,
                    "RUST_HIR_SEMANTIC_GRAPH_READY",
                    &format!(
                        "rust-analyzer emitted {node_count} semantic nodes, {site_count} dependency sites, and {relation_count} relations from the confined project model"
                    ),
                    None,
                    None,
                    "rust-hir-semantic-graph-ready",
                );
                for issue in delta.issues {
                    self.reasons.insert("rust-hir-semantic-incomplete".into());
                    self.add_diagnostic(
                        DiagnosticSeverity::Warning,
                        issue.code,
                        &issue.reason,
                        issue.path.as_deref(),
                        None,
                        &format!("{}:{}", issue.code, issue.reason),
                    );
                }
            }
            Err(_error) => {
                self.reasons.insert("rust-hir-backend-failure".into());
                self.profile.properties.insert(
                    "rust_hir_backend".into(),
                    Value::String("rust-analyzer-hir".into()),
                );
                self.profile
                    .properties
                    .insert("rust_hir_status".into(), Value::String("failed".into()));
                self.profile.properties.insert(
                    "rust_hir_enable_gate".into(),
                    Value::String("semantic-backend-failure".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_failure_kind".into(),
                    Value::String("typed-recoverable".into()),
                );
                self.profile.properties.insert(
                    "rust_hir_failure_stage".into(),
                    Value::String("semantic-extraction-or-validation".into()),
                );
                self.add_diagnostic(
                    DiagnosticSeverity::Warning,
                    "RUST_HIR_BACKEND_FAILURE",
                    "Rust HIR semantic graph was discarded atomically after a typed backend failure; syntax graph output was preserved",
                    None,
                    None,
                    "rust-hir-backend-failure",
                );
            }
        }
    }

    fn semantic_crate_contexts(
        &self,
        packages: &[Package],
        model: &SafeProjectModel,
    ) -> Result<BTreeMap<String, SemanticCrateContext>> {
        let mut contexts = BTreeMap::new();
        for krate in &model.snapshot().crates {
            let (package_index, package) = packages
                .iter()
                .enumerate()
                .find(|(_, package)| {
                    krate
                        .key
                        .strip_prefix(&package.manifest_path)
                        .is_some_and(|suffix| suffix.starts_with('#'))
                })
                .with_context(|| format!("map semantic crate {} to Cargo package", krate.key))?;
            let scope = format!("{}:{}", krate.target_kind, krate.target_name);
            let mut module_nodes = BTreeMap::new();
            let mut ambiguous_module_paths = BTreeSet::new();
            for (key, node_ids) in &self.module_nodes {
                if key.package_index != package_index || key.scope != scope {
                    continue;
                }
                if node_ids.len() == 1 {
                    module_nodes.insert(
                        key.path.clone(),
                        node_ids.iter().next().expect("one module node").clone(),
                    );
                } else if !node_ids.is_empty() {
                    ambiguous_module_paths.insert(key.path.clone());
                }
            }
            if !module_nodes.contains_key(&Vec::new())
                && !ambiguous_module_paths.contains(&Vec::new())
            {
                bail!("semantic crate {} has no syntax root module", krate.key);
            }
            contexts.insert(
                krate.key.clone(),
                SemanticCrateContext {
                    package_locator: package_locator(package),
                    module_nodes,
                    ambiguous_module_paths,
                    cfg: krate.cfg.clone(),
                },
            );
        }
        Ok(contexts)
    }

    fn merge_semantic_delta(&mut self, delta: &SemanticDelta) -> Result<()> {
        let mut nodes = self.nodes.clone();
        let mut edges = self.edges.clone();
        let mut sites = self.sites.clone();
        let mut files = self.files.clone();
        for node in &delta.nodes {
            if let Some(existing) = nodes.get(&node.id) {
                if existing != node {
                    bail!("semantic delta conflicts with node {}", node.id);
                }
            } else {
                nodes.insert(node.id.clone(), node.clone());
            }
        }
        for site in &delta.sites {
            if let Some(existing) = sites.get(&site.id) {
                if existing != site {
                    bail!("semantic delta conflicts with site {}", site.id);
                }
                continue;
            }
            let primary = site
                .evidence
                .first()
                .with_context(|| format!("semantic site {} has no evidence", site.id))?;
            let path = primary
                .path
                .as_deref()
                .with_context(|| format!("semantic site {} has no evidence path", site.id))?;
            let file = files.get_mut(path).with_context(|| {
                format!("semantic site {} references unknown file {path}", site.id)
            })?;
            file.discovered_sites += 1;
            file.emitted_sites += 1;
            sites.insert(site.id.clone(), site.clone());
        }
        for edge in &delta.edges {
            if let Some(existing) = edges.get(&edge.id) {
                if existing != edge {
                    bail!("semantic delta conflicts with edge {}", edge.id);
                }
            } else {
                edges.insert(edge.id.clone(), edge.clone());
            }
        }
        let semantic_import_sites = delta
            .sites
            .iter()
            .filter(|site| {
                matches!(
                    site.kind.as_str(),
                    "rust_use" | "rust_reexport" | "extern_crate"
                )
            })
            .count();
        if semantic_import_sites != delta.refined_use_keys.len() {
            bail!(
                "semantic import refinement ledger has {semantic_import_sites} sites but {} occurrence keys",
                delta.refined_use_keys.len()
            );
        }
        let semantic_type_use_sites = delta
            .sites
            .iter()
            .filter(|site| site.kind == "type_use")
            .count();
        if semantic_type_use_sites != delta.refined_type_use_keys.len() {
            bail!(
                "semantic type-use refinement ledger has {semantic_type_use_sites} sites but {} occurrence keys",
                delta.refined_type_use_keys.len()
            );
        }
        let semantic_call_sites = delta
            .sites
            .iter()
            .filter(|site| site.kind == "call")
            .count();
        if semantic_call_sites != delta.refined_call_keys.len() {
            bail!(
                "semantic call refinement ledger has {semantic_call_sites} sites but {} occurrence keys",
                delta.refined_call_keys.len()
            );
        }
        let nodes_vec: Vec<_> = nodes.values().cloned().collect();
        let edges_vec: Vec<_> = edges.values().cloned().collect();
        let sites_vec: Vec<_> = sites.values().cloned().collect();
        validate_semantic_graph(&nodes_vec, &edges_vec, &sites_vec)
            .context("validate Rust HIR semantic delta")?;
        self.nodes = nodes;
        self.edges = edges;
        self.sites = sites;
        self.files = files;
        self.semantic_use_occurrences
            .extend(delta.refined_use_keys.iter().cloned());
        self.semantic_type_use_occurrences
            .extend(delta.refined_type_use_keys.iter().cloned());
        self.semantic_call_occurrences
            .extend(delta.refined_call_keys.iter().cloned());
        Ok(())
    }

    fn record_hir_project_unavailable(&mut self, path: Option<&str>, reason: &str) {
        self.profile.properties.insert(
            "rust_hir_project_model".into(),
            Value::String("unavailable".into()),
        );
        self.profile.properties.insert(
            "rust_hir_enable_gate".into(),
            Value::String("crate-graph-unavailable".into()),
        );
        self.reasons
            .insert("rust-hir-crate-graph-unavailable".into());
        self.add_diagnostic(
            DiagnosticSeverity::Warning,
            "RUST_HIR_CRATE_GRAPH_UNAVAILABLE",
            reason,
            path,
            None,
            "rust-hir-project-model-unavailable",
        );
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
                        "edition": target.edition,
                        "required_features": target.required_features,
                        "test": target.test,
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
                        target_specifier,
                        site_specifier,
                        alias,
                        glob,
                        reexport,
                        inline_ancestors,
                        condition,
                        span,
                    } => {
                        let occurrence_key = UseOccurrenceKey::from_occurrence(
                            &source.rel_path,
                            &target_specifier,
                            alias.as_deref(),
                            glob,
                            reexport,
                            &inline_ancestors,
                            &condition,
                            span,
                        );
                        if self.semantic_use_occurrences.contains(&occurrence_key) {
                            continue;
                        }
                        let resolution = self.resolve_rust_path(
                            packages,
                            source.package_index,
                            &target_specifier,
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
                            &site_specifier,
                            edge_kind,
                            condition,
                            resolution,
                            source_evidence(&source.rel_path, span, site_kind),
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::TypeUse {
                        specifier,
                        context,
                        inline_ancestors,
                        condition,
                        span,
                    } => {
                        let occurrence_key = TypeUseOccurrenceKey::from_occurrence(
                            &source.rel_path,
                            &specifier,
                            context,
                            &inline_ancestors,
                            &condition,
                            span,
                        );
                        if self.semantic_type_use_occurrences.contains(&occurrence_key) {
                            continue;
                        }
                        let resolution = self.resolve_rust_type_fallback(
                            packages,
                            source.package_index,
                            &specifier,
                            &source.rel_path,
                            span,
                        )?;
                        let mut evidence =
                            source_evidence(&source.rel_path, span, "Rust type-use fallback");
                        evidence.properties.insert(
                            "type_use_context".into(),
                            Value::String(context.as_str().into()),
                        );
                        evidence.properties.insert(
                            "semantic_refinement".into(),
                            Value::String("unavailable".into()),
                        );
                        self.add_site(
                            &source_node,
                            "type_use",
                            &specifier,
                            "type_uses",
                            condition,
                            resolution,
                            evidence,
                        )?;
                        self.increment_file_site(&source.rel_path);
                    }
                    Occurrence::ExternCrate {
                        specifier,
                        alias,
                        inline_ancestors,
                        condition,
                        span,
                    } => {
                        let occurrence_key = UseOccurrenceKey::from_occurrence(
                            &source.rel_path,
                            &specifier,
                            alias.as_deref(),
                            false,
                            false,
                            &inline_ancestors,
                            &condition,
                            span,
                        );
                        if self.semantic_use_occurrences.contains(&occurrence_key) {
                            continue;
                        }
                        let resolution = self.resolve_rust_path(
                            packages,
                            source.package_index,
                            &specifier,
                            &source.rel_path,
                            &inline_ancestors,
                            span,
                        )?;
                        let site_specifier = alias
                            .as_deref()
                            .map(|alias| format!("{specifier} as {alias}"))
                            .unwrap_or_else(|| specifier.clone());
                        self.add_site(
                            &source_node,
                            "extern_crate",
                            &site_specifier,
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
                    Occurrence::MacroExpansionBoundary {
                        specifier,
                        boundary_kind,
                        condition,
                        span,
                    } => {
                        let (
                            node_kind,
                            site_kind,
                            diagnostic_code,
                            coverage_reason,
                            reason,
                            message,
                        ) = if boundary_kind == crate::source::MacroExpansionBoundaryKind::Bang {
                            (
                                "macro_expansion",
                                "macro_expansion",
                                "MACRO_EXPANSION_NOT_EVALUATED",
                                "macro-expansion-not-evaluated",
                                "macro expansion identity could not be proven safe in static scan",
                                "A bang macro boundary was preserved without assuming that its unqualified name denotes a built-in macro",
                            )
                        } else {
                            (
                                "proc_macro_expansion",
                                "proc_macro_expansion",
                                "PROC_MACRO_EXPANSION_NOT_EXECUTED",
                                "proc-macro-expansion-not-executed",
                                "macro expansion was not executed or loaded in safe scan",
                                "A derive or attribute macro boundary was preserved without executing project or external macro code",
                            )
                        };
                        let unknown = self.unknown_node(
                            node_kind,
                            &specifier,
                            &source.rel_path,
                            span,
                            reason,
                        )?;
                        let mut evidence = source_evidence(
                            &source.rel_path,
                            span,
                            "safe macro expansion boundary",
                        );
                        evidence.properties.insert(
                            "macro_boundary_kind".into(),
                            Value::String(boundary_kind.as_str().into()),
                        );
                        self.add_site(
                            &source_node,
                            site_kind,
                            &specifier,
                            "expands",
                            condition,
                            unresolved(unknown, reason),
                            evidence.clone(),
                        )?;
                        self.increment_file_site(&source.rel_path);
                        self.reasons.insert(coverage_reason.into());
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            diagnostic_code,
                            message,
                            Some(&source.rel_path),
                            Some(evidence),
                            &format!(
                                "{}:{}:{}:{}:{}:{}:{}",
                                source.rel_path,
                                span.start_line,
                                span.start_column,
                                span.end_line,
                                span.end_column,
                                boundary_kind.as_str(),
                                specifier
                            ),
                        );
                    }
                    Occurrence::BuildEnvironmentMacro {
                        macro_name,
                        variable,
                        raw_argument,
                        condition,
                        span,
                    } => {
                        let out_dir = variable.as_deref() == Some("OUT_DIR");
                        let specifier = variable.as_deref().unwrap_or(&raw_argument);
                        let (node_kind, diagnostic_code, coverage_reason, reason, message) =
                            if out_dir {
                                (
                                    "build_script_output",
                                    "RUST_HIR_OUT_DIR_UNAVAILABLE",
                                    "rust-hir-out-dir-unavailable",
                                    "build-script OUT_DIR output is unavailable in safe scan",
                                    "env! depends on build-script OUT_DIR output, which safe scan does not execute or read",
                                )
                            } else {
                                (
                                    "build_environment",
                                    "BUILD_ENVIRONMENT_NOT_EVALUATED",
                                    "build-environment-not-evaluated",
                                    "compile-time build environment was not evaluated in safe scan",
                                    "A compile-time env!/option_env! boundary was preserved without evaluating project build environment",
                                )
                            };
                        let unknown = self.unknown_node(
                            node_kind,
                            specifier,
                            &source.rel_path,
                            span,
                            reason,
                        )?;
                        let mut evidence = source_evidence(
                            &source.rel_path,
                            span,
                            "safe build environment boundary",
                        );
                        evidence
                            .properties
                            .insert("macro_name".into(), Value::String(macro_name.clone()));
                        if let Some(variable) = &variable {
                            evidence.properties.insert(
                                "environment_variable".into(),
                                Value::String(variable.clone()),
                            );
                        }
                        self.add_site(
                            &source_node,
                            "build_environment",
                            specifier,
                            "reads_build_environment",
                            condition,
                            unresolved(unknown, reason),
                            evidence.clone(),
                        )?;
                        self.increment_file_site(&source.rel_path);
                        self.reasons.insert(coverage_reason.into());
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            diagnostic_code,
                            message,
                            Some(&source.rel_path),
                            Some(evidence),
                            &format!(
                                "{}:{}:{}:{}:{}:{}:{}",
                                source.rel_path,
                                span.start_line,
                                span.start_column,
                                span.end_line,
                                span.end_column,
                                macro_name,
                                specifier
                            ),
                        );
                    }
                    Occurrence::UnsupportedAttribute {
                        specifier,
                        reason,
                        condition,
                        span,
                    } => {
                        self.unsupported_syntax += 1;
                        self.reasons.insert("unsupported-attribute".into());
                        let unknown = self.unknown_node(
                            "rust_attribute",
                            &specifier,
                            &source.rel_path,
                            span,
                            &reason,
                        )?;
                        let evidence = source_evidence(
                            &source.rel_path,
                            span,
                            "unsupported Rust attribute payload",
                        );
                        self.add_site(
                            &source_node,
                            "unsupported_attribute",
                            &specifier,
                            "requires",
                            condition,
                            unresolved(unknown, &reason),
                            evidence.clone(),
                        )?;
                        self.increment_file_site(&source.rel_path);
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            "RUST_ATTRIBUTE_UNSUPPORTED",
                            "A Rust attribute payload could not be parsed and was preserved as an unresolved boundary",
                            Some(&source.rel_path),
                            Some(evidence),
                            &format!(
                                "{}:{}:{}:{}:{}:{}",
                                source.rel_path,
                                span.start_line,
                                span.start_column,
                                span.end_line,
                                span.end_column,
                                specifier
                            ),
                        );
                    }
                    Occurrence::UnsupportedMacroArguments {
                        specifier,
                        condition,
                        span,
                    } => {
                        self.unsupported_syntax += 1;
                        self.reasons.insert("unsupported-macro-arguments".into());
                        let reason = "built-in macro arguments could not be inspected in safe scan";
                        let unknown = self.unknown_node(
                            "rust_macro_arguments",
                            &specifier,
                            &source.rel_path,
                            span,
                            reason,
                        )?;
                        let evidence = source_evidence(
                            &source.rel_path,
                            span,
                            "unsupported built-in macro arguments",
                        );
                        self.add_site(
                            &source_node,
                            "unsupported_macro_arguments",
                            &specifier,
                            "requires",
                            condition,
                            unresolved(unknown, reason),
                            evidence.clone(),
                        )?;
                        self.increment_file_site(&source.rel_path);
                        self.add_diagnostic(
                            DiagnosticSeverity::Warning,
                            "RUST_MACRO_ARGUMENTS_UNSUPPORTED",
                            "Built-in macro arguments could not be parsed recursively; completeness was withheld",
                            Some(&source.rel_path),
                            Some(evidence),
                            &format!(
                                "{}:{}:{}:{}:{}:{}",
                                source.rel_path,
                                span.start_line,
                                span.start_column,
                                span.end_line,
                                span.end_column,
                                specifier
                            ),
                        );
                    }
                    Occurrence::Call { .. } => {}
                    Occurrence::Module { inline: true, .. } => {}
                }
            }
        }
        Ok(())
    }

    fn resolve_rust_type_fallback(
        &mut self,
        packages: &[Package],
        package_index: Option<usize>,
        specifier: &str,
        path: &str,
        span: SourceSpan,
    ) -> Result<TargetResolution> {
        let first = specifier
            .split("::")
            .find(|part| !part.is_empty())
            .unwrap_or(specifier)
            .trim_start_matches("r#");
        if matches!(first, "std" | "core" | "alloc" | "proc_macro") {
            let target = self.external_node(&format!("rust-sysroot:{first}"), first, None)?;
            return Ok(TargetResolution {
                target_ids: vec![target],
                status: ResolutionStatus::External,
                precision: Precision::Heuristic,
                reason: Some(format!(
                    "type use is rooted in external sysroot crate {first}, but exact HIR resolution was unavailable"
                )),
            });
        }
        if let Some(package_index) = package_index
            && let Some(resolution) = self
                .dependency_resolutions
                .get(&(package_index, first.to_owned()))
            && resolution.status == ResolutionStatus::External
        {
            let mut resolution = resolution.clone();
            resolution.precision = Precision::Heuristic;
            resolution.reason = Some(format!(
                "type use is rooted in external dependency {first}, but exact HIR resolution was unavailable"
            ));
            return Ok(resolution);
        }

        let package_name = package_index
            .and_then(|index| packages.get(index))
            .map(|package| package.name.as_str())
            .unwrap_or("unknown");
        let reason = format!(
            "type use was recognized in package {package_name}, but exact HIR resolution was unavailable"
        );
        let unknown = self.unknown_node("rust_type", specifier, path, span, &reason)?;
        Ok(unresolved(unknown, &reason))
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
            let out_dir_boundary = raw_argument.contains("OUT_DIR");
            let (diagnostic_code, coverage_reason, message, unresolved_reason) = if out_dir_boundary
            {
                (
                    "RUST_HIR_OUT_DIR_UNAVAILABLE",
                    "rust-hir-out-dir-unavailable",
                    "include! depends on build-script OUT_DIR output, which safe scan does not execute or read",
                    "build-script OUT_DIR output is unavailable in safe scan",
                )
            } else {
                (
                    "DYNAMIC_INCLUDE_UNRESOLVED",
                    "dynamic-include",
                    "include macro argument is not a string literal",
                    "include argument is not a string literal",
                )
            };
            self.reasons.insert(coverage_reason.into());
            let evidence = source_evidence(source_path, span, "dynamic include boundary");
            self.add_diagnostic(
                DiagnosticSeverity::Warning,
                diagnostic_code,
                message,
                Some(source_path),
                Some(evidence),
                &format!(
                    "{source_path}:{}:{}:{}:{}:{macro_name}",
                    span.start_line, span.start_column, span.end_line, span.end_column
                ),
            );
            let unknown = self.unknown_node(
                "include",
                raw_argument,
                source_path,
                span,
                unresolved_reason,
            )?;
            return Ok((raw_argument.into(), unresolved(unknown, unresolved_reason)));
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
        let reason = "included path is missing or outside the scan root";
        self.reasons.insert("include-path-unavailable".into());
        self.add_diagnostic(
            DiagnosticSeverity::Warning,
            "RUST_INCLUDE_PATH_UNAVAILABLE",
            reason,
            Some(source_path),
            Some(source_evidence(
                source_path,
                span,
                "confined include boundary",
            )),
            &format!(
                "{source_path}:{}:{}:{}:{}:{macro_name}",
                span.start_line, span.start_column, span.end_line, span.end_column
            ),
        );
        let unknown = self.unknown_node("include", &argument, source_path, span, reason)?;
        Ok((argument, unresolved(unknown, reason)))
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
    rust_mode: String,
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
        } else {
            let path = entry.into_path();
            let lexical = relative_path(root, &path);
            failures.push(DiscoveryFailure {
                path: lexical.clone(),
                reason: format!("Cargo manifest {lexical} is not a regular file"),
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

fn cargo_ancestor_manifest_failed(
    root: &Path,
    entry: &ManifestDocument,
    failures: &[DiscoveryFailure],
) -> bool {
    let mut directory = entry.dir.as_path();
    loop {
        let candidate = directory.join("Cargo.toml");
        let relative = relative_path(root, &candidate);
        if failures.iter().any(|failure| {
            failure.path == relative || failure.path == skipped_ledger_path(&relative)
        }) {
            return true;
        }
        if directory == root {
            return false;
        }
        let Some(parent) = directory.parent().filter(|parent| parent.starts_with(root)) else {
            return false;
        };
        directory = parent;
    }
}

fn supported_rust_edition(edition: &str) -> bool {
    matches!(edition, "2015" | "2018" | "2021" | "2024")
}

fn rust_semantic_complete_eligible(profile: &Profile, coverage: &Coverage) -> bool {
    coverage.files_skipped == 0
        && coverage.unsupported_syntax == 0
        && coverage.candidates == 0
        && coverage.external == 0
        && coverage.unresolved == 0
        && !coverage.project_code_executed
        && profile.properties.get("analysis").and_then(Value::as_str)
            == Some("syntax+hir-imports-types-calls")
        && profile
            .properties
            .get("analysis_backend")
            .and_then(Value::as_str)
            == Some("static-syntax+rust-analyzer-hir")
        && profile
            .properties
            .get("rust_hir_backend")
            .and_then(Value::as_str)
            == Some("rust-analyzer-hir")
        && profile
            .properties
            .get("rust_hir_status")
            .and_then(Value::as_str)
            == Some("import-type-call-graph-emitted")
        && profile
            .properties
            .get("rust_hir_project_model")
            .and_then(Value::as_str)
            == Some("ready")
        && profile
            .properties
            .get("rust_hir_sysroot_status")
            .and_then(Value::as_str)
            == Some("attested")
        && profile
            .properties
            .get("rust_hir_sysroot_crate_count")
            .and_then(Value::as_u64)
            == Some(3)
        && profile
            .properties
            .get("rust_hir_project_external_count")
            .and_then(Value::as_u64)
            == Some(0)
        && profile
            .properties
            .get("rust_hir_enable_gate")
            .and_then(Value::as_str)
            == Some(RELEASE_GATE_VERIFIED)
        && profile
            .properties
            .get("crate_graph_source")
            .and_then(Value::as_str)
            == Some("confined-cargo-metadata")
        && profile
            .properties
            .get("cargo_metadata_input")
            .and_then(Value::as_str)
            == Some("confined-mirror")
        && profile
            .properties
            .get("rust_toolchain_probe_status")
            .and_then(Value::as_str)
            == Some("compatible")
        && profile
            .properties
            .get("rust_hir_toolchain_status")
            .and_then(Value::as_str)
            == Some("compatible")
        && profile
            .properties
            .get("proc_macro_expansion")
            .and_then(Value::as_str)
            == Some("disabled")
        && profile
            .properties
            .get("build_script_policy")
            .and_then(Value::as_str)
            == Some("disabled")
        && profile
            .properties
            .get("proc_macro_policy")
            .and_then(Value::as_str)
            == Some("disabled")
        && profile
            .properties
            .get("rust_hir_semantic_issue_count")
            .and_then(Value::as_u64)
            == Some(0)
        && profile
            .properties
            .get("project_code_executed")
            .and_then(Value::as_bool)
            == Some(false)
        && profile
            .properties
            .get("project_toolchain_executed")
            .and_then(Value::as_bool)
            == Some(false)
        && profile
            .properties
            .get("build_scripts_executed")
            .and_then(Value::as_bool)
            == Some(false)
        && profile
            .properties
            .get("proc_macros_executed")
            .and_then(Value::as_bool)
            == Some(false)
}

fn configured_rust_release_gate() -> &'static str {
    rust_release_gate_from_env_value(std::env::var_os(RUST_RELEASE_GATE_ENV).as_deref())
}

fn rust_release_gate_from_env_value(value: Option<&OsStr>) -> &'static str {
    if value == Some(OsStr::new(RELEASE_GATE_VERIFIED)) {
        RELEASE_GATE_VERIFIED
    } else {
        RELEASE_GATE_PENDING
    }
}

fn rust_profile(
    packages: &[Package],
    toolchain_probe: &RustToolchainProbe,
    hir_toolchain_status: ToolchainProbeStatus,
    declared_toolchain: Option<&str>,
    declared_toolchain_status: &str,
) -> Profile {
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
    selection.rust_mode = match selection.rust_mode.trim() {
        "build" => "build",
        "test" => "test",
        _ => "check",
    }
    .into();
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
        &selection.rust_mode,
    );
    let expanded_profile_features = features.clone();
    let mut profile_properties = properties(json!({
        "analysis": "syntax",
        "analysis_backend": "static-syntax",
        "rust_hir_backend": "disabled",
        "rust_hir_status": "not-invoked",
        "rust_hir_scaffold": "available",
        "rust_hir_project_model": if hir_toolchain_status == ToolchainProbeStatus::Compatible {
            "pending"
        } else {
            "not-invoked"
        },
        "rust_hir_enable_gate": if hir_toolchain_status == ToolchainProbeStatus::Compatible {
            "semantic-emission-pending"
        } else {
            "toolchain-unsupported"
        },
        "rust_hir_project_file_count": 0,
        "rust_hir_project_crate_count": 0,
        "rust_hir_project_external_count": 0,
        "rust_hir_semantic_node_count": 0,
        "rust_hir_semantic_relation_count": 0,
        "rust_hir_semantic_site_count": 0,
        "rust_hir_semantic_call_site_count": 0,
        "rust_hir_semantic_issue_count": 0,
        "rust_hir_cfg_profile": "debug-unwind",
        "rust_hir_integration_policy": RUST_HIR_INTEGRATION_POLICY,
        "rust_analyzer_version": RUST_ANALYZER_CRATE_VERSION,
        "rust_analyzer_revision": RUST_ANALYZER_REVISION,
        "rust_analyzer_salsa_version": RUST_ANALYZER_SALSA_VERSION,
        "rust_toolchain_baseline": RUST_TOOLCHAIN_BASELINE,
        "rust_toolchain_probe_status": toolchain_probe.status().as_str(),
        "rust_hir_toolchain_status": hir_toolchain_status.as_str(),
        "rust_toolchain_declaration_status": declared_toolchain_status,
        "rust_toolchain_observed": toolchain_probe.as_value(),
        "cargo_metadata_input": "confined-mirror",
        "crate_graph_source_policy": "confined-cargo-metadata-or-static-manifest",
        "syntax_fallback": "enabled",
        "effective_target": selected_target,
        "host_target": host_target,
        "requested_features": selection.rust_features,
        "expanded_features": expanded_profile_features,
        "configured_targets": selection.rust_targets,
        "rust_mode": selection.rust_mode,
        "build_scripts_executed": false,
        "proc_macros_executed": false,
        "build_script_policy": "disabled",
        "proc_macro_policy": "disabled",
        "proc_macro_expansion": "disabled",
        "project_code_executed": false,
        "project_toolchain_executed": false
    }));
    profile_properties.insert(
        "rust_hir_sysroot_status".into(),
        Value::String(
            if hir_toolchain_status == ToolchainProbeStatus::Compatible {
                "pending"
            } else {
                "not-invoked"
            }
            .into(),
        ),
    );
    profile_properties.insert("rust_hir_sysroot_file_count".into(), Value::from(0));
    profile_properties.insert("rust_hir_sysroot_crate_count".into(), Value::from(0));
    profile_properties.insert(
        "rust_hir_sysroot_contract_version".into(),
        Value::String(RUST_SYSROOT_CONTRACT_VERSION.into()),
    );
    profile_properties.insert(
        "rust_hir_sysroot_component_version".into(),
        Value::String(RUST_SYSROOT_COMPONENT_VERSION.into()),
    );
    profile_properties.insert(
        "rust_hir_sysroot_source_layout".into(),
        Value::String(RUST_SYSROOT_SOURCE_LAYOUT.into()),
    );
    Profile {
        id,
        language: "rust".into(),
        toolchain: Some(json!({
            "metadata_command": "cargo metadata --format-version 1 --no-deps --frozen --offline",
            "adapter_version": ADAPTER_VERSION,
            "hir_probe": toolchain_probe.as_value(),
            "declared_toolchain": declared_toolchain,
            "declared_toolchain_status": declared_toolchain_status,
        })),
        command: Some(selection.rust_mode.clone()),
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
        properties: profile_properties,
    }
}

fn rust_profile_id(
    host_target: &str,
    effective_target: &str,
    requested_features: &[String],
    expanded_features: &[String],
    configured_targets: &[String],
    rust_mode: &str,
) -> String {
    stable_id_from_value(
        "profile",
        &json!({
            "language": "rust",
            "analysis": "syntax",
            "command": rust_mode,
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

#[derive(Debug)]
enum RustToolchainDeclaration {
    Absent,
    Valid { path: String, channel: String },
    Invalid { path: String, reason: String },
}

impl RustToolchainDeclaration {
    fn status(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Valid { .. } => "valid",
            Self::Invalid { .. } => "invalid",
        }
    }

    fn channel(&self) -> Option<&str> {
        match self {
            Self::Valid { channel, .. } => Some(channel),
            Self::Absent | Self::Invalid { .. } => None,
        }
    }

    fn path(&self) -> Option<&str> {
        match self {
            Self::Valid { path, .. } | Self::Invalid { path, .. } => Some(path),
            Self::Absent => None,
        }
    }

    fn rejection_reason(&self) -> Option<String> {
        match self {
            Self::Valid { channel, .. } if channel != RUST_TOOLCHAIN_BASELINE => Some(format!(
                "repository toolchain declaration {channel} does not exactly match {RUST_TOOLCHAIN_BASELINE}"
            )),
            Self::Invalid { reason, .. } => Some(format!(
                "repository toolchain declaration is invalid: {reason}"
            )),
            Self::Absent | Self::Valid { .. } => None,
        }
    }
}

fn declared_rust_toolchain(root: &Path) -> RustToolchainDeclaration {
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        let candidate = root.join(name);
        match fs::symlink_metadata(&candidate) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return RustToolchainDeclaration::Invalid {
                    path: name.to_owned(),
                    reason: "metadata could not be read".into(),
                };
            }
        }
        let canonical = match candidate.canonicalize() {
            Ok(canonical) => canonical,
            Err(_) => {
                return RustToolchainDeclaration::Invalid {
                    path: name.to_owned(),
                    reason: "path could not be resolved".into(),
                };
            }
        };
        if !canonical.starts_with(root) || !canonical.is_file() {
            return RustToolchainDeclaration::Invalid {
                path: name.to_owned(),
                reason: "path resolves outside the scan root or is not a regular file".into(),
            };
        }
        let source = match fs::read_to_string(canonical) {
            Ok(source) => source,
            Err(_) => {
                return RustToolchainDeclaration::Invalid {
                    path: name.to_owned(),
                    reason: "file is unreadable or is not UTF-8".into(),
                };
            }
        };
        let declared = if name.ends_with(".toml") {
            let parsed = match toml::from_str::<toml::Value>(&source) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return RustToolchainDeclaration::Invalid {
                        path: name.to_owned(),
                        reason: "TOML is malformed".into(),
                    };
                }
            };
            match parsed
                .get("toolchain")
                .and_then(|toolchain| toolchain.get("channel"))
                .and_then(toml::Value::as_str)
                .map(str::trim)
                .filter(|channel| !channel.is_empty())
            {
                Some(channel) => channel.to_owned(),
                None => {
                    return RustToolchainDeclaration::Invalid {
                        path: name.to_owned(),
                        reason: "toolchain.channel is missing or empty".into(),
                    };
                }
            }
        } else {
            source.trim().to_owned()
        };
        if declared.is_empty() {
            return RustToolchainDeclaration::Invalid {
                path: name.to_owned(),
                reason: "toolchain channel is empty".into(),
            };
        }
        return RustToolchainDeclaration::Valid {
            path: name.to_owned(),
            channel: declared,
        };
    }
    RustToolchainDeclaration::Absent
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
    fn source_hash_uses_raw_utf8_bytes_and_explicit_algorithm_prefix() {
        assert_eq!(
            source_content_hash("abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn write_complete_semantic_fixture(root: &Path) {
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='complete'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"complete\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("src/lib.rs"), "pub mod model;\n").unwrap();
        fs::write(root.join("src/model.rs"), "pub struct Thing;\n").unwrap();
    }

    fn forced_semantic_failure(
        _model: &SafeProjectModel,
        _contexts: &BTreeMap<String, SemanticCrateContext>,
        _occurrences_by_path: &BTreeMap<String, Vec<Occurrence>>,
        _profile_id: &str,
    ) -> Result<SemanticDelta> {
        bail!("forced typed semantic backend failure")
    }

    fn invalid_semantic_delta(
        model: &SafeProjectModel,
        contexts: &BTreeMap<String, SemanticCrateContext>,
        occurrences_by_path: &BTreeMap<String, Vec<Occurrence>>,
        profile_id: &str,
    ) -> Result<SemanticDelta> {
        let mut delta = extract_semantic_delta(model, contexts, occurrences_by_path, profile_id)?;
        let site = delta
            .sites
            .first_mut()
            .context("fixture must emit a semantic import site")?;
        site.evidence
            .first_mut()
            .context("semantic fixture site must have evidence")?
            .path = Some("__missing_semantic_input__.rs".into());
        Ok(delta)
    }

    #[test]
    fn development_hir_profile_requires_an_attested_sysroot_for_semantic_complete() {
        let temp = tempfile::tempdir().unwrap();
        write_complete_semantic_fixture(temp.path());

        let result = scan(temp.path()).unwrap();

        assert_eq!(result.coverage.files_skipped, 0);
        assert_eq!(result.coverage.unsupported_syntax, 0);
        assert_eq!(result.coverage.unresolved, 0);
        assert!(
            result
                .coverage
                .completeness
                .contains(&CompletenessLevel::SyntaxComplete)
        );
        assert!(
            !result
                .coverage
                .completeness
                .contains(&CompletenessLevel::SemanticComplete)
        );
        assert_eq!(
            result.profile.properties["rust_hir_enable_gate"],
            "release-gate-pending"
        );
        assert_eq!(
            result.profile.properties["rust_hir_sysroot_status"],
            "unavailable"
        );
        assert!(
            result
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == "rust-hir-sysroot-unavailable")
        );
        crate::emit::build_events("semantic-complete-contract", &result).unwrap();
    }

    #[test]
    fn nested_cfg_attr_conditions_are_preserved_without_sysroot_promotion() {
        let temp = tempfile::tempdir().unwrap();
        write_complete_semantic_fixture(temp.path());
        fs::write(
            temp.path().join("src/lib.rs"),
            r#"pub struct Local;

#[cfg_attr(feature = "p", cfg_attr(feature = "q", cfg(unix)))]
pub fn consume(_: Local) {}
"#,
        )
        .unwrap();

        let result = scan(temp.path()).unwrap();

        assert!(
            !result
                .coverage
                .completeness
                .contains(&CompletenessLevel::SemanticComplete)
        );
        let condition = result
            .sites
            .iter()
            .filter(|site| site.kind == "type_use")
            .map(|site| site.condition.render())
            .find(|condition| condition.contains("\"p\"") && condition.contains("\"q\""))
            .expect("nested cfg_attr type-use condition");
        assert!(condition.contains("rust.cfg.unix"));
        assert!(condition.matches('!').count() >= 2);
    }

    #[test]
    fn typed_hir_failure_preserves_syntax_and_discards_semantic_output() {
        let temp = tempfile::tempdir().unwrap();
        write_complete_semantic_fixture(temp.path());

        let result = scan_with_semantic_extractor(temp.path(), forced_semantic_failure).unwrap();

        assert_eq!(result.profile.properties["rust_hir_status"], "failed");
        assert_eq!(
            result.profile.properties["rust_hir_enable_gate"],
            "semantic-backend-failure"
        );
        assert!(
            result
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == "rust-hir-backend-failure")
        );
        assert!(
            !result
                .coverage
                .completeness
                .contains(&CompletenessLevel::SemanticComplete)
        );
        assert!(result.nodes.iter().any(|node| node.kind == "module"));
        assert!(
            result
                .nodes
                .iter()
                .all(|node| !matches!(node.kind.as_str(), "symbol" | "type"))
        );
        assert!(
            result
                .edges
                .iter()
                .all(|edge| edge.phase != Phase::Semantic)
        );
        assert!(result.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "RUST_HIR_BACKEND_FAILURE"
                && !diagnostic
                    .message
                    .contains(temp.path().to_string_lossy().as_ref())
        }));
    }

    #[test]
    fn late_semantic_validation_failure_is_atomic() {
        let temp = tempfile::tempdir().unwrap();
        write_complete_semantic_fixture(temp.path());

        let result = scan_with_semantic_extractor(temp.path(), invalid_semantic_delta).unwrap();

        assert_eq!(result.profile.properties["rust_hir_status"], "failed");
        assert!(
            result
                .nodes
                .iter()
                .all(|node| !matches!(node.kind.as_str(), "symbol" | "type"))
        );
        assert!(result.sites.iter().all(|site| {
            site.evidence
                .iter()
                .all(|evidence| evidence.kind != EvidenceKind::Semantic)
        }));
        assert!(
            result
                .edges
                .iter()
                .all(|edge| edge.phase != Phase::Semantic)
        );
        assert!(
            result
                .files
                .iter()
                .all(|file| file.discovered_sites == file.emitted_sites)
        );
    }

    #[test]
    fn scan_result_satisfies_site_edge_invariants() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workspace");
        let result = scan(&fixture).unwrap();
        validate_semantic_graph(&result.nodes, &result.edges, &result.sites).unwrap();
        assert!(result.sites.iter().all(|site| !site.evidence.is_empty()));
        assert!(result.edges.iter().any(|edge| edge.phase == Phase::Source));
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.phase == Phase::Semantic)
        );
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

    #[test]
    fn invalid_nested_attribute_payload_is_not_reported_as_semantic_complete() {
        let temp = tempfile::tempdir().unwrap();
        write_complete_semantic_fixture(temp.path());
        fs::write(
            temp.path().join("src/lib.rs"),
            "#[repr(align(env!(\"OUT_DIR\")))]\npub struct Broken(u8);\n",
        )
        .unwrap();

        let result = scan(temp.path()).unwrap();

        assert!(result.coverage.unsupported_syntax > 0);
        assert!(
            !result
                .coverage
                .completeness
                .contains(&CompletenessLevel::SemanticComplete)
        );
        assert!(
            result
                .coverage
                .reasons
                .iter()
                .any(|reason| reason == "unsupported-attribute")
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUST_ATTRIBUTE_UNSUPPORTED")
        );
    }

    #[test]
    fn unverified_builtin_attribute_forms_are_not_reported_as_semantic_complete() {
        for source in [
            "#[repr = \"C\"]\npub struct Broken(u8);\n",
            "#[inline(foo)]\npub fn broken() {}\n",
            "#[repr(C, Rust)]\npub struct Broken(u8);\n",
            "#[cfg(not(unix, windows))]\npub fn broken() {}\n",
            "#[cfg(foo::bar)]\npub fn broken() {}\n",
            "#[cfg(foo::bar = \"x\")]\npub fn broken() {}\n",
            "#[cfg_attr(foo::bar, cfg(unix))]\npub fn broken() {}\n",
            "#[cfg_attr(unix, cfg(not(a, b)))]\npub fn broken() {}\n",
        ] {
            let temp = tempfile::tempdir().unwrap();
            write_complete_semantic_fixture(temp.path());
            fs::write(temp.path().join("src/lib.rs"), source).unwrap();

            let result = scan(temp.path()).unwrap();

            assert!(result.coverage.unsupported_syntax > 0, "source: {source}");
            assert!(
                !result
                    .coverage
                    .completeness
                    .contains(&CompletenessLevel::SemanticComplete),
                "source: {source}"
            );
            assert!(
                result
                    .diagnostics
                    .iter()
                    .any(|diagnostic| { diagnostic.code == "RUST_ATTRIBUTE_UNSUPPORTED" })
            );
        }
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
        assert_eq!(
            result.profile.properties["rust_toolchain_baseline"],
            RUST_TOOLCHAIN_BASELINE
        );
        assert_eq!(
            result.profile.properties["rust_hir_integration_policy"],
            RUST_HIR_INTEGRATION_POLICY
        );
        assert_eq!(result.profile.properties["project_code_executed"], false);
        assert_eq!(
            result.profile.properties["project_toolchain_executed"],
            false
        );
        assert_eq!(
            result.profile.properties["rust_hir_toolchain_status"],
            "unsupported"
        );
        assert_eq!(
            result.profile.properties["rust_toolchain_declaration_status"],
            "valid"
        );
        assert_eq!(
            result.profile.properties["rust_toolchain_probe_status"],
            result.profile.properties["rust_toolchain_observed"]["status"]
        );
    }

    #[test]
    fn malformed_toolchain_declaration_fails_closed_for_hir() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='malformed-toolchain'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        std::fs::write(temp.path().join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        std::fs::write(
            temp.path().join("rust-toolchain.toml"),
            "[toolchain\nchannel='1.93.1'\n",
        )
        .unwrap();

        let result = scan(temp.path()).unwrap();
        assert_eq!(
            result.profile.properties["rust_hir_toolchain_status"],
            "unsupported"
        );
        assert_eq!(
            result.profile.properties["rust_toolchain_declaration_status"],
            "invalid"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUST_TOOLCHAIN_INVALID")
        );
        assert!(
            !result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUST_HIR_SCAFFOLD_READY")
        );
    }

    #[cfg(unix)]
    #[test]
    fn external_toolchain_symlink_fails_closed_for_hir() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='linked-toolchain'\nversion='0.1.0'\nedition='2024'\n",
        )
        .unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn value() {}\n").unwrap();
        let outside = temp.path().join("rust-toolchain.toml");
        std::fs::write(&outside, "[toolchain]\nchannel='1.93.1'\n").unwrap();
        symlink(&outside, root.join("rust-toolchain.toml")).unwrap();

        let result = scan(&root).unwrap();
        assert_eq!(
            result.profile.properties["rust_hir_toolchain_status"],
            "unsupported"
        );
        assert_eq!(
            result.profile.properties["rust_toolchain_declaration_status"],
            "invalid"
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "RUST_TOOLCHAIN_INVALID")
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
            "check",
        );
        let same_linux = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &no_values,
            &default_features,
            &no_values,
            "check",
        );
        let macos = rust_profile_id(
            "aarch64-apple-darwin",
            "aarch64-apple-darwin",
            &no_values,
            &default_features,
            &no_values,
            "check",
        );
        let requested = vec!["full".to_owned()];
        let expanded = vec!["default".to_owned(), "full".to_owned()];
        let with_feature = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &requested,
            &expanded,
            &no_values,
            "check",
        );
        let test_mode = rust_profile_id(
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            &no_values,
            &default_features,
            &no_values,
            "test",
        );

        assert_eq!(linux, same_linux);
        assert_ne!(linux, macos);
        assert_ne!(linux, with_feature);
        assert_ne!(linux, test_mode);
        assert!(linux.starts_with("profile:sha256:"));
    }
}
