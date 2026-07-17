use crate::manifest::{ManifestDocument, normalize_path, slash_path};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};
use tempfile::{Builder as TempDirBuilder, TempDir};
use toml::Value;

const MIRROR_ERROR: &str = "RUST_CARGO_MIRROR_PREFLIGHT";
const MIRROR_PATH_ERROR: &str = "RUST_CARGO_MIRROR_PATH_CONFINEMENT";
const MIRROR_IO_ERROR: &str = "RUST_CARGO_MIRROR_MATERIALIZE";

/// A fail-closed Cargo input error. `path` is always an inventory-relative
/// ledger path; the worker-owned temporary directory is never included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CargoMirrorFailure {
    pub code: &'static str,
    pub path: String,
    pub reason: String,
}

impl CargoMirrorFailure {
    fn new(code: &'static str, path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            code,
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for CargoMirrorFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}: {}", self.code, self.path, self.reason)
    }
}

impl Error for CargoMirrorFailure {}

type MirrorResult<T> = Result<T, CargoMirrorFailure>;

/// Worker-owned, source-free input tree for `cargo metadata`.
///
/// The `TempDir` lifetime owns both the neutral command environment and the
/// `project` subtree. Only sanitized manifests, an admitted lockfile, and empty
/// target placeholders are materialized below `project`.
#[derive(Debug)]
pub(crate) struct CargoInputMirror {
    neutral: TempDir,
    original_root: PathBuf,
    project_root: PathBuf,
    manifest_path: PathBuf,
    mirror_to_inventory: BTreeMap<PathBuf, PathBuf>,
    manifest_rel_paths: BTreeSet<PathBuf>,
}

impl CargoInputMirror {
    pub(crate) fn workspace_directory(
        root: &Path,
        entry_manifest: &Path,
        documents: &[ManifestDocument],
    ) -> MirrorResult<PathBuf> {
        let original_root = root
            .canonicalize()
            .map_err(|_| failure(".", "inventory root could not be canonicalized"))?;
        let index = DocumentIndex::build(&original_root, documents)?;
        let entry_rel = inventory_relative(&original_root, entry_manifest).ok_or_else(|| {
            path_failure(
                "__depgraph_skipped__/Cargo.toml",
                "entry manifest is outside the inventory root",
            )
        })?;
        let entry_position = index.by_path.get(&entry_rel).copied().ok_or_else(|| {
            failure(
                slash_path(&entry_rel),
                "entry manifest is not present in the admitted manifest inventory",
            )
        })?;
        let workspace = workspace_document_for_entry(
            &original_root,
            &documents[entry_position],
            documents,
            &index,
        )?;
        Ok(workspace.dir.clone())
    }

    /// Preflights and materializes a confined Cargo input in one operation.
    ///
    /// `root` is the canonical inventory root, `entry_manifest` identifies the
    /// manifest passed to Cargo, and `lockfile` contains bytes already admitted
    /// by the caller's safe lockfile reader.
    pub(crate) fn materialize(
        root: &Path,
        entry_manifest: &Path,
        documents: &[ManifestDocument],
        lockfile: Option<&[u8]>,
    ) -> MirrorResult<Self> {
        let neutral = create_neutral_environment(root)?;
        Self::materialize_with_neutral(root, entry_manifest, documents, lockfile, neutral)
    }

    fn materialize_with_neutral(
        root: &Path,
        entry_manifest: &Path,
        documents: &[ManifestDocument],
        lockfile: Option<&[u8]>,
        neutral: TempDir,
    ) -> MirrorResult<Self> {
        let original_root = root
            .canonicalize()
            .map_err(|_| failure(".", "inventory root could not be canonicalized"))?;
        if !original_root.is_dir() {
            return Err(failure(".", "inventory root is not a directory"));
        }
        let index = DocumentIndex::build(&original_root, documents)?;
        let entry_rel = inventory_relative(&original_root, entry_manifest).ok_or_else(|| {
            path_failure(
                "__depgraph_skipped__/Cargo.toml",
                "entry manifest is outside the inventory root",
            )
        })?;
        let entry_index = index.by_path.get(&entry_rel).copied().ok_or_else(|| {
            failure(
                slash_path(&entry_rel),
                "entry manifest is not present in the admitted manifest inventory",
            )
        })?;
        let cargo_root = workspace_document_for_entry(
            &original_root,
            &documents[entry_index],
            documents,
            &index,
        )?;
        let cargo_root_position = document_position(&index, cargo_root)?;
        let reachable =
            reachable_document_positions(&original_root, entry_index, documents, &index)?;

        let mut placeholders = BTreeSet::new();
        let mut sanitized = Vec::with_capacity(reachable.len());
        for &position in &reachable {
            let document = &documents[position];
            sanitized.push((
                index.rel_for(document)?,
                sanitize_manifest(
                    &original_root,
                    document,
                    documents,
                    &index,
                    &mut placeholders,
                    position == cargo_root_position,
                )?,
            ));
        }
        for &position in &reachable {
            collect_implicit_targets(
                &original_root,
                &documents[position],
                documents,
                &index,
                &mut placeholders,
            )?;
        }

        let manifest_rel_paths: BTreeSet<_> = sanitized
            .iter()
            .map(|(relative, _)| relative.clone())
            .collect();
        if let Some(collision) = placeholders
            .iter()
            .find(|path| manifest_rel_paths.contains(*path))
        {
            return Err(failure(
                slash_path(collision),
                "target placeholder collides with an admitted manifest",
            ));
        }
        let needs_workspace_guard = !manifest_rel_paths.contains(Path::new("Cargo.toml"));
        if needs_workspace_guard && placeholders.contains(Path::new("Cargo.toml")) {
            return Err(failure(
                "Cargo.toml",
                "target placeholder collides with the mirror workspace guard",
            ));
        }

        let project_root = neutral.path().join("project");
        fs::create_dir(&project_root)
            .map_err(|_| materialize_failure(".", "mirror project root could not be created"))?;
        if needs_workspace_guard {
            write_new_file(
                &project_root.join("Cargo.toml"),
                b"[workspace]\nmembers = []\nresolver = \"3\"\n",
                Path::new("__depgraph_guard__/Cargo.toml"),
            )?;
        }

        let mut mirror_to_inventory = BTreeMap::new();
        mirror_to_inventory.insert(project_root.clone(), original_root.clone());
        for (relative, value) in &sanitized {
            let source = toml::to_string(value).map_err(|_| {
                materialize_failure(
                    slash_path(relative),
                    "sanitized manifest could not be serialized",
                )
            })?;
            let destination = project_root.join(relative);
            write_new_file(&destination, source.as_bytes(), relative)?;
            mirror_to_inventory.insert(destination, original_root.join(relative));
            insert_directory_mappings(
                &project_root,
                &original_root,
                relative.parent().unwrap_or_else(|| Path::new("")),
                &mut mirror_to_inventory,
            );
        }
        for relative in &placeholders {
            let destination = project_root.join(relative);
            write_new_file(&destination, &[], relative)?;
            mirror_to_inventory.insert(destination, original_root.join(relative));
            insert_directory_mappings(
                &project_root,
                &original_root,
                relative.parent().unwrap_or_else(|| Path::new("")),
                &mut mirror_to_inventory,
            );
        }

        if let Some(bytes) = lockfile {
            let workspace_document = workspace_document_for_entry(
                &original_root,
                &documents[entry_index],
                documents,
                &index,
            )?;
            let workspace_rel_dir = index.rel_dir_for(workspace_document)?;
            let lock_rel = workspace_rel_dir.join("Cargo.lock");
            if manifest_rel_paths.contains(&lock_rel) || placeholders.contains(&lock_rel) {
                return Err(materialize_failure(
                    slash_path(&lock_rel),
                    "Cargo.lock collides with another mirror input",
                ));
            }
            let lock_destination = project_root.join(&lock_rel);
            write_new_file(&lock_destination, bytes, &lock_rel)?;
            mirror_to_inventory.insert(lock_destination, original_root.join(&lock_rel));
            insert_directory_mappings(
                &project_root,
                &original_root,
                lock_rel.parent().unwrap_or_else(|| Path::new("")),
                &mut mirror_to_inventory,
            );
        }

        let manifest_path = project_root.join(&entry_rel);
        Ok(Self {
            neutral,
            original_root,
            project_root,
            manifest_path,
            mirror_to_inventory,
            manifest_rel_paths,
        })
    }

    pub(crate) fn neutral_root(&self) -> &Path {
        self.neutral.path()
    }

    pub(crate) fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub(crate) fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    /// Maps a Cargo-returned mirror path to an exact admitted inventory path.
    /// Unknown paths and lexical escapes are rejected without echoing the
    /// worker-owned temporary path.
    pub(crate) fn remap_path(&self, mirror_path: &Path) -> MirrorResult<PathBuf> {
        if !mirror_path.is_absolute() {
            return Err(path_failure(
                "__depgraph_skipped__/cargo-metadata-path",
                "Cargo returned a non-absolute mirror path",
            ));
        }
        let normalized = normalize_path(mirror_path);
        let relative = confined_relative(&self.project_root, &normalized).ok_or_else(|| {
            path_failure(
                "__depgraph_skipped__/cargo-metadata-path",
                "Cargo returned a path outside the confined mirror",
            )
        })?;
        let admitted_path = self.project_root.join(&relative);
        self.mirror_to_inventory
            .get(&admitted_path)
            .cloned()
            .ok_or_else(|| {
                path_failure(
                    slash_path(&relative),
                    "Cargo returned a path not present in the mirror inventory",
                )
            })
    }

    /// Produces a stable package identity from a mirror manifest path.
    pub(crate) fn stable_manifest_id(&self, mirror_manifest_path: &Path) -> MirrorResult<String> {
        let inventory_path = self.remap_path(mirror_manifest_path)?;
        let relative =
            inventory_relative(&self.original_root, &inventory_path).ok_or_else(|| {
                path_failure(
                    "__depgraph_skipped__/cargo-metadata-path",
                    "remapped manifest escaped the inventory root",
                )
            })?;
        if !self.manifest_rel_paths.contains(&relative) {
            return Err(path_failure(
                slash_path(&relative),
                "Cargo package identity does not name an admitted manifest",
            ));
        }
        Ok(format!("inventory-manifest:{}", slash_path(&relative)))
    }
}

struct DocumentIndex {
    by_path: BTreeMap<PathBuf, usize>,
    by_dir: BTreeMap<PathBuf, usize>,
}

impl DocumentIndex {
    fn build(root: &Path, documents: &[ManifestDocument]) -> MirrorResult<Self> {
        let mut by_path = BTreeMap::new();
        let mut by_dir = BTreeMap::new();
        for (position, document) in documents.iter().enumerate() {
            let relative = safe_inventory_relative(&document.rel_path).ok_or_else(|| {
                path_failure(
                    "__depgraph_skipped__/Cargo.toml",
                    "manifest inventory path is not a safe relative path",
                )
            })?;
            let ledger = slash_path(&relative);
            let expected = normalize_path(&root.join(&relative));
            if normalize_path(&document.abs_path) != expected
                || normalize_path(&document.dir) != expected.parent().unwrap_or(root)
            {
                return Err(path_failure(
                    ledger,
                    "manifest inventory coordinates are inconsistent",
                ));
            }
            validate_regular_file(root, &expected, &document.rel_path)?;
            if by_path.insert(relative, position).is_some() {
                return Err(failure(
                    document.rel_path.clone(),
                    "manifest inventory contains a duplicate path",
                ));
            }
            if by_dir
                .insert(expected.parent().unwrap_or(root).to_path_buf(), position)
                .is_some()
            {
                return Err(failure(
                    document.rel_path.clone(),
                    "manifest inventory contains multiple manifests for one directory",
                ));
            }
        }
        if documents.is_empty() {
            return Err(failure("Cargo.toml", "manifest inventory is empty"));
        }
        Ok(Self { by_path, by_dir })
    }

    fn rel_for(&self, document: &ManifestDocument) -> MirrorResult<PathBuf> {
        safe_inventory_relative(&document.rel_path).ok_or_else(|| {
            path_failure(
                "__depgraph_skipped__/Cargo.toml",
                "manifest inventory path is not a safe relative path",
            )
        })
    }

    fn rel_dir_for(&self, document: &ManifestDocument) -> MirrorResult<PathBuf> {
        let relative = self.rel_for(document)?;
        Ok(relative.parent().map(Path::to_path_buf).unwrap_or_default())
    }
}

fn reachable_document_positions(
    root: &Path,
    entry_position: usize,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
) -> MirrorResult<Vec<usize>> {
    let entry = &documents[entry_position];
    let workspace = workspace_document_for_entry(root, entry, documents, index)?;
    let workspace_position = document_position(index, workspace)?;
    let mut selected = BTreeSet::from([entry_position, workspace_position]);

    if let Some(workspace_table) = workspace.value.get("workspace").and_then(Value::as_table) {
        for key in ["members", "default-members"] {
            let Some(entries) = workspace_table.get(key) else {
                continue;
            };
            let entries = entries.as_array().ok_or_else(|| {
                failure(
                    &workspace.rel_path,
                    format!("workspace.{key} must be an array of paths"),
                )
            })?;
            for entry in entries {
                let raw = entry.as_str().ok_or_else(|| {
                    failure(
                        &workspace.rel_path,
                        format!("workspace.{key} contains a non-string path"),
                    )
                })?;
                reject_workspace_pattern(raw, &workspace.rel_path, key)?;
                let directory =
                    resolve_relative(root, &workspace.dir, raw, &workspace.rel_path, true)?;
                let member = manifest_at_directory(root, &directory, documents, index, workspace)?;
                selected.insert(document_position(index, member)?);
            }
        }
    }

    loop {
        let before = selected.len();
        let current: Vec<_> = selected.iter().copied().collect();
        for position in current {
            add_reachable_manifest_paths(
                root,
                &documents[position],
                documents,
                index,
                &mut selected,
                position == workspace_position,
            )?;
        }
        if selected.len() == before {
            break;
        }
    }

    let mut selected: Vec<_> = selected.into_iter().collect();
    selected.sort_by(|left, right| documents[*left].rel_path.cmp(&documents[*right].rel_path));
    Ok(selected)
}

fn add_reachable_manifest_paths(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
    selected: &mut BTreeSet<usize>,
    cargo_root: bool,
) -> MirrorResult<()> {
    if let Some(raw) = document
        .value
        .get("package")
        .and_then(Value::as_table)
        .and_then(|package| package.get("workspace"))
        .and_then(Value::as_str)
    {
        let directory = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
        let workspace = manifest_at_directory(root, &directory, documents, index, document)?;
        selected.insert(document_position(index, workspace)?);
    }

    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        add_dependency_paths(root, document, index, &document.value, key, selected)?;
    }
    if let Some(targets) = document.value.get("target").and_then(Value::as_table) {
        for target in targets.values() {
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                add_dependency_paths(root, document, index, target, key, selected)?;
            }
        }
    }
    if let Some(workspace) = document.value.get("workspace").and_then(Value::as_table) {
        add_dependency_paths(
            root,
            document,
            index,
            &Value::Table(workspace.clone()),
            "dependencies",
            selected,
        )?;
    }
    if cargo_root {
        if let Some(patches) = document.value.get("patch").and_then(Value::as_table) {
            for patch in patches.values() {
                add_dependency_specs(root, document, index, patch, selected)?;
            }
        }
        if let Some(replacements) = document.value.get("replace") {
            add_dependency_specs(root, document, index, replacements, selected)?;
        }
    }
    Ok(())
}

fn add_dependency_paths(
    root: &Path,
    document: &ManifestDocument,
    index: &DocumentIndex,
    parent: &Value,
    key: &str,
    selected: &mut BTreeSet<usize>,
) -> MirrorResult<()> {
    let Some(dependencies) = parent.get(key) else {
        return Ok(());
    };
    add_dependency_specs(root, document, index, dependencies, selected)
}

fn add_dependency_specs(
    root: &Path,
    document: &ManifestDocument,
    index: &DocumentIndex,
    dependencies: &Value,
    selected: &mut BTreeSet<usize>,
) -> MirrorResult<()> {
    let dependencies = dependencies.as_table().ok_or_else(|| {
        failure(
            &document.rel_path,
            "Cargo dependency collection is not a table",
        )
    })?;
    for dependency in dependencies.values() {
        let Some(raw) = dependency
            .as_table()
            .and_then(|dependency| dependency.get("path"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let directory = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
        let position = index.by_dir.get(&directory).copied().ok_or_else(|| {
            path_failure(
                &document.rel_path,
                "dependency path does not name an admitted manifest directory",
            )
        })?;
        selected.insert(position);
    }
    Ok(())
}

fn document_position(index: &DocumentIndex, document: &ManifestDocument) -> MirrorResult<usize> {
    let relative = index.rel_for(document)?;
    index.by_path.get(&relative).copied().ok_or_else(|| {
        failure(
            &document.rel_path,
            "manifest is absent from the admitted document index",
        )
    })
}

fn sanitize_manifest(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
    placeholders: &mut BTreeSet<PathBuf>,
    cargo_root: bool,
) -> MirrorResult<Value> {
    let mut value = document.value.clone();
    let ledger = document.rel_path.as_str();

    if value.get("project").is_some() {
        return Err(failure(
            ledger,
            "legacy project manifests are not admitted by the confined mirror",
        ));
    }
    if value.get("cargo-features").is_some() {
        return Err(failure(
            ledger,
            "cargo-features may introduce path-bearing manifest semantics that are not admitted",
        ));
    }

    // Cargo searches parent directories for a workspace when a package does
    // not declare one. Seal a standalone Cargo root as its own workspace so
    // that lookup cannot escape the worker-owned project subtree.
    if cargo_root && value.get("workspace").is_none() {
        value
            .as_table_mut()
            .ok_or_else(|| failure(ledger, "manifest root is not a TOML table"))?
            .insert("workspace".into(), Value::Table(toml::Table::new()));
    }

    if let Some(package) = value.get_mut("package").and_then(Value::as_table_mut) {
        if ["default-target", "forced-target"]
            .iter()
            .any(|key| package.contains_key(*key))
        {
            return Err(failure(
                ledger,
                "custom target specification paths are not admitted by the confined mirror",
            ));
        }
        for key in ["metadata", "readme", "license-file", "include", "exclude"] {
            package.remove(key);
        }
        rewrite_package_paths(root, document, documents, index, package, placeholders)?;
    }
    if let Some(workspace) = value.get_mut("workspace").and_then(Value::as_table_mut) {
        workspace.remove("metadata");
        workspace.remove("lints");
        if let Some(package) = workspace.get_mut("package").and_then(Value::as_table_mut) {
            for key in ["readme", "license-file", "include", "exclude"] {
                package.remove(key);
            }
        }
        rewrite_workspace_paths(root, document, documents, index, workspace)?;
        rewrite_dependency_key(root, document, index, workspace, "dependencies")?;
    }

    let root_table = value
        .as_table_mut()
        .ok_or_else(|| failure(ledger, "manifest root is not a TOML table"))?;
    for key in ["profile", "lints", "badges"] {
        root_table.remove(key);
    }
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        rewrite_dependency_key(root, document, index, root_table, key)?;
    }
    if let Some(targets) = root_table.get_mut("target").and_then(Value::as_table_mut) {
        for (_, target) in targets.iter_mut() {
            let target = target
                .as_table_mut()
                .ok_or_else(|| failure(ledger, "target configuration is not a table"))?;
            for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                rewrite_dependency_key(root, document, index, target, key)?;
            }
        }
    }
    if cargo_root {
        if let Some(patches) = root_table.get_mut("patch").and_then(Value::as_table_mut) {
            for (source, patch) in patches.iter_mut() {
                reject_local_file_url(source, ledger)?;
                let patch = patch
                    .as_table_mut()
                    .ok_or_else(|| failure(ledger, "patch source is not a dependency table"))?;
                rewrite_dependency_specs(root, document, index, patch)?;
            }
        }
        if let Some(replacements) = root_table.get_mut("replace").and_then(Value::as_table_mut) {
            rewrite_replacements(root, document, index, replacements)?;
        }
    } else {
        root_table.remove("patch");
        root_table.remove("replace");
    }
    rewrite_explicit_target(root, document, root_table, "lib", placeholders)?;
    for key in ["bin", "example", "test", "bench"] {
        rewrite_explicit_target_array(root, document, root_table, key, placeholders)?;
    }
    reject_unknown_path_keys(&value, &mut Vec::new(), ledger)?;
    Ok(value)
}

fn rewrite_package_paths(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
    package: &mut toml::Table,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    if let Some(workspace) = package.get_mut("workspace") {
        let raw = workspace.as_str().ok_or_else(|| {
            failure(
                &document.rel_path,
                "package.workspace must be a path string",
            )
        })?;
        let target = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
        let target_document = manifest_at_directory(root, &target, documents, index, document)?;
        if target_document.value.get("workspace").is_none() {
            return Err(failure(
                &document.rel_path,
                "package.workspace does not name an admitted workspace manifest",
            ));
        }
        *workspace = Value::String(relative_string(&document.dir, &target));
    }

    if let Some(build) = package.get_mut("build") {
        match build {
            Value::Boolean(false) => {}
            Value::String(raw) => {
                let target = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
                validate_regular_file(root, &target, &document.rel_path)?;
                let relative = inventory_relative(root, &target).ok_or_else(|| {
                    path_failure(
                        &document.rel_path,
                        "package.build escaped the inventory root",
                    )
                })?;
                placeholders.insert(relative);
                *raw = relative_string(&document.dir, &target);
            }
            _ => {
                return Err(failure(
                    &document.rel_path,
                    "package.build must be false or a relative path string",
                ));
            }
        }
    }
    Ok(())
}

fn rewrite_workspace_paths(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
    workspace: &mut toml::Table,
) -> MirrorResult<()> {
    for key in ["members", "default-members"] {
        let Some(entries) = workspace.get_mut(key) else {
            continue;
        };
        let entries = entries.as_array_mut().ok_or_else(|| {
            failure(
                &document.rel_path,
                format!("workspace.{key} must be an array of relative paths"),
            )
        })?;
        for entry in entries {
            let raw = entry.as_str().ok_or_else(|| {
                failure(
                    &document.rel_path,
                    format!("workspace.{key} contains a non-string path"),
                )
            })?;
            reject_workspace_pattern(raw, &document.rel_path, key)?;
            let target = resolve_relative(root, &document.dir, raw, &document.rel_path, true)?;
            manifest_at_directory(root, &target, documents, index, document)?;
            *entry = Value::String(relative_string(&document.dir, &target));
        }
    }
    let Some(entries) = workspace.get_mut("exclude") else {
        return Ok(());
    };
    let entries = entries.as_array_mut().ok_or_else(|| {
        failure(
            &document.rel_path,
            "workspace.exclude must be an array of relative paths",
        )
    })?;
    for entry in entries {
        let raw = entry.as_str().ok_or_else(|| {
            failure(
                &document.rel_path,
                "workspace.exclude contains a non-string path",
            )
        })?;
        reject_workspace_pattern(raw, &document.rel_path, "exclude")?;
        let target = resolve_relative(root, &document.dir, raw, &document.rel_path, true)?;
        validate_existing_components(root, &target, &document.rel_path)?;
        *entry = Value::String(relative_string(&document.dir, &target));
    }
    Ok(())
}

fn reject_workspace_pattern(raw: &str, ledger: &str, key: &str) -> MirrorResult<()> {
    if raw.contains(['*', '?', '[', ']']) {
        return Err(path_failure(
            ledger,
            format!("workspace.{key} glob patterns are not admitted by the confined mirror"),
        ));
    }
    if Path::new(raw)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(path_failure(
            ledger,
            format!("workspace.{key} parent traversal is not admitted"),
        ));
    }
    Ok(())
}

fn rewrite_dependency_key(
    root: &Path,
    document: &ManifestDocument,
    index: &DocumentIndex,
    parent: &mut toml::Table,
    key: &str,
) -> MirrorResult<()> {
    let Some(dependencies) = parent.get_mut(key) else {
        return Ok(());
    };
    let dependencies = dependencies.as_table_mut().ok_or_else(|| {
        failure(
            &document.rel_path,
            format!("{key} is not a dependency table"),
        )
    })?;
    rewrite_dependency_specs(root, document, index, dependencies)
}

fn rewrite_dependency_specs(
    root: &Path,
    document: &ManifestDocument,
    index: &DocumentIndex,
    dependencies: &mut toml::Table,
) -> MirrorResult<()> {
    for (_, dependency) in dependencies.iter_mut() {
        let Some(dependency) = dependency.as_table_mut() else {
            continue;
        };
        if let Some(git) = dependency.get("git").and_then(Value::as_str) {
            reject_local_file_url(git, &document.rel_path)?;
        }
        let Some(path) = dependency.get_mut("path") else {
            continue;
        };
        let raw = path
            .as_str()
            .ok_or_else(|| failure(&document.rel_path, "dependency path must be a path string"))?;
        let target = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
        if !index.by_dir.contains_key(&target) {
            return Err(path_failure(
                &document.rel_path,
                "dependency path does not name an admitted manifest directory",
            ));
        }
        let target_manifest = target.join("Cargo.toml");
        validate_regular_file(root, &target_manifest, &document.rel_path)?;
        *path = Value::String(relative_string(&document.dir, &target));
    }
    Ok(())
}

fn rewrite_replacements(
    root: &Path,
    document: &ManifestDocument,
    index: &DocumentIndex,
    replacements: &mut toml::Table,
) -> MirrorResult<()> {
    for package_id in replacements.keys() {
        reject_local_file_url(package_id, &document.rel_path)?;
    }
    rewrite_dependency_specs(root, document, index, replacements)
}

fn rewrite_explicit_target(
    root: &Path,
    document: &ManifestDocument,
    parent: &mut toml::Table,
    key: &str,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    let Some(target) = parent.get_mut(key) else {
        return Ok(());
    };
    let target = target
        .as_table_mut()
        .ok_or_else(|| failure(&document.rel_path, format!("{key} target is not a table")))?;
    rewrite_target_path(root, document, target, placeholders)
}

fn rewrite_explicit_target_array(
    root: &Path,
    document: &ManifestDocument,
    parent: &mut toml::Table,
    key: &str,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    let Some(targets) = parent.get_mut(key) else {
        return Ok(());
    };
    let targets = targets.as_array_mut().ok_or_else(|| {
        failure(
            &document.rel_path,
            format!("{key} targets are not an array"),
        )
    })?;
    for target in targets {
        let target = target.as_table_mut().ok_or_else(|| {
            failure(
                &document.rel_path,
                format!("{key} target entry is not a table"),
            )
        })?;
        rewrite_target_path(root, document, target, placeholders)?;
    }
    Ok(())
}

fn rewrite_target_path(
    root: &Path,
    document: &ManifestDocument,
    target: &mut toml::Table,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    let Some(path) = target.get_mut("path") else {
        return Ok(());
    };
    let raw = path
        .as_str()
        .ok_or_else(|| failure(&document.rel_path, "target path must be a path string"))?;
    let target_path = resolve_relative(root, &document.dir, raw, &document.rel_path, false)?;
    validate_regular_file(root, &target_path, &document.rel_path)?;
    let relative = inventory_relative(root, &target_path).ok_or_else(|| {
        path_failure(&document.rel_path, "target path escaped the inventory root")
    })?;
    placeholders.insert(relative);
    *path = Value::String(relative_string(&document.dir, &target_path));
    Ok(())
}

fn reject_unknown_path_keys(
    value: &Value,
    context: &mut Vec<String>,
    ledger: &str,
) -> MirrorResult<()> {
    match value {
        Value::Table(table) => {
            for key in table.keys() {
                let path_bearing = key.to_ascii_lowercase().contains("path");
                let admitted = key == "path" && known_path_context(context);
                if path_bearing && !admitted && !identifier_map_context(context) {
                    return Err(failure(
                        ledger,
                        "manifest contains a path-bearing key outside an admitted Cargo path field",
                    ));
                }
            }
            for (key, child) in table {
                context.push(key.clone());
                reject_unknown_path_keys(child, context, ledger)?;
                context.pop();
            }
        }
        Value::Array(array) => {
            for child in array {
                context.push("#".into());
                reject_unknown_path_keys(child, context, ledger)?;
                context.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn known_path_context(context: &[String]) -> bool {
    matches!(context, [section, _] if dependency_section(section))
        || matches!(context, [target, _, section, _] if target == "target" && dependency_section(section))
        || matches!(context, [workspace, dependencies, _] if workspace == "workspace" && dependencies == "dependencies")
        || matches!(context, [patch, _, _] if patch == "patch")
        || matches!(context, [replace, _] if replace == "replace")
        || matches!(context, [lib] if lib == "lib")
        || matches!(context, [kind, marker] if marker == "#" && matches!(kind.as_str(), "bin" | "example" | "test" | "bench"))
}

fn dependency_section(section: &str) -> bool {
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies"
    )
}

/// These Cargo tables use their immediate keys as user-defined identifiers,
/// rather than as fields. An identifier containing `path` is therefore safe;
/// nested specification tables are still checked as Cargo-owned fields.
fn identifier_map_context(context: &[String]) -> bool {
    matches!(context, [section] if dependency_section(section) || matches!(section.as_str(), "features" | "target" | "profile" | "patch" | "replace"))
        || matches!(context, [target, _, section] if target == "target" && dependency_section(section))
        || matches!(context, [workspace, dependencies] if workspace == "workspace" && dependencies == "dependencies")
        || matches!(context, [patch, _] if patch == "patch")
        || matches!(context, [lints, _] if lints == "lints")
        || matches!(context, [workspace, lints, _] if workspace == "workspace" && lints == "lints")
}

fn reject_local_file_url(value: &str, ledger: &str) -> MirrorResult<()> {
    let value = value.trim();
    let normalized = value.to_ascii_lowercase();
    let scheme = normalized
        .split_once('+')
        .map_or(normalized.as_str(), |(_, remainder)| remainder);
    if scheme.starts_with("file:")
        || portable_absolute_path(value)
        || value.starts_with("./")
        || value.starts_with("../")
    {
        return Err(path_failure(
            ledger,
            "local file URL sources are not admitted by the confined mirror",
        ));
    }
    Ok(())
}

fn manifest_at_directory<'a>(
    root: &Path,
    target: &Path,
    documents: &'a [ManifestDocument],
    index: &DocumentIndex,
    owner: &ManifestDocument,
) -> MirrorResult<&'a ManifestDocument> {
    let position = index.by_dir.get(target).copied().ok_or_else(|| {
        path_failure(
            &owner.rel_path,
            "path does not name an admitted manifest directory",
        )
    })?;
    let manifest = &documents[position];
    validate_regular_file(root, &manifest.abs_path, &owner.rel_path)?;
    Ok(manifest)
}

fn workspace_document_for_entry<'a>(
    root: &Path,
    entry: &'a ManifestDocument,
    documents: &'a [ManifestDocument],
    index: &DocumentIndex,
) -> MirrorResult<&'a ManifestDocument> {
    if let Some(raw) = entry
        .value
        .get("package")
        .and_then(Value::as_table)
        .and_then(|package| package.get("workspace"))
        .and_then(Value::as_str)
    {
        let target = resolve_relative(root, &entry.dir, raw, &entry.rel_path, false)?;
        return manifest_at_directory(root, &target, documents, index, entry);
    }
    if entry.value.get("workspace").is_some() {
        return Ok(entry);
    }
    documents
        .iter()
        .filter(|document| {
            document.value.get("workspace").is_some() && entry.dir.starts_with(&document.dir)
        })
        .max_by_key(|document| document.dir.components().count())
        .map_or(Ok(entry), Ok)
}

fn collect_implicit_targets(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    let Some(package) = document.value.get("package").and_then(Value::as_table) else {
        return Ok(());
    };
    let edition_2015 = effective_edition(root, document, documents, index)? == "2015";
    let has_manual_target = ["lib", "bin", "example", "test", "bench"]
        .iter()
        .any(|key| document.value.get(*key).is_some());
    let auto_enabled = |flag: &str| {
        package
            .get(flag)
            .and_then(Value::as_bool)
            .unwrap_or(!(edition_2015 && has_manual_target))
    };
    collect_inferred_manual_targets(root, document, package, placeholders, edition_2015)?;
    if auto_enabled("autolib") || document.value.get("lib").is_some() {
        collect_optional_regular_file(
            root,
            &document.dir.join("src/lib.rs"),
            document,
            placeholders,
        )?;
    }
    if auto_enabled("autobins") {
        collect_optional_regular_file(
            root,
            &document.dir.join("src/main.rs"),
            document,
            placeholders,
        )?;
        collect_rust_tree(root, &document.dir.join("src/bin"), document, placeholders)?;
    }
    if package.get("build").is_none() {
        collect_optional_regular_file(
            root,
            &document.dir.join("build.rs"),
            document,
            placeholders,
        )?;
    }
    for (flag, relative) in [
        ("autoexamples", "examples"),
        ("autotests", "tests"),
        ("autobenches", "benches"),
    ] {
        if auto_enabled(flag) {
            collect_rust_tree(root, &document.dir.join(relative), document, placeholders)?;
        }
    }
    Ok(())
}

fn collect_inferred_manual_targets(
    root: &Path,
    document: &ManifestDocument,
    package: &toml::Table,
    placeholders: &mut BTreeSet<PathBuf>,
    edition_2015: bool,
) -> MirrorResult<()> {
    let package_name = package.get("name").and_then(Value::as_str).unwrap_or("");
    for (key, directory) in [
        ("bin", "src/bin"),
        ("example", "examples"),
        ("test", "tests"),
        ("bench", "benches"),
    ] {
        let Some(targets) = document.value.get(key).and_then(Value::as_array) else {
            continue;
        };
        for target in targets {
            let Some(target) = target.as_table() else {
                continue;
            };
            if target.get("path").is_some() {
                continue;
            }
            let Some(name) = target.get("name").and_then(Value::as_str) else {
                continue;
            };
            let mut candidates = vec![
                document.dir.join(directory).join(format!("{name}.rs")),
                document.dir.join(directory).join(name).join("main.rs"),
            ];
            if key == "bin" && name == package_name {
                candidates.push(document.dir.join("src/main.rs"));
            }
            if edition_2015 {
                candidates.push(document.dir.join("src").join(format!("{name}.rs")));
            }
            for candidate in candidates {
                collect_optional_regular_file(root, &candidate, document, placeholders)?;
            }
        }
    }
    Ok(())
}

fn effective_edition(
    root: &Path,
    document: &ManifestDocument,
    documents: &[ManifestDocument],
    index: &DocumentIndex,
) -> MirrorResult<String> {
    let package = document.value.get("package").and_then(Value::as_table);
    if let Some(edition) = package
        .and_then(|package| package.get("edition"))
        .and_then(Value::as_str)
    {
        return Ok(edition.to_owned());
    }
    let inherited = package
        .and_then(|package| package.get("edition"))
        .and_then(Value::as_table)
        .and_then(|edition| edition.get("workspace"))
        .and_then(Value::as_bool)
        == Some(true);
    if inherited {
        let workspace = workspace_document_for_entry(root, document, documents, index)?;
        if let Some(edition) = workspace
            .value
            .get("workspace")
            .and_then(Value::as_table)
            .and_then(|workspace| workspace.get("package"))
            .and_then(Value::as_table)
            .and_then(|package| package.get("edition"))
            .and_then(Value::as_str)
        {
            return Ok(edition.to_owned());
        }
    }
    Ok("2015".into())
}

fn collect_optional_regular_file(
    root: &Path,
    path: &Path,
    document: &ManifestDocument,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    validate_existing_components(root, path, &document.rel_path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(path_failure(
            &document.rel_path,
            "implicit Cargo target is a symbolic link",
        )),
        Ok(metadata) if metadata.is_file() => {
            let relative = inventory_relative(root, path).ok_or_else(|| {
                path_failure(
                    &document.rel_path,
                    "implicit Cargo target escaped the inventory root",
                )
            })?;
            placeholders.insert(relative);
            Ok(())
        }
        Ok(_) => Err(path_failure(
            &document.rel_path,
            "implicit Cargo target path is not a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(path_failure(
            &document.rel_path,
            "implicit Cargo target could not be inspected",
        )),
    }
}

fn collect_rust_tree(
    root: &Path,
    directory: &Path,
    document: &ManifestDocument,
    placeholders: &mut BTreeSet<PathBuf>,
) -> MirrorResult<()> {
    validate_existing_components(root, directory, &document.rel_path)?;
    match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(path_failure(
                &document.rel_path,
                "implicit Cargo target directory could not be inspected",
            ));
        }
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(path_failure(
                &document.rel_path,
                "implicit Cargo target directory is a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(path_failure(
                &document.rel_path,
                "implicit Cargo target directory is not a directory",
            ));
        }
        Ok(_) => {}
    }
    let entries = fs::read_dir(directory).map_err(|_| {
        path_failure(
            &document.rel_path,
            "implicit Cargo target directory could not be listed",
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|_| {
            path_failure(
                &document.rel_path,
                "implicit Cargo target entry could not be inspected",
            )
        })?;
        let file_type = entry.file_type().map_err(|_| {
            path_failure(
                &document.rel_path,
                "implicit Cargo target entry type could not be inspected",
            )
        })?;
        if file_type.is_symlink() {
            return Err(path_failure(
                &document.rel_path,
                "implicit Cargo target directory contains a symbolic link",
            ));
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_optional_regular_file(root, &path.join("main.rs"), document, placeholders)?;
            continue;
        }
        if file_type.is_file() && path.extension().and_then(|value| value.to_str()) == Some("rs") {
            collect_optional_regular_file(root, &path, document, placeholders)?;
        }
    }
    Ok(())
}

fn resolve_relative(
    root: &Path,
    base: &Path,
    raw: &str,
    ledger: &str,
    reject_parent: bool,
) -> MirrorResult<PathBuf> {
    if raw.is_empty() || raw.contains('\0') || raw.contains('\\') {
        return Err(path_failure(
            ledger,
            "Cargo path is not a portable non-empty relative path",
        ));
    }
    let path = Path::new(raw);
    let absolute_input = portable_absolute_path(raw);
    if reject_parent
        && path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(path_failure(
            ledger,
            "parent traversal is not admitted for this Cargo path",
        ));
    }
    let candidate = if absolute_input {
        normalize_path(path)
    } else {
        normalize_path(&base.join(path))
    };
    let relative = confined_relative(root, &candidate)
        .ok_or_else(|| path_failure(ledger, "Cargo path resolves outside the inventory root"))?;
    let target = normalize_path(&root.join(relative));
    validate_existing_components(root, &target, ledger)?;
    Ok(target)
}

fn portable_absolute_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    Path::new(raw).is_absolute()
        || raw.starts_with("//")
        || raw.starts_with(r"\\")
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

fn validate_regular_file(root: &Path, path: &Path, ledger: &str) -> MirrorResult<()> {
    validate_existing_components(root, path, ledger)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        path_failure(
            ledger,
            "Cargo path does not resolve to an inspectable regular file",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(path_failure(
            ledger,
            "Cargo path does not resolve to a non-symlink regular file",
        ));
    }
    Ok(())
}

fn validate_existing_components(root: &Path, path: &Path, ledger: &str) -> MirrorResult<()> {
    let relative = confined_relative(root, path)
        .ok_or_else(|| path_failure(ledger, "Cargo path resolves outside the inventory root"))?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        cursor.push(component);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(path_failure(
                    ledger,
                    "Cargo path contains a symbolic-link component",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(path_failure(
                    ledger,
                    "Cargo path component could not be inspected",
                ));
            }
        }
    }
    Ok(())
}

fn safe_inventory_relative(value: &str) -> Option<PathBuf> {
    if value.is_empty() || value.contains('\\') || portable_absolute_path(value) {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        return None;
    }
    let normalized = normalize_path(path);
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

fn inventory_relative(root: &Path, path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        normalize_path(path)
    } else {
        normalize_path(&root.join(path))
    };
    let relative = confined_relative(root, &absolute)?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    Some(normalize_path(&relative))
}

fn confined_relative(root: &Path, path: &Path) -> Option<PathBuf> {
    if let Ok(relative) = path.strip_prefix(root) {
        return Some(relative.to_path_buf());
    }
    #[cfg(windows)]
    {
        let root_key = windows_path_key(root);
        let path_key = windows_path_key(path);
        let prefix = format!("{root_key}\\");
        if path_key != root_key && !path_key.starts_with(&prefix) {
            return None;
        }
        let root_normal_components = root
            .components()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        let path_components: Vec<_> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(component) => Some(component.to_owned()),
                _ => None,
            })
            .collect();
        if path_components.len() < root_normal_components {
            return None;
        }
        return Some(path_components[root_normal_components..].iter().collect());
    }
    #[cfg(not(windows))]
    None
}

#[cfg(windows)]
fn windows_path_key(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if let Some(remainder) = value.strip_prefix(r"\\?\UNC\") {
        value = format!(r"\\{remainder}");
    } else if let Some(remainder) = value.strip_prefix(r"\\?\") {
        value = remainder.to_owned();
    } else if let Some(remainder) = value.strip_prefix(r"\??\") {
        value = remainder.to_owned();
    }
    value.trim_end_matches('\\').to_ascii_lowercase()
}

fn relative_string(from: &Path, to: &Path) -> String {
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let common = from_components
        .iter()
        .zip(&to_components)
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..from_components.len() {
        relative.push("..");
    }
    for component in &to_components[common..] {
        relative.push(component.as_os_str());
    }
    slash_path(&relative)
}

fn create_neutral_environment(root: &Path) -> MirrorResult<TempDir> {
    let mut candidates = vec![std::env::temp_dir()];
    #[cfg(unix)]
    candidates.extend([PathBuf::from("/tmp"), PathBuf::from("/var/tmp")]);
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        candidates.push(PathBuf::from(system_root).join("Temp"));
    }
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let Ok(candidate) = candidate.canonicalize() else {
            continue;
        };
        if !candidate.is_dir() || candidate.starts_with(root) || !seen.insert(candidate.clone()) {
            continue;
        }
        if let Ok(directory) = TempDirBuilder::new()
            .prefix("depgraph-cargo-mirror-")
            .tempdir_in(candidate)
        {
            return Ok(directory);
        }
    }
    Err(materialize_failure(
        ".",
        "no writable neutral directory exists outside the inventory root",
    ))
}

fn write_new_file(path: &Path, bytes: &[u8], ledger: &Path) -> MirrorResult<()> {
    let parent = path.parent().ok_or_else(|| {
        materialize_failure(slash_path(ledger), "mirror file has no parent directory")
    })?;
    fs::create_dir_all(parent).map_err(|_| {
        materialize_failure(
            slash_path(ledger),
            "mirror parent directory could not be created",
        )
    })?;
    if path.exists() {
        return Err(materialize_failure(
            slash_path(ledger),
            "mirror input path was materialized more than once",
        ));
    }
    fs::write(path, bytes)
        .map_err(|_| materialize_failure(slash_path(ledger), "mirror input could not be written"))
}

fn insert_directory_mappings(
    project_root: &Path,
    original_root: &Path,
    relative: &Path,
    mappings: &mut BTreeMap<PathBuf, PathBuf>,
) {
    let mut current = PathBuf::new();
    for component in relative.components() {
        if let Component::Normal(component) = component {
            current.push(component);
            mappings.insert(project_root.join(&current), original_root.join(&current));
        }
    }
}

fn failure(path: impl Into<String>, reason: impl Into<String>) -> CargoMirrorFailure {
    CargoMirrorFailure::new(MIRROR_ERROR, path, reason)
}

fn path_failure(path: impl Into<String>, reason: impl Into<String>) -> CargoMirrorFailure {
    CargoMirrorFailure::new(MIRROR_PATH_ERROR, path, reason)
}

fn materialize_failure(path: impl Into<String>, reason: impl Into<String>) -> CargoMirrorFailure {
    CargoMirrorFailure::new(MIRROR_IO_ERROR, path, reason)
}

#[cfg(test)]
mod tests {
    use super::{CargoInputMirror, MIRROR_PATH_ERROR};
    use crate::manifest::{ManifestDocument, slash_path};
    use std::{
        path::{Path, PathBuf},
        process::Command,
    };
    use tempfile::Builder as TempDirBuilder;
    use toml::Value;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().expect("test file parent")).expect("create parent");
        std::fs::write(path, bytes).expect("write test file");
    }

    fn document(root: &Path, relative: &str, source: &str) -> ManifestDocument {
        let abs_path = root.join(relative);
        write(&abs_path, source.as_bytes());
        ManifestDocument {
            abs_path: abs_path.clone(),
            rel_path: relative.into(),
            dir: abs_path.parent().expect("manifest parent").to_path_buf(),
            rel_dir: abs_path
                .parent()
                .expect("manifest parent")
                .strip_prefix(root)
                .map(slash_path)
                .unwrap_or_else(|_| ".".into()),
            value: toml::from_str(source).expect("valid test manifest"),
        }
    }

    fn manifest_absolute(path: &Path) -> String {
        #[cfg(windows)]
        {
            let path = path.to_string_lossy().replace('/', "\\");
            return path
                .strip_prefix(r"\\?\")
                .unwrap_or(&path)
                .replace('\\', "/");
        }
        #[cfg(not(windows))]
        slash_path(path)
    }

    #[test]
    fn materializes_sanitized_manifests_and_empty_targets() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        std::fs::create_dir(&root).expect("inventory root");
        let root = root.canonicalize().expect("canonical inventory root");
        let workspace = document(
            &root,
            "Cargo.toml",
            r#"
                [workspace]
                members = ["crates/app", "crates/dep"]
                default-members = ["crates/app"]
                exclude = ["retired"]

                [workspace.metadata.private]
                path = "/must/not/leak"

                [profile.release]
                rpath = true

                [profile.release.package.pathfinder]
                opt-level = 1
            "#,
        );
        let app = document(
            &root,
            "crates/app/Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                build = "build/custom.rs"
                readme = "README.md"
                include = ["secret/**"]

                [package.metadata.private]
                path = "/must/not/leak"

                [dependencies]
                dep = { path = "../dep" }

                [lib]
                path = "source/lib.rs"
            "#,
        );
        let dep = document(
            &root,
            "crates/dep/Cargo.toml",
            r#"
                [package]
                name = "dep"
                version = "1.0.0"
            "#,
        );
        write(&root.join("crates/app/build/custom.rs"), b"secret build");
        write(&root.join("crates/app/source/lib.rs"), b"secret lib");
        write(&root.join("crates/dep/src/lib.rs"), b"secret dep");

        let documents = [workspace, app, dep];
        let mirror = CargoInputMirror::materialize(
            &root,
            &root.join("Cargo.toml"),
            &documents,
            Some(b"version = 4\n"),
        )
        .expect("confined mirror");

        assert!(!mirror.neutral_root().starts_with(&root));
        assert_eq!(
            std::fs::read(mirror.project_root().join("crates/app/source/lib.rs"))
                .expect("placeholder"),
            b""
        );
        assert_eq!(
            std::fs::read(mirror.project_root().join("crates/dep/src/lib.rs"))
                .expect("placeholder"),
            b""
        );
        assert_eq!(
            std::fs::read(mirror.project_root().join("Cargo.lock")).expect("lockfile"),
            b"version = 4\n"
        );
        let sanitized =
            std::fs::read_to_string(mirror.project_root().join("crates/app/Cargo.toml"))
                .expect("sanitized manifest");
        assert!(!sanitized.contains("README"));
        assert!(!sanitized.contains("secret/**"));
        assert!(!sanitized.contains("must/not/leak"));
        assert!(sanitized.contains("path = \"../dep\""));
        assert!(sanitized.contains("path = \"source/lib.rs\""));
        let workspace_sanitized = std::fs::read_to_string(mirror.project_root().join("Cargo.toml"))
            .expect("sanitized workspace manifest");
        assert!(!workspace_sanitized.contains("must/not/leak"));
        assert!(!workspace_sanitized.contains("rpath"));
        assert!(!workspace_sanitized.contains("pathfinder"));

        assert_eq!(
            mirror
                .remap_path(&mirror.project_root().join("crates/app/source/lib.rs"))
                .expect("remapped target"),
            root.join("crates/app/source/lib.rs")
        );
        #[cfg(windows)]
        assert_eq!(
            mirror
                .remap_path(Path::new(&manifest_absolute(
                    &mirror.project_root().join("crates/app/source/lib.rs")
                )))
                .expect("remapped non-verbatim Cargo target"),
            root.join("crates/app/source/lib.rs")
        );
        assert_eq!(
            mirror
                .stable_manifest_id(&mirror.project_root().join("crates/app/Cargo.toml"))
                .expect("stable identity"),
            "inventory-manifest:crates/app/Cargo.toml"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ignores_unreachable_manifests_and_their_unsafe_target_layout() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).expect("inventory root");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let workspace = document(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\"]\nresolver = \"3\"\n",
        );
        let app = document(
            &root,
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n",
        );
        write(&root.join("app/src/lib.rs"), b"safe app");
        let unrelated = document(
            &root,
            "testdata/bad/Cargo.toml",
            r#"
                cargo-features = ["unknown-path-semantics"]

                [package]
                name = "unrelated"
                version = "1.0.0"

                [dependencies]
                outside = { path = "../../../../outside" }
            "#,
        );
        symlink(&outside, root.join("testdata/bad/src")).expect("unrelated source symlink");

        let mirror = CargoInputMirror::materialize(
            &root,
            &root.join("Cargo.toml"),
            &[workspace, app, unrelated],
            None,
        )
        .expect("unreachable unsafe fixture must not disable workspace metadata");

        assert!(mirror.project_root().join("app/Cargo.toml").is_file());
        assert!(mirror.project_root().join("app/src/lib.rs").is_file());
        assert!(!mirror.project_root().join("testdata/bad").exists());
    }

    #[test]
    fn standalone_entry_is_sealed_against_parent_workspace_discovery() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        std::fs::create_dir_all(root.join("nested/src")).expect("nested source directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let entry = document(
            &root,
            "nested/Cargo.toml",
            "[package]\nname='standalone'\nversion='1.0.0'\nedition='2024'\n",
        );
        write(&root.join("nested/src/lib.rs"), b"pub struct Standalone;");

        let lockfile = b"version = 4\n\n[[package]]\nname = 'standalone'\nversion = '1.0.0'\n";
        let mirror = CargoInputMirror::materialize(
            &root,
            &root.join("nested/Cargo.toml"),
            &[entry],
            Some(lockfile),
        )
        .expect("standalone mirror");
        let sanitized: Value = toml::from_str(
            &std::fs::read_to_string(mirror.manifest_path()).expect("sanitized entry manifest"),
        )
        .expect("sanitized TOML");

        assert!(sanitized.get("workspace").is_some_and(Value::is_table));
        assert_eq!(
            mirror.manifest_path(),
            mirror.project_root().join("nested/Cargo.toml")
        );

        // This malformed ancestor would be parsed by Cargo's automatic
        // workspace search if the synthesized boundary were removed.
        write(&mirror.neutral_root().join("Cargo.toml"), b"[workspace\n");
        let cargo_home = mirror.neutral_root().join("cargo-home-test");
        let cargo_target = mirror.neutral_root().join("cargo-target-test");
        std::fs::create_dir(&cargo_home).expect("test Cargo home");
        std::fs::create_dir(&cargo_target).expect("test Cargo target");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let filesystem_root = mirror
            .neutral_root()
            .ancestors()
            .last()
            .expect("filesystem root");
        let output = Command::new(cargo)
            .arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--no-deps")
            .arg("--frozen")
            .arg("--offline")
            .arg("--manifest-path")
            .arg(mirror.manifest_path())
            .current_dir(filesystem_root)
            .env("CARGO_HOME", cargo_home)
            .env("CARGO_TARGET_DIR", cargo_target)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .expect("run Cargo workspace-boundary regression test");
        assert!(
            output.status.success(),
            "Cargo crossed the mirror workspace boundary: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("Cargo metadata JSON");
        let cargo_workspace = PathBuf::from(
            metadata["workspace_root"]
                .as_str()
                .expect("Cargo workspace root"),
        )
        .canonicalize()
        .expect("canonical Cargo workspace root");
        let expected_workspace = mirror
            .manifest_path()
            .parent()
            .expect("entry manifest parent")
            .canonicalize()
            .expect("canonical expected workspace root");
        assert_eq!(cargo_workspace, expected_workspace);
    }

    #[test]
    fn sibling_path_dependency_cannot_discover_a_workspace_above_the_project_guard() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let hostile_parent = temp.path().join("hostile");
        let neutral_parent = hostile_parent.join("temporary");
        std::fs::create_dir_all(root.join("app/src")).expect("app source directory");
        std::fs::create_dir_all(root.join("dep/src")).expect("dependency source directory");
        std::fs::create_dir_all(&neutral_parent).expect("controlled neutral parent");
        write(&hostile_parent.join("Cargo.toml"), b"[workspace\n");
        let root = root.canonicalize().expect("canonical inventory root");
        let app = document(
            &root,
            "app/Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                edition = "2024"

                [workspace]

                [dependencies]
                dep = { path = "../dep" }
            "#,
        );
        let dependency = document(
            &root,
            "dep/Cargo.toml",
            "[package]\nname='dep'\nversion='1.0.0'\nedition='2024'\n",
        );
        write(&root.join("app/src/lib.rs"), b"pub struct App;");
        write(&root.join("dep/src/lib.rs"), b"pub struct Dependency;");
        let neutral = TempDirBuilder::new()
            .prefix("depgraph-cargo-mirror-test-")
            .tempdir_in(neutral_parent)
            .expect("controlled neutral directory");
        let lockfile = br#"version = 4

[[package]]
name = "app"
version = "1.0.0"
dependencies = [
 "dep",
]

[[package]]
name = "dep"
version = "1.0.0"
"#;
        let mirror = CargoInputMirror::materialize_with_neutral(
            &root,
            &root.join("app/Cargo.toml"),
            &[app, dependency],
            Some(lockfile),
            neutral,
        )
        .expect("guarded sibling dependency mirror");
        let guard = std::fs::read_to_string(mirror.project_root().join("Cargo.toml"))
            .expect("mirror workspace guard");
        assert!(guard.contains("members = []"));

        let cargo_home = mirror.neutral_root().join("cargo-home-test");
        let cargo_target = mirror.neutral_root().join("cargo-target-test");
        std::fs::create_dir(&cargo_home).expect("test Cargo home");
        std::fs::create_dir(&cargo_target).expect("test Cargo target");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let filesystem_root = mirror
            .neutral_root()
            .ancestors()
            .last()
            .expect("filesystem root");
        let output = Command::new(cargo)
            .arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--no-deps")
            .arg("--frozen")
            .arg("--offline")
            .arg("--manifest-path")
            .arg(mirror.manifest_path())
            .current_dir(filesystem_root)
            .env("CARGO_HOME", cargo_home)
            .env("CARGO_TARGET_DIR", cargo_target)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .expect("run guarded sibling dependency regression test");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() || (stderr.contains("dep") && stderr.contains("workspace")),
            "Cargo did not reach sibling dependency workspace resolution: {stderr}"
        );
        assert!(
            !stderr.contains(hostile_parent.to_string_lossy().as_ref()),
            "Cargo read the hostile workspace ancestor: {stderr}"
        );
        assert!(
            !stderr.contains("invalid table header"),
            "Cargo parsed the malformed workspace above the mirror: {stderr}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ignores_disabled_and_nested_non_target_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(root.join("tests/fixtures")).expect("test fixture directory");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                autotests = false
            "#,
        );
        write(&root.join("src/lib.rs"), b"safe app");
        symlink(&outside, root.join("tests/fixtures/external")).expect("nested non-target symlink");

        let mirror =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect("disabled test discovery must ignore its fixture tree");

        assert!(mirror.project_root().join("src/lib.rs").is_file());
        assert!(!mirror.project_root().join("tests").exists());
    }

    #[cfg(unix)]
    #[test]
    fn edition_2015_manual_targets_disable_other_auto_discovery() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(root.join("tests/fixtures")).expect("test fixture directory");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [[test]]
                name = "manual"
                path = "tests/manual.rs"
            "#,
        );
        write(&root.join("src/lib.rs"), b"safe app");
        write(&root.join("tests/manual.rs"), b"manual target");
        symlink(&outside, root.join("tests/fixtures/external")).expect("nested non-target symlink");

        let mirror =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect("manual 2015 target must disable other test discovery");

        assert!(mirror.project_root().join("tests/manual.rs").is_file());
        assert!(!mirror.project_root().join("tests/fixtures").exists());
    }

    #[test]
    fn manual_target_without_path_keeps_its_inferred_entrypoint() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        std::fs::create_dir_all(&root).expect("inventory root");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                edition = "2024"
                autobins = false

                [[bin]]
                name = "tool"
            "#,
        );
        write(&root.join("src/bin/tool.rs"), b"manual binary");

        let mirror =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect("manual target inference");

        assert_eq!(
            std::fs::read(mirror.project_root().join("src/bin/tool.rs"))
                .expect("manual target placeholder"),
            b""
        );
    }

    #[test]
    fn package_workspace_selects_the_matching_workspace_lock_location() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        std::fs::create_dir_all(&root).expect("inventory root");
        let root = root.canonicalize().expect("canonical inventory root");
        let member_dir = root.join("a-member");
        let workspace_dir = root.join("z-workspace");
        let member_source = format!(
            "[package]\nname = \"member\"\nversion = \"1.0.0\"\nedition = \"2024\"\nworkspace = {:?}\n",
            manifest_absolute(&workspace_dir)
        );
        let workspace_source = format!(
            "[workspace]\nmembers = [{:?}]\nresolver = \"3\"\n",
            manifest_absolute(&member_dir)
        );
        let member = document(&root, "a-member/Cargo.toml", &member_source);
        let workspace = document(&root, "z-workspace/Cargo.toml", &workspace_source);
        write(&root.join("a-member/src/lib.rs"), b"member");
        let documents = [member, workspace];

        assert_eq!(
            CargoInputMirror::workspace_directory(
                &root,
                &root.join("a-member/Cargo.toml"),
                &documents,
            )
            .expect("workspace directory"),
            workspace_dir
        );
        let mirror = CargoInputMirror::materialize(
            &root,
            &root.join("a-member/Cargo.toml"),
            &documents,
            Some(b"version = 4\n"),
        )
        .expect("workspace mirror");
        assert_eq!(
            std::fs::read(mirror.project_root().join("z-workspace/Cargo.lock"))
                .expect("workspace lock"),
            b"version = 4\n"
        );
        assert!(!mirror.project_root().join("a-member/Cargo.lock").exists());
    }

    #[test]
    fn rejects_workspace_globs_and_parent_traversal() {
        for member in ["crates/*", "../outside"] {
            let temp = tempfile::tempdir().expect("temporary workspace");
            let root = temp.path().join("inventory");
            std::fs::create_dir(&root).expect("inventory root");
            let root = root.canonicalize().expect("canonical inventory root");
            let source = format!("[workspace]\nmembers = [\"{member}\"]\n");
            let workspace = document(&root, "Cargo.toml", &source);
            let failure =
                CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[workspace], None)
                    .expect_err("unsafe workspace member must fail");
            assert_eq!(failure.code, MIRROR_PATH_ERROR);
            assert_eq!(failure.path, "Cargo.toml");
            assert!(
                !failure
                    .to_string()
                    .contains(temp.path().to_string_lossy().as_ref())
            );
        }
    }

    #[test]
    fn rejects_external_and_unknown_path_fields_before_materialization() {
        for source in [
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [dependencies]
                dep = { path = "../../outside" }
            "#,
            r#"
                future-path = "../outside"

                [package]
                name = "app"
                version = "1.0.0"
            "#,
            r#"
                cargo-features = ["future-path-semantics"]

                [package]
                name = "app"
                version = "1.0.0"
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [dependencies]
                dep = { git = "file:///outside/repository" }
            "#,
            r#"
                [project]
                name = "app"
                version = "1.0.0"
                workspace = "/outside/workspace"
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [patch."file:///outside/index"]
                app = { path = "." }
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [replace]
                "file:///outside/index#app@1.0.0" = { path = "." }
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                default-target = "../outside/custom-target.json"
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"
                forced-target = "../outside/custom-target.json"
            "#,
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [lib]
                path = "C:drive-relative.rs"
            "#,
        ] {
            let temp = tempfile::tempdir().expect("temporary workspace");
            let root = temp.path().join("inventory");
            std::fs::create_dir(&root).expect("inventory root");
            let root = root.canonicalize().expect("canonical inventory root");
            let manifest = document(&root, "Cargo.toml", source);
            let failure =
                CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                    .expect_err("unsafe path must fail");
            assert_eq!(failure.path, "Cargo.toml");
            assert!(!failure.to_string().contains("depgraph-cargo-mirror-"));
        }
    }

    #[test]
    fn rewrites_inventory_absolute_paths_and_rejects_external_absolute_paths() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).expect("inventory root");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let outside = outside.canonicalize().expect("canonical outside directory");
        let dependency_source = "[package]\nname = \"dep\"\nversion = \"1.0.0\"\n";
        let dependency = document(&root, "dep/Cargo.toml", dependency_source);
        let source = format!(
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n\n[dependencies]\ndep = {{ path = {:?} }}\n",
            manifest_absolute(&root.join("dep"))
        );
        let manifest = document(&root, "Cargo.toml", &source);
        let mirror = CargoInputMirror::materialize(
            &root,
            &root.join("Cargo.toml"),
            &[manifest, dependency],
            None,
        )
        .expect("inventory absolute dependency is admitted");
        let sanitized =
            std::fs::read_to_string(mirror.manifest_path()).expect("sanitized entry manifest");
        assert!(sanitized.contains("path = \"dep\""));
        assert!(!sanitized.contains(&root.to_string_lossy().to_string()));

        let external_source = format!(
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n\n[dependencies]\ndep = {{ path = {:?} }}\n",
            manifest_absolute(&outside)
        );
        let external_manifest = document(&root, "Cargo.toml", &external_source);
        let failure = CargoInputMirror::materialize(
            &root,
            &root.join("Cargo.toml"),
            &[external_manifest],
            None,
        )
        .expect_err("external absolute dependency must fail");
        assert_eq!(failure.code, MIRROR_PATH_ERROR);
        assert_eq!(failure.path, "Cargo.toml");
        assert!(
            !failure
                .to_string()
                .contains(outside.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_components() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).expect("inventory root");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            r#"
                [package]
                name = "app"
                version = "1.0.0"

                [lib]
                path = "linked/lib.rs"
            "#,
        );
        write(&outside.join("lib.rs"), b"outside");
        symlink(&outside, root.join("linked")).expect("source symlink");

        let failure =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect_err("symlink target must fail");
        assert_eq!(failure.code, MIRROR_PATH_ERROR);
        assert_eq!(failure.path, "Cargo.toml");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_an_implicit_target_below_a_symlinked_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).expect("inventory root");
        std::fs::create_dir_all(&outside).expect("outside directory");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n",
        );
        write(&outside.join("lib.rs"), b"outside");
        symlink(&outside, root.join("src")).expect("implicit source symlink");

        let failure =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect_err("implicit symlink target must fail");
        assert_eq!(failure.code, MIRROR_PATH_ERROR);
        assert_eq!(failure.path, "Cargo.toml");
    }

    #[test]
    fn remap_rejects_unmaterialized_paths_without_temp_path_leakage() {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let root = temp.path().join("inventory");
        std::fs::create_dir(&root).expect("inventory root");
        let root = root.canonicalize().expect("canonical inventory root");
        let manifest = document(
            &root,
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"1.0.0\"\n",
        );
        let mirror =
            CargoInputMirror::materialize(&root, &root.join("Cargo.toml"), &[manifest], None)
                .expect("confined mirror");
        let unknown = mirror.project_root().join("not-admitted.rs");
        let failure = mirror
            .remap_path(&unknown)
            .expect_err("unmaterialized path must fail");
        assert_eq!(
            failure.path,
            PathBuf::from("not-admitted.rs").to_string_lossy()
        );
        assert!(!failure.to_string().contains("depgraph-cargo-mirror-"));
    }
}
