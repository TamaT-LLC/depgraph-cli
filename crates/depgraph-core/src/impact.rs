use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Read,
    path::{Component, Path},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::stable_id_from_value;
use depgraph_store::{EdgeRecord, GraphSnapshot, NodeRecord, RuntimeEdgeContext};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    query::{
        GraphQueryFilter, PathStep, PathStepMaterializer, render_condition,
        resolve_selector_bounded_cancellable,
    },
    service_limits::{
        MAX_DEPENDENCY_PATH_STEPS, MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        MAX_IMPACT_MATERIALIZED_PATH_STEPS,
    },
    worker::resolve_safe_executable,
};

const MAX_GIT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHANGED_PATHS: usize = 100_000;
pub const IMPACT_QUERY_CACHE_SCHEMA_VERSION: &str = "depgraph-impact-query-cache-v1";

#[derive(Debug, thiserror::Error)]
#[error("impact dependency-path materialization exceeded its service bound")]
struct ImpactPathMaterializationExhausted;

#[derive(Debug, thiserror::Error)]
#[error("impact runtime-context preprocessing exceeded its service bound")]
struct ImpactRuntimeContextIndexExhausted;

#[derive(Debug, thiserror::Error)]
#[error("impact changed-set preprocessing exceeded its service bound")]
struct ImpactChangedSetPreprocessingExhausted;

#[cfg(test)]
pub(crate) fn changed_set_preprocessing_exhausted_for_test() -> anyhow::Error {
    ImpactChangedSetPreprocessingExhausted.into()
}

#[derive(Debug, thiserror::Error)]
#[error("impact adjacency preprocessing exceeded its service bound")]
struct ImpactAdjacencyPreprocessingExhausted;

pub(crate) fn is_resource_exhausted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<ImpactPathMaterializationExhausted>()
        .is_some()
        || error
            .downcast_ref::<ImpactRuntimeContextIndexExhausted>()
            .is_some()
        || error
            .downcast_ref::<ImpactChangedSetPreprocessingExhausted>()
            .is_some()
        || error
            .downcast_ref::<ImpactAdjacencyPreprocessingExhausted>()
            .is_some()
        || crate::query::is_resource_exhausted(error)
}

pub(crate) fn is_integrity(error: &anyhow::Error) -> bool {
    crate::query::is_integrity(error)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GitChange {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub similarity: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitChangedSet {
    pub requested_ref: String,
    pub resolved_ref: String,
    pub merge_base: String,
    pub head: String,
    pub repository_prefix: String,
    pub changes: Vec<GitChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitChurn {
    pub head: String,
    pub counts_by_path: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedNodeMapping {
    pub change: GitChange,
    pub old_node_ids: Vec<String>,
    pub new_node_ids: Vec<String>,
    pub correlated_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactFilters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    pub profiles: Vec<String>,
    pub conditions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    pub max_nodes: usize,
    pub max_edges: usize,
}

impl ImpactFilters {
    pub fn new(
        depth: Option<usize>,
        profiles: Vec<String>,
        conditions: Vec<String>,
        max_nodes: usize,
        max_edges: usize,
    ) -> Result<Self> {
        if max_nodes == 0 {
            bail!("impact max-nodes must be greater than zero");
        }
        if max_edges == 0 {
            bail!("impact max-edges must be greater than zero");
        }
        Ok(Self {
            depth,
            profiles: normalize_filter("profile", profiles)?,
            conditions: normalize_filter("condition", conditions)?,
            phases: Vec::new(),
            sessions: Vec::new(),
            environments: Vec::new(),
            max_nodes,
            max_edges,
        })
    }

    pub fn with_runtime_filters(
        mut self,
        phases: Vec<String>,
        sessions: Vec<String>,
        environments: Vec<String>,
    ) -> Result<Self> {
        self.phases = normalize_filter("phase", phases)?;
        self.sessions = normalize_filter("session", sessions)?;
        self.environments = normalize_filter("environment", environments)?;
        Ok(self)
    }

    fn matches(
        &self,
        edge: &EdgeRecord,
        runtime_contexts: Option<&BTreeMap<String, RuntimeEdgeContext>>,
    ) -> bool {
        let structural = (self.profiles.is_empty()
            || self.profiles.binary_search(&edge.profile_id).is_ok())
            && (self.conditions.is_empty()
                || self
                    .conditions
                    .binary_search(&render_condition(&edge.condition))
                    .is_ok())
            && (self.phases.is_empty() || self.phases.binary_search(&edge.phase).is_ok());
        if !structural {
            return false;
        }
        if self.sessions.is_empty() && self.environments.is_empty() {
            return true;
        }
        if edge.phase != "runtime" {
            return false;
        }
        let Some(context) = runtime_contexts.and_then(|contexts| contexts.get(&edge.id)) else {
            return false;
        };
        let session_matches = self.sessions.is_empty()
            || context
                .session_ids
                .iter()
                .chain(context.source_session_ids.iter())
                .any(|value| self.sessions.binary_search(value).is_ok());
        let environment_matches = self.environments.is_empty()
            || context
                .environment_names
                .iter()
                .chain(context.runtimes.iter())
                .chain(context.regions.iter())
                .any(|value| self.environments.binary_search(value).is_ok());
        session_matches && environment_matches
    }
}

fn normalize_filter(name: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            bail!("impact {name} filter must not be empty");
        }
        normalized.push(value.to_owned());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactDiagnostic {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactNode {
    pub node: NodeRecord,
    pub depth: usize,
    pub changed_node_id: String,
    pub dependency_path: Vec<PathStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImpactResult {
    pub root: NodeRecord,
    pub root_impacted: bool,
    pub complete: bool,
    pub filters: ImpactFilters,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_set: Option<GitChangedSet>,
    pub mappings: Vec<ChangedNodeMapping>,
    pub changed_nodes: Vec<NodeRecord>,
    pub impacts: Vec<ImpactNode>,
    pub diagnostics: Vec<ImpactDiagnostic>,
}

pub fn impact_query_cache_key(
    snapshot_id: &str,
    selector: &str,
    filters: &ImpactFilters,
) -> String {
    stable_id_from_value(
        "impact-query",
        &json!({
            "schema": IMPACT_QUERY_CACHE_SCHEMA_VERSION,
            "snapshot_id": snapshot_id,
            "selector": selector,
            "filters": filters,
        }),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitChangeKey {
    status: String,
    similarity: Option<u8>,
    old_path: Option<String>,
    new_path: Option<String>,
}

pub fn read_git_changed_set(root: &Path, requested_ref: &str) -> Result<GitChangedSet> {
    read_git_changed_set_cancellable(root, requested_ref, || false)
}

pub(crate) fn read_git_changed_set_cancellable(
    root: &Path,
    requested_ref: &str,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<GitChangedSet> {
    validate_git_ref(requested_ref)?;
    check_cancelled(&mut is_cancelled)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("scan root {} is unavailable", root.display()))?;
    let git = resolve_safe_executable("git", &root)?;
    let prefix = git_text_cancellable(
        &git,
        &root,
        ["rev-parse", "--show-prefix"],
        &mut is_cancelled,
    )?;
    let prefix = normalize_repository_prefix(&prefix)?;
    let repository_root = git_text_cancellable(
        &git,
        &root,
        ["rev-parse", "--show-toplevel"],
        &mut is_cancelled,
    )?;
    let repository_root = Path::new(&repository_root)
        .canonicalize()
        .context("Git repository root is unavailable")?;
    if !root.starts_with(&repository_root) {
        bail!("security policy violation: Git repository root does not contain the scan root");
    }
    let head = resolve_commit_cancellable(&git, &repository_root, "HEAD", &mut is_cancelled)?;
    let resolved_ref =
        resolve_commit_cancellable(&git, &repository_root, requested_ref, &mut is_cancelled)?;
    let merge_base = git_text_cancellable(
        &git,
        &repository_root,
        ["merge-base", &resolved_ref, &head],
        &mut is_cancelled,
    )?;
    validate_object_id("merge base", &merge_base)?;

    let mut changes = BTreeMap::<GitChangeKey, BTreeSet<String>>::new();
    let committed = git_bytes_cancellable(
        &git,
        &repository_root,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            &merge_base,
            &head,
        ],
        &mut is_cancelled,
    )?;
    parse_name_status_into(
        &committed,
        "committed",
        &prefix,
        &mut changes,
        MAX_CHANGED_PATHS,
        &mut is_cancelled,
    )?;
    drop(committed);
    let worktree = git_bytes_cancellable(
        &git,
        &repository_root,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            &head,
        ],
        &mut is_cancelled,
    )?;
    parse_name_status_into(
        &worktree,
        "worktree",
        &prefix,
        &mut changes,
        MAX_CHANGED_PATHS,
        &mut is_cancelled,
    )?;
    drop(worktree);
    let untracked = git_bytes_cancellable(
        &git,
        &repository_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        &mut is_cancelled,
    )?;
    parse_untracked_paths_into(
        &untracked,
        &prefix,
        &mut changes,
        MAX_CHANGED_PATHS,
        &mut is_cancelled,
    )?;

    let mut finalized_changes = Vec::with_capacity(changes.len());
    for (key, sources) in changes {
        check_cancelled(&mut is_cancelled)?;
        finalized_changes.push(GitChange {
            status: key.status,
            similarity: key.similarity,
            old_path: key.old_path,
            new_path: key.new_path,
            sources: sources.into_iter().collect(),
        });
    }

    Ok(GitChangedSet {
        requested_ref: requested_ref.to_owned(),
        resolved_ref,
        merge_base: merge_base.to_ascii_lowercase(),
        head,
        repository_prefix: prefix,
        changes: finalized_changes,
    })
}

pub(crate) fn read_git_churn_cancellable(
    root: &Path,
    maximum_commits: u32,
    path_filters: &[String],
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<GitChurn> {
    if maximum_commits == 0 {
        bail!("Git churn commit limit must be greater than zero");
    }
    let normalized_filters = path_filters
        .iter()
        .map(|path| normalize_git_path(path))
        .collect::<Result<Vec<_>>>()?;
    check_cancelled(&mut is_cancelled)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("scan root {} is unavailable", root.display()))?;
    let git = resolve_safe_executable("git", &root)?;
    let prefix = git_text_cancellable(
        &git,
        &root,
        ["rev-parse", "--show-prefix"],
        &mut is_cancelled,
    )?;
    let prefix = normalize_repository_prefix(&prefix)?;
    let repository_root = git_text_cancellable(
        &git,
        &root,
        ["rev-parse", "--show-toplevel"],
        &mut is_cancelled,
    )?;
    let repository_root = Path::new(&repository_root)
        .canonicalize()
        .context("Git repository root is unavailable")?;
    if !root.starts_with(&repository_root) {
        bail!("security policy violation: Git repository root does not contain the scan root");
    }
    let head = resolve_commit_cancellable(&git, &repository_root, "HEAD", &mut is_cancelled)?;
    let maximum = format!("--max-count={maximum_commits}");
    let commit_bytes = git_bytes_cancellable(
        &git,
        &repository_root,
        [
            "log",
            "-z",
            "--format=%H",
            maximum.as_str(),
            "--end-of-options",
            head.as_str(),
        ],
        &mut is_cancelled,
    )?;
    let mut commits = Vec::new();
    for field in nul_fields(&commit_bytes) {
        check_cancelled(&mut is_cancelled)?;
        let oid = parse_utf8_field(field, "Git commit ID")?;
        validate_object_id("Git commit", &oid)?;
        commits.push(oid);
    }

    let mut counts_by_path = BTreeMap::<String, u64>::new();
    let mut path_occurrences = 0_usize;
    for oid in commits {
        check_cancelled(&mut is_cancelled)?;
        let paths = git_bytes_cancellable(
            &git,
            &repository_root,
            [
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-r",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=none",
                oid.as_str(),
            ],
            &mut is_cancelled,
        )?;
        parse_nul_paths(&paths, &prefix, &mut is_cancelled, |path| {
            if path_occurrences >= MAX_CHANGED_PATHS {
                return Err(ImpactChangedSetPreprocessingExhausted.into());
            }
            path_occurrences += 1;
            if normalized_filters.is_empty()
                || normalized_filters
                    .iter()
                    .any(|filter| path_matches_filter(&path, filter))
            {
                let count = counts_by_path.entry(path).or_insert(0);
                *count = count.saturating_add(1);
            }
            Ok(())
        })?;
    }
    Ok(GitChurn {
        head,
        counts_by_path,
    })
}

fn path_matches_filter(path: &str, filter: &str) -> bool {
    path == filter
        || path
            .strip_prefix(filter)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn validate_git_ref(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('-')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("Git ref is invalid");
    }
    Ok(())
}

fn resolve_commit_cancellable(
    git: &Path,
    root: &Path,
    value: &str,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<String> {
    let revision = format!("{value}^{{commit}}");
    let resolved = git_text_cancellable(
        git,
        root,
        ["rev-parse", "--verify", "--end-of-options", &revision],
        is_cancelled,
    )
    .with_context(|| format!("Git ref {value:?} does not resolve to a commit"))?;
    validate_object_id("Git ref", &resolved)?;
    Ok(resolved.to_ascii_lowercase())
}

fn validate_object_id(name: &str, value: &str) -> Result<()> {
    if !(40..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{name} returned an invalid object ID");
    }
    Ok(())
}

fn git_text_cancellable<'a>(
    git: &Path,
    root: &Path,
    args: impl IntoIterator<Item = &'a str>,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<String> {
    let bytes = git_bytes_cancellable(git, root, args, is_cancelled)?;
    let value = String::from_utf8(bytes).context("Git returned non-UTF-8 metadata")?;
    Ok(value.trim().to_owned())
}

fn git_bytes_cancellable<'a>(
    git: &Path,
    root: &Path,
    args: impl IntoIterator<Item = &'a str>,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>> {
    check_cancelled(is_cancelled)?;
    let mut command = Command::new(git);
    command
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "diff.external=",
            "-c",
            "maintenance.auto=false",
            "-C",
        ])
        .arg(root)
        .args(args)
        .env("PAGER", "cat")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        if key
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat");
    run_bounded_child_cancellable(command, MAX_GIT_OUTPUT_BYTES, is_cancelled)
}

fn run_bounded_child_cancellable(
    mut command: Command,
    maximum_output_bytes: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>> {
    let mut child = command
        .spawn()
        .context("failed to run read-only Git query")?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Git stdout pipe is unavailable");
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        bail!("Git stderr pipe is unavailable");
    };
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&overflow);
    let stderr_overflow = Arc::clone(&overflow);
    let stdout_reader =
        thread::spawn(move || read_bounded_pipe(stdout, maximum_output_bytes, &stdout_overflow));
    let stderr_reader =
        thread::spawn(move || read_bounded_pipe(stderr, maximum_output_bytes, &stderr_overflow));
    let status = loop {
        if is_cancelled() {
            kill_reap_and_join(&mut child, stdout_reader, stderr_reader);
            bail!("Git changed-set query was cancelled");
        }
        if overflow.load(Ordering::Acquire) {
            kill_reap_and_join(&mut child, stdout_reader, stderr_reader);
            check_cancelled(is_cancelled)?;
            return Err(ImpactChangedSetPreprocessingExhausted.into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                kill_reap_and_join(&mut child, stdout_reader, stderr_reader);
                bail!("failed to poll read-only Git query");
            }
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Git stdout reader failed"))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Git stderr reader failed"))?;
    check_cancelled(is_cancelled)?;
    if overflow.load(Ordering::Acquire) {
        return Err(ImpactChangedSetPreprocessingExhausted.into());
    }
    let stdout = stdout?;
    stderr?;
    if !status.success() {
        bail!("read-only Git query failed");
    }
    Ok(stdout)
}

fn kill_reap_and_join(
    child: &mut Child,
    stdout_reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stderr_reader: thread::JoinHandle<std::io::Result<Vec<u8>>>,
) {
    let _ = child.kill();
    let _ = child.wait();
    let _ = stdout_reader.join();
    let _ = stderr_reader.join();
}

fn read_bounded_pipe(
    mut pipe: impl Read,
    maximum_output_bytes: usize,
    overflow: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    const BUFFER_BYTES: usize = 8 * 1024;

    let mut bytes = Vec::with_capacity(maximum_output_bytes.min(BUFFER_BYTES));
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let retained = maximum_output_bytes.saturating_sub(bytes.len()).min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        if retained < read {
            overflow.store(true, Ordering::Release);
        }
    }
    Ok(bytes)
}

fn check_cancelled(is_cancelled: &mut (impl FnMut() -> bool + ?Sized)) -> Result<()> {
    if is_cancelled() {
        bail!("graph operation was cancelled");
    }
    Ok(())
}

fn normalize_repository_prefix(value: &str) -> Result<String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let value = value.trim_end_matches('/');
    let value = normalize_git_path(value)?;
    Ok(format!("{value}/"))
}

fn parse_name_status(
    bytes: &[u8],
    source: &str,
    prefix: &str,
    is_cancelled: &mut impl FnMut() -> bool,
    mut visit: impl FnMut(GitChange) -> Result<()>,
) -> Result<()> {
    let mut fields = nul_fields(bytes);
    while let Some(field) = fields.next() {
        check_cancelled(is_cancelled)?;
        let token = parse_utf8_field(field, "Git status")?;
        let (status, similarity, paths) = parse_status(&token)?;
        let first = parse_utf8_field(
            fields
                .next()
                .context("Git name-status output ended before its path fields")?,
            "Git path",
        )?;
        let second = if paths == 2 {
            Some(parse_utf8_field(
                fields
                    .next()
                    .context("Git name-status output ended before its path fields")?,
                "Git path",
            )?)
        } else {
            None
        };
        let (old_path, new_path) = if let Some(second) = second {
            (
                strip_repository_prefix(&first, prefix)?,
                strip_repository_prefix(&second, prefix)?,
            )
        } else if status == "deleted" {
            (strip_repository_prefix(&first, prefix)?, None)
        } else {
            (None, strip_repository_prefix(&first, prefix)?)
        };
        if old_path.is_none() && new_path.is_none() {
            continue;
        }
        visit(GitChange {
            status,
            similarity,
            old_path,
            new_path,
            sources: vec![source.to_owned()],
        })?;
    }
    Ok(())
}

fn parse_status(token: &str) -> Result<(String, Option<u8>, usize)> {
    let code = token
        .as_bytes()
        .first()
        .copied()
        .context("Git emitted an empty status")?;
    let (status, paths) = match code {
        b'A' => ("added", 1),
        b'M' => ("modified", 1),
        b'D' => ("deleted", 1),
        b'R' => ("renamed", 2),
        b'C' => ("copied", 2),
        b'T' => ("type_changed", 1),
        b'U' => ("unmerged", 1),
        _ => bail!("Git emitted unsupported name-status code {token:?}"),
    };
    let similarity = if matches!(code, b'R' | b'C') {
        let score = token[1..]
            .parse::<u8>()
            .with_context(|| format!("Git emitted invalid similarity score {token:?}"))?;
        if score > 100 {
            bail!("Git emitted invalid similarity score {token:?}");
        }
        Some(score)
    } else {
        if token.len() != 1 {
            bail!("Git emitted invalid name-status code {token:?}");
        }
        None
    };
    Ok((status.to_owned(), similarity, paths))
}

fn parse_nul_paths(
    bytes: &[u8],
    prefix: &str,
    is_cancelled: &mut impl FnMut() -> bool,
    mut visit: impl FnMut(String) -> Result<()>,
) -> Result<()> {
    for field in nul_fields(bytes) {
        check_cancelled(is_cancelled)?;
        let path = parse_utf8_field(field, "Git path")?;
        if let Some(path) = strip_repository_prefix(&path, prefix)? {
            visit(path)?;
        }
    }
    Ok(())
}

fn nul_fields(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
}

fn parse_utf8_field(value: &[u8], name: &str) -> Result<String> {
    String::from_utf8(value.to_vec()).with_context(|| format!("{name} is not valid UTF-8"))
}

fn strip_repository_prefix(path: &str, prefix: &str) -> Result<Option<String>> {
    let path = normalize_git_path(path)?;
    if prefix.is_empty() {
        return Ok(Some(path));
    }
    Ok(path.strip_prefix(prefix).map(ToOwned::to_owned))
}

fn normalize_git_path(value: &str) -> Result<String> {
    if value.is_empty() || value.contains('\\') {
        bail!("Git emitted an unsafe repository path");
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("Git emitted an unsafe repository path {value:?}");
    }
    Ok(value.to_owned())
}

fn parse_name_status_into(
    bytes: &[u8],
    source: &str,
    prefix: &str,
    changes: &mut BTreeMap<GitChangeKey, BTreeSet<String>>,
    maximum_changes: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    parse_name_status(bytes, source, prefix, is_cancelled, |change| {
        insert_change_bounded(changes, change, maximum_changes)
    })
}

fn parse_untracked_paths_into(
    bytes: &[u8],
    prefix: &str,
    changes: &mut BTreeMap<GitChangeKey, BTreeSet<String>>,
    maximum_changes: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    parse_nul_paths(bytes, prefix, is_cancelled, |path| {
        insert_change_bounded(
            changes,
            GitChange {
                status: "untracked".to_owned(),
                similarity: None,
                old_path: None,
                new_path: Some(path),
                sources: vec!["worktree".to_owned()],
            },
            maximum_changes,
        )
    })
}

fn insert_change_bounded(
    changes: &mut BTreeMap<GitChangeKey, BTreeSet<String>>,
    change: GitChange,
    maximum_changes: usize,
) -> Result<()> {
    let key = GitChangeKey {
        status: change.status,
        similarity: change.similarity,
        old_path: change.old_path,
        new_path: change.new_path,
    };
    let at_capacity = changes.len() >= maximum_changes;
    match changes.entry(key) {
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            entry.get_mut().extend(change.sources);
        }
        std::collections::btree_map::Entry::Vacant(entry) => {
            if at_capacity {
                return Err(ImpactChangedSetPreprocessingExhausted.into());
            }
            entry.insert(change.sources.into_iter().collect());
        }
    }
    Ok(())
}

pub fn map_changed_set(
    snapshot: &GraphSnapshot,
    changed_set: &GitChangedSet,
) -> Result<Vec<ChangedNodeMapping>> {
    map_changed_set_cancellable(snapshot, changed_set, &mut || false)
}

pub(crate) fn map_changed_set_cancellable(
    snapshot: &GraphSnapshot,
    changed_set: &GitChangedSet,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<ChangedNodeMapping>> {
    map_changed_set_with_limit(
        snapshot,
        changed_set,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        is_cancelled,
    )
}

fn map_changed_set_with_limit(
    snapshot: &GraphSnapshot,
    changed_set: &GitChangedSet,
    maximum: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<ChangedNodeMapping>> {
    let mut work = ImpactChangedSetWork::new(maximum, is_cancelled);
    let index = path_node_index_cancellable(snapshot, &mut work)?;
    let mut mappings = Vec::with_capacity(changed_set.changes.len());
    for change in &changed_set.changes {
        work.step()?;
        let mut correlated = BTreeSet::new();
        let old_node_ids = copy_changed_node_ids(
            change.old_path.as_deref().and_then(|path| index.get(path)),
            &mut correlated,
            &mut work,
        )?;
        let new_node_ids = copy_changed_node_ids(
            change.new_path.as_deref().and_then(|path| index.get(path)),
            &mut correlated,
            &mut work,
        )?;
        let mut correlated_node_ids = Vec::with_capacity(correlated.len());
        for node_id in correlated {
            work.step()?;
            correlated_node_ids.push(node_id);
            #[cfg(test)]
            CHANGED_CORRELATED_ID_MATERIALIZATION_VISITS.fetch_add(1, Ordering::Relaxed);
        }
        let mut sources = Vec::with_capacity(change.sources.len());
        for source in &change.sources {
            work.step()?;
            sources.push(source.clone());
            #[cfg(test)]
            CHANGED_SOURCE_MATERIALIZATION_VISITS.fetch_add(1, Ordering::Relaxed);
        }
        mappings.push(ChangedNodeMapping {
            change: GitChange {
                status: change.status.clone(),
                similarity: change.similarity,
                old_path: change.old_path.clone(),
                new_path: change.new_path.clone(),
                sources,
            },
            old_node_ids,
            new_node_ids,
            correlated_node_ids,
        });
    }
    Ok(mappings)
}

fn path_node_index_cancellable(
    snapshot: &GraphSnapshot,
    work: &mut ImpactChangedSetWork<'_>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut index = BTreeMap::<String, BTreeSet<String>>::new();
    for node in &snapshot.nodes {
        work.step()?;
        for key in ["path", "source_path", "manifest_path", "relative_path"] {
            if let Some(path) = node.properties.get(key).and_then(serde_json::Value::as_str) {
                index_node_path(&mut index, path, &node.id, work)?;
            }
        }
        if let Some(identity) = node.properties.get("canonical_identity") {
            for key in ["path", "source_path", "relative_path"] {
                if let Some(path) = identity.get(key).and_then(serde_json::Value::as_str) {
                    index_node_path(&mut index, path, &node.id, work)?;
                }
            }
        }
    }

    let mut sites = BTreeMap::new();
    for site in &snapshot.sites {
        work.step()?;
        #[cfg(test)]
        PATH_NODE_INDEX_SITE_VISITS.fetch_add(1, Ordering::Relaxed);
        sites.insert(site.id.as_str(), site);
    }
    let mut edges = BTreeMap::new();
    for edge in &snapshot.edges {
        work.step()?;
        #[cfg(test)]
        PATH_NODE_INDEX_EDGE_VISITS.fetch_add(1, Ordering::Relaxed);
        edges.insert(edge.id.as_str(), edge);
    }
    for evidence in &snapshot.evidence {
        work.step()?;
        match evidence.owner_type.as_str() {
            "node" => index_node_path(&mut index, &evidence.path, &evidence.owner_id, work)?,
            "site" => {
                if let Some(site) = sites.get(evidence.owner_id.as_str()) {
                    index_node_path(&mut index, &evidence.path, &site.source, work)?;
                }
            }
            "edge" => {
                if let Some(edge) = edges.get(evidence.owner_id.as_str()) {
                    index_node_path(&mut index, &evidence.path, &edge.source, work)?;
                    if matches!(
                        edge.kind.as_str(),
                        "declares" | "contains" | "defines" | "routes" | "instantiates"
                    ) {
                        index_node_path(&mut index, &evidence.path, &edge.target, work)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(index)
}

fn index_node_path(
    index: &mut BTreeMap<String, BTreeSet<String>>,
    path: &str,
    node_id: &str,
    work: &mut ImpactChangedSetWork<'_>,
) -> Result<()> {
    if let Ok(path) = normalize_git_path(path) {
        work.step()?;
        index.entry(path).or_default().insert(node_id.to_owned());
    }
    Ok(())
}

fn copy_changed_node_ids(
    ids: Option<&BTreeSet<String>>,
    correlated: &mut BTreeSet<String>,
    work: &mut ImpactChangedSetWork<'_>,
) -> Result<Vec<String>> {
    let mut copied = Vec::with_capacity(ids.map_or(0, BTreeSet::len));
    for node_id in ids.into_iter().flatten() {
        work.step()?;
        #[cfg(test)]
        CHANGED_NODE_ID_COPY_VISITS.fetch_add(1, Ordering::Relaxed);
        copied.push(node_id.clone());
        work.step()?;
        correlated.insert(node_id.clone());
    }
    Ok(copied)
}

struct ImpactChangedSetWork<'a> {
    used: usize,
    maximum: usize,
    is_cancelled: &'a mut dyn FnMut() -> bool,
}

impl<'a> ImpactChangedSetWork<'a> {
    fn new(maximum: usize, is_cancelled: &'a mut dyn FnMut() -> bool) -> Self {
        Self {
            used: 0,
            maximum,
            is_cancelled,
        }
    }

    fn step(&mut self) -> Result<()> {
        check_cancelled(self.is_cancelled)?;
        if self.used >= self.maximum {
            return Err(ImpactChangedSetPreprocessingExhausted.into());
        }
        self.used += 1;
        #[cfg(test)]
        CHANGED_SET_WORK_ITEMS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
static PATH_NODE_INDEX_SITE_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PATH_NODE_INDEX_EDGE_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CHANGED_NODE_ID_COPY_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CHANGED_CORRELATED_ID_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CHANGED_SOURCE_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static CHANGED_SET_WORK_ITEMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[derive(Default)]
struct TraversalBudget {
    node_ids: BTreeSet<String>,
    edge_ids: BTreeSet<String>,
    complete: bool,
    diagnostics: BTreeMap<String, ImpactDiagnostic>,
}

impl TraversalBudget {
    fn new(root_id: &str) -> Self {
        Self {
            node_ids: BTreeSet::from([root_id.to_owned()]),
            edge_ids: BTreeSet::new(),
            complete: true,
            diagnostics: BTreeMap::new(),
        }
    }

    fn admit_edge(&mut self, edge: &EdgeRecord, filters: &ImpactFilters) -> bool {
        if self.edge_ids.contains(&edge.id) {
            return true;
        }
        if self.edge_ids.len() >= filters.max_edges {
            self.limit(
                "impact_edge_limit_reached",
                format!(
                    "impact traversal stopped after {} unique edges (limit {})",
                    self.edge_ids.len(),
                    filters.max_edges
                ),
            );
            return false;
        }
        self.edge_ids.insert(edge.id.clone());
        true
    }

    fn admit_node(&mut self, node_id: &str, filters: &ImpactFilters) -> bool {
        if self.node_ids.contains(node_id) {
            return true;
        }
        if self.node_ids.len() >= filters.max_nodes {
            self.limit(
                "impact_node_limit_reached",
                format!(
                    "impact traversal stopped after {} unique nodes (limit {})",
                    self.node_ids.len(),
                    filters.max_nodes
                ),
            );
            return false;
        }
        self.node_ids.insert(node_id.to_owned());
        true
    }

    fn limit(&mut self, code: &str, message: String) {
        self.complete = false;
        self.diagnostics
            .entry(code.to_owned())
            .or_insert_with(|| ImpactDiagnostic {
                code: code.to_owned(),
                message,
            });
    }
}

pub fn impact(
    snapshot: &GraphSnapshot,
    selector: &str,
    changed_set: Option<&GitChangedSet>,
    filters: ImpactFilters,
) -> Result<ImpactResult> {
    impact_cancellable(snapshot, selector, changed_set, filters, || false)
}

pub(crate) fn impact_cancellable(
    snapshot: &GraphSnapshot,
    selector: &str,
    changed_set: Option<&GitChangedSet>,
    filters: ImpactFilters,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<ImpactResult> {
    check_cancelled(&mut is_cancelled)?;
    let root = resolve_selector_bounded_cancellable(
        snapshot,
        selector,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        &mut is_cancelled,
    )?;
    let mut node_map = BTreeMap::new();
    for node in &snapshot.nodes {
        check_cancelled(&mut is_cancelled)?;
        node_map.insert(node.id.clone(), node.clone());
    }
    let mut edge_map = BTreeMap::new();
    for edge in &snapshot.edges {
        check_cancelled(&mut is_cancelled)?;
        edge_map.insert(edge.id.clone(), edge);
    }
    let mappings = changed_set
        .map(|set| map_changed_set_cancellable(snapshot, set, &mut is_cancelled))
        .transpose()?
        .unwrap_or_default();
    let changed_ids = if changed_set.is_some() {
        let mut changed_ids = BTreeSet::new();
        let mut changed_id_work = 0_usize;
        for mapping in &mappings {
            for node_id in &mapping.correlated_node_ids {
                check_cancelled(&mut is_cancelled)?;
                if changed_id_work >= MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS {
                    return Err(ImpactChangedSetPreprocessingExhausted.into());
                }
                changed_id_work += 1;
                changed_ids.insert(node_id.clone());
            }
        }
        changed_ids
    } else {
        BTreeSet::from([root.id.clone()])
    };
    let mut changed_nodes = Vec::new();
    for id in &changed_ids {
        check_cancelled(&mut is_cancelled)?;
        if let Some(node) = node_map.get(id).cloned() {
            changed_nodes.push(node);
        }
    }
    let mut budget = TraversalBudget::new(&root.id);
    let runtime_contexts =
        runtime_context_index_cancellable(snapshot, &filters, &mut is_cancelled)?;
    let forward = adjacency_cancellable(
        snapshot,
        false,
        &filters,
        runtime_contexts.as_ref(),
        &mut is_cancelled,
    )?;
    let reverse = adjacency_cancellable(
        snapshot,
        true,
        &filters,
        runtime_contexts.as_ref(),
        &mut is_cancelled,
    )?;
    let root_path = if changed_ids.contains(&root.id) {
        Some(Vec::new())
    } else {
        shortest_path_to_changed(
            &root.id,
            &changed_ids,
            &forward,
            &edge_map,
            &filters,
            &mut budget,
            &mut is_cancelled,
        )?
    };
    let root_impacted = root_path.is_some();
    let mut impacts = Vec::new();
    if let Some(root_path) = root_path {
        let changed_node_id = root_path
            .last()
            .map(|edge: &EdgeRecord| edge.target.clone())
            .unwrap_or_else(|| root.id.clone());
        let scoped =
            reverse_path_index(&root.id, &reverse, &filters, &mut budget, &mut is_cancelled)?;
        preflight_path_materialization(&scoped, root_path.len(), &node_map, &mut is_cancelled)?;
        let evidence_filter = GraphQueryFilter {
            phases: filters.phases.clone(),
            profiles: filters.profiles.clone(),
            sessions: filters.sessions.clone(),
            environments: filters.environments.clone(),
        };
        let mut projection_edges = Vec::new();
        for edge_id in scoped.successor.values() {
            check_cancelled(&mut is_cancelled)?;
            projection_edges.push(
                edge_map
                    .get(edge_id)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("impact reverse path edge is unavailable"))?,
            );
        }
        for edge in &root_path {
            check_cancelled(&mut is_cancelled)?;
            projection_edges.push(edge);
        }
        let mut path_steps = PathStepMaterializer::new(
            snapshot,
            &evidence_filter,
            projection_edges.iter().copied(),
            MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
            &mut is_cancelled,
        )?;
        for (node_id, depth) in scoped.depths {
            check_cancelled(&mut is_cancelled)?;
            let Some(node) = node_map.get(&node_id).cloned() else {
                continue;
            };
            let path_length = depth + root_path.len();
            let mut dependency_path = Vec::with_capacity(path_length);
            let mut current = node_id.as_str();
            while current != root.id {
                check_cancelled(&mut is_cancelled)?;
                let edge_id = scoped.successor.get(current).ok_or_else(|| {
                    anyhow::anyhow!("impact reverse path successor is unavailable")
                })?;
                let edge = edge_map
                    .get(edge_id)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("impact reverse path edge is unavailable"))?;
                dependency_path.push(path_steps.materialize(edge, &mut is_cancelled)?);
                current = edge.target.as_str();
            }
            for edge in &root_path {
                check_cancelled(&mut is_cancelled)?;
                dependency_path.push(path_steps.materialize(edge, &mut is_cancelled)?);
            }
            impacts.push(ImpactNode {
                node,
                depth,
                changed_node_id: changed_node_id.clone(),
                dependency_path,
            });
        }
    }

    let mut diagnostics = budget
        .diagnostics
        .into_values()
        .map(|diagnostic| {
            (
                (diagnostic.code.clone(), diagnostic.message.clone()),
                diagnostic,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if changed_set.is_some() {
        for mapping in &mappings {
            check_cancelled(&mut is_cancelled)?;
            if mapping.correlated_node_ids.is_empty() {
                let code = "changed_path_unmapped".to_owned();
                let message = format!(
                    "changed path {} was not present in the selected snapshot",
                    mapping
                        .change
                        .new_path
                        .as_deref()
                        .or(mapping.change.old_path.as_deref())
                        .unwrap_or("unknown")
                );
                diagnostics.insert(
                    (code.clone(), message.clone()),
                    ImpactDiagnostic { code, message },
                );
            }
        }
    }
    check_cancelled(&mut is_cancelled)?;
    let mut finalized_diagnostics = Vec::with_capacity(diagnostics.len());
    for diagnostic in diagnostics.into_values() {
        check_cancelled(&mut is_cancelled)?;
        finalized_diagnostics.push(diagnostic);
    }

    Ok(ImpactResult {
        root,
        root_impacted,
        complete: budget.complete,
        filters,
        changed_set: changed_set.cloned(),
        mappings,
        changed_nodes,
        impacts,
        diagnostics: finalized_diagnostics,
    })
}

fn adjacency_cancellable<'a>(
    snapshot: &'a GraphSnapshot,
    reverse: bool,
    filters: &ImpactFilters,
    runtime_contexts: Option<&BTreeMap<String, RuntimeEdgeContext>>,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Vec<&'a EdgeRecord>>> {
    adjacency_with_limit(
        snapshot,
        reverse,
        filters,
        runtime_contexts,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        is_cancelled,
    )
}

fn adjacency_with_limit<'a>(
    snapshot: &'a GraphSnapshot,
    reverse: bool,
    filters: &ImpactFilters,
    runtime_contexts: Option<&BTreeMap<String, RuntimeEdgeContext>>,
    maximum_work: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Vec<&'a EdgeRecord>>> {
    let mut work = ImpactAdjacencyWork::new(maximum_work);
    let mut ordered = BTreeMap::<String, BTreeMap<(String, String), &EdgeRecord>>::new();
    for edge in &snapshot.edges {
        work.step(is_cancelled)?;
        #[cfg(test)]
        IMPACT_ADJACENCY_EDGE_SCANS.fetch_add(1, Ordering::Relaxed);
        if !filters.matches(edge, runtime_contexts) {
            continue;
        }
        work.step(is_cancelled)?;
        let key = if reverse { &edge.target } else { &edge.source };
        let next = if reverse { &edge.source } else { &edge.target };
        ordered
            .entry(key.clone())
            .or_default()
            .insert((next.clone(), edge.id.clone()), edge);
        #[cfg(test)]
        IMPACT_ADJACENCY_INSERT_VISITS.fetch_add(1, Ordering::Relaxed);
    }
    let mut adjacency = BTreeMap::new();
    for (source, edges) in ordered {
        let mut materialized = Vec::with_capacity(edges.len());
        for edge in edges.into_values() {
            work.step(is_cancelled)?;
            materialized.push(edge);
            #[cfg(test)]
            IMPACT_ADJACENCY_MATERIALIZATION_VISITS.fetch_add(1, Ordering::Relaxed);
        }
        adjacency.insert(source, materialized);
    }
    Ok(adjacency)
}

struct ImpactAdjacencyWork {
    used: usize,
    maximum: usize,
}

impl ImpactAdjacencyWork {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        check_cancelled(is_cancelled)?;
        if self.used >= self.maximum {
            return Err(ImpactAdjacencyPreprocessingExhausted.into());
        }
        self.used += 1;
        #[cfg(test)]
        IMPACT_ADJACENCY_WORK_ITEMS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
static IMPACT_ADJACENCY_WORK_ITEMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static IMPACT_ADJACENCY_EDGE_SCANS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static IMPACT_ADJACENCY_INSERT_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static IMPACT_ADJACENCY_MATERIALIZATION_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn runtime_context_index_cancellable(
    snapshot: &GraphSnapshot,
    filters: &ImpactFilters,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<BTreeMap<String, RuntimeEdgeContext>>> {
    runtime_context_index_with_limit(
        snapshot,
        filters,
        MAX_GRAPH_SERVICE_PREPROCESSING_WORK_ITEMS,
        is_cancelled,
    )
}

fn runtime_context_index_with_limit(
    snapshot: &GraphSnapshot,
    filters: &ImpactFilters,
    maximum_work: usize,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<BTreeMap<String, RuntimeEdgeContext>>> {
    if (filters.sessions.is_empty() && filters.environments.is_empty())
        || (!filters.phases.is_empty()
            && filters
                .phases
                .binary_search_by(|phase| phase.as_str().cmp("runtime"))
                .is_err())
    {
        return Ok(None);
    }
    #[cfg(test)]
    RUNTIME_CONTEXT_INDEX_BUILDS.fetch_add(1, Ordering::Relaxed);

    let mut work = RuntimeContextWorkBudget::new(maximum_work);
    let mut accumulators = BTreeMap::<String, RuntimeContextAccumulator>::new();
    for evidence in &snapshot.evidence {
        work.step(is_cancelled)?;
        #[cfg(test)]
        RUNTIME_CONTEXT_EVIDENCE_VISITS.fetch_add(1, Ordering::Relaxed);
        if evidence.owner_type != "edge" || evidence.kind != "runtime" {
            continue;
        }
        if !accumulators.contains_key(&evidence.owner_id) {
            work.step(is_cancelled)?;
            accumulators.insert(
                evidence.owner_id.clone(),
                RuntimeContextAccumulator::default(),
            );
        }
        let accumulator = accumulators
            .get_mut(&evidence.owner_id)
            .expect("runtime context accumulator was inserted");
        insert_runtime_string(
            &mut accumulator.session_ids,
            evidence.properties.get("session_id"),
            &mut work,
            is_cancelled,
        )?;
        insert_runtime_string(
            &mut accumulator.source_session_ids,
            evidence.properties.get("source_session_id"),
            &mut work,
            is_cancelled,
        )?;
        if let Some(environment) = evidence.properties.get("environment") {
            insert_runtime_string(
                &mut accumulator.environment_names,
                environment.get("name"),
                &mut work,
                is_cancelled,
            )?;
            insert_runtime_string(
                &mut accumulator.runtimes,
                environment.get("runtime"),
                &mut work,
                is_cancelled,
            )?;
            insert_runtime_string(
                &mut accumulator.regions,
                environment.get("region"),
                &mut work,
                is_cancelled,
            )?;
        }
        accumulator.observation_count = accumulator.observation_count.saturating_add(
            evidence
                .properties
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        );
        update_runtime_min(
            &mut accumulator.first_observed_at,
            evidence
                .properties
                .get("first_observed_at")
                .and_then(serde_json::Value::as_str),
            &mut work,
            is_cancelled,
        )?;
        update_runtime_max(
            &mut accumulator.last_observed_at,
            evidence
                .properties
                .get("last_observed_at")
                .and_then(serde_json::Value::as_str),
            &mut work,
            is_cancelled,
        )?;
    }
    let mut contexts = BTreeMap::new();
    for (edge_id, accumulator) in accumulators {
        work.step(is_cancelled)?;
        contexts.insert(
            edge_id,
            RuntimeEdgeContext {
                session_ids: materialize_runtime_values(
                    accumulator.session_ids,
                    &mut work,
                    is_cancelled,
                )?,
                source_session_ids: materialize_runtime_values(
                    accumulator.source_session_ids,
                    &mut work,
                    is_cancelled,
                )?,
                environment_names: materialize_runtime_values(
                    accumulator.environment_names,
                    &mut work,
                    is_cancelled,
                )?,
                runtimes: materialize_runtime_values(
                    accumulator.runtimes,
                    &mut work,
                    is_cancelled,
                )?,
                regions: materialize_runtime_values(accumulator.regions, &mut work, is_cancelled)?,
                observation_count: accumulator.observation_count,
                first_observed_at: accumulator.first_observed_at,
                last_observed_at: accumulator.last_observed_at,
            },
        );
    }
    check_cancelled(is_cancelled)?;
    Ok(Some(contexts))
}

#[derive(Default)]
struct RuntimeContextAccumulator {
    session_ids: BTreeSet<String>,
    source_session_ids: BTreeSet<String>,
    environment_names: BTreeSet<String>,
    runtimes: BTreeSet<String>,
    regions: BTreeSet<String>,
    observation_count: u64,
    first_observed_at: Option<String>,
    last_observed_at: Option<String>,
}

struct RuntimeContextWorkBudget {
    used: usize,
    maximum: usize,
}

impl RuntimeContextWorkBudget {
    const fn new(maximum: usize) -> Self {
        Self { used: 0, maximum }
    }

    fn step(&mut self, is_cancelled: &mut impl FnMut() -> bool) -> Result<()> {
        check_cancelled(is_cancelled)?;
        if self.used >= self.maximum {
            return Err(ImpactRuntimeContextIndexExhausted.into());
        }
        self.used += 1;
        #[cfg(test)]
        RUNTIME_CONTEXT_WORK_ITEMS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn insert_runtime_string(
    output: &mut BTreeSet<String>,
    value: Option<&serde_json::Value>,
    work: &mut RuntimeContextWorkBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if let Some(value) = value.and_then(serde_json::Value::as_str)
        && !output.contains(value)
    {
        work.step(is_cancelled)?;
        output.insert(value.to_owned());
    }
    Ok(())
}

fn update_runtime_min(
    current: &mut Option<String>,
    value: Option<&str>,
    work: &mut RuntimeContextWorkBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if let Some(value) = value
        && current.as_deref().is_none_or(|current| value < current)
    {
        work.step(is_cancelled)?;
        *current = Some(value.to_owned());
    }
    Ok(())
}

fn update_runtime_max(
    current: &mut Option<String>,
    value: Option<&str>,
    work: &mut RuntimeContextWorkBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    if let Some(value) = value
        && current.as_deref().is_none_or(|current| value > current)
    {
        work.step(is_cancelled)?;
        *current = Some(value.to_owned());
    }
    Ok(())
}

fn materialize_runtime_values(
    values: BTreeSet<String>,
    work: &mut RuntimeContextWorkBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<String>> {
    let mut materialized = Vec::with_capacity(values.len());
    for value in values {
        work.step(is_cancelled)?;
        materialized.push(value);
        #[cfg(test)]
        RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(materialized)
}

#[cfg(test)]
static RUNTIME_CONTEXT_INDEX_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RUNTIME_CONTEXT_EVIDENCE_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RUNTIME_CONTEXT_WORK_ITEMS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn shortest_path_to_changed(
    root_id: &str,
    changed_ids: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<&EdgeRecord>>,
    edge_map: &BTreeMap<String, &EdgeRecord>,
    filters: &ImpactFilters,
    budget: &mut TraversalBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<Vec<EdgeRecord>>> {
    if changed_ids.is_empty() {
        return Ok(None);
    }
    let mut queue = VecDeque::from([root_id.to_owned()]);
    let mut seen = BTreeSet::from([root_id.to_owned()]);
    let mut predecessor = BTreeMap::<String, String>::new();
    let mut found = None;
    'search: while let Some(node_id) = queue.pop_front() {
        check_cancelled(is_cancelled)?;
        for edge in adjacency.get(&node_id).into_iter().flatten() {
            check_cancelled(is_cancelled)?;
            if !budget.admit_edge(edge, filters) {
                break 'search;
            }
            if !seen.contains(&edge.target) && !budget.admit_node(&edge.target, filters) {
                break 'search;
            }
            if seen.insert(edge.target.clone()) {
                predecessor.insert(edge.target.clone(), edge.id.clone());
                if changed_ids.contains(&edge.target) {
                    found = Some(edge.target.clone());
                    break 'search;
                }
                queue.push_back(edge.target.clone());
            }
        }
    }
    let Some(mut current) = found else {
        return Ok(None);
    };
    let mut reversed = Vec::new();
    while current != root_id {
        check_cancelled(is_cancelled)?;
        if reversed.len() >= MAX_DEPENDENCY_PATH_STEPS {
            return Err(ImpactPathMaterializationExhausted.into());
        }
        let Some(edge_id) = predecessor.get(&current) else {
            return Ok(None);
        };
        let Some(edge) = edge_map.get(edge_id).copied() else {
            return Ok(None);
        };
        reversed.push(edge.clone());
        current = edge.source.clone();
    }
    reversed.reverse();
    Ok(Some(reversed))
}

struct ReversePathIndex {
    successor: BTreeMap<String, String>,
    depths: BTreeMap<String, usize>,
}

fn reverse_path_index(
    root_id: &str,
    adjacency: &BTreeMap<String, Vec<&EdgeRecord>>,
    filters: &ImpactFilters,
    budget: &mut TraversalBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<ReversePathIndex> {
    let mut queue = VecDeque::from([(root_id.to_owned(), 0_usize)]);
    let mut seen = BTreeSet::from([root_id.to_owned()]);
    let mut successor = BTreeMap::<String, String>::new();
    let mut depths = BTreeMap::from([(root_id.to_owned(), 0_usize)]);
    'search: while let Some((node_id, depth)) = queue.pop_front() {
        check_cancelled(is_cancelled)?;
        if filters.depth.is_some_and(|limit| depth >= limit) {
            continue;
        }
        for edge in adjacency.get(&node_id).into_iter().flatten() {
            check_cancelled(is_cancelled)?;
            if !budget.admit_edge(edge, filters) {
                break 'search;
            }
            if !seen.contains(&edge.source) && !budget.admit_node(&edge.source, filters) {
                break 'search;
            }
            if seen.insert(edge.source.clone()) {
                successor.insert(edge.source.clone(), edge.id.clone());
                depths.insert(edge.source.clone(), depth + 1);
                queue.push_back((edge.source.clone(), depth + 1));
            }
        }
    }

    check_cancelled(is_cancelled)?;
    Ok(ReversePathIndex { successor, depths })
}

fn preflight_path_materialization(
    paths: &ReversePathIndex,
    suffix_length: usize,
    nodes: &BTreeMap<String, NodeRecord>,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<()> {
    let mut cumulative_steps = 0_usize;
    for (node_id, depth) in &paths.depths {
        check_cancelled(is_cancelled)?;
        if !nodes.contains_key(node_id) {
            continue;
        }
        let path_steps = depth
            .checked_add(suffix_length)
            .ok_or(ImpactPathMaterializationExhausted)?;
        if path_steps > MAX_DEPENDENCY_PATH_STEPS {
            return Err(ImpactPathMaterializationExhausted.into());
        }
        cumulative_steps = cumulative_steps
            .checked_add(path_steps)
            .ok_or(ImpactPathMaterializationExhausted)?;
        if cumulative_steps > MAX_IMPACT_MATERIALIZED_PATH_STEPS {
            return Err(ImpactPathMaterializationExhausted.into());
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::Instant;
    use std::{fs, sync::Mutex};

    use depgraph_store::{
        CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ScanRecord,
    };
    use serde_json::json;

    use super::*;

    static IMPACT_PREPROCESSING_TEST_LOCK: Mutex<()> = Mutex::new(());
    static CHANGED_SET_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_changed_set_counters() {
        for counter in [
            &PATH_NODE_INDEX_SITE_VISITS,
            &PATH_NODE_INDEX_EDGE_VISITS,
            &CHANGED_NODE_ID_COPY_VISITS,
            &CHANGED_CORRELATED_ID_MATERIALIZATION_VISITS,
            &CHANGED_SOURCE_MATERIALIZATION_VISITS,
            &CHANGED_SET_WORK_ITEMS,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }

    fn run_git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn reads_committed_rename_dirty_worktree_and_untracked_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        run_git(root.path(), &["init", "--quiet"]);
        run_git(
            root.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git(root.path(), &["config", "user.name", "Test"]);
        fs::create_dir(root.path().join("src"))?;
        fs::write(root.path().join("src/old.rs"), "pub fn value() {}\n")?;
        run_git(root.path(), &["add", "src/old.rs"]);
        run_git(root.path(), &["commit", "--quiet", "-m", "base"]);
        let base = run_git(root.path(), &["rev-parse", "HEAD"]);
        run_git(root.path(), &["mv", "src/old.rs", "src/new.rs"]);
        run_git(root.path(), &["commit", "--quiet", "-m", "rename"]);
        fs::write(
            root.path().join("src/new.rs"),
            "pub fn value() { println!(\"dirty\"); }\n",
        )?;
        fs::write(root.path().join("src/untracked.rs"), "pub fn new() {}\n")?;

        let first = read_git_changed_set(root.path(), &base)?;
        let second = read_git_changed_set(root.path(), &base)?;
        assert_eq!(first, second);
        assert!(first.changes.iter().any(|change| {
            change.status == "renamed"
                && change.old_path.as_deref() == Some("src/old.rs")
                && change.new_path.as_deref() == Some("src/new.rs")
                && change.sources == ["committed"]
        }));
        assert!(first.changes.iter().any(|change| {
            change.status == "modified"
                && change.new_path.as_deref() == Some("src/new.rs")
                && change.sources == ["worktree"]
        }));
        assert!(first.changes.iter().any(|change| {
            change.status == "untracked" && change.new_path.as_deref() == Some("src/untracked.rs")
        }));
        let nested = read_git_changed_set(&root.path().join("src"), &base)?;
        assert_eq!(nested.repository_prefix, "src/");
        assert!(nested.changes.iter().any(|change| {
            change.status == "renamed"
                && change.old_path.as_deref() == Some("old.rs")
                && change.new_path.as_deref() == Some("new.rs")
        }));
        Ok(())
    }

    #[test]
    fn changed_ref_is_a_comparison_base_and_head_is_the_audited_commit() -> Result<()> {
        let root = tempfile::tempdir()?;
        run_git(root.path(), &["init", "--quiet"]);
        run_git(
            root.path(),
            &["config", "user.email", "test@example.invalid"],
        );
        run_git(root.path(), &["config", "user.name", "Test"]);
        fs::write(root.path().join("base.rs"), "pub fn base() {}\n")?;
        run_git(root.path(), &["add", "base.rs"]);
        run_git(root.path(), &["commit", "--quiet", "-m", "base"]);
        let base = run_git(root.path(), &["rev-parse", "HEAD"]);
        let original_branch = run_git(root.path(), &["branch", "--show-current"]);

        run_git(root.path(), &["checkout", "--quiet", "-b", "side"]);
        fs::write(root.path().join("side.rs"), "pub fn side() {}\n")?;
        run_git(root.path(), &["add", "side.rs"]);
        run_git(root.path(), &["commit", "--quiet", "-m", "side"]);
        let side = run_git(root.path(), &["rev-parse", "HEAD"]);

        run_git(root.path(), &["checkout", "--quiet", &original_branch]);
        fs::write(root.path().join("head.rs"), "pub fn head() {}\n")?;
        run_git(root.path(), &["add", "head.rs"]);
        run_git(root.path(), &["commit", "--quiet", "-m", "head"]);
        let head = run_git(root.path(), &["rev-parse", "HEAD"]);

        let changed_set = read_git_changed_set(root.path(), &side)?;
        assert_eq!(changed_set.resolved_ref, side);
        assert_eq!(changed_set.merge_base, base);
        assert_eq!(changed_set.head, head);
        assert!(changed_set.changes.iter().any(|change| {
            change.status == "added"
                && change.new_path.as_deref() == Some("head.rs")
                && change.sources == ["committed"]
        }));
        assert!(!changed_set.changes.iter().any(|change| {
            change.old_path.as_deref() == Some("side.rs")
                || change.new_path.as_deref() == Some("side.rs")
        }));
        Ok(())
    }

    #[test]
    fn changed_path_parsing_enforces_one_cumulative_distinct_key_limit() -> Result<()> {
        let mut changes = BTreeMap::new();
        let mut never_cancelled = || false;
        parse_name_status_into(
            b"M\0src/a.rs\0M\0src/b.rs\0",
            "committed",
            "",
            &mut changes,
            2,
            &mut never_cancelled,
        )?;
        assert_eq!(changes.len(), 2, "the exact distinct-key limit succeeds");

        parse_name_status_into(
            b"M\0src/a.rs\0",
            "worktree",
            "",
            &mut changes,
            2,
            &mut never_cancelled,
        )?;
        assert_eq!(
            changes.len(),
            2,
            "a duplicate key does not consume capacity"
        );
        let duplicate_key = GitChangeKey {
            status: "modified".to_owned(),
            similarity: None,
            old_path: None,
            new_path: Some("src/a.rs".to_owned()),
        };
        assert_eq!(
            changes
                .get(&duplicate_key)
                .expect("duplicate key is retained")
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["committed", "worktree"]
        );

        let error =
            parse_untracked_paths_into(b"src/c.rs\0", "", &mut changes, 2, &mut never_cancelled)
                .expect_err("the next distinct key must fail before map insertion");
        assert!(is_resource_exhausted(&error));
        assert_eq!(
            changes.len(),
            2,
            "the over-limit untracked key was never inserted"
        );
        assert!(changes.keys().all(|key| {
            key.old_path.as_deref() != Some("src/c.rs")
                && key.new_path.as_deref() != Some("src/c.rs")
        }));
        Ok(())
    }

    #[test]
    fn changed_path_parser_observes_cancellation_before_the_next_entry() {
        let mut changes = BTreeMap::new();
        let mut checks = 0_usize;
        let error = parse_name_status_into(
            b"M\0src/a.rs\0M\0src/b.rs\0",
            "committed",
            "",
            &mut changes,
            2,
            &mut || {
                checks += 1;
                checks >= 2
            },
        )
        .expect_err("cancellation during parsing must return no changed set");
        assert!(!is_resource_exhausted(&error));
        assert_eq!(changes.len(), 1);
        assert!(changes.keys().all(|key| {
            key.old_path.as_deref() != Some("src/b.rs")
                && key.new_path.as_deref() != Some("src/b.rs")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_child_output_overflow_kills_reaps_and_joins_promptly() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let pid_path = temporary.path().join("overflow-helper.pid");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg(
                "echo $$ > \"$1\"; while :; do printf 'Bearer review-secret /Users/private/repository '; done >&2",
            )
            .arg("depgraph-overflow-helper")
            .arg(&pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let error = run_bounded_child_cancellable(command, 64, &mut || false)
            .expect_err("unbounded helper output must fail closed");
        assert!(is_resource_exhausted(&error));
        assert_eq!(
            error.to_string(),
            ImpactChangedSetPreprocessingExhausted.to_string()
        );
        for forbidden in ["Bearer", "review-secret", "/Users/private"] {
            assert!(!error.to_string().contains(forbidden));
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "overflow supervision did not terminate promptly"
        );

        let pid = fs::read_to_string(&pid_path)?.trim().to_owned();
        let process_still_exists = Command::new("kill")
            .args(["-0", &pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        assert!(
            !process_still_exists,
            "overflow helper {pid} was not killed and reaped"
        );
        Ok(())
    }

    fn node(id: &str, kind: &str, path: Option<&str>) -> NodeRecord {
        let language = match kind {
            "package_instance" | "type" => "rust",
            "symbol" => "go",
            _ => "web",
        };
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("{kind}:{id}"),
            display_name: id.to_owned(),
            properties: path.map_or_else(
                || json!({"language": language}),
                |path| json!({"language": language, "path": path}),
            ),
        }
    }

    fn edge(id: &str, source: &str, target: &str, profile: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "depends_on".to_owned(),
            phase: "semantic".to_owned(),
            environment: "server".to_owned(),
            profile_id: profile.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"eq","key":"runtime","value":"server"}),
            generated: false,
        }
    }

    fn graph() -> GraphSnapshot {
        let edges = vec![
            edge("e-package-file", "package", "file", "prod"),
            edge("e-symbol-file", "symbol", "file", "prod"),
            edge("e-route-symbol", "route", "symbol", "prod"),
            edge("e-type-route", "type", "route", "prod"),
            edge("e-dev-file", "dev", "file", "dev"),
        ];
        let evidence = edges
            .iter()
            .enumerate()
            .map(|(ordinal, edge)| EvidenceRecord {
                owner_type: "edge".to_owned(),
                owner_id: edge.id.clone(),
                ordinal: ordinal as i64,
                kind: "semantic".to_owned(),
                extractor: "fixture".to_owned(),
                extractor_version: "1".to_owned(),
                path: match edge.id.as_str() {
                    "e-route-symbol" => "src/route.ts".to_owned(),
                    "e-type-route" => "src/type.ts".to_owned(),
                    _ => "src/new.ts".to_owned(),
                },
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
                detail: Some("fixture evidence".to_owned()),
                properties: json!({}),
            })
            .collect();
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: ".".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: String::new(),
                completed_at: None,
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
            },
            profiles: Vec::new(),
            nodes: vec![
                node("file", "file", Some("src/new.ts")),
                node("symbol", "symbol", None),
                node("route", "route", Some("src/route.ts")),
                node("package", "package_instance", None),
                node("type", "type", Some("src/type.ts")),
                node("dev", "symbol", None),
            ],
            sites: Vec::new(),
            edges,
            evidence,
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: Default::default(),
        }
    }

    fn rename_set() -> GitChangedSet {
        GitChangedSet {
            requested_ref: "main".to_owned(),
            resolved_ref: "a".repeat(40),
            merge_base: "a".repeat(40),
            head: "b".repeat(40),
            repository_prefix: String::new(),
            changes: vec![GitChange {
                status: "renamed".to_owned(),
                similarity: Some(100),
                old_path: Some("src/old.ts".to_owned()),
                new_path: Some("src/new.ts".to_owned()),
                sources: vec!["committed".to_owned()],
            }],
        }
    }

    fn hostile_changed_set_fixture() -> (GraphSnapshot, GitChangedSet, usize) {
        let node_count = 32_usize;
        let site_count = 8_usize;
        let edge_count = 8_usize;
        let source_count = 8_usize;
        let mut snapshot = graph();
        snapshot.nodes = (0..node_count)
            .map(|index| node(&format!("shared:{index:02}"), "file", Some("src/shared.rs")))
            .collect();
        snapshot.sites = (0..site_count)
            .map(|index| {
                serde_json::from_value(json!({
                    "id": format!("site:{index:02}"),
                    "source": format!("shared:{:02}", index % node_count),
                    "kind": "import",
                    "specifier": "fixture:dependency",
                    "resolution_status": "resolved",
                    "target_ids": [format!("shared:{:02}", (index + 1) % node_count)],
                    "profile_id": "fixture:profile",
                    "condition": {"op":"all","conditions":[]},
                    "precision": "exact"
                }))
                .expect("valid changed-set site")
            })
            .collect();
        snapshot.edges = (0..edge_count)
            .map(|index| {
                edge(
                    &format!("edge:{index:02}"),
                    &format!("shared:{:02}", index % node_count),
                    &format!("shared:{:02}", (index + 1) % node_count),
                    "fixture:profile",
                )
            })
            .collect();
        snapshot.evidence.clear();
        let changed_set = GitChangedSet {
            requested_ref: "main".to_owned(),
            resolved_ref: "a".repeat(40),
            merge_base: "a".repeat(40),
            head: "b".repeat(40),
            repository_prefix: String::new(),
            changes: vec![GitChange {
                status: "modified".to_owned(),
                similarity: None,
                old_path: Some("src/shared.rs".to_owned()),
                new_path: Some("src/shared.rs".to_owned()),
                sources: (0..source_count)
                    .map(|index| format!("source-{index}"))
                    .collect(),
            }],
        };
        let calculated_work = node_count * 2
            + site_count
            + edge_count
            + 1
            + node_count * 2 * 2
            + node_count
            + source_count;
        (snapshot, changed_set, calculated_work)
    }

    #[test]
    fn warm_query_cache_keys_are_snapshot_selector_and_filter_scoped() -> Result<()> {
        let filters = ImpactFilters::new(None, vec![], vec![], 20, 30)?;
        let first = impact_query_cache_key("snapshot:one", "path:src/new.ts", &filters);
        assert_eq!(
            first,
            impact_query_cache_key("snapshot:one", "path:src/new.ts", &filters)
        );
        assert_ne!(
            first,
            impact_query_cache_key("snapshot:two", "path:src/new.ts", &filters)
        );
        assert_ne!(
            first,
            impact_query_cache_key("snapshot:one", "path:src/other.ts", &filters)
        );
        assert_ne!(
            first,
            impact_query_cache_key(
                "snapshot:one",
                "path:src/new.ts",
                &ImpactFilters::new(Some(1), vec![], vec![], 20, 30)?,
            )
        );
        Ok(())
    }

    #[test]
    fn rename_maps_old_and_new_paths_to_one_correlated_identity() {
        let _guard = CHANGED_SET_TEST_LOCK.lock().expect("changed-set test lock");
        let mappings = map_changed_set(&graph(), &rename_set()).expect("changed paths map");
        assert!(mappings[0].old_node_ids.is_empty());
        assert_eq!(
            mappings[0].new_node_ids,
            ["dev", "file", "package", "symbol"]
        );
        assert_eq!(
            mappings[0].correlated_node_ids,
            ["dev", "file", "package", "symbol"]
        );
    }

    #[test]
    fn changed_set_preprocessing_is_exactly_bounded_and_cancellable_in_each_nested_loop() {
        let _guard = CHANGED_SET_TEST_LOCK.lock().expect("changed-set test lock");
        let (snapshot, changed_set, calculated_work) = hostile_changed_set_fixture();

        reset_changed_set_counters();
        let mappings =
            map_changed_set_with_limit(&snapshot, &changed_set, calculated_work, &mut || false)
                .expect("the exact calculated changed-set work bound must succeed");
        assert_eq!(
            CHANGED_SET_WORK_ITEMS.load(Ordering::Relaxed),
            calculated_work
        );
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].old_node_ids.len(), snapshot.nodes.len());
        assert_eq!(mappings[0].new_node_ids, mappings[0].old_node_ids);
        assert_eq!(
            mappings[0].correlated_node_ids, mappings[0].old_node_ids,
            "correlated IDs remain sorted and deduplicated"
        );
        assert_eq!(mappings[0].change.sources, changed_set.changes[0].sources);

        reset_changed_set_counters();
        let error =
            map_changed_set_with_limit(&snapshot, &changed_set, calculated_work - 1, &mut || false)
                .expect_err("one work item above the maximum must return no mapping");
        assert!(
            error
                .downcast_ref::<ImpactChangedSetPreprocessingExhausted>()
                .is_some()
        );
        assert_eq!(
            CHANGED_SET_WORK_ITEMS.load(Ordering::Relaxed),
            calculated_work - 1
        );

        for (counter, stage) in [
            (&PATH_NODE_INDEX_SITE_VISITS, "site index"),
            (&PATH_NODE_INDEX_EDGE_VISITS, "edge index"),
            (&CHANGED_NODE_ID_COPY_VISITS, "path node-ID copy"),
            (
                &CHANGED_CORRELATED_ID_MATERIALIZATION_VISITS,
                "correlated-ID materialization",
            ),
            (
                &CHANGED_SOURCE_MATERIALIZATION_VISITS,
                "source materialization",
            ),
        ] {
            reset_changed_set_counters();
            let result =
                map_changed_set_with_limit(&snapshot, &changed_set, calculated_work, &mut || {
                    counter.load(Ordering::Relaxed) >= 3
                });
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("cancellation inside {stage} must return no mapping"),
            };
            assert!(error.to_string().contains("cancelled"), "stage: {stage}");
            assert_eq!(counter.load(Ordering::Relaxed), 3, "stage: {stage}");
        }
    }

    #[test]
    fn reverse_impact_is_deterministic_filterable_and_has_paths() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("impact preprocessing test lock");
        let _changed_set_guard = CHANGED_SET_TEST_LOCK.lock().expect("changed-set test lock");
        let graph = graph();
        let condition = render_condition(&graph.edges[0].condition);
        let filters = ImpactFilters::new(
            None,
            vec!["prod".to_owned(), "prod".to_owned()],
            vec![condition.clone(), condition.clone()],
            20,
            20,
        )?;
        assert_eq!(filters.profiles, ["prod"]);
        assert_eq!(filters.conditions, [condition.as_str()]);
        let first = impact(&graph, "path:src/new.ts", Some(&rename_set()), filters)?;
        let second = impact(
            &graph,
            "path:src/new.ts",
            Some(&rename_set()),
            ImpactFilters::new(None, vec!["prod".to_owned()], vec![condition], 20, 20)?,
        )?;
        let cached: ImpactResult = serde_json::from_value(serde_json::to_value(&first)?)?;
        assert_eq!(cached, first);
        assert!(first.root_impacted);
        assert!(first.complete);
        assert_eq!(
            first
                .impacts
                .iter()
                .map(|impact| impact.node.id.as_str())
                .collect::<Vec<_>>(),
            ["file", "package", "route", "symbol", "type"]
        );
        assert_eq!(
            first
                .impacts
                .iter()
                .filter_map(|impact| impact.node.properties["language"].as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["go", "rust", "web"])
        );
        let route = first
            .impacts
            .iter()
            .find(|impact| impact.node.id == "route")
            .unwrap();
        assert_eq!(route.depth, 2);
        assert_eq!(route.dependency_path.len(), 2);
        assert_eq!(route.dependency_path[0].edge.id, "e-route-symbol");
        assert_eq!(route.dependency_path[0].evidence[0].path, "src/route.ts");
        assert!(!route.dependency_path[0].condition_text.is_empty());
        let type_impact = first
            .impacts
            .iter()
            .find(|impact| impact.node.id == "type")
            .unwrap();
        assert_eq!(type_impact.depth, 3);
        assert_eq!(type_impact.dependency_path.len(), 3);
        assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);

        let excluded = impact(
            &graph,
            "path:src/new.ts",
            Some(&rename_set()),
            ImpactFilters::new(
                None,
                vec!["prod".to_owned()],
                vec!["runtime == client".to_owned()],
                20,
                20,
            )?,
        )?;
        assert_eq!(
            excluded
                .impacts
                .iter()
                .map(|impact| impact.node.id.as_str())
                .collect::<Vec<_>>(),
            ["file"]
        );
        Ok(())
    }

    #[test]
    fn high_fanout_adjacency_is_ordered_once_tightly_bounded_and_cancellable() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("impact preprocessing test lock");
        let edge_count = 256_usize;
        let mut graph = graph();
        graph.edges = (0..edge_count)
            .rev()
            .map(|index| {
                edge(
                    &format!("edge:{:04}", edge_count - index),
                    "fanout:root",
                    &format!("fanout:{index:04}"),
                    "fixture:profile",
                )
            })
            .collect();
        graph.evidence.clear();
        let filters = ImpactFilters::new(None, Vec::new(), Vec::new(), edge_count + 1, edge_count)?;
        let exact_work = edge_count * 3;
        let reset = || {
            for counter in [
                &IMPACT_ADJACENCY_WORK_ITEMS,
                &IMPACT_ADJACENCY_EDGE_SCANS,
                &IMPACT_ADJACENCY_INSERT_VISITS,
                &IMPACT_ADJACENCY_MATERIALIZATION_VISITS,
            ] {
                counter.store(0, Ordering::Relaxed);
            }
        };

        reset();
        let adjacency =
            adjacency_with_limit(&graph, false, &filters, None, exact_work, &mut || false)?;
        let bucket = adjacency.get("fanout:root").expect("fanout bucket");
        assert_eq!(bucket.len(), edge_count);
        assert!(
            bucket
                .windows(2)
                .all(|pair| { (&pair[0].target, &pair[0].id) < (&pair[1].target, &pair[1].id) })
        );
        assert_eq!(
            IMPACT_ADJACENCY_WORK_ITEMS.load(Ordering::Relaxed),
            exact_work
        );
        assert_eq!(
            IMPACT_ADJACENCY_EDGE_SCANS.load(Ordering::Relaxed),
            edge_count
        );
        assert_eq!(
            IMPACT_ADJACENCY_INSERT_VISITS.load(Ordering::Relaxed),
            edge_count
        );
        assert_eq!(
            IMPACT_ADJACENCY_MATERIALIZATION_VISITS.load(Ordering::Relaxed),
            edge_count
        );

        reset();
        let error =
            adjacency_with_limit(&graph, false, &filters, None, exact_work - 1, &mut || false)
                .expect_err("one adjacency work item above the bound returns no adjacency");
        assert!(
            error
                .downcast_ref::<ImpactAdjacencyPreprocessingExhausted>()
                .is_some()
        );

        for (counter, stage) in [
            (&IMPACT_ADJACENCY_INSERT_VISITS, "ordered insertion"),
            (
                &IMPACT_ADJACENCY_MATERIALIZATION_VISITS,
                "ordered materialization",
            ),
        ] {
            reset();
            let result =
                adjacency_with_limit(&graph, false, &filters, None, exact_work, &mut || {
                    counter.load(Ordering::Relaxed) >= 3
                });
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("cancellation inside {stage} must return no adjacency"),
            };
            assert_eq!(error.to_string(), "graph operation was cancelled");
            assert_eq!(counter.load(Ordering::Relaxed), 3, "stage: {stage}");
            if stage == "ordered materialization" {
                assert_eq!(
                    IMPACT_ADJACENCY_EDGE_SCANS.load(Ordering::Relaxed),
                    edge_count,
                    "ordered materialization must not rescan edges"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn runtime_environment_filter_excludes_static_edges_with_the_same_label() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("runtime index test lock");
        let mut graph = graph();
        let filters = ImpactFilters::new(None, Vec::new(), Vec::new(), 20, 20)?
            .with_runtime_filters(Vec::new(), Vec::new(), vec!["server".to_owned()])?;
        let runtime_contexts = runtime_context_index_cancellable(&graph, &filters, &mut || false)?;
        assert!(
            graph
                .edges
                .iter()
                .all(|edge| !filters.matches(edge, runtime_contexts.as_ref()))
        );

        graph.edges[0].phase = "runtime".to_owned();
        graph.evidence.push(EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: graph.edges[0].id.clone(),
            ordinal: graph.evidence.len() as i64,
            kind: "runtime".to_owned(),
            extractor: "runtime-trace".to_owned(),
            extractor_version: "1.0".to_owned(),
            path: String::new(),
            start_line: 1,
            start_column: 1,
            end_line: 1,
            end_column: 1,
            detail: None,
            properties: json!({
                "session_id":"runtime-session",
                "source_session_id":"collector-session",
                "environment":{"name":"server"}
            }),
        });
        let runtime_contexts = runtime_context_index_cancellable(&graph, &filters, &mut || false)?;
        assert!(filters.matches(&graph.edges[0], runtime_contexts.as_ref()));
        Ok(())
    }

    #[test]
    fn runtime_context_index_is_single_pass_bounded_and_cancellable() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("runtime index test lock");
        let mut graph = graph();
        graph.edges[0].phase = "runtime".to_owned();
        graph.evidence = (0..128)
            .map(|ordinal| EvidenceRecord {
                owner_type: "edge".to_owned(),
                owner_id: graph.edges[0].id.clone(),
                ordinal,
                kind: "runtime".to_owned(),
                extractor: "runtime-trace".to_owned(),
                extractor_version: "1.0".to_owned(),
                path: String::new(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1,
                detail: None,
                properties: json!({
                    "session_id": format!("session-{}", ordinal % 4),
                    "source_session_id": format!("source-{}", ordinal % 3),
                    "environment": {
                        "name": format!("environment-{}", ordinal % 2),
                        "runtime": "node",
                        "region": "test-region"
                    },
                    "count": 1,
                    "first_observed_at": format!("2026-01-01T00:00:{:02}Z", ordinal % 60),
                    "last_observed_at": format!("2026-01-01T00:01:{:02}Z", ordinal % 60)
                }),
            })
            .collect();
        let filters = ImpactFilters::new(None, Vec::new(), Vec::new(), 128, 1)?
            .with_runtime_filters(
                Vec::new(),
                vec!["session-1".to_owned()],
                vec!["environment-1".to_owned()],
            )?;

        RUNTIME_CONTEXT_INDEX_BUILDS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_EVIDENCE_VISITS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_WORK_ITEMS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.store(0, Ordering::Relaxed);
        let contexts = runtime_context_index_with_limit(&graph, &filters, 10_000, &mut || false)?
            .expect("runtime filters build an index");
        let required_work = RUNTIME_CONTEXT_WORK_ITEMS.load(Ordering::Relaxed);
        assert!(required_work > graph.evidence.len());
        assert_eq!(RUNTIME_CONTEXT_INDEX_BUILDS.load(Ordering::Relaxed), 1);
        assert_eq!(
            RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed),
            128,
            "the evidence input must be scanned exactly once"
        );
        assert_eq!(
            contexts[&graph.edges[0].id],
            depgraph_store::runtime_context_for_edge(&graph, &graph.edges[0]),
            "the indexed context must preserve the store helper semantics"
        );
        for _ in 0..1_000 {
            for edge in &graph.edges {
                let _ = filters.matches(edge, Some(&contexts));
            }
        }
        assert_eq!(
            RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed),
            128,
            "edge matching must not rescan evidence"
        );

        RUNTIME_CONTEXT_WORK_ITEMS.store(0, Ordering::Relaxed);
        runtime_context_index_with_limit(&graph, &filters, required_work, &mut || false)?
            .expect("the exact runtime-context work bound must be accepted");
        assert_eq!(
            RUNTIME_CONTEXT_WORK_ITEMS.load(Ordering::Relaxed),
            required_work
        );
        let over_limit =
            runtime_context_index_with_limit(&graph, &filters, required_work - 1, &mut || false)
                .expect_err("one work item above the hard bound must fail closed");
        assert!(
            over_limit
                .downcast_ref::<ImpactRuntimeContextIndexExhausted>()
                .is_some()
        );

        RUNTIME_CONTEXT_EVIDENCE_VISITS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.store(0, Ordering::Relaxed);
        let cancelled = runtime_context_index_with_limit(&graph, &filters, 10_000, &mut || {
            RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed) >= 3
        })
        .expect_err("cancellation inside the evidence scan must fail closed");
        assert_eq!(cancelled.to_string(), "graph operation was cancelled");
        assert_eq!(RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed), 3);

        RUNTIME_CONTEXT_EVIDENCE_VISITS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.store(0, Ordering::Relaxed);
        let cancelled = runtime_context_index_with_limit(&graph, &filters, 10_000, &mut || {
            RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.load(Ordering::Relaxed) >= 1
        })
        .expect_err("cancellation inside set materialization must fail closed");
        assert_eq!(cancelled.to_string(), "graph operation was cancelled");
        assert_eq!(RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed), 128);
        assert_eq!(
            RUNTIME_CONTEXT_OUTPUT_VALUE_VISITS.load(Ordering::Relaxed),
            1
        );

        RUNTIME_CONTEXT_INDEX_BUILDS.store(0, Ordering::Relaxed);
        RUNTIME_CONTEXT_EVIDENCE_VISITS.store(0, Ordering::Relaxed);
        let no_runtime_filters = ImpactFilters::new(None, Vec::new(), Vec::new(), 128, 1)?;
        assert!(
            runtime_context_index_cancellable(&graph, &no_runtime_filters, &mut || false)?
                .is_none()
        );
        assert_eq!(RUNTIME_CONTEXT_INDEX_BUILDS.load(Ordering::Relaxed), 0);
        assert_eq!(RUNTIME_CONTEXT_EVIDENCE_VISITS.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn runtime_impact_path_evidence_respects_the_session_filter() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("runtime index test lock");
        let mut graph = graph();
        let edge = graph
            .edges
            .iter_mut()
            .find(|edge| edge.id == "e-symbol-file")
            .context("fixture edge")?;
        edge.phase = "runtime".to_owned();
        for (ordinal, session) in ["session-a", "session-b"].into_iter().enumerate() {
            graph.evidence.push(EvidenceRecord {
                owner_type: "edge".to_owned(),
                owner_id: edge.id.clone(),
                ordinal: graph.evidence.len() as i64 + ordinal as i64,
                kind: "runtime".to_owned(),
                extractor: "runtime-trace".to_owned(),
                extractor_version: "1.0".to_owned(),
                path: String::new(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 1,
                detail: None,
                properties: json!({
                    "session_id":format!("runtime-{session}"),
                    "source_session_id":session,
                    "environment":{"name":"server"}
                }),
            });
        }
        let filters = ImpactFilters::new(None, Vec::new(), Vec::new(), 20, 20)?
            .with_runtime_filters(
                vec!["runtime".to_owned()],
                vec!["session-a".to_owned()],
                vec!["server".to_owned()],
            )?;
        let result = impact(&graph, "id:file", None, filters)?;
        let symbol = result
            .impacts
            .iter()
            .find(|impact| impact.node.id == "symbol")
            .context("runtime impact")?;
        assert_eq!(symbol.dependency_path.len(), 1);
        assert_eq!(symbol.dependency_path[0].evidence.len(), 1);
        assert_eq!(
            symbol.dependency_path[0].evidence[0].properties["source_session_id"],
            json!("session-a")
        );
        Ok(())
    }

    #[test]
    fn depth_and_limits_are_explicit_not_silent() -> Result<()> {
        let _guard = IMPACT_PREPROCESSING_TEST_LOCK
            .lock()
            .expect("impact preprocessing test lock");
        let _changed_set_guard = CHANGED_SET_TEST_LOCK.lock().expect("changed-set test lock");
        let graph = graph();
        let shallow = impact(
            &graph,
            "path:src/new.ts",
            Some(&rename_set()),
            ImpactFilters::new(Some(1), vec!["prod".to_owned()], Vec::new(), 20, 20)?,
        )?;
        assert_eq!(
            shallow
                .impacts
                .iter()
                .map(|impact| impact.node.id.as_str())
                .collect::<Vec<_>>(),
            ["file", "package", "symbol"]
        );
        let bounded = impact(
            &graph,
            "path:src/new.ts",
            Some(&rename_set()),
            ImpactFilters::new(None, vec!["prod".to_owned()], Vec::new(), 2, 20)?,
        )?;
        assert!(!bounded.complete);
        assert!(
            bounded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "impact_node_limit_reached")
        );
        let edge_bounded = impact(
            &graph,
            "path:src/new.ts",
            Some(&rename_set()),
            ImpactFilters::new(None, vec!["prod".to_owned()], Vec::new(), 20, 1)?,
        )?;
        assert!(!edge_bounded.complete);
        assert!(
            edge_bounded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "impact_edge_limit_reached")
        );

        let mut ambiguous = graph;
        ambiguous.nodes[1].display_name = "duplicate".to_owned();
        ambiguous.nodes[2].display_name = "duplicate".to_owned();
        let error = impact(
            &ambiguous,
            "duplicate",
            None,
            ImpactFilters::new(None, Vec::new(), Vec::new(), 20, 20)?,
        )
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
        Ok(())
    }
}
