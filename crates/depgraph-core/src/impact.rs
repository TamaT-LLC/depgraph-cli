use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Component, Path},
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};
use depgraph_store::{EdgeRecord, GraphSnapshot, NodeRecord, runtime_context_for_edge};
use serde::Serialize;

use crate::{
    query::{PathStep, path_steps_for_edges, render_condition, resolve_selector},
    worker::resolve_safe_executable,
};

const MAX_GIT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHANGED_PATHS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct GitChange {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitChangedSet {
    pub requested_ref: String,
    pub resolved_ref: String,
    pub merge_base: String,
    pub head: String,
    pub repository_prefix: String,
    pub changes: Vec<GitChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedNodeMapping {
    pub change: GitChange,
    pub old_node_ids: Vec<String>,
    pub new_node_ids: Vec<String>,
    pub correlated_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactFilters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    pub profiles: Vec<String>,
    pub conditions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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

    fn matches(&self, snapshot: &GraphSnapshot, edge: &EdgeRecord) -> bool {
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
        let context = runtime_context_for_edge(snapshot, edge);
        let session_matches = self.sessions.is_empty()
            || context
                .session_ids
                .iter()
                .chain(context.source_session_ids.iter())
                .any(|value| self.sessions.binary_search(value).is_ok());
        let environment_matches = self.environments.is_empty()
            || std::iter::once(&edge.environment)
                .chain(context.environment_names.iter())
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactDiagnostic {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImpactNode {
    pub node: NodeRecord,
    pub depth: usize,
    pub changed_node_id: String,
    pub dependency_path: Vec<PathStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImpactResult {
    pub root: NodeRecord,
    pub root_impacted: bool,
    pub complete: bool,
    pub filters: ImpactFilters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_set: Option<GitChangedSet>,
    pub mappings: Vec<ChangedNodeMapping>,
    pub changed_nodes: Vec<NodeRecord>,
    pub impacts: Vec<ImpactNode>,
    pub diagnostics: Vec<ImpactDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GitChangeKey {
    status: String,
    similarity: Option<u8>,
    old_path: Option<String>,
    new_path: Option<String>,
}

pub fn read_git_changed_set(root: &Path, requested_ref: &str) -> Result<GitChangedSet> {
    validate_git_ref(requested_ref)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("scan root {} is unavailable", root.display()))?;
    let git = resolve_safe_executable("git", &root)?;
    let prefix = git_text(&git, &root, ["rev-parse", "--show-prefix"])?;
    let prefix = normalize_repository_prefix(&prefix)?;
    let repository_root = git_text(&git, &root, ["rev-parse", "--show-toplevel"])?;
    let repository_root = Path::new(&repository_root)
        .canonicalize()
        .context("Git repository root is unavailable")?;
    if !root.starts_with(&repository_root) {
        bail!("security policy violation: Git repository root does not contain the scan root");
    }
    let head = resolve_commit(&git, &repository_root, "HEAD")?;
    let resolved_ref = resolve_commit(&git, &repository_root, requested_ref)?;
    let merge_base = git_text(&git, &repository_root, ["merge-base", &resolved_ref, &head])?;
    validate_object_id("merge base", &merge_base)?;

    let committed = git_bytes(
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
    )?;
    let worktree = git_bytes(
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
    )?;
    let untracked = git_bytes(
        &git,
        &repository_root,
        ["ls-files", "--others", "--exclude-standard", "-z"],
    )?;

    let mut changes = BTreeMap::<GitChangeKey, BTreeSet<String>>::new();
    for change in parse_name_status(&committed, "committed", &prefix)? {
        insert_change(&mut changes, change);
    }
    for change in parse_name_status(&worktree, "worktree", &prefix)? {
        insert_change(&mut changes, change);
    }
    for path in parse_nul_paths(&untracked, &prefix)? {
        insert_change(
            &mut changes,
            GitChange {
                status: "untracked".to_owned(),
                similarity: None,
                old_path: None,
                new_path: Some(path),
                sources: vec!["worktree".to_owned()],
            },
        );
    }
    if changes.len() > MAX_CHANGED_PATHS {
        bail!(
            "Git changed set contains more than {MAX_CHANGED_PATHS} paths; narrow the repository scope"
        );
    }

    Ok(GitChangedSet {
        requested_ref: requested_ref.to_owned(),
        resolved_ref,
        merge_base: merge_base.to_ascii_lowercase(),
        head,
        repository_prefix: prefix,
        changes: changes
            .into_iter()
            .map(|(key, sources)| GitChange {
                status: key.status,
                similarity: key.similarity,
                old_path: key.old_path,
                new_path: key.new_path,
                sources: sources.into_iter().collect(),
            })
            .collect(),
    })
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

fn resolve_commit(git: &Path, root: &Path, value: &str) -> Result<String> {
    let revision = format!("{value}^{{commit}}");
    let resolved = git_text(
        git,
        root,
        ["rev-parse", "--verify", "--end-of-options", &revision],
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

fn git_text<'a>(
    git: &Path,
    root: &Path,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<String> {
    let bytes = git_bytes(git, root, args)?;
    let value = String::from_utf8(bytes).context("Git returned non-UTF-8 metadata")?;
    Ok(value.trim().to_owned())
}

fn git_bytes<'a>(
    git: &Path,
    root: &Path,
    args: impl IntoIterator<Item = &'a str>,
) -> Result<Vec<u8>> {
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
        .stdin(Stdio::null());
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
    let output = command
        .output()
        .context("failed to run read-only Git query")?;
    if output.stdout.len() > MAX_GIT_OUTPUT_BYTES || output.stderr.len() > MAX_GIT_OUTPUT_BYTES {
        bail!("Git changed-set output exceeded the bounded output limit");
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("read-only Git query failed: {}", stderr.trim());
    }
    Ok(output.stdout)
}

fn normalize_repository_prefix(value: &str) -> Result<String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let value = value.trim_end_matches('/');
    let value = normalize_git_path(value)?;
    Ok(format!("{value}/"))
}

fn parse_name_status(bytes: &[u8], source: &str, prefix: &str) -> Result<Vec<GitChange>> {
    let fields = nul_fields(bytes);
    let mut changes = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let token = parse_utf8_field(fields[index], "Git status")?;
        index += 1;
        let (status, similarity, paths) = parse_status(&token)?;
        if index + paths > fields.len() {
            bail!("Git name-status output ended before its path fields");
        }
        let first = parse_utf8_field(fields[index], "Git path")?;
        index += 1;
        let second = if paths == 2 {
            let path = parse_utf8_field(fields[index], "Git path")?;
            index += 1;
            Some(path)
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
        changes.push(GitChange {
            status,
            similarity,
            old_path,
            new_path,
            sources: vec![source.to_owned()],
        });
    }
    Ok(changes)
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

fn parse_nul_paths(bytes: &[u8], prefix: &str) -> Result<Vec<String>> {
    nul_fields(bytes)
        .into_iter()
        .map(|field| parse_utf8_field(field, "Git path"))
        .filter_map(|path| match path {
            Ok(path) => strip_repository_prefix(&path, prefix).transpose(),
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn nul_fields(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect()
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

fn insert_change(changes: &mut BTreeMap<GitChangeKey, BTreeSet<String>>, change: GitChange) {
    let key = GitChangeKey {
        status: change.status,
        similarity: change.similarity,
        old_path: change.old_path,
        new_path: change.new_path,
    };
    changes.entry(key).or_default().extend(change.sources);
}

pub fn map_changed_set(
    snapshot: &GraphSnapshot,
    changed_set: &GitChangedSet,
) -> Vec<ChangedNodeMapping> {
    let index = path_node_index(snapshot);
    changed_set
        .changes
        .iter()
        .map(|change| {
            let old_node_ids: Vec<String> = change
                .old_path
                .as_deref()
                .and_then(|path| index.get(path))
                .map(|ids| ids.iter().cloned().collect())
                .unwrap_or_default();
            let new_node_ids: Vec<String> = change
                .new_path
                .as_deref()
                .and_then(|path| index.get(path))
                .map(|ids| ids.iter().cloned().collect())
                .unwrap_or_default();
            let correlated_node_ids = old_node_ids
                .iter()
                .chain(&new_node_ids)
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            ChangedNodeMapping {
                change: change.clone(),
                old_node_ids,
                new_node_ids,
                correlated_node_ids,
            }
        })
        .collect()
}

fn path_node_index(snapshot: &GraphSnapshot) -> BTreeMap<String, BTreeSet<String>> {
    let mut index = BTreeMap::<String, BTreeSet<String>>::new();
    for node in &snapshot.nodes {
        for key in ["path", "source_path", "manifest_path", "relative_path"] {
            if let Some(path) = node.properties.get(key).and_then(serde_json::Value::as_str) {
                index_node_path(&mut index, path, &node.id);
            }
        }
        if let Some(identity) = node.properties.get("canonical_identity") {
            for key in ["path", "source_path", "relative_path"] {
                if let Some(path) = identity.get(key).and_then(serde_json::Value::as_str) {
                    index_node_path(&mut index, path, &node.id);
                }
            }
        }
    }

    let sites: BTreeMap<_, _> = snapshot
        .sites
        .iter()
        .map(|site| (site.id.as_str(), site))
        .collect();
    let edges: BTreeMap<_, _> = snapshot
        .edges
        .iter()
        .map(|edge| (edge.id.as_str(), edge))
        .collect();
    for evidence in &snapshot.evidence {
        match evidence.owner_type.as_str() {
            "node" => index_node_path(&mut index, &evidence.path, &evidence.owner_id),
            "site" => {
                if let Some(site) = sites.get(evidence.owner_id.as_str()) {
                    index_node_path(&mut index, &evidence.path, &site.source);
                }
            }
            "edge" => {
                if let Some(edge) = edges.get(evidence.owner_id.as_str()) {
                    index_node_path(&mut index, &evidence.path, &edge.source);
                    if matches!(
                        edge.kind.as_str(),
                        "declares" | "contains" | "defines" | "routes" | "instantiates"
                    ) {
                        index_node_path(&mut index, &evidence.path, &edge.target);
                    }
                }
            }
            _ => {}
        }
    }
    index
}

fn index_node_path(index: &mut BTreeMap<String, BTreeSet<String>>, path: &str, node_id: &str) {
    if let Ok(path) = normalize_git_path(path) {
        index.entry(path).or_default().insert(node_id.to_owned());
    }
}

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
    let root = resolve_selector(snapshot, selector)?;
    let node_map: BTreeMap<_, _> = snapshot
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node.clone()))
        .collect();
    let edge_map: BTreeMap<_, _> = snapshot
        .edges
        .iter()
        .map(|edge| (edge.id.clone(), edge))
        .collect();
    let mappings = changed_set
        .map(|set| map_changed_set(snapshot, set))
        .unwrap_or_default();
    let changed_ids = if changed_set.is_some() {
        mappings
            .iter()
            .flat_map(|mapping| mapping.correlated_node_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::from([root.id.clone()])
    };
    let changed_nodes = changed_ids
        .iter()
        .filter_map(|id| node_map.get(id).cloned())
        .collect();
    let mut budget = TraversalBudget::new(&root.id);
    let forward = adjacency(snapshot, false, &filters);
    let reverse = adjacency(snapshot, true, &filters);

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
        )
    };
    let root_impacted = root_path.is_some();
    let mut impacts = Vec::new();
    if let Some(root_path) = root_path {
        let changed_node_id = root_path
            .last()
            .map(|edge: &EdgeRecord| edge.target.clone())
            .unwrap_or_else(|| root.id.clone());
        let scoped = reverse_paths(&root.id, &reverse, &edge_map, &filters, &mut budget);
        for (node_id, (depth, prefix)) in scoped {
            let Some(node) = node_map.get(&node_id).cloned() else {
                continue;
            };
            let mut path = prefix;
            path.extend(root_path.clone());
            impacts.push(ImpactNode {
                node,
                depth,
                changed_node_id: changed_node_id.clone(),
                dependency_path: path_steps_for_edges(snapshot, &path),
            });
        }
        impacts.sort_by(|left, right| left.node.id.cmp(&right.node.id));
    }

    let mut diagnostics: Vec<_> = budget.diagnostics.into_values().collect();
    if changed_set.is_some() {
        for mapping in &mappings {
            if mapping.correlated_node_ids.is_empty() {
                diagnostics.push(ImpactDiagnostic {
                    code: "changed_path_unmapped".to_owned(),
                    message: format!(
                        "changed path {} was not present in the selected snapshot",
                        mapping
                            .change
                            .new_path
                            .as_deref()
                            .or(mapping.change.old_path.as_deref())
                            .unwrap_or("unknown")
                    ),
                });
            }
        }
    }
    diagnostics.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then(left.message.cmp(&right.message))
    });
    diagnostics.dedup_by(|left, right| left.code == right.code && left.message == right.message);

    Ok(ImpactResult {
        root,
        root_impacted,
        complete: budget.complete,
        filters,
        changed_set: changed_set.cloned(),
        mappings,
        changed_nodes,
        impacts,
        diagnostics,
    })
}

fn adjacency<'a>(
    snapshot: &'a GraphSnapshot,
    reverse: bool,
    filters: &ImpactFilters,
) -> BTreeMap<String, Vec<&'a EdgeRecord>> {
    let mut adjacency = BTreeMap::<String, Vec<&EdgeRecord>>::new();
    for edge in snapshot
        .edges
        .iter()
        .filter(|edge| filters.matches(snapshot, edge))
    {
        let key = if reverse { &edge.target } else { &edge.source };
        adjacency.entry(key.clone()).or_default().push(edge);
    }
    for edges in adjacency.values_mut() {
        edges.sort_by(|left, right| {
            let left_next = if reverse { &left.source } else { &left.target };
            let right_next = if reverse {
                &right.source
            } else {
                &right.target
            };
            left_next.cmp(right_next).then(left.id.cmp(&right.id))
        });
    }
    adjacency
}

fn shortest_path_to_changed(
    root_id: &str,
    changed_ids: &BTreeSet<String>,
    adjacency: &BTreeMap<String, Vec<&EdgeRecord>>,
    edge_map: &BTreeMap<String, &EdgeRecord>,
    filters: &ImpactFilters,
    budget: &mut TraversalBudget,
) -> Option<Vec<EdgeRecord>> {
    if changed_ids.is_empty() {
        return None;
    }
    let mut queue = VecDeque::from([root_id.to_owned()]);
    let mut seen = BTreeSet::from([root_id.to_owned()]);
    let mut predecessor = BTreeMap::<String, String>::new();
    let mut found = None;
    'search: while let Some(node_id) = queue.pop_front() {
        for edge in adjacency.get(&node_id).into_iter().flatten() {
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
    let mut current = found?;
    let mut reversed = Vec::new();
    while current != root_id {
        let edge_id = predecessor.get(&current)?;
        let edge = *edge_map.get(edge_id)?;
        reversed.push(edge.clone());
        current = edge.source.clone();
    }
    reversed.reverse();
    Some(reversed)
}

fn reverse_paths(
    root_id: &str,
    adjacency: &BTreeMap<String, Vec<&EdgeRecord>>,
    edge_map: &BTreeMap<String, &EdgeRecord>,
    filters: &ImpactFilters,
    budget: &mut TraversalBudget,
) -> BTreeMap<String, (usize, Vec<EdgeRecord>)> {
    let mut queue = VecDeque::from([(root_id.to_owned(), 0_usize)]);
    let mut seen = BTreeSet::from([root_id.to_owned()]);
    let mut successor = BTreeMap::<String, String>::new();
    let mut depths = BTreeMap::from([(root_id.to_owned(), 0_usize)]);
    'search: while let Some((node_id, depth)) = queue.pop_front() {
        if filters.depth.is_some_and(|limit| depth >= limit) {
            continue;
        }
        for edge in adjacency.get(&node_id).into_iter().flatten() {
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

    let mut paths = BTreeMap::new();
    for (node_id, depth) in depths {
        let mut current = node_id.clone();
        let mut edges = Vec::new();
        while current != root_id {
            let Some(edge_id) = successor.get(&current) else {
                break;
            };
            let Some(edge) = edge_map.get(edge_id).copied() else {
                break;
            };
            edges.push(edge.clone());
            current = edge.target.clone();
        }
        paths.insert(node_id, (depth, edges));
    }
    paths
}

#[cfg(test)]
mod tests {
    use std::fs;

    use depgraph_store::{
        CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, NodeRecord, ScanRecord,
    };
    use serde_json::json;

    use super::*;

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

    #[test]
    fn rename_maps_old_and_new_paths_to_one_correlated_identity() {
        let mappings = map_changed_set(&graph(), &rename_set());
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
    fn reverse_impact_is_deterministic_filterable_and_has_paths() -> Result<()> {
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
    fn depth_and_limits_are_explicit_not_silent() -> Result<()> {
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
