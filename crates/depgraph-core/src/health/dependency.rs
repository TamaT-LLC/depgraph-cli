use std::collections::{BTreeMap, BTreeSet};

use depgraph_store::{EdgeRecord, GraphSnapshot, NodeRecord, SiteRecord};
use serde_json::json;

use super::{
    BlockerKind, FindingBlocker, FindingEvidenceRef, FindingIdentity, FindingKind, HealthFinding,
    Remediation, SourceLocation, finding_fingerprint, finish_finding,
};
use super::{HealthAnalysisError, budget::HealthAnalysisBudget};

const MANIFEST_SITE_KINDS: &[&str] = &[
    "cargo_dependency",
    "module_requirement",
    "package_dependency",
    "package_peer_dependency",
    "package_optional_dependency",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestIdentity {
    pub path: String,
    pub digest: String,
    pub declared: BTreeSet<String>,
    pub drifted: bool,
}

pub(crate) fn manifest_paths_cancellable(
    snapshot: &GraphSnapshot,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<BTreeSet<String>, HealthAnalysisError> {
    let mut budget = HealthAnalysisBudget::new(maximum_work);
    let mut nodes = BTreeMap::new();
    let mut paths = BTreeSet::new();
    for node in &snapshot.nodes {
        budget.step(&mut is_cancelled)?;
        nodes.insert(node.id.as_str(), node);
        if let Some(path) = node
            .properties
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
        {
            paths.insert(path.to_owned());
        }
    }
    for site in &snapshot.sites {
        budget.step(&mut is_cancelled)?;
        if !MANIFEST_SITE_KINDS.contains(&site.kind.as_str()) {
            continue;
        }
        if let Some(source) = nodes.get(site.source.as_str()) {
            paths.insert(manifest_path_for(source, &site.kind));
        }
    }
    Ok(paths)
}

#[must_use]
pub fn analyze_dependencies(
    snapshot: &GraphSnapshot,
    manifests: &[ManifestIdentity],
) -> Vec<HealthFinding> {
    analyze_dependencies_cancellable(snapshot, manifests, usize::MAX, usize::MAX, || false)
        .expect("unbounded, non-cancellable dependency analysis cannot fail")
}

pub fn analyze_dependencies_cancellable(
    snapshot: &GraphSnapshot,
    manifests: &[ManifestIdentity],
    maximum_findings: usize,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HealthAnalysisError> {
    let mut budget = HealthAnalysisBudget::new(maximum_work);
    let mut findings = Vec::new();
    let mut finding_ids = BTreeSet::new();
    let mut nodes = BTreeMap::<&str, &NodeRecord>::new();
    for node in &snapshot.nodes {
        budget.step(&mut is_cancelled)?;
        nodes.insert(node.id.as_str(), node);
    }
    let mut profiles = BTreeMap::new();
    for profile in &snapshot.profiles {
        budget.step(&mut is_cancelled)?;
        profiles.insert(profile.id.as_str(), profile);
    }
    let mut manifests_by_path = BTreeMap::new();
    for manifest in manifests {
        budget.step(&mut is_cancelled)?;
        manifests_by_path.insert(manifest.path.as_str(), manifest);
    }
    let manifest_scopes = manifest_scope_index(snapshot, &nodes, &mut budget, &mut is_cancelled)?;
    let usage_targets = package_usage_targets(
        snapshot,
        &nodes,
        &manifest_scopes,
        &mut budget,
        &mut is_cancelled,
    )?;
    let mut graph_names_by_manifest = BTreeMap::<String, BTreeSet<String>>::new();
    for site in &snapshot.sites {
        budget.step(&mut is_cancelled)?;
        if !MANIFEST_SITE_KINDS.contains(&site.kind.as_str()) {
            continue;
        }
        let Some(specifier) = site.specifier.as_deref() else {
            continue;
        };
        let Some(source) = nodes.get(site.source.as_str()).copied() else {
            continue;
        };
        let manifest_path = manifest_path_for(source, &site.kind);
        graph_names_by_manifest
            .entry(manifest_path.clone())
            .or_default()
            .insert(specifier.to_owned());
        let matching_manifest = manifests_by_path.get(manifest_path.as_str()).copied();
        let drift = matching_manifest.is_none_or(|manifest| manifest.drifted);
        // A module requirement is only comparable to usage owners inside the
        // same repository-relative manifest scope. Keep the distinction
        // between a non-module site (which is intentionally unscoped) and a
        // module site whose manifest path is malformed: the latter must not
        // fall back to mixing owners from every manifest.
        let usage_scope =
            (site.kind == "module_requirement").then(|| canonical_manifest_scope(&manifest_path));
        let usage_scope_path = usage_scope.as_ref().and_then(|scope| scope.as_deref());
        let scope_enforced = site.kind == "module_requirement";
        let mut scope_uncertain = scope_enforced && usage_scope_path.is_none();
        let usage_paths = if site.kind == "module_requirement" {
            go_requirement_usage_paths(site, &nodes, &mut budget, &mut is_cancelled)?
        } else {
            vec![specifier.to_owned()]
        };
        let mut used_from_production = false;
        let mut used_from_test = false;
        for usage_path in usage_paths {
            if let Some(owners) = usage_targets.get(&usage_path) {
                collect_usage_owners(
                    owners,
                    usage_scope_path,
                    scope_enforced,
                    &mut scope_uncertain,
                    &mut used_from_production,
                    &mut used_from_test,
                    &mut budget,
                    &mut is_cancelled,
                )?;
            }
            if site.kind == "module_requirement" && !(used_from_production && used_from_test) {
                // Go manifests declare a module path while source imports may
                // point at any package below that module. The helper starts at
                // the slash-delimited prefix so this remains O(log n +
                // matching packages), and stops at the first key outside the
                // prefix. The slash boundary avoids treating a similarly named
                // module (for example foo/barista) as a use of foo/bar.
                for (_, owners) in go_module_usage_targets(&usage_targets, &usage_path) {
                    budget.step(&mut is_cancelled)?;
                    collect_usage_owners(
                        owners,
                        usage_scope_path,
                        scope_enforced,
                        &mut scope_uncertain,
                        &mut used_from_production,
                        &mut used_from_test,
                        &mut budget,
                        &mut is_cancelled,
                    )?;
                    if used_from_production && used_from_test {
                        break;
                    }
                }
            }
            if used_from_production && used_from_test {
                break;
            }
        }
        let production_declared = is_production_declaration(site);
        let profile_coverage = dependency_profile_coverage(
            profiles.get(site.profile_id.as_str()).copied(),
            &mut budget,
            &mut is_cancelled,
        )?;
        if !used_from_production && !used_from_test {
            push_finding(
                &mut findings,
                &mut finding_ids,
                maximum_findings,
                dependency_finding(
                    FindingKind::UnusedDependency,
                    source,
                    site,
                    specifier,
                    &manifest_path,
                    drift,
                    "declared dependency has no graph usage edges",
                    profile_coverage,
                    scope_uncertain,
                ),
            )?;
        } else if production_declared && used_from_test && !used_from_production {
            push_finding(
                &mut findings,
                &mut finding_ids,
                maximum_findings,
                dependency_finding(
                    FindingKind::TestOnlyDependency,
                    source,
                    site,
                    specifier,
                    &manifest_path,
                    drift,
                    "production dependency is only referenced from test code",
                    profile_coverage,
                    scope_uncertain,
                ),
            )?;
        }
        if let Some(manifest) = matching_manifest
            && !manifest.declared.contains(specifier)
        {
            push_finding(
                &mut findings,
                &mut finding_ids,
                maximum_findings,
                dependency_finding(
                    FindingKind::ManifestMismatch,
                    source,
                    site,
                    specifier,
                    &manifest_path,
                    true,
                    "graph dependency site is absent from the request-fixed manifest",
                    profile_coverage,
                    scope_uncertain,
                ),
            )?;
        }
    }
    for manifest in manifests {
        budget.step(&mut is_cancelled)?;
        let graph_names = graph_names_by_manifest.get(manifest.path.as_str());
        for declared in &manifest.declared {
            budget.step(&mut is_cancelled)?;
            if !graph_names.is_some_and(|names| names.contains(declared)) {
                push_finding(
                    &mut findings,
                    &mut finding_ids,
                    maximum_findings,
                    finish_finding(
                        FindingIdentity {
                            kind: FindingKind::ManifestMismatch,
                            subject_id: format!("manifest:{}:{declared}", manifest.path),
                            profile_scope: None,
                            witness_key: json!({
                                "dependency": declared,
                                "manifest": manifest.path
                            }),
                        },
                        "package_instance",
                        Some(SourceLocation {
                            path: manifest.path.clone(),
                            start_line: None,
                            start_column: None,
                            end_line: None,
                            end_column: None,
                        }),
                        format!(
                            "manifest {} declares {declared} but the snapshot has no matching site",
                            manifest.path
                        ),
                        vec![FindingBlocker {
                            kind: if manifest.drifted {
                                BlockerKind::ManifestDrift
                            } else {
                                BlockerKind::IncompleteCoverage
                            },
                            detail: format!("digest {}", manifest.digest),
                        }],
                        Vec::new(),
                        vec![Remediation {
                            kind: "manual-review".to_owned(),
                            detail: "rescan after aligning the live manifest and snapshot"
                                .to_owned(),
                        }],
                        Vec::new(),
                        false,
                        !manifest.drifted,
                    ),
                )?;
            }
        }
    }
    consolidate_findings(findings, &mut budget, &mut is_cancelled)
}

fn push_finding(
    findings: &mut Vec<HealthFinding>,
    finding_ids: &mut BTreeSet<String>,
    maximum_findings: usize,
    finding: HealthFinding,
) -> Result<(), HealthAnalysisError> {
    if !finding_ids.contains(&finding.id) && finding_ids.len() >= maximum_findings {
        return Err(HealthAnalysisError::ResourceExhausted);
    }
    finding_ids.insert(finding.id.clone());
    findings.push(finding);
    Ok(())
}

fn consolidate_findings(
    mut findings: Vec<HealthFinding>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HealthAnalysisError> {
    budget.step(is_cancelled)?;
    findings.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then(left.fingerprint.cmp(&right.fingerprint))
    });
    let mut consolidated = Vec::<HealthFinding>::with_capacity(findings.len());
    for finding in findings {
        budget.step(is_cancelled)?;
        let Some(existing) = consolidated.last_mut().filter(|item| item.id == finding.id) else {
            consolidated.push(finding);
            continue;
        };
        existing.confidence = existing.confidence.min(finding.confidence);
        existing.severity = existing.severity.max(finding.severity);
        if finding.reason < existing.reason {
            existing.reason = finding.reason;
        }
        existing.blockers.extend(finding.blockers);
        existing.evidence.extend(finding.evidence);
        existing.remediations.extend(finding.remediations);
        existing.suppressions.extend(finding.suppressions);
    }
    for finding in &mut consolidated {
        budget.step(is_cancelled)?;
        finding.blockers.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.detail.cmp(&right.detail))
        });
        finding.blockers.dedup();
        finding.evidence.sort_by(|left, right| {
            left.owner_type
                .cmp(&right.owner_type)
                .then(left.owner_id.cmp(&right.owner_id))
                .then(left.kind.cmp(&right.kind))
                .then(left.path.cmp(&right.path))
        });
        finding.evidence.dedup();
        finding.remediations.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.detail.cmp(&right.detail))
        });
        finding.remediations.dedup();
        finding.suppressions.sort_by(|left, right| {
            left.id
                .cmp(&right.id)
                .then(left.finding_id.cmp(&right.finding_id))
                .then(left.ticket.cmp(&right.ticket))
        });
        finding.suppressions.dedup();
        finding.fingerprint = finding_fingerprint(finding);
    }
    Ok(consolidated)
}

#[derive(Clone)]
struct UsageOwner {
    is_test: bool,
    manifest_scope: ManifestScope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ManifestScope {
    Unknown,
    Unambiguous(String),
    Ambiguous,
}

fn manifest_scope_index<'a>(
    snapshot: &'a GraphSnapshot,
    nodes: &BTreeMap<&'a str, &'a NodeRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<&'a str, ManifestScope>, HealthAnalysisError> {
    let mut parents = BTreeMap::<&'a str, Vec<&'a str>>::new();
    for edge in &snapshot.edges {
        budget.step(is_cancelled)?;
        // Usage edges can originate at a file, package, or semantic symbol.
        // Worker semantic declarations retain the owning package through a
        // `declares` chain, so include both structural parent relations when
        // deriving a repository-relative manifest scope.
        if !matches!(edge.kind.as_str(), "contains" | "declares")
            || !nodes.contains_key(edge.source.as_str())
            || !nodes.contains_key(edge.target.as_str())
        {
            continue;
        }
        parents
            .entry(edge.target.as_str())
            .or_default()
            .push(edge.source.as_str());
    }

    let mut scopes = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    struct ManifestScopeFrame<'a> {
        node_id: &'a str,
        next_parent: usize,
        parent_scopes: BTreeSet<String>,
        ambiguous: bool,
    }

    // Resolve the containment/declaration forest with an explicit stack. A
    // hostile graph can contain an arbitrarily deep semantic declaration chain;
    // recursive DFS would overflow the Rust stack before the health work budget
    // has a chance to stop it. Each frame keeps the same memoized, cycle-safe
    // semantics as the former recursive walk while making depth heap-bounded.
    for &root in nodes.keys() {
        budget.step(is_cancelled)?;
        if scopes.contains_key(root) {
            continue;
        }
        let Some(node) = nodes.get(root).copied() else {
            scopes.insert(root, ManifestScope::Unknown);
            continue;
        };
        if let Some(scope) = node
            .properties
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .and_then(canonical_manifest_scope)
        {
            scopes.insert(root, ManifestScope::Unambiguous(scope));
            continue;
        }
        if !visiting.insert(root) {
            continue;
        }

        let mut stack = vec![ManifestScopeFrame {
            node_id: root,
            next_parent: 0,
            parent_scopes: BTreeSet::new(),
            ambiguous: false,
        }];
        while !stack.is_empty() {
            let frame_index = stack.len() - 1;
            let next_parent = {
                let frame = &mut stack[frame_index];
                match parents.get(frame.node_id) {
                    Some(parent_ids) if frame.next_parent < parent_ids.len() => {
                        let parent_id = parent_ids[frame.next_parent];
                        frame.next_parent += 1;
                        Some(parent_id)
                    }
                    _ => None,
                }
            };

            let Some(parent_id) = next_parent else {
                let frame = stack.pop().expect("non-empty manifest scope stack");
                visiting.remove(frame.node_id);
                let scope = if frame.ambiguous || frame.parent_scopes.len() > 1 {
                    ManifestScope::Ambiguous
                } else if frame.parent_scopes.len() == 1 {
                    ManifestScope::Unambiguous(
                        frame
                            .parent_scopes
                            .into_iter()
                            .next()
                            .expect("one parent scope"),
                    )
                } else {
                    ManifestScope::Unknown
                };
                scopes.insert(frame.node_id, scope.clone());
                if let Some(parent_frame) = stack.last_mut() {
                    match scope {
                        ManifestScope::Unambiguous(scope) => {
                            parent_frame.parent_scopes.insert(scope);
                        }
                        ManifestScope::Ambiguous => parent_frame.ambiguous = true,
                        ManifestScope::Unknown => parent_frame.ambiguous = true,
                    }
                }
                continue;
            };

            // This is the iterative equivalent of entering a recursive child;
            // charge it before consulting the memo table so cancellation and
            // resource exhaustion remain observable at the same boundaries.
            budget.step(is_cancelled)?;
            if let Some(cached_scope) = scopes.get(parent_id) {
                match cached_scope {
                    ManifestScope::Unambiguous(scope) => {
                        stack[frame_index].parent_scopes.insert(scope.clone());
                    }
                    ManifestScope::Ambiguous | ManifestScope::Unknown => {
                        stack[frame_index].ambiguous = true;
                    }
                }
                continue;
            }
            let Some(parent) = nodes.get(parent_id).copied() else {
                scopes.insert(parent_id, ManifestScope::Unknown);
                stack[frame_index].ambiguous = true;
                continue;
            };
            if let Some(scope) = parent
                .properties
                .get("manifest_path")
                .and_then(serde_json::Value::as_str)
                .and_then(canonical_manifest_scope)
            {
                scopes.insert(parent_id, ManifestScope::Unambiguous(scope.clone()));
                stack[frame_index].parent_scopes.insert(scope);
                continue;
            }
            if visiting.insert(parent_id) {
                stack.push(ManifestScopeFrame {
                    node_id: parent_id,
                    next_parent: 0,
                    parent_scopes: BTreeSet::new(),
                    ambiguous: false,
                });
            } else {
                // Structural cycles make ownership indeterminate. Propagate
                // that state through every dependent frame so another parent
                // cannot accidentally make the result look unambiguous.
                stack[frame_index].ambiguous = true;
            }
        }
    }
    Ok(scopes)
}

fn package_usage_targets(
    snapshot: &GraphSnapshot,
    nodes: &BTreeMap<&str, &NodeRecord>,
    manifest_scopes: &BTreeMap<&str, ManifestScope>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Vec<UsageOwner>>, HealthAnalysisError> {
    let mut sites = BTreeMap::new();
    for site in &snapshot.sites {
        budget.step(is_cancelled)?;
        sites.insert(site.id.as_str(), site);
    }
    let mut usage = BTreeMap::<String, Vec<UsageOwner>>::new();
    for edge in &snapshot.edges {
        budget.step(is_cancelled)?;
        if matches!(
            edge.kind.as_str(),
            "depends_on" | "build_depends_on" | "contains" | "declares"
        ) {
            continue;
        }
        let Some(target) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        let Some(source) = nodes.get(edge.source.as_str()) else {
            continue;
        };
        let Some(package) = package_name(target) else {
            continue;
        };
        let owner = UsageOwner {
            is_test: is_test_node(source, edge),
            manifest_scope: manifest_scopes
                .get(edge.source.as_str())
                .cloned()
                .unwrap_or(ManifestScope::Unknown),
        };
        // A local Go replacement can resolve an import of the requested module
        // to a package whose declared module path is different. Retain the
        // import site's specifier as a usage key so the requirement is credited
        // only when the source actually imports its requested path; a direct
        // import of the replacement module must not hide an unused requirement.
        if is_go_node(target)
            && matches!(edge.kind.as_str(), "imports" | "side_effect_imports")
            && let Some(site_id) = edge.site_id.as_deref()
            && let Some(site) = sites.get(site_id)
            && matches!(site.kind.as_str(), "import" | "side_effect_import")
            && let Some(specifier) = site.specifier.as_deref()
            && is_go_module_path(specifier)
            && specifier != package.as_str()
        {
            usage
                .entry(specifier.to_owned())
                .or_default()
                .push(owner.clone());
        }
        usage.entry(package).or_default().push(owner);
    }
    Ok(usage)
}

#[allow(clippy::too_many_arguments)]
fn collect_usage_owners(
    owners: &[UsageOwner],
    manifest_scope: Option<&str>,
    scope_enforced: bool,
    scope_uncertain: &mut bool,
    used_from_production: &mut bool,
    used_from_test: &mut bool,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    for owner in owners {
        budget.step(is_cancelled)?;
        if scope_enforced {
            match (manifest_scope, &owner.manifest_scope) {
                (Some(expected), ManifestScope::Unambiguous(actual)) if actual == expected => {}
                (Some(_), ManifestScope::Unambiguous(_)) => continue,
                (Some(_), ManifestScope::Ambiguous | ManifestScope::Unknown) => {
                    *scope_uncertain = true;
                    continue;
                }
                (None, _) => {
                    *scope_uncertain = true;
                    continue;
                }
            }
        }
        if owner.is_test {
            *used_from_test = true;
        } else {
            *used_from_production = true;
        }
        if *used_from_production && *used_from_test {
            break;
        }
    }
    Ok(())
}

fn go_requirement_usage_paths(
    site: &SiteRecord,
    nodes: &BTreeMap<&str, &NodeRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<String>, HealthAnalysisError> {
    let mut paths = BTreeSet::new();
    if let Some(specifier) = site.specifier.as_deref() {
        paths.insert(specifier.to_owned());
    }
    for target_id in &site.target_ids {
        budget.step(is_cancelled)?;
        let Some(target) = nodes.get(target_id.as_str()).copied() else {
            continue;
        };
        // The requested path identifies the requirement declared by go.mod;
        // resolved module/package/replace paths describe the replacement and
        // must not make that requirement look used by themselves.
        let Some(path) = target
            .properties
            .get("requested_module_path")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if is_go_module_path(path) {
            paths.insert(path.to_owned());
        }
    }
    Ok(paths.into_iter().collect())
}

fn is_go_module_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('.')
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
}

fn is_go_node(node: &NodeRecord) -> bool {
    node.properties
        .get("language")
        .and_then(serde_json::Value::as_str)
        == Some("go")
        || node
            .properties
            .get("ecosystem")
            .and_then(serde_json::Value::as_str)
            == Some("go")
}

/// Return only package usage keys below a Go module path.
///
/// `BTreeMap::range` seeks to the first slash-delimited prefix in O(log n);
/// `take_while` then visits only matching subpackages, preserving the
/// analyzer's bounded work accounting.
fn go_module_usage_targets<'a>(
    usage_targets: &'a BTreeMap<String, Vec<UsageOwner>>,
    module_path: &str,
) -> impl Iterator<Item = (&'a String, &'a Vec<UsageOwner>)> {
    let prefix = format!("{module_path}/");
    usage_targets
        .range(prefix.clone()..)
        .take_while(move |(used_package, _)| used_package.starts_with(&prefix))
}

fn is_test_node(node: &NodeRecord, edge: &EdgeRecord) -> bool {
    let path = node
        .properties
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    path.contains("/tests/")
        || path.starts_with("tests/")
        || path.contains("_test.")
        || path.ends_with("_test.go")
        || path.contains(".test.")
        || path.contains(".spec.")
        || edge.environment == "test"
        || node
            .properties
            .get("test")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        || node
            .properties
            .get("target_kind")
            .and_then(|value| value.as_str())
            == Some("test")
}

fn is_production_declaration(site: &SiteRecord) -> bool {
    !matches!(site.kind.as_str(), "package_peer_dependency")
        && site.condition.get("dev").and_then(|value| value.as_bool()) != Some(true)
        && site.condition.get("kind").and_then(|value| value.as_str()) != Some("dev")
}

fn package_name(node: &NodeRecord) -> Option<String> {
    if is_go_node(node) {
        // Go package declarations use a short package_name (for example
        // "http"), while go.mod requirements and import usage are keyed by
        // canonical module/import paths. Prefer those canonical identities so
        // importing a package below a required module cannot be reported as an
        // unused dependency.
        for key in ["import_path", "package_path", "module_path"] {
            if let Some(value) = node.properties.get(key).and_then(serde_json::Value::as_str) {
                return Some(value.to_owned());
            }
        }
    }
    for key in [
        "name",
        "package",
        "package_name",
        "module_path",
        "import_path",
    ] {
        if let Some(value) = node.properties.get(key).and_then(|value| value.as_str()) {
            return Some(value.to_owned());
        }
    }
    None
}

fn manifest_path_for(node: &NodeRecord, site_kind: &str) -> String {
    if let Some(path) = node
        .properties
        .get("manifest_path")
        .and_then(|value| value.as_str())
    {
        return path.to_owned();
    }
    match site_kind {
        "cargo_dependency" => "Cargo.toml".to_owned(),
        "module_requirement" => "go.mod".to_owned(),
        _ => "package.json".to_owned(),
    }
}

fn canonical_manifest_scope(path: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return None;
    }
    Some(path.to_owned())
}

#[allow(clippy::too_many_arguments)]
fn dependency_finding(
    kind: FindingKind,
    source: &NodeRecord,
    site: &SiteRecord,
    specifier: &str,
    manifest_path: &str,
    drift: bool,
    reason: &str,
    profile_coverage: DependencyProfileCoverage,
    scope_uncertain: bool,
) -> HealthFinding {
    let mut blockers = Vec::new();
    if drift {
        blockers.push(FindingBlocker {
            kind: BlockerKind::ManifestDrift,
            detail: format!("{manifest_path} drifted from the snapshot file record"),
        });
    }
    if site.resolution_status == "candidates" {
        blockers.push(FindingBlocker {
            kind: BlockerKind::Candidate,
            detail: format!("site {} is a candidate", site.id),
        });
    }
    if site.resolution_status == "unresolved" {
        blockers.push(FindingBlocker {
            kind: BlockerKind::Unresolved,
            detail: format!("site {} is unresolved", site.id),
        });
    }
    if scope_uncertain {
        blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: format!(
                "manifest scope for dependency usage in {manifest_path} is missing or ambiguous"
            ),
        });
    }
    if !profile_coverage.analyzed {
        blockers.push(FindingBlocker {
            kind: BlockerKind::ProfileNotAnalyzed,
            detail: format!("profile {} is absent from the snapshot", site.profile_id),
        });
    } else if !profile_coverage.syntax_complete {
        blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: format!(
                "profile {} has no syntax-complete coverage",
                site.profile_id
            ),
        });
    }
    finish_finding(
        FindingIdentity {
            kind,
            subject_id: source.id.clone(),
            profile_scope: None,
            witness_key: json!({
                "dependency": specifier,
                "manifest": manifest_path
            }),
        },
        source.kind.clone(),
        Some(SourceLocation {
            path: manifest_path.to_owned(),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
        }),
        format!("{reason}: {specifier}"),
        blockers,
        vec![FindingEvidenceRef {
            owner_type: "site".to_owned(),
            owner_id: site.id.clone(),
            kind: site.kind.clone(),
            path: manifest_path.to_owned(),
        }],
        vec![Remediation {
            kind: "manual-review".to_owned(),
            detail: "remove or relocate the dependency after reviewing blockers".to_owned(),
        }],
        Vec::new(),
        false,
        !drift && profile_coverage.semantic_complete,
    )
}

#[derive(Clone, Copy)]
struct DependencyProfileCoverage {
    analyzed: bool,
    syntax_complete: bool,
    semantic_complete: bool,
}

fn dependency_profile_coverage(
    profile: Option<&depgraph_store::ProfileRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<DependencyProfileCoverage, HealthAnalysisError> {
    let Some(profile) = profile else {
        return Ok(DependencyProfileCoverage {
            analyzed: false,
            syntax_complete: false,
            semantic_complete: false,
        });
    };
    let mut syntax_complete = false;
    let mut semantic_complete = false;
    if let Some(coverage) = &profile.coverage {
        for level in &coverage.completeness {
            budget.step(is_cancelled)?;
            if level == "semantic-complete" || level.ends_with("+semantic-complete") {
                syntax_complete = true;
                semantic_complete = true;
            } else if level == "syntax-complete" || level.ends_with("+syntax-complete") {
                syntax_complete = true;
            }
        }
    }
    Ok(DependencyProfileCoverage {
        analyzed: true,
        syntax_complete,
        semantic_complete,
    })
}

#[cfg(test)]
mod tests {
    use depgraph_store::{
        CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, ProfileRecord, ScanRecord,
        SiteRecord,
    };
    use serde_json::json;

    use super::*;
    use crate::health::{BlockerKind, Confidence};

    fn empty_scan() -> ScanRecord {
        ScanRecord {
            id: "scan-dep".to_owned(),
            root: "/tmp/fixture".to_owned(),
            status: "completed".to_owned(),
            strict: false,
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            completed_at: Some("2026-01-01T00:00:01Z".to_owned()),
            project_code_executed: false,
            error: None,
            parent_snapshot_id: None,
            source_revision: Some("b".repeat(40)),
        }
    }

    fn package(id: &str, name: &str, manifest: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "package_instance".to_owned(),
            locator: format!("pkg://{name}"),
            display_name: name.to_owned(),
            properties: json!({
                "name": name,
                "manifest_path": manifest,
                "language": "rust"
            }),
        }
    }

    fn file(id: &str, path: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("repo://{path}"),
            display_name: path.to_owned(),
            properties: json!({"path": path, "language": "rust"}),
        }
    }

    fn dep_site(id: &str, source: &str, specifier: &str) -> SiteRecord {
        SiteRecord {
            id: id.to_owned(),
            source: source.to_owned(),
            kind: "cargo_dependency".to_owned(),
            specifier: Some(specifier.to_owned()),
            profile_id: "rust:lib".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            target_ids: vec![format!("pkg:{specifier}")],
            reason: None,
        }
    }

    fn usage_edge(source: &str, target: &str) -> EdgeRecord {
        EdgeRecord {
            id: format!("edge:{source}->{target}"),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "imports".to_owned(),
            phase: "source".to_owned(),
            environment: "host".to_owned(),
            profile_id: "rust:lib".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            generated: false,
        }
    }

    fn structural_edge(id: &str, source: &str, target: &str, kind: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: kind.to_owned(),
            phase: "source".to_owned(),
            environment: "host".to_owned(),
            profile_id: "profile:go-scope".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            generated: false,
        }
    }

    fn graph(
        nodes: Vec<NodeRecord>,
        sites: Vec<SiteRecord>,
        edges: Vec<EdgeRecord>,
    ) -> GraphSnapshot {
        GraphSnapshot {
            scan: empty_scan(),
            profiles: vec![ProfileRecord {
                id: "rust:lib".to_owned(),
                language: "rust".to_owned(),
                toolchain: None,
                command: None,
                target: None,
                features: Vec::new(),
                environment: json!({}),
                source_revision: None,
                properties: json!({}),
                coverage: Some(CoverageRecord {
                    completeness: vec!["semantic-complete".to_owned()],
                    ..CoverageRecord::default()
                }),
            }],
            nodes,
            sites,
            edges,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        }
    }

    fn ecosystem_profile(id: &str, language: &str) -> ProfileRecord {
        ProfileRecord {
            id: id.to_owned(),
            language: language.to_owned(),
            toolchain: None,
            command: None,
            target: None,
            features: Vec::new(),
            environment: json!({}),
            source_revision: None,
            properties: json!({}),
            coverage: Some(CoverageRecord {
                completeness: vec!["semantic-complete".to_owned()],
                ..CoverageRecord::default()
            }),
        }
    }

    fn ecosystem_package(id: &str, name: &str, manifest: &str, language: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "package_instance".to_owned(),
            locator: format!("package://{name}"),
            display_name: name.to_owned(),
            properties: json!({
                "name": name,
                "manifest_path": manifest,
                "language": language,
                "module_path": name
            }),
        }
    }

    fn ecosystem_file(id: &str, path: &str, language: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: "file".to_owned(),
            locator: format!("file://{path}"),
            display_name: path.to_owned(),
            properties: json!({"path": path, "language": language}),
        }
    }

    fn ecosystem_file_with_manifest(
        id: &str,
        path: &str,
        language: &str,
        manifest: &str,
    ) -> NodeRecord {
        let mut node = ecosystem_file(id, path, language);
        node.properties["manifest_path"] = json!(manifest);
        node
    }

    fn ecosystem_test_file_with_manifest(
        id: &str,
        path: &str,
        language: &str,
        manifest: &str,
    ) -> NodeRecord {
        let mut node = ecosystem_file_with_manifest(id, path, language, manifest);
        node.properties["test"] = json!(true);
        node
    }

    fn ecosystem_site(
        id: &str,
        source: &str,
        kind: &str,
        profile_id: &str,
        specifier: &str,
        target: &str,
        condition: serde_json::Value,
    ) -> SiteRecord {
        SiteRecord {
            id: id.to_owned(),
            source: source.to_owned(),
            kind: kind.to_owned(),
            specifier: Some(specifier.to_owned()),
            profile_id: profile_id.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition,
            target_ids: vec![target.to_owned()],
            reason: None,
        }
    }

    fn ecosystem_usage_edge(id: &str, source: &str, target: &str, profile_id: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: "imports".to_owned(),
            phase: "source".to_owned(),
            environment: "host".to_owned(),
            profile_id: profile_id.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            generated: false,
        }
    }

    fn ecosystem_usage_edge_with_site(
        id: &str,
        site_id: &str,
        source: &str,
        target: &str,
        profile_id: &str,
    ) -> EdgeRecord {
        let mut edge = ecosystem_usage_edge(id, source, target, profile_id);
        edge.site_id = Some(site_id.to_owned());
        edge
    }

    fn ecosystem_graph(
        profile: ProfileRecord,
        nodes: Vec<NodeRecord>,
        sites: Vec<SiteRecord>,
        edges: Vec<EdgeRecord>,
    ) -> GraphSnapshot {
        GraphSnapshot {
            scan: empty_scan(),
            profiles: vec![profile],
            nodes,
            sites,
            edges,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        }
    }

    #[test]
    fn issue_423_detects_unused_test_only_and_manifest_mismatch() {
        let snapshot = graph(
            vec![
                package("pkg:app", "app", "Cargo.toml"),
                package("pkg:unused", "unused-crate", "Cargo.toml"),
                package("pkg:serde", "serde", "Cargo.toml"),
                file("file:lib.rs", "src/lib.rs"),
                file("file:test.rs", "tests/unused.rs"),
            ],
            vec![
                dep_site("site:unused", "pkg:app", "unused-crate"),
                dep_site("site:serde", "pkg:app", "serde"),
            ],
            vec![usage_edge("file:test.rs", "pkg:serde")],
        );
        let manifests = [ManifestIdentity {
            path: "Cargo.toml".to_owned(),
            digest: "sha256:1".to_owned(),
            declared: BTreeSet::from(["unused-crate".to_owned(), "serde".to_owned()]),
            drifted: false,
        }];
        let findings = analyze_dependencies(&snapshot, &manifests);
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::UnusedDependency
                    && finding.reason.contains("unused-crate"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == FindingKind::TestOnlyDependency
                    && finding.reason.contains("serde"))
        );
    }

    #[test]
    fn issue_423_manifest_drift_degrades_to_indeterminate() {
        let snapshot = graph(
            vec![package("pkg:app", "app", "Cargo.toml")],
            vec![dep_site("site:left", "pkg:app", "left-pad")],
            Vec::new(),
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: "Cargo.toml".to_owned(),
                digest: "sha256:drift".to_owned(),
                declared: BTreeSet::from(["left-pad".to_owned()]),
                drifted: true,
            }],
        );
        let unused = findings
            .iter()
            .find(|finding| finding.kind == FindingKind::UnusedDependency)
            .expect("unused");
        assert_eq!(unused.confidence, Confidence::Indeterminate);
        assert!(
            unused
                .blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::ManifestDrift)
        );
    }

    #[test]
    fn issue_423_dependency_syntax_coverage_is_probable_without_a_hard_blocker() {
        let mut snapshot = graph(
            vec![
                package("pkg:app", "app", "Cargo.toml"),
                package("pkg:unused", "unused-crate", "Cargo.toml"),
            ],
            vec![dep_site("site:unused", "pkg:app", "unused-crate")],
            Vec::new(),
        );
        snapshot.profiles[0].coverage = Some(CoverageRecord {
            completeness: vec!["syntax-complete".to_owned()],
            ..CoverageRecord::default()
        });
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: "Cargo.toml".to_owned(),
                digest: "sha256:current".to_owned(),
                declared: BTreeSet::from(["unused-crate".to_owned()]),
                drifted: false,
            }],
        );
        let unused = findings
            .iter()
            .find(|finding| finding.kind == FindingKind::UnusedDependency)
            .expect("unused dependency");
        assert_eq!(unused.confidence, Confidence::Probable);
        assert!(unused.blockers.is_empty());
    }

    #[test]
    fn issue_423_dependency_analysis_is_bounded_and_cancellable() {
        let snapshot = graph(
            vec![package("pkg:app", "app", "Cargo.toml")],
            vec![dep_site("site:left", "pkg:app", "left-pad")],
            Vec::new(),
        );
        let manifests = [ManifestIdentity {
            path: "Cargo.toml".to_owned(),
            digest: "sha256:current".to_owned(),
            declared: BTreeSet::from(["left-pad".to_owned()]),
            drifted: false,
        }];
        assert_eq!(
            analyze_dependencies_cancellable(&snapshot, &manifests, usize::MAX, 0, || false),
            Err(HealthAnalysisError::ResourceExhausted)
        );
        assert_eq!(
            analyze_dependencies_cancellable(&snapshot, &manifests, usize::MAX, usize::MAX, || {
                true
            },),
            Err(HealthAnalysisError::Cancelled)
        );
    }

    #[test]
    fn issue_437_manifest_scope_index_is_stack_safe_for_deep_graphs() {
        let depth = 20_000;
        let mut nodes = Vec::with_capacity(depth);
        for index in 0..depth {
            // Reverse the IDs so the first BTreeMap root is the leaf. That
            // forces one traversal to materialize the complete hostile depth
            // instead of letting ascending roots populate one cached level at
            // a time.
            let id = depth - index - 1;
            let mut node = file(&format!("file:{id:05}"), &format!("src/{id:05}.rs"));
            if index == 0 {
                node.properties["manifest_path"] = json!("Cargo.toml");
            }
            nodes.push(node);
        }
        nodes.push(ecosystem_package(
            "pkg:app",
            "example.com/app",
            "Cargo.toml",
            "go",
        ));
        nodes.push(NodeRecord {
            id: "pkg:deep".to_owned(),
            kind: "module".to_owned(),
            locator: "go-package:example.net/deep/pkg".to_owned(),
            display_name: "example.net/deep/pkg".to_owned(),
            properties: json!({
                "language": "go",
                "module_path": "example.net/deep",
                "package_path": "example.net/deep/pkg",
                "package_name": "pkg"
            }),
        });
        let mut edges = Vec::with_capacity(depth - 1);
        for index in 0..(depth - 1) {
            edges.push(EdgeRecord {
                id: format!("edge:contains:{index}"),
                site_id: None,
                source: format!("file:{:05}", depth - index - 1),
                target: format!("file:{:05}", depth - index - 2),
                kind: if index == 0 { "contains" } else { "declares" }.to_owned(),
                phase: "source".to_owned(),
                environment: "host".to_owned(),
                profile_id: "rust:lib".to_owned(),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition: json!({}),
                generated: false,
            });
        }
        edges.push(usage_edge("file:00000", "pkg:deep"));
        let mut snapshot = graph(nodes, Vec::new(), edges);
        snapshot.sites.push(SiteRecord {
            id: "site:deep-module".to_owned(),
            source: "pkg:app".to_owned(),
            kind: "module_requirement".to_owned(),
            specifier: Some("example.net/deep".to_owned()),
            profile_id: "rust:lib".to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({}),
            target_ids: vec!["pkg:deep".to_owned()],
            reason: None,
        });
        let manifests = [ManifestIdentity {
            path: "Cargo.toml".to_owned(),
            digest: "sha256:deep-chain".to_owned(),
            declared: BTreeSet::from(["example.net/deep".to_owned()]),
            drifted: false,
        }];
        assert!(analyze_dependencies(&snapshot, &manifests).is_empty());
    }

    #[test]
    fn issue_437_ambiguous_parent_scope_propagates_fail_closed() {
        let profile_id = "profile:go-scope";
        let manifest_a = "a/go.mod";
        let manifest_b = "b/go.mod";
        let mut manifest_a_owner = ecosystem_file("scope:manifest-a", "a/manifest-owner.go", "go");
        manifest_a_owner.properties["manifest_path"] = json!(manifest_a);
        let mut manifest_b_owner = ecosystem_file("scope:manifest-b", "b/manifest-owner.go", "go");
        manifest_b_owner.properties["manifest_path"] = json!(manifest_b);
        let dependency = NodeRecord {
            id: "go:dependency".to_owned(),
            kind: "module".to_owned(),
            locator: "go-package:example.net/dependency/pkg".to_owned(),
            display_name: "example.net/dependency/pkg".to_owned(),
            properties: json!({
                "language": "go",
                "module_path": "example.net/dependency",
                "package_path": "example.net/dependency/pkg",
                "package_name": "pkg"
            }),
        };
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest_a, "go"),
                dependency,
                ecosystem_file("scope:a", "shared/a.go", "go"),
                ecosystem_file("scope:b", "shared/b.go", "go"),
                ecosystem_file("scope:c", "shared/c.go", "go"),
                manifest_a_owner,
                manifest_b_owner,
            ],
            vec![ecosystem_site(
                "site:dependency",
                "go:app",
                "module_requirement",
                profile_id,
                "example.net/dependency",
                "go:dependency",
                json!({}),
            )],
            vec![
                structural_edge("edge:b-a", "scope:b", "scope:a", "contains"),
                structural_edge("edge:c-a", "scope:c", "scope:a", "contains"),
                structural_edge(
                    "edge:manifest-a-b",
                    "scope:manifest-a",
                    "scope:b",
                    "contains",
                ),
                structural_edge(
                    "edge:manifest-b-b",
                    "scope:manifest-b",
                    "scope:b",
                    "contains",
                ),
                structural_edge(
                    "edge:manifest-a-c",
                    "scope:manifest-a",
                    "scope:c",
                    "contains",
                ),
                ecosystem_usage_edge("edge:ambiguous-use", "scope:a", "go:dependency", profile_id),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest_a.to_owned(),
                digest: "sha256:scope-a".to_owned(),
                declared: BTreeSet::from(["example.net/dependency".to_owned()]),
                drifted: false,
            }],
        );
        let finding = findings
            .iter()
            .find(|finding| {
                finding.kind == FindingKind::UnusedDependency
                    && finding
                        .evidence
                        .iter()
                        .any(|evidence| evidence.owner_id == "site:dependency")
            })
            .expect("ambiguous owner remains visible");
        assert_eq!(finding.confidence, crate::health::Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("missing or ambiguous")
        }));
    }

    #[test]
    fn issue_437_unknown_parent_scope_does_not_hide_usage() {
        let profile_id = "profile:go-scope";
        let manifest = "app/go.mod";
        let dependency = NodeRecord {
            id: "go:unknown-parent-dependency".to_owned(),
            kind: "module".to_owned(),
            locator: "go-package:example.net/unknown-parent/pkg".to_owned(),
            display_name: "example.net/unknown-parent/pkg".to_owned(),
            properties: json!({
                "language": "go",
                "module_path": "example.net/unknown-parent",
                "package_path": "example.net/unknown-parent/pkg",
                "package_name": "pkg"
            }),
        };
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:unknown-parent-app", "example.com/app", manifest, "go"),
                dependency,
                ecosystem_file("scope:owner", "shared/owner.go", "go"),
                ecosystem_file_with_manifest("scope:known", "shared/known.go", "go", manifest),
                ecosystem_file("scope:unknown", "shared/unknown.go", "go"),
            ],
            vec![ecosystem_site(
                "site:unknown-parent-dependency",
                "go:unknown-parent-app",
                "module_requirement",
                profile_id,
                "example.net/unknown-parent",
                "go:unknown-parent-dependency",
                json!({}),
            )],
            vec![
                structural_edge("edge:known-owner", "scope:known", "scope:owner", "contains"),
                structural_edge(
                    "edge:unknown-owner",
                    "scope:unknown",
                    "scope:owner",
                    "contains",
                ),
                ecosystem_usage_edge(
                    "edge:unknown-parent-use",
                    "scope:owner",
                    "go:unknown-parent-dependency",
                    profile_id,
                ),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:unknown-parent".to_owned(),
                declared: BTreeSet::from(["example.net/unknown-parent".to_owned()]),
                drifted: false,
            }],
        );
        let finding = findings
            .iter()
            .find(|finding| {
                finding.kind == FindingKind::UnusedDependency
                    && finding
                        .evidence
                        .iter()
                        .any(|evidence| evidence.owner_id == "site:unknown-parent-dependency")
            })
            .expect("unknown parent owner remains visible");
        assert_eq!(finding.confidence, crate::health::Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("missing or ambiguous")
        }));
    }

    #[test]
    fn issue_437_structural_cycle_scope_propagates_fail_closed() {
        let profile_id = "profile:go-scope";
        let manifest = "a/go.mod";
        let mut manifest_owner = ecosystem_file("cycle:manifest", "a/manifest-owner.go", "go");
        manifest_owner.properties["manifest_path"] = json!(manifest);
        let dependency = NodeRecord {
            id: "go:cycle-dependency".to_owned(),
            kind: "module".to_owned(),
            locator: "go-package:example.net/cycle/pkg".to_owned(),
            display_name: "example.net/cycle/pkg".to_owned(),
            properties: json!({
                "language": "go",
                "module_path": "example.net/cycle",
                "package_path": "example.net/cycle/pkg",
                "package_name": "pkg"
            }),
        };
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:cycle-app", "example.com/app", manifest, "go"),
                dependency,
                ecosystem_file("cycle:a", "shared/a.go", "go"),
                ecosystem_file("cycle:b", "shared/b.go", "go"),
                manifest_owner,
            ],
            vec![ecosystem_site(
                "site:cycle-dependency",
                "go:cycle-app",
                "module_requirement",
                profile_id,
                "example.net/cycle",
                "go:cycle-dependency",
                json!({}),
            )],
            vec![
                structural_edge("edge:cycle-a-b", "cycle:a", "cycle:b", "declares"),
                structural_edge("edge:cycle-b-a", "cycle:b", "cycle:a", "declares"),
                structural_edge(
                    "edge:manifest-cycle-b",
                    "cycle:manifest",
                    "cycle:b",
                    "contains",
                ),
                ecosystem_usage_edge(
                    "edge:cycle-use",
                    "cycle:a",
                    "go:cycle-dependency",
                    profile_id,
                ),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:cycle-scope".to_owned(),
                declared: BTreeSet::from(["example.net/cycle".to_owned()]),
                drifted: false,
            }],
        );
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.owner_id == "site:cycle-dependency")
        }));
    }

    #[test]
    fn issue_423_duplicate_dependency_sites_merge_into_one_stable_finding() {
        let snapshot = graph(
            vec![
                package("pkg:app", "app", "Cargo.toml"),
                package("pkg:left-pad", "left-pad", "Cargo.toml"),
            ],
            vec![
                dep_site("site:left-a", "pkg:app", "left-pad"),
                dep_site("site:left-b", "pkg:app", "left-pad"),
            ],
            Vec::new(),
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: "Cargo.toml".to_owned(),
                digest: "sha256:current".to_owned(),
                declared: BTreeSet::from(["left-pad".to_owned()]),
                drifted: false,
            }],
        );
        let unused = findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::UnusedDependency)
            .collect::<Vec<_>>();
        assert_eq!(unused.len(), 1);
        assert_eq!(unused[0].evidence.len(), 2);
        assert_eq!(unused[0].evidence[0].owner_id, "site:left-a");
        assert_eq!(unused[0].evidence[1].owner_id, "site:left-b");
    }

    #[test]
    fn issue_437_go_dependency_findings_cover_unused_test_only_and_manifest_mismatch() {
        let profile_id = "profile:go-health";
        let manifest = "app/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest, "go"),
                ecosystem_package("go:unused", "example.com/unused", manifest, "go"),
                ecosystem_package("go:test-only", "example.com/test-only", manifest, "go"),
                ecosystem_package("go:mismatch", "example.com/mismatch", manifest, "go"),
                ecosystem_test_file_with_manifest(
                    "go:test",
                    "app/internal/consumer_test.go",
                    "go",
                    manifest,
                ),
                ecosystem_file_with_manifest("go:main", "app/cmd/main.go", "go", manifest),
            ],
            vec![
                ecosystem_site(
                    "site:go-unused",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.com/unused",
                    "go:unused",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-test-only",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.com/test-only",
                    "go:test-only",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-mismatch",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.com/mismatch",
                    "go:mismatch",
                    json!({}),
                ),
            ],
            vec![
                ecosystem_usage_edge("edge:go-test-only", "go:test", "go:test-only", profile_id),
                ecosystem_usage_edge("edge:go-mismatch", "go:main", "go:mismatch", profile_id),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:go-health".to_owned(),
                declared: BTreeSet::from([
                    "example.com/unused".to_owned(),
                    "example.com/test-only".to_owned(),
                ]),
                drifted: false,
            }],
        );

        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.com/unused")
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::TestOnlyDependency
                && finding.reason.contains("example.com/test-only")
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::ManifestMismatch
                && finding.reason.contains("example.com/mismatch")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.com/mismatch")
        }));
    }

    #[test]
    fn issue_437_go_module_dependency_matches_an_imported_subpackage() {
        let profile_id = "profile:go-module-prefix";
        let manifest = "app/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest, "go"),
                NodeRecord {
                    id: "go:external-package".to_owned(),
                    kind: "module".to_owned(),
                    locator: "go-package:example.net/external/pkg".to_owned(),
                    display_name: "example.net/external/pkg".to_owned(),
                    properties: json!({
                        "language": "go",
                        "module_path": "example.net/external",
                        "package_path": "example.net/external/pkg",
                        "package_name": "pkg",
                        "relative_dir": "pkg"
                    }),
                },
                NodeRecord {
                    id: "go:similar-requirement".to_owned(),
                    kind: "external_system".to_owned(),
                    locator: "gomod:example.net/extern".to_owned(),
                    display_name: "example.net/extern".to_owned(),
                    properties: json!({
                        "ecosystem": "go",
                        "external": true,
                        "module_path": "example.net/extern"
                    }),
                },
                NodeRecord {
                    id: "go:externalized-package".to_owned(),
                    kind: "module".to_owned(),
                    locator: "go-package:example.net/externalized/pkg".to_owned(),
                    display_name: "example.net/externalized/pkg".to_owned(),
                    properties: json!({
                        "language": "go",
                        "module_path": "example.net/externalized",
                        "package_path": "example.net/externalized/pkg",
                        "package_name": "pkg",
                        "relative_dir": "pkg"
                    }),
                },
                ecosystem_file_with_manifest("go:main", "app/main.go", "go", manifest),
            ],
            vec![
                ecosystem_site(
                    "site:go-module",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.net/external",
                    "go:external-package",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-similar-prefix",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.net/extern",
                    "go:similar-requirement",
                    json!({}),
                ),
            ],
            vec![
                ecosystem_usage_edge(
                    "edge:go-module-import",
                    "go:main",
                    "go:external-package",
                    profile_id,
                ),
                ecosystem_usage_edge(
                    "edge:go-similar-import",
                    "go:main",
                    "go:externalized-package",
                    profile_id,
                ),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:go-module-prefix".to_owned(),
                declared: BTreeSet::from([
                    "example.net/external".to_owned(),
                    "example.net/extern".to_owned(),
                ]),
                drifted: false,
            }],
        );
        assert!(!findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.net/external")
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.net/extern")
        }));
    }

    #[test]
    fn issue_437_go_requirement_does_not_match_direct_replacement_target_import() {
        let profile_id = "profile:go-replacement";
        let manifest = "app/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest, "go"),
                NodeRecord {
                    id: "go:replacement-requirement".to_owned(),
                    kind: "external_system".to_owned(),
                    locator: "gomod:example.com/original".to_owned(),
                    display_name: "example.net/replacement".to_owned(),
                    properties: json!({
                        "ecosystem": "go",
                        "external": true,
                        "module_path": "example.net/replacement",
                        "requested_module_path": "example.com/original",
                        "replace_path": "example.net/replacement"
                    }),
                },
                NodeRecord {
                    id: "go:replacement-package".to_owned(),
                    kind: "module".to_owned(),
                    locator: "go-package:example.net/replacement/pkg".to_owned(),
                    display_name: "example.net/replacement/pkg".to_owned(),
                    properties: json!({
                        "language": "go",
                        "module_path": "example.net/replacement",
                        "package_path": "example.net/replacement/pkg",
                        "package_name": "pkg"
                    }),
                },
                ecosystem_file_with_manifest("go:main", "app/main.go", "go", manifest),
            ],
            vec![
                ecosystem_site(
                    "site:go-replacement",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.com/original",
                    "go:replacement-requirement",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-replacement-import",
                    "go:main",
                    "import",
                    profile_id,
                    "example.net/replacement/pkg",
                    "go:replacement-package",
                    json!({}),
                ),
            ],
            vec![ecosystem_usage_edge_with_site(
                "edge:go-replacement-import",
                "site:go-replacement-import",
                "go:main",
                "go:replacement-package",
                profile_id,
            )],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:go-replacement".to_owned(),
                declared: BTreeSet::from(["example.com/original".to_owned()]),
                drifted: false,
            }],
        );
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.com/original")
        }));
    }

    #[test]
    fn issue_437_go_requirement_matches_requested_import_through_replacement() {
        let profile_id = "profile:go-replacement-requested";
        let manifest = "app/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest, "go"),
                NodeRecord {
                    id: "go:replacement-requirement".to_owned(),
                    kind: "external_system".to_owned(),
                    locator: "gomod:example.com/original".to_owned(),
                    display_name: "example.net/replacement".to_owned(),
                    properties: json!({
                        "ecosystem": "go",
                        "external": true,
                        "module_path": "example.net/replacement",
                        "requested_module_path": "example.com/original",
                        "replace_path": "example.net/replacement"
                    }),
                },
                NodeRecord {
                    id: "go:replacement-package".to_owned(),
                    kind: "module".to_owned(),
                    locator: "go-package:example.net/replacement/pkg".to_owned(),
                    display_name: "example.net/replacement/pkg".to_owned(),
                    properties: json!({
                        "language": "go",
                        "module_path": "example.net/replacement",
                        "package_path": "example.net/replacement/pkg",
                        "package_name": "pkg"
                    }),
                },
                ecosystem_file_with_manifest("go:main", "app/main.go", "go", manifest),
            ],
            vec![
                ecosystem_site(
                    "site:go-replacement",
                    "go:app",
                    "module_requirement",
                    profile_id,
                    "example.com/original",
                    "go:replacement-requirement",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-replacement-import",
                    "go:main",
                    "import",
                    profile_id,
                    "example.com/original/pkg",
                    "go:replacement-package",
                    json!({}),
                ),
            ],
            vec![ecosystem_usage_edge_with_site(
                "edge:go-replacement-import",
                "site:go-replacement-import",
                "go:main",
                "go:replacement-package",
                profile_id,
            )],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:go-replacement-requested".to_owned(),
                declared: BTreeSet::from(["example.com/original".to_owned()]),
                drifted: false,
            }],
        );
        assert!(!findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding.reason.contains("example.com/original")
        }));
    }

    #[test]
    fn issue_437_go_dependency_usage_is_scoped_to_its_manifest() {
        let profile_id = "profile:go-multi-module";
        let manifest_a = "app-a/go.mod";
        let manifest_b = "app-b/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app-a", "example.com/app-a", manifest_a, "go"),
                ecosystem_package("go:app-b", "example.com/app-b", manifest_b, "go"),
                NodeRecord {
                    id: "go:shared-package".to_owned(),
                    kind: "module".to_owned(),
                    locator: "go-package:example.net/shared/pkg".to_owned(),
                    display_name: "example.net/shared/pkg".to_owned(),
                    properties: json!({
                        "language": "go",
                        "module_path": "example.net/shared",
                        "package_path": "example.net/shared/pkg",
                        "package_name": "pkg"
                    }),
                },
                ecosystem_file_with_manifest("go:a-main", "app-a/main.go", "go", manifest_a),
                ecosystem_file_with_manifest("go:b-main", "app-b/main.go", "go", manifest_b),
            ],
            vec![
                ecosystem_site(
                    "site:go-a-shared",
                    "go:app-a",
                    "module_requirement",
                    profile_id,
                    "example.net/shared",
                    "go:shared-package",
                    json!({}),
                ),
                ecosystem_site(
                    "site:go-b-shared",
                    "go:app-b",
                    "module_requirement",
                    profile_id,
                    "example.net/shared",
                    "go:shared-package",
                    json!({}),
                ),
            ],
            vec![ecosystem_usage_edge(
                "edge:go-b-shared-import",
                "go:b-main",
                "go:shared-package",
                profile_id,
            )],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[
                ManifestIdentity {
                    path: manifest_a.to_owned(),
                    digest: "sha256:go-a".to_owned(),
                    declared: BTreeSet::from(["example.net/shared".to_owned()]),
                    drifted: false,
                },
                ManifestIdentity {
                    path: manifest_b.to_owned(),
                    digest: "sha256:go-b".to_owned(),
                    declared: BTreeSet::from(["example.net/shared".to_owned()]),
                    drifted: false,
                },
            ],
        );
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.owner_id == "site:go-a-shared")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency
                && finding
                    .evidence
                    .iter()
                    .any(|evidence| evidence.owner_id == "site:go-b-shared")
        }));
    }

    #[test]
    fn issue_437_invalid_manifest_scope_does_not_mix_go_usage() {
        let profile_id = "profile:go-invalid-manifest";
        let manifest = "/checkout/app/go.mod";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "go"),
            vec![
                ecosystem_package("go:app", "example.com/app", manifest, "go"),
                ecosystem_package("go:external", "example.net/external", manifest, "go"),
                ecosystem_file_with_manifest("go:main", "app/main.go", "go", manifest),
            ],
            vec![ecosystem_site(
                "site:go-external",
                "go:app",
                "module_requirement",
                profile_id,
                "example.net/external",
                "go:external",
                json!({}),
            )],
            vec![ecosystem_usage_edge(
                "edge:go-external-import",
                "go:main",
                "go:external",
                profile_id,
            )],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:go-invalid-manifest".to_owned(),
                declared: BTreeSet::from(["example.net/external".to_owned()]),
                drifted: false,
            }],
        );
        let finding = findings
            .iter()
            .find(|finding| {
                finding.kind == FindingKind::UnusedDependency
                    && finding.reason.contains("example.net/external")
            })
            .expect("invalid manifest scope remains visible");
        assert_eq!(finding.confidence, crate::health::Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("missing or ambiguous")
        }));
    }

    #[test]
    fn issue_437_web_dependency_findings_cover_unused_test_only_and_manifest_mismatch() {
        let profile_id = "profile:web-health";
        let manifest = "apps/web/package.json";
        let snapshot = ecosystem_graph(
            ecosystem_profile(profile_id, "web"),
            vec![
                ecosystem_package("web:app", "@fixture/web", manifest, "web"),
                ecosystem_package("web:unused", "unused-web", manifest, "web"),
                ecosystem_package("web:test-only", "test-only-web", manifest, "web"),
                ecosystem_package("web:mismatch", "mismatch-web", manifest, "web"),
                ecosystem_file("web:test", "apps/web/src/consumer.test.ts", "typescript"),
                ecosystem_file("web:main", "apps/web/src/main.ts", "typescript"),
            ],
            vec![
                ecosystem_site(
                    "site:web-unused",
                    "web:app",
                    "package_dependency",
                    profile_id,
                    "unused-web",
                    "web:unused",
                    json!({}),
                ),
                ecosystem_site(
                    "site:web-test-only",
                    "web:app",
                    "package_dependency",
                    profile_id,
                    "test-only-web",
                    "web:test-only",
                    json!({}),
                ),
                ecosystem_site(
                    "site:web-mismatch",
                    "web:app",
                    "package_dependency",
                    profile_id,
                    "mismatch-web",
                    "web:mismatch",
                    json!({}),
                ),
            ],
            vec![
                ecosystem_usage_edge(
                    "edge:web-test-only",
                    "web:test",
                    "web:test-only",
                    profile_id,
                ),
                ecosystem_usage_edge("edge:web-mismatch", "web:main", "web:mismatch", profile_id),
            ],
        );
        let findings = analyze_dependencies(
            &snapshot,
            &[ManifestIdentity {
                path: manifest.to_owned(),
                digest: "sha256:web-health".to_owned(),
                declared: BTreeSet::from(["unused-web".to_owned(), "test-only-web".to_owned()]),
                drifted: false,
            }],
        );

        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency && finding.reason.contains("unused-web")
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::TestOnlyDependency
                && finding.reason.contains("test-only-web")
        }));
        assert!(findings.iter().any(|finding| {
            finding.kind == FindingKind::ManifestMismatch && finding.reason.contains("mismatch-web")
        }));
        assert!(!findings.iter().any(|finding| {
            finding.kind == FindingKind::UnusedDependency && finding.reason.contains("mismatch-web")
        }));
    }
}
