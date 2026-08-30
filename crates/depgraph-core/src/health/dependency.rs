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
    let usage_targets = package_usage_targets(snapshot, &nodes, &mut budget, &mut is_cancelled)?;
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
        let mut used_from_production = false;
        let mut used_from_test = false;
        if let Some(owners) = usage_targets.get(specifier) {
            for owner in owners {
                budget.step(&mut is_cancelled)?;
                if owner.is_test {
                    used_from_test = true;
                } else {
                    used_from_production = true;
                }
                if used_from_production && used_from_test {
                    break;
                }
            }
        }
        if site.kind == "module_requirement" && !(used_from_production && used_from_test) {
            // Go manifests declare a module path while source imports may point
            // at any package below that module. The helper starts at the
            // slash-delimited prefix so this remains O(log n + matching
            // packages), and stops at the first key outside the prefix. The
            // slash boundary avoids treating a similarly named module (for
            // example foo/barista) as a use of foo/bar.
            for (_, owners) in go_module_usage_targets(&usage_targets, specifier) {
                budget.step(&mut is_cancelled)?;
                for owner in owners {
                    budget.step(&mut is_cancelled)?;
                    if owner.is_test {
                        used_from_test = true;
                    } else {
                        used_from_production = true;
                    }
                    if used_from_production && used_from_test {
                        break;
                    }
                }
                if used_from_production && used_from_test {
                    break;
                }
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

struct UsageOwner {
    is_test: bool,
}

fn package_usage_targets(
    snapshot: &GraphSnapshot,
    nodes: &BTreeMap<&str, &NodeRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeMap<String, Vec<UsageOwner>>, HealthAnalysisError> {
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
        usage.entry(package).or_default().push(UsageOwner {
            is_test: is_test_node(source, edge),
        });
    }
    Ok(usage)
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
    let is_go = node
        .properties
        .get("language")
        .and_then(serde_json::Value::as_str)
        == Some("go")
        || node
            .properties
            .get("ecosystem")
            .and_then(serde_json::Value::as_str)
            == Some("go");
    if is_go {
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
                ecosystem_file("go:test", "app/internal/consumer_test.go", "go"),
                ecosystem_file("go:main", "app/cmd/main.go", "go"),
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
                        "package_name": "pkg",
                        "relative_dir": "pkg"
                    }),
                },
                NodeRecord {
                    id: "go:similar-package".to_owned(),
                    kind: "external_system".to_owned(),
                    locator: "gomod:example.net/external/pkg".to_owned(),
                    display_name: "example.net/external/pkg".to_owned(),
                    properties: json!({
                        "ecosystem": "go",
                        "external": true,
                        "import_path": "example.net/external/pkg"
                    }),
                },
                ecosystem_file("go:main", "app/main.go", "go"),
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
                    "go:similar-package",
                    json!({}),
                ),
            ],
            vec![ecosystem_usage_edge(
                "edge:go-module-import",
                "go:main",
                "go:external-package",
                profile_id,
            )],
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
