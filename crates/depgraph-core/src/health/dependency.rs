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
    for key in ["name", "package", "package_name", "module_path"] {
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
            health_policy_config_digest: None,
            health_analyzer_version: None,
            health_finding_contract_version: None,
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
                .all(|finding| finding.suppressions.is_empty())
        );
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
}
