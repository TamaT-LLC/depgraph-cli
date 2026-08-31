use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use depgraph_protocol::Condition;
use depgraph_store::{EdgeRecord, GraphSnapshot, NodeRecord, SiteRecord};

use super::{
    BlockerKind, FindingBlocker, FindingEvidenceRef, FindingIdentity, FindingKind, HealthFinding,
    Remediation, SourceLocation, SurfaceRole, classify_surface, finish_finding,
};
use super::{HealthAnalysisError, budget::HealthAnalysisBudget};

const STRUCTURAL_EDGE_KINDS: &[&str] = &["contains", "declares"];

#[must_use]
pub fn analyze_unused(snapshot: &GraphSnapshot) -> Vec<HealthFinding> {
    analyze_unused_cancellable(snapshot, usize::MAX, usize::MAX, || false)
        .expect("unbounded, non-cancellable unused analysis cannot fail")
}

pub fn analyze_unused_cancellable(
    snapshot: &GraphSnapshot,
    maximum_findings: usize,
    maximum_work: usize,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HealthAnalysisError> {
    let mut budget = HealthAnalysisBudget::new(maximum_work);
    let index = SnapshotIndex::build(snapshot, &mut budget, &mut is_cancelled)?;
    let mut findings = Vec::new();
    for node in &snapshot.nodes {
        budget.step(&mut is_cancelled)?;
        let kind = match node.kind.as_str() {
            "file" => FindingKind::UnusedFile,
            "symbol" => FindingKind::UnusedExport,
            "type" => FindingKind::UnusedType,
            _ => continue,
        };
        if let Some(finding) = analyze_subject(&index, node, kind, &mut budget, &mut is_cancelled)?
        {
            if findings.len() >= maximum_findings {
                return Err(HealthAnalysisError::ResourceExhausted);
            }
            findings.push(finding);
        }
    }
    budget.step(&mut is_cancelled)?;
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(findings)
}

fn analyze_subject(
    index: &SnapshotIndex<'_>,
    node: &NodeRecord,
    kind: FindingKind,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<HealthFinding>, HealthAnalysisError> {
    if kind == FindingKind::UnusedExport && classify_surface(node).role == SurfaceRole::Internal {
        return Ok(None);
    }
    let incoming = index
        .incoming
        .get(node.id.as_str())
        .map_or(&[][..], Vec::as_slice);
    let mut incoming_usage = Vec::new();
    for edge in incoming {
        budget.step(is_cancelled)?;
        if is_usage_edge(edge, &node.id) {
            incoming_usage.push(*edge);
        }
    }
    let mut usage = Vec::new();
    for edge in &incoming_usage {
        budget.step(is_cancelled)?;
        if is_definite_usage(edge) {
            usage.push(*edge);
        }
    }
    let mut blockers = Vec::new();
    collect_surface_blockers(node, &mut blockers);
    collect_edge_blockers(&incoming_usage, &mut blockers, budget, is_cancelled)?;
    collect_site_blockers(index, &node.id, &mut blockers, budget, is_cancelled)?;
    collect_coverage_blockers(index, node, &mut blockers, budget, is_cancelled)?;
    let applicable = applicable_profiles(index, node, budget, is_cancelled)?;
    if applicable.is_empty() {
        let detail = node
            .properties
            .get("language")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || "no analyzed profile applies to this subject".to_owned(),
                |language| format!("no analyzed profile applies to language {language}"),
            );
        blockers.push(FindingBlocker {
            kind: BlockerKind::ProfileNotAnalyzed,
            detail,
        });
    }
    for profile in &applicable {
        budget.step(is_cancelled)?;
        if !index.profiles_by_id.contains_key(profile.as_str()) {
            blockers.push(FindingBlocker {
                kind: BlockerKind::ProfileNotAnalyzed,
                detail: format!("profile {profile} is applicable but missing from the snapshot"),
            });
        }
    }
    let mut usage_profiles = BTreeSet::new();
    for edge in &usage {
        budget.step(is_cancelled)?;
        usage_profiles.insert(edge.profile_id.as_str());
    }
    if kind == FindingKind::UnusedFile
        && node
            .properties
            .get("language")
            .and_then(serde_json::Value::as_str)
            == Some("go")
    {
        // The Go worker's import edge targets the package/module node, not an
        // arbitrary source file.  An exact package import therefore accounts
        // for every source file in that package for the matching profile.
        if let Some(package_profiles) = index.go_file_usage_profiles.get(node.id.as_str()) {
            usage_profiles.extend(package_profiles.iter().copied());
        }
        // A Go main package is selected by the build as an entry surface even
        // when no repository edge points at its source file. The index has
        // already evaluated each file's build condition for each real Go
        // profile, so an inactive file cannot make this entry treatment hide
        // an UnusedFile finding.
        let is_go_test = node
            .properties
            .get("test")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if !is_go_test
            && index.go_main_file_ids.contains(node.id.as_str())
            && let Some(active_profiles) = index.go_file_active_profiles.get(node.id.as_str())
        {
            usage_profiles.extend(active_profiles.iter().copied());
        }
        blockers.extend(
            index
                .go_file_blockers
                .get(node.id.as_str())
                .into_iter()
                .flatten()
                .cloned(),
        );
    }
    let mut unused_across_profiles = true;
    for profile in &applicable {
        budget.step(is_cancelled)?;
        if index.profiles_by_id.contains_key(profile.as_str())
            && usage_profiles.contains(profile.as_str())
        {
            unused_across_profiles = false;
            break;
        }
    }
    if !unused_across_profiles {
        return Ok(None);
    }
    if usage.is_empty() && applicable.is_empty() && incoming.is_empty() {
        // Keep isolated subjects; they are unused unless blocked.
    } else if !usage.is_empty() && unused_across_profiles {
        blockers.push(FindingBlocker {
            kind: BlockerKind::ProfileNotAnalyzed,
            detail: "incoming usage exists in a non-applicable profile only".to_owned(),
        });
    }
    let profiles_complete = profiles_satisfy(
        index,
        &applicable,
        profile_is_semantically_complete,
        budget,
        is_cancelled,
    )?;
    let profiles_have_minimum_coverage = profiles_satisfy(
        index,
        &applicable,
        profile_has_syntax_coverage,
        budget,
        is_cancelled,
    )?;
    if !profiles_have_minimum_coverage
        && !blockers
            .iter()
            .any(|blocker| blocker.kind == BlockerKind::IncompleteCoverage)
    {
        blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: "an applicable profile is below syntax-complete".to_owned(),
        });
    }
    blockers.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then(left.detail.cmp(&right.detail))
    });
    blockers.dedup();
    let location = subject_location(node);
    let path = location
        .as_ref()
        .map(|value| value.path.clone())
        .unwrap_or_else(|| node.locator.clone());
    let mut evidence = Vec::with_capacity(usage.len());
    for edge in &usage {
        budget.step(is_cancelled)?;
        evidence.push(FindingEvidenceRef {
            owner_type: "edge".to_owned(),
            owner_id: edge.id.clone(),
            kind: edge.kind.clone(),
            path: edge.profile_id.clone(),
        });
    }
    Ok(Some(finish_finding(
        FindingIdentity {
            kind,
            subject_id: node.id.clone(),
            profile_scope: None,
            witness_key: serde_json::json!({ "path": path, "subject_id": node.id }),
        },
        node.kind.clone(),
        location,
        format!(
            "{} {} has no incoming usage edges across applicable profiles",
            kind.as_str(),
            node.display_name
        ),
        blockers,
        evidence,
        vec![Remediation {
            kind: "manual-review".to_owned(),
            detail: "review blockers before deleting or unexporting the subject".to_owned(),
        }],
        Vec::new(),
        !unused_across_profiles,
        profiles_complete,
    )))
}

struct SnapshotIndex<'a> {
    incoming: HashMap<&'a str, Vec<&'a EdgeRecord>>,
    // Go imports are resolved to package/module nodes because a Go package is
    // compiled as one unit. Keep production package-level usage profiles
    // alongside the ordinary incoming-edge index so file findings do not
    // mistake an imported package's production files for unused files.
    go_file_usage_profiles: HashMap<&'a str, HashSet<&'a str>>,
    // A package import can be unresolved between multiple local package
    // candidates, or its condition can be undecidable for a profile. Those
    // states must remain visible on every affected source file rather than
    // silently becoming Confirmed unused findings.
    go_file_blockers: HashMap<&'a str, Vec<FindingBlocker>>,
    go_file_active_profiles: HashMap<&'a str, HashSet<&'a str>>,
    // Assembly and other production file nodes can carry the package scope
    // without a package_name property.
    go_main_file_ids: HashSet<&'a str>,
    sites_by_target: HashMap<&'a str, Vec<&'a SiteRecord>>,
    dynamic_site_ids: HashSet<&'a str>,
    targetless_candidate: bool,
    targetless_unresolved: bool,
    targetless_dynamic: bool,
    coverage_omitted_paths: HashSet<&'a str>,
    profiles_by_id: HashMap<&'a str, &'a depgraph_store::ProfileRecord>,
    profile_ids_by_language: HashMap<String, Vec<&'a str>>,
    fixture_profile_ids: Vec<&'a str>,
    all_profile_ids: Vec<&'a str>,
    matrix_profile_ids_by_language: HashMap<String, Vec<&'a str>>,
    fixture_matrix_profile_ids: Vec<&'a str>,
    all_matrix_profile_ids: Vec<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GoPackageIdentity<'a> {
    package_path: &'a str,
    module_path: Option<&'a str>,
    manifest_path: Option<&'a str>,
}

impl<'a> SnapshotIndex<'a> {
    fn build(
        snapshot: &'a GraphSnapshot,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, HealthAnalysisError> {
        let mut incoming = HashMap::<&str, Vec<&EdgeRecord>>::new();
        for edge in &snapshot.edges {
            budget.step(is_cancelled)?;
            incoming.entry(edge.target.as_str()).or_default().push(edge);
        }

        let mut profiles_by_id = HashMap::new();
        let mut profile_ids_by_language = HashMap::<String, Vec<&str>>::new();
        let mut fixture_profile_ids = Vec::new();
        let mut all_profile_ids = Vec::new();
        for profile in &snapshot.profiles {
            budget.step(is_cancelled)?;
            profiles_by_id.insert(profile.id.as_str(), profile);
            all_profile_ids.push(profile.id.as_str());
            if profile.language == "fixture" {
                fixture_profile_ids.push(profile.id.as_str());
            } else {
                profile_ids_by_language
                    .entry(health_language_family(&profile.language).to_owned())
                    .or_default()
                    .push(profile.id.as_str());
            }
        }

        let mut matrix_profile_ids_by_language = HashMap::<String, Vec<&str>>::new();
        let mut fixture_matrix_profile_ids = Vec::new();
        let mut all_matrix_profile_ids = Vec::new();
        let mut go_profile_ids = BTreeSet::<&str>::new();
        if let Some(profile_ids) = profile_ids_by_language.get("go") {
            go_profile_ids.extend(profile_ids.iter().copied());
        }
        // Build conditions are evaluated against every Go profile represented
        // by the snapshot, including matrix entries that refer to a profile
        // record. This keeps inactive files visible even when they have no
        // package import or main-entry edge.
        for entry in &snapshot.profile_matrix.entries {
            budget.step(is_cancelled)?;
            for profile_id in &entry.profile_ids {
                budget.step(is_cancelled)?;
                all_matrix_profile_ids.push(profile_id.as_str());
                if entry.language == "fixture" {
                    fixture_matrix_profile_ids.push(profile_id.as_str());
                } else {
                    matrix_profile_ids_by_language
                        .entry(health_language_family(&entry.language).to_owned())
                        .or_default()
                        .push(profile_id.as_str());
                    if health_language_family(&entry.language) == "go" {
                        go_profile_ids.insert(profile_id.as_str());
                    }
                }
            }
        }

        let mut go_package_identity_by_id = HashMap::<&str, GoPackageIdentity<'a>>::new();
        let mut go_package_scopes_by_path = HashMap::<&str, BTreeSet<GoPackageIdentity<'a>>>::new();
        let mut go_main_package_scopes = HashSet::<GoPackageIdentity<'a>>::new();
        for node in &snapshot.nodes {
            budget.step(is_cancelled)?;
            if node.kind != "module"
                || node
                    .properties
                    .get("language")
                    .and_then(serde_json::Value::as_str)
                    != Some("go")
            {
                continue;
            }
            if let Some(identity) = go_package_identity(node) {
                go_package_identity_by_id.insert(node.id.as_str(), identity);
                go_package_scopes_by_path
                    .entry(identity.package_path)
                    .or_default()
                    .insert(identity);
                if node
                    .properties
                    .get("package_name")
                    .and_then(serde_json::Value::as_str)
                    == Some("main")
                {
                    go_main_package_scopes.insert(identity);
                }
            }
        }
        let mut go_package_usage_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        let mut go_package_uncertain_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        let mut go_package_candidate_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        for edge in &snapshot.edges {
            budget.step(is_cancelled)?;
            let Some(package_identity) = go_package_identity_by_id.get(edge.target.as_str()) else {
                continue;
            };
            if !is_usage_edge(edge, edge.target.as_str()) {
                continue;
            }
            let condition = go_edge_condition_state(edge, &profiles_by_id, budget, is_cancelled)?;
            if edge.resolution_status == "candidates" {
                if condition != GoConditionState::False {
                    go_package_candidate_profiles
                        .entry(*package_identity)
                        .or_default()
                        .insert(edge.profile_id.as_str());
                }
            } else {
                match (is_definite_usage(edge), condition) {
                    (true, GoConditionState::True) => {
                        go_package_usage_profiles
                            .entry(*package_identity)
                            .or_default()
                            .insert(edge.profile_id.as_str());
                    }
                    (false, GoConditionState::True) | (_, GoConditionState::Unknown) => {
                        go_package_uncertain_profiles
                            .entry(*package_identity)
                            .or_default()
                            .insert(edge.profile_id.as_str());
                    }
                    (_, GoConditionState::False) => {}
                }
            }
        }
        // Preserve the same candidate semantics when a snapshot contains the
        // dependency site but its edge delta was omitted. Worker output
        // normally emits both records, while replayed/partial snapshots are
        // still required to fail closed for every package file target.
        for site in &snapshot.sites {
            budget.step(is_cancelled)?;
            if site.resolution_status != "candidates" {
                continue;
            }
            let condition = go_condition_state(
                &site.condition,
                site.profile_id.as_str(),
                &profiles_by_id,
                budget,
                is_cancelled,
            )?;
            if condition == GoConditionState::False {
                continue;
            }
            for target_id in &site.target_ids {
                budget.step(is_cancelled)?;
                let Some(package_identity) = go_package_identity_by_id.get(target_id.as_str())
                else {
                    continue;
                };
                go_package_candidate_profiles
                    .entry(*package_identity)
                    .or_default()
                    .insert(site.profile_id.as_str());
            }
        }
        let mut go_file_usage_profiles = HashMap::<&str, HashSet<&str>>::new();
        let mut go_file_blockers = HashMap::<&str, Vec<FindingBlocker>>::new();
        let mut go_file_active_profiles = HashMap::<&str, HashSet<&str>>::new();
        let mut go_file_unknown_profiles = HashMap::<&str, HashSet<&str>>::new();
        let mut go_main_file_ids = HashSet::<&str>::new();

        // First evaluate the worker's structured contains conditions once for
        // every Go file/profile pair. The result is also used below when
        // package-level import evidence is projected onto source files.
        for node in &snapshot.nodes {
            budget.step(is_cancelled)?;
            if node.kind != "file"
                || node
                    .properties
                    .get("language")
                    .and_then(serde_json::Value::as_str)
                    != Some("go")
            {
                continue;
            }
            let node_id = node.id.as_str();
            let mut active_profiles = HashSet::new();
            let mut unknown_profiles = HashSet::new();
            for profile_id in &go_profile_ids {
                budget.step(is_cancelled)?;
                match go_file_condition_state(
                    node,
                    profile_id,
                    incoming.get(node_id),
                    &profiles_by_id,
                    budget,
                    is_cancelled,
                )? {
                    GoConditionState::True => {
                        active_profiles.insert(*profile_id);
                    }
                    GoConditionState::False => {}
                    GoConditionState::Unknown => {
                        unknown_profiles.insert(*profile_id);
                        go_file_blockers
                            .entry(node_id)
                            .or_default()
                            .push(go_incomplete_condition_blocker(node, profile_id));
                    }
                }
            }
            let has_build_constraint = node
                .properties
                .get("build_constraint")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|constraint| !constraint.trim().is_empty());
            if has_build_constraint && active_profiles.is_empty() && unknown_profiles.is_empty() {
                go_file_blockers
                    .entry(node_id)
                    .or_default()
                    .push(go_inactive_condition_blocker(node));
            }
            if !active_profiles.is_empty() {
                go_file_active_profiles.insert(node_id, active_profiles);
            }
            if !unknown_profiles.is_empty() {
                go_file_unknown_profiles.insert(node_id, unknown_profiles);
            }
        }

        // Package imports point at a package node. Project exact, uncertain,
        // and candidate package evidence onto each production file only when
        // that file is active in the same profile.
        for node in &snapshot.nodes {
            budget.step(is_cancelled)?;
            if node.kind != "file"
                || node
                    .properties
                    .get("language")
                    .and_then(serde_json::Value::as_str)
                    != Some("go")
                || node
                    .properties
                    .get("test")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
            {
                continue;
            }
            let Some(package_path) = node
                .properties
                .get("package_path")
                .and_then(serde_json::Value::as_str)
            else {
                continue;
            };
            let Some(file_identity) = go_package_identity(node) else {
                continue;
            };
            let active_profiles = go_file_active_profiles.get(node.id.as_str());
            let unknown_profiles = go_file_unknown_profiles.get(node.id.as_str());
            let mut file_profiles = BTreeSet::new();
            if let Some(profiles) = active_profiles {
                for profile_id in profiles {
                    budget.step(is_cancelled)?;
                    file_profiles.insert(*profile_id);
                }
            }
            if let Some(profiles) = unknown_profiles {
                for profile_id in profiles {
                    budget.step(is_cancelled)?;
                    file_profiles.insert(*profile_id);
                }
            }
            let Some(scopes) = go_package_scopes_by_path.get(package_path) else {
                for profile_id in file_profiles {
                    budget.step(is_cancelled)?;
                    go_file_blockers.entry(node.id.as_str()).or_default().push(
                        go_unresolved_package_scope_blocker(package_path, profile_id),
                    );
                }
                continue;
            };
            let mut matching_scopes = Vec::new();
            for scope in scopes {
                budget.step(is_cancelled)?;
                if go_package_scope_matches(file_identity, *scope) {
                    matching_scopes.push(*scope);
                }
            }
            if matching_scopes.len() != 1 {
                // A file that cannot be assigned to exactly one package scope
                // must not inherit a sibling module's usage. Preserve the
                // uncertainty for both zero and multiple matching scopes: a
                // stale file identity can otherwise turn package usage into a
                // Confirmed unused-file result.
                for profile_id in file_profiles {
                    budget.step(is_cancelled)?;
                    go_file_blockers.entry(node.id.as_str()).or_default().push(
                        go_unresolved_package_scope_blocker(package_path, profile_id),
                    );
                    let mut has_candidate = false;
                    for scope in scopes {
                        budget.step(is_cancelled)?;
                        if go_package_candidate_profiles
                            .get(scope)
                            .is_some_and(|profiles| profiles.contains(profile_id))
                        {
                            has_candidate = true;
                            break;
                        }
                    }
                    if has_candidate {
                        go_file_blockers
                            .entry(node.id.as_str())
                            .or_default()
                            .push(go_candidate_package_blocker(package_path, profile_id));
                    }
                }
                continue;
            }
            let scope = matching_scopes[0];
            if go_main_package_scopes.contains(&scope) {
                go_main_file_ids.insert(node.id.as_str());
            }
            let package_profiles = go_package_usage_profiles.get(&scope);
            if let Some(active_profiles) = active_profiles {
                for profile_id in active_profiles {
                    budget.step(is_cancelled)?;
                    if package_profiles.is_some_and(|profiles| profiles.contains(profile_id)) {
                        go_file_usage_profiles
                            .entry(node.id.as_str())
                            .or_default()
                            .insert(*profile_id);
                    }
                }
            }
            let uncertain_profiles = go_package_uncertain_profiles.get(&scope);
            let candidate_profiles = go_package_candidate_profiles.get(&scope);
            for profile_id in file_profiles {
                budget.step(is_cancelled)?;
                if uncertain_profiles.is_some_and(|profiles| profiles.contains(profile_id)) {
                    go_file_blockers.entry(node.id.as_str()).or_default().push(
                        go_incomplete_package_usage_blocker(package_path, profile_id),
                    );
                }
                if candidate_profiles.is_some_and(|profiles| profiles.contains(profile_id)) {
                    go_file_blockers
                        .entry(node.id.as_str())
                        .or_default()
                        .push(go_candidate_package_blocker(package_path, profile_id));
                }
            }
        }
        let mut dynamic_site_ids = HashSet::new();
        for evidence in &snapshot.evidence {
            budget.step(is_cancelled)?;
            if evidence.owner_type == "site"
                && evidence
                    .properties
                    .get("occurrence_kind")
                    .and_then(serde_json::Value::as_str)
                    == Some("dynamic_import")
            {
                dynamic_site_ids.insert(evidence.owner_id.as_str());
            }
        }
        let mut sites_by_target = HashMap::<&str, Vec<&SiteRecord>>::new();
        let mut targetless_candidate = false;
        let mut targetless_unresolved = false;
        let mut targetless_dynamic = false;
        for site in &snapshot.sites {
            budget.step(is_cancelled)?;
            if site.target_ids.is_empty() {
                targetless_candidate |= site.resolution_status == "candidates";
                targetless_unresolved |= site.resolution_status == "unresolved";
                targetless_dynamic |=
                    matches!(site.kind.as_str(), "dynamic_import" | "dynamic-load")
                        || dynamic_site_ids.contains(site.id.as_str());
            }
            for target_id in &site.target_ids {
                budget.step(is_cancelled)?;
                sites_by_target
                    .entry(target_id.as_str())
                    .or_default()
                    .push(site);
            }
        }
        let mut coverage_omitted_paths = HashSet::new();
        for record in &snapshot.file_coverage {
            budget.step(is_cancelled)?;
            if record.skipped || record.reason.as_deref() == Some("unsupported_syntax") {
                coverage_omitted_paths.insert(record.path.as_str());
            }
        }
        Ok(Self {
            incoming,
            go_file_usage_profiles,
            go_file_blockers,
            go_file_active_profiles,
            go_main_file_ids,
            sites_by_target,
            dynamic_site_ids,
            targetless_candidate,
            targetless_unresolved,
            targetless_dynamic,
            coverage_omitted_paths,
            profiles_by_id,
            profile_ids_by_language,
            fixture_profile_ids,
            all_profile_ids,
            matrix_profile_ids_by_language,
            fixture_matrix_profile_ids,
            all_matrix_profile_ids,
        })
    }
}

fn go_package_identity<'a>(node: &'a NodeRecord) -> Option<GoPackageIdentity<'a>> {
    let package_path = node
        .properties
        .get("package_path")
        .and_then(serde_json::Value::as_str)?;
    let optional_property = |key| {
        node.properties
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
    };
    Some(GoPackageIdentity {
        package_path,
        module_path: optional_property("module_path"),
        manifest_path: optional_property("manifest_path"),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GoConditionState {
    True,
    False,
    Unknown,
}

const GOOS_TAGS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

const GOARCH_TAGS: &[&str] = &[
    "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le", "mipsle", "ppc64",
    "ppc64le", "riscv64", "s390x", "sparc64", "wasm",
];

const UNIX_GOOS_TAGS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "linux",
    "netbsd",
    "openbsd",
    "solaris",
];

fn go_edge_condition_state(
    edge: &EdgeRecord,
    profiles_by_id: &HashMap<&str, &depgraph_store::ProfileRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<GoConditionState, HealthAnalysisError> {
    go_condition_state(
        &edge.condition,
        edge.profile_id.as_str(),
        profiles_by_id,
        budget,
        is_cancelled,
    )
}

fn go_condition_state(
    condition_value: &serde_json::Value,
    profile_id: &str,
    profiles_by_id: &HashMap<&str, &depgraph_store::ProfileRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<GoConditionState, HealthAnalysisError> {
    let Some(profile) = profiles_by_id.get(profile_id) else {
        return Ok(GoConditionState::Unknown);
    };
    let Some(condition) = parse_go_condition(condition_value) else {
        return Ok(GoConditionState::Unknown);
    };
    evaluate_go_condition(&condition, profile, 0, budget, is_cancelled)
}

fn go_file_condition_state(
    node: &NodeRecord,
    profile_id: &str,
    incoming: Option<&Vec<&EdgeRecord>>,
    profiles_by_id: &HashMap<&str, &depgraph_store::ProfileRecord>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<GoConditionState, HealthAnalysisError> {
    let has_build_constraint = node
        .properties
        .get("build_constraint")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|constraint| !constraint.trim().is_empty());
    let mut states = Vec::new();
    let mut has_fallback_condition = false;
    if let Some(incoming) = incoming {
        for edge in incoming {
            if edge.profile_id == profile_id && edge.kind == "contains" {
                has_fallback_condition |=
                    has_build_constraint && go_condition_is_always(&edge.condition);
                states.push(go_edge_condition_state(
                    edge,
                    profiles_by_id,
                    budget,
                    is_cancelled,
                )?);
            }
        }
    }
    if has_fallback_condition {
        // A build-constraint parse failure is emitted with the worker's
        // unconditional fallback condition. The non-empty source text keeps
        // that fallback distinguishable from an ordinary unconstrained file.
        return Ok(GoConditionState::Unknown);
    }
    if !states.is_empty() {
        return Ok(combine_go_condition_states(states));
    }
    if has_build_constraint {
        // The worker emits the structured condition on the contains edge. A
        // legacy snapshot with only build_constraint text has no safe way to
        // establish profile truth without reproducing the Go parser, so it is
        // deliberately surfaced as incomplete rather than treated as active.
        Ok(GoConditionState::Unknown)
    } else {
        Ok(GoConditionState::True)
    }
}

fn combine_go_condition_states(states: Vec<GoConditionState>) -> GoConditionState {
    if states.contains(&GoConditionState::True) {
        GoConditionState::True
    } else if states.contains(&GoConditionState::Unknown) {
        GoConditionState::Unknown
    } else {
        GoConditionState::False
    }
}

fn parse_go_condition(value: &serde_json::Value) -> Option<Condition> {
    if value.as_object().is_some_and(|object| object.is_empty()) {
        Some(Condition::default())
    } else {
        serde_json::from_value(value.clone()).ok()
    }
}

fn go_condition_is_always(value: &serde_json::Value) -> bool {
    matches!(
        parse_go_condition(value),
        Some(Condition::All { conditions }) if conditions.is_empty()
    )
}

fn evaluate_go_condition(
    condition: &Condition,
    profile: &depgraph_store::ProfileRecord,
    depth: usize,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<GoConditionState, HealthAnalysisError> {
    budget.step(is_cancelled)?;
    // Conditions are normally validated at ingestion. Keep health analysis
    // bounded anyway because snapshots can be supplied by external workers.
    if depth > 128 {
        return Ok(GoConditionState::Unknown);
    }
    match condition {
        Condition::All { conditions } => {
            let mut saw_false = false;
            let mut saw_unknown = false;
            for child in conditions {
                match evaluate_go_condition(child, profile, depth + 1, budget, is_cancelled)? {
                    GoConditionState::False => saw_false = true,
                    GoConditionState::Unknown => saw_unknown = true,
                    GoConditionState::True => {}
                }
            }
            if saw_false {
                Ok(GoConditionState::False)
            } else if saw_unknown {
                Ok(GoConditionState::Unknown)
            } else {
                Ok(GoConditionState::True)
            }
        }
        Condition::Any { conditions } => {
            let mut saw_true = false;
            let mut saw_unknown = false;
            for child in conditions {
                match evaluate_go_condition(child, profile, depth + 1, budget, is_cancelled)? {
                    GoConditionState::True => saw_true = true,
                    GoConditionState::Unknown => saw_unknown = true,
                    GoConditionState::False => {}
                }
            }
            if saw_true {
                Ok(GoConditionState::True)
            } else if saw_unknown {
                Ok(GoConditionState::Unknown)
            } else {
                Ok(GoConditionState::False)
            }
        }
        Condition::Not { condition } => Ok(
            match evaluate_go_condition(condition, profile, depth + 1, budget, is_cancelled)? {
                GoConditionState::True => GoConditionState::False,
                GoConditionState::False => GoConditionState::True,
                GoConditionState::Unknown => GoConditionState::Unknown,
            },
        ),
        Condition::Eq { key, value } => Ok(profile
            .environment
            .as_object()
            .and_then(|environment| environment.get(key))
            .map_or(GoConditionState::Unknown, |actual| {
                if actual == value {
                    GoConditionState::True
                } else {
                    GoConditionState::False
                }
            })),
        Condition::In { key, values } => Ok(profile
            .environment
            .as_object()
            .and_then(|environment| environment.get(key))
            .map_or(GoConditionState::Unknown, |actual| {
                if values.iter().any(|value| value == actual) {
                    GoConditionState::True
                } else {
                    GoConditionState::False
                }
            })),
        Condition::Defined { key } => Ok(evaluate_go_build_tag(key, profile)),
    }
}

fn evaluate_go_build_tag(key: &str, profile: &depgraph_store::ProfileRecord) -> GoConditionState {
    let Some(tag) = key.strip_prefix("go.build_tag:") else {
        return GoConditionState::Unknown;
    };
    // Compare the actual profile value before consulting the closed list. A
    // newer Go release may use a platform value this binary does not know yet.
    if profile_string(profile, "GOOS") == Some(tag)
        || profile_string(profile, "GOARCH") == Some(tag)
    {
        return GoConditionState::True;
    }
    if GOOS_TAGS.contains(&tag) {
        return profile_string(profile, "GOOS").map_or(GoConditionState::Unknown, |value| {
            if goos_defines_tag(value, tag) {
                GoConditionState::True
            } else {
                GoConditionState::False
            }
        });
    }
    if GOARCH_TAGS.contains(&tag) {
        return profile_string(profile, "GOARCH")
            .map_or(GoConditionState::Unknown, |_| GoConditionState::False);
    }
    if tag == "unix" {
        return profile_string(profile, "GOOS").map_or(GoConditionState::Unknown, |value| {
            if UNIX_GOOS_TAGS.contains(&value) {
                GoConditionState::True
            } else {
                GoConditionState::False
            }
        });
    }
    if tag == "cgo" {
        return profile_string(profile, "CGO_ENABLED").map_or(GoConditionState::Unknown, |value| {
            match value {
                "1" => GoConditionState::True,
                "0" => GoConditionState::False,
                _ => GoConditionState::Unknown,
            }
        });
    }
    // Compiler and release tags require toolchain semantics not represented by
    // the condition evaluator. Preserve them as unknown so they remain a
    // deterministic blocker instead of becoming a false negative.
    if matches!(tag, "gc" | "gccgo") || tag.starts_with("go1.") || tag.starts_with("goexperiment.")
    {
        return GoConditionState::Unknown;
    }
    if profile.features.iter().any(|feature| feature == tag) {
        return GoConditionState::True;
    }
    match profile_string(profile, "GO_TAGS") {
        Some(tags) if tags.split(',').any(|value| value.trim() == tag) => GoConditionState::True,
        Some(_) => GoConditionState::False,
        None => GoConditionState::Unknown,
    }
}

fn goos_defines_tag(goos: &str, tag: &str) -> bool {
    goos == tag
        || matches!(
            (goos, tag),
            ("android", "linux") | ("ios", "darwin") | ("illumos", "solaris")
        )
}

fn profile_string<'a>(profile: &'a depgraph_store::ProfileRecord, key: &str) -> Option<&'a str> {
    profile
        .environment
        .as_object()
        .and_then(|environment| environment.get(key))
        .and_then(serde_json::Value::as_str)
}

fn go_incomplete_condition_blocker(node: &NodeRecord, profile_id: &str) -> FindingBlocker {
    FindingBlocker {
        kind: BlockerKind::IncompleteCoverage,
        detail: format!(
            "Go build condition for {} is unsupported or ambiguous in profile {profile_id}",
            go_file_display_name(node)
        ),
    }
}

fn go_inactive_condition_blocker(node: &NodeRecord) -> FindingBlocker {
    FindingBlocker {
        kind: BlockerKind::IncompleteCoverage,
        detail: format!(
            "Go build condition for {} is inactive in every analyzed Go profile",
            go_file_display_name(node)
        ),
    }
}

fn go_incomplete_package_usage_blocker(package_path: &str, profile_id: &str) -> FindingBlocker {
    FindingBlocker {
        kind: BlockerKind::IncompleteCoverage,
        detail: format!(
            "Go package usage for {package_path} is unresolved, imprecise, or conditionally ambiguous in profile {profile_id}"
        ),
    }
}

fn go_candidate_package_blocker(package_path: &str, profile_id: &str) -> FindingBlocker {
    FindingBlocker {
        kind: BlockerKind::Candidate,
        detail: format!(
            "Go package import target {package_path} is a candidate in profile {profile_id}"
        ),
    }
}

fn go_unresolved_package_scope_blocker(package_path: &str, profile_id: &str) -> FindingBlocker {
    FindingBlocker {
        kind: BlockerKind::IncompleteCoverage,
        detail: format!(
            "Go package scope for {package_path} is missing or ambiguous in profile {profile_id}"
        ),
    }
}

fn go_file_display_name(node: &NodeRecord) -> &str {
    node.properties
        .get("path")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            node.properties
                .get("source_path")
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or(node.locator.as_str())
}

fn go_package_scope_matches(file: GoPackageIdentity<'_>, package: GoPackageIdentity<'_>) -> bool {
    file.package_path == package.package_path
        && file
            .module_path
            .is_none_or(|module_path| package.module_path == Some(module_path))
        && file
            .manifest_path
            .is_none_or(|manifest_path| package.manifest_path == Some(manifest_path))
}

fn is_usage_edge(edge: &EdgeRecord, subject_id: &str) -> bool {
    edge.source != subject_id
        && !STRUCTURAL_EDGE_KINDS.contains(&edge.kind.as_str())
        && !matches!(edge.kind.as_str(), "depends_on" | "build_depends_on")
}

fn is_definite_usage(edge: &EdgeRecord) -> bool {
    edge.resolution_status == "resolved" && matches!(edge.precision.as_str(), "exact" | "precise")
}

fn collect_surface_blockers(node: &NodeRecord, blockers: &mut Vec<FindingBlocker>) {
    let classified = classify_surface(node);
    let kind = match classified.role {
        SurfaceRole::EntryPoint => Some(BlockerKind::EntryPoint),
        SurfaceRole::PublicSurface => Some(BlockerKind::PublicSurface),
        SurfaceRole::DynamicLoading => Some(BlockerKind::DynamicLoading),
        SurfaceRole::Generated => Some(BlockerKind::GeneratedArtifact),
        SurfaceRole::InsufficientEvidence => Some(BlockerKind::InsufficientSurfaceEvidence),
        SurfaceRole::Internal => None,
    };
    if let Some(kind) = kind {
        blockers.push(FindingBlocker {
            kind,
            detail: classified.reasons.join("; "),
        });
    }
}

fn collect_edge_blockers(
    usage: &[&EdgeRecord],
    blockers: &mut Vec<FindingBlocker>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    for edge in usage {
        budget.step(is_cancelled)?;
        match edge.resolution_status.as_str() {
            "candidates" => blockers.push(FindingBlocker {
                kind: BlockerKind::Candidate,
                detail: format!("edge {} is a candidate", edge.id),
            }),
            "unresolved" => blockers.push(FindingBlocker {
                kind: BlockerKind::Unresolved,
                detail: format!("edge {} is unresolved", edge.id),
            }),
            _ => {}
        }
        match edge.precision.as_str() {
            "heuristic" => blockers.push(FindingBlocker {
                kind: BlockerKind::HeuristicPrecision,
                detail: format!("edge {} is heuristic", edge.id),
            }),
            "overapprox" => blockers.push(FindingBlocker {
                kind: BlockerKind::OverapproxPrecision,
                detail: format!("edge {} is overapprox", edge.id),
            }),
            _ => {}
        }
    }
    Ok(())
}

fn collect_site_blockers(
    index: &SnapshotIndex<'_>,
    subject_id: &str,
    blockers: &mut Vec<FindingBlocker>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    for site in index.sites_by_target.get(subject_id).into_iter().flatten() {
        budget.step(is_cancelled)?;
        let dynamic = matches!(site.kind.as_str(), "dynamic_import" | "dynamic-load")
            || index.dynamic_site_ids.contains(site.id.as_str());
        if dynamic {
            blockers.push(FindingBlocker {
                kind: BlockerKind::DynamicLoading,
                detail: format!(
                    "site {} reaches the subject through dynamic loading",
                    site.id
                ),
            });
        }
        match site.resolution_status.as_str() {
            "candidates" => blockers.push(FindingBlocker {
                kind: BlockerKind::Candidate,
                detail: format!("site {} lists the subject as a candidate", site.id),
            }),
            "unresolved" => blockers.push(FindingBlocker {
                kind: BlockerKind::Unresolved,
                detail: format!("site {} lists the subject as unresolved", site.id),
            }),
            _ => {}
        }
    }
    if index.targetless_candidate {
        blockers.push(FindingBlocker {
            kind: BlockerKind::Candidate,
            detail: "a candidate site has no target identity and may hide subject usage".to_owned(),
        });
    }
    if index.targetless_unresolved {
        blockers.push(FindingBlocker {
            kind: BlockerKind::Unresolved,
            detail: "an unresolved site has no target identity and may hide subject usage"
                .to_owned(),
        });
    }
    if index.targetless_dynamic {
        blockers.push(FindingBlocker {
            kind: BlockerKind::DynamicLoading,
            detail: "a dynamic-loading site has no target identity and may hide subject usage"
                .to_owned(),
        });
    }
    Ok(())
}

fn collect_coverage_blockers(
    index: &SnapshotIndex<'_>,
    node: &NodeRecord,
    blockers: &mut Vec<FindingBlocker>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    let path = node
        .properties
        .get("path")
        .and_then(|value| value.as_str())
        .or_else(|| {
            node.properties
                .get("source_path")
                .and_then(|value| value.as_str())
        });
    let Some(path) = path else {
        return Ok(());
    };
    budget.step(is_cancelled)?;
    if index.coverage_omitted_paths.contains(path) {
        blockers.push(FindingBlocker {
            kind: BlockerKind::CoverageOmission,
            detail: format!("file coverage skipped or unsupported {path}"),
        });
    }
    Ok(())
}

fn applicable_profiles(
    index: &SnapshotIndex<'_>,
    node: &NodeRecord,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<BTreeSet<String>, HealthAnalysisError> {
    let explicit_profile = node
        .properties
        .get("profile_id")
        .and_then(|value| value.as_str());
    let language = node
        .properties
        .get("language")
        .and_then(|value| value.as_str());
    let mut profiles = BTreeSet::new();
    if let Some(profile_id) = explicit_profile {
        budget.step(is_cancelled)?;
        profiles.insert(profile_id.to_owned());
    }
    if let Some(language) = language {
        let language = health_language_family(language);
        for profile_id in index
            .profile_ids_by_language
            .get(language)
            .into_iter()
            .flatten()
            .chain(&index.fixture_profile_ids)
            .chain(
                index
                    .matrix_profile_ids_by_language
                    .get(language)
                    .into_iter()
                    .flatten(),
            )
            .chain(&index.fixture_matrix_profile_ids)
        {
            budget.step(is_cancelled)?;
            profiles.insert((*profile_id).to_owned());
        }
    } else {
        for profile_id in index
            .all_profile_ids
            .iter()
            .chain(&index.all_matrix_profile_ids)
        {
            budget.step(is_cancelled)?;
            profiles.insert((*profile_id).to_owned());
        }
    }
    Ok(profiles)
}

fn health_language_family(language: &str) -> &str {
    match language {
        "typescript" | "javascript" | "ts" | "tsx" | "js" | "jsx" | "astro" | "web" => "web",
        other => other,
    }
}

fn profiles_satisfy(
    index: &SnapshotIndex<'_>,
    applicable: &BTreeSet<String>,
    predicate: fn(&depgraph_store::ProfileRecord) -> bool,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool, HealthAnalysisError> {
    for profile_id in applicable {
        budget.step(is_cancelled)?;
        let matching = index.profiles_by_id.get(profile_id.as_str()).copied();
        if !matching.is_some_and(predicate) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn profile_is_semantically_complete(profile: &depgraph_store::ProfileRecord) -> bool {
    profile.coverage.as_ref().is_some_and(|coverage| {
        coverage
            .completeness
            .iter()
            .any(|level| level == "semantic-complete" || level.ends_with("+semantic-complete"))
    })
}

fn profile_has_syntax_coverage(profile: &depgraph_store::ProfileRecord) -> bool {
    profile.coverage.as_ref().is_some_and(|coverage| {
        coverage.completeness.iter().any(|level| {
            level == "syntax-complete"
                || level == "semantic-complete"
                || level.ends_with("+syntax-complete")
                || level.ends_with("+semantic-complete")
        })
    })
}

fn subject_location(node: &NodeRecord) -> Option<SourceLocation> {
    let path = node
        .properties
        .get("path")
        .and_then(|value| value.as_str())
        .or_else(|| {
            node.properties
                .get("source_path")
                .and_then(|value| value.as_str())
        })?;
    let path = crate::service::RepositoryRelativePath::parse(path)
        .ok()?
        .as_str()
        .to_owned();
    Some(SourceLocation {
        path,
        start_line: node
            .properties
            .get("start_line")
            .and_then(serde_json::Value::as_u64),
        start_column: node
            .properties
            .get("start_column")
            .and_then(serde_json::Value::as_u64),
        end_line: node
            .properties
            .get("end_line")
            .and_then(serde_json::Value::as_u64),
        end_column: node
            .properties
            .get("end_column")
            .and_then(serde_json::Value::as_u64),
    })
}

#[allow(dead_code)]
pub(crate) fn incoming_by_target(snapshot: &GraphSnapshot) -> BTreeMap<&str, Vec<&EdgeRecord>> {
    let mut incoming = BTreeMap::<&str, Vec<&EdgeRecord>>::new();
    for edge in &snapshot.edges {
        incoming.entry(edge.target.as_str()).or_default().push(edge);
    }
    incoming
}

#[allow(dead_code)]
pub(crate) fn sites_by_specifier(snapshot: &GraphSnapshot) -> BTreeMap<String, Vec<&SiteRecord>> {
    let mut sites = BTreeMap::<String, Vec<&SiteRecord>>::new();
    for site in &snapshot.sites {
        if let Some(specifier) = &site.specifier {
            sites.entry(specifier.clone()).or_default().push(site);
        }
    }
    sites
}

#[cfg(test)]
mod tests {
    use depgraph_store::{
        CoverageRecord, EdgeRecord, FileCoverageRecord, GraphSnapshot, NodeRecord, ProfileRecord,
        ScanRecord, SiteRecord,
    };
    use serde_json::json;

    use super::*;
    use crate::health::Confidence;
    use depgraph_store::ProfileMatrixRecord;

    fn scan() -> ScanRecord {
        ScanRecord {
            id: "scan-unused".to_owned(),
            root: "/tmp/fixture".to_owned(),
            status: "completed".to_owned(),
            strict: false,
            started_at: "2026-01-01T00:00:00Z".to_owned(),
            completed_at: Some("2026-01-01T00:00:01Z".to_owned()),
            project_code_executed: false,
            error: None,
            parent_snapshot_id: None,
            source_revision: Some("a".repeat(40)),
            health_policy_config_digest: None,
            health_analyzer_version: None,
            health_finding_contract_version: None,
        }
    }

    fn coverage(complete: bool) -> CoverageRecord {
        CoverageRecord {
            profiles: 1,
            completeness: vec![if complete {
                "semantic-complete".to_owned()
            } else {
                "syntax-complete".to_owned()
            }],
            ..CoverageRecord::default()
        }
    }

    fn profile(id: &str, language: &str, complete: bool) -> ProfileRecord {
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
            coverage: Some(coverage(complete)),
        }
    }

    fn node(
        id: &str,
        kind: &str,
        language: &str,
        path: &str,
        extra: serde_json::Value,
    ) -> NodeRecord {
        let mut properties = extra.as_object().cloned().unwrap_or_default();
        properties.insert("language".to_owned(), json!(language));
        properties.insert("path".to_owned(), json!(path));
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: format!("repo://{path}"),
            display_name: id.to_owned(),
            properties: serde_json::Value::Object(properties),
        }
    }

    fn edge(id: &str, source: &str, target: &str, kind: &str, profile_id: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: None,
            source: source.to_owned(),
            target: target.to_owned(),
            kind: kind.to_owned(),
            phase: "semantic".to_owned(),
            environment: "host".to_owned(),
            profile_id: profile_id.to_owned(),
            resolution_status: "resolved".to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"all","conditions":[]}),
            generated: false,
        }
    }

    fn snapshot(
        profiles: Vec<ProfileRecord>,
        nodes: Vec<NodeRecord>,
        edges: Vec<EdgeRecord>,
        sites: Vec<SiteRecord>,
        file_coverage: Vec<FileCoverageRecord>,
        matrix: depgraph_store::ProfileMatrixRecord,
    ) -> GraphSnapshot {
        GraphSnapshot {
            scan: scan(),
            profiles,
            nodes,
            sites,
            edges,
            evidence: Vec::new(),
            diagnostics: Vec::new(),
            file_coverage,
            adapter_logs: Vec::new(),
            coverage: coverage(true),
            profile_matrix: matrix,
        }
    }

    #[test]
    fn issue_423_detects_unused_file_export_and_type_on_three_languages() {
        let rust = snapshot(
            vec![
                profile("rust:lib", "rust", true),
                profile("go:package", "go", true),
                profile("typescript:source", "typescript", true),
            ],
            vec![
                node("file:dead.rs", "file", "rust", "src/dead.rs", json!({})),
                node(
                    "symbol:helper",
                    "symbol",
                    "go",
                    "pkg/helper.go",
                    json!({"name": "Helper"}),
                ),
                node(
                    "type:Unused",
                    "type",
                    "typescript",
                    "src/unused.ts",
                    json!({"exported": true}),
                ),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&rust);
        assert!(
            findings
                .iter()
                .all(|finding| finding.suppressions.is_empty())
        );
        let kinds = findings
            .iter()
            .map(|finding| finding.kind)
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&FindingKind::UnusedFile));
        assert!(kinds.contains(&FindingKind::UnusedExport));
        assert!(kinds.contains(&FindingKind::UnusedType));
        let file = findings
            .iter()
            .find(|finding| finding.kind == FindingKind::UnusedFile)
            .expect("unused file");
        assert_eq!(file.confidence, Confidence::Confirmed);
    }

    #[test]
    fn issue_423_real_web_profile_owns_typescript_javascript_and_metadata_nodes() {
        let graph = snapshot(
            vec![profile("profile:web", "web", true)],
            vec![
                node(
                    "file:src/index.ts",
                    "file",
                    "typescript",
                    "src/index.ts",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "file:src/used.ts",
                    "file",
                    "typescript",
                    "src/used.ts",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "file:src/unused.ts",
                    "file",
                    "typescript",
                    "src/unused.ts",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "symbol:unusedValue",
                    "symbol",
                    "typescript",
                    "src/unused.ts",
                    json!({"exported": true, "profile_id": "profile:web"}),
                ),
                node(
                    "file:package.json",
                    "file",
                    "data",
                    "package.json",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "file:tsconfig.json",
                    "file",
                    "data",
                    "tsconfig.json",
                    json!({"profile_id": "profile:web"}),
                ),
            ],
            vec![edge(
                "edge:index-used",
                "file:src/index.ts",
                "file:src/used.ts",
                "imports",
                "profile:web",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let findings = analyze_unused(&graph);
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "file:src/used.ts"),
            "an exact incoming Web-profile edge must prevent an unused-file finding"
        );

        let unused_file = findings
            .iter()
            .find(|finding| finding.subject_id == "file:src/unused.ts")
            .expect("unused TypeScript file");
        assert_eq!(unused_file.confidence, Confidence::Confirmed);
        assert!(
            unused_file
                .blockers
                .iter()
                .all(|blocker| { blocker.kind != BlockerKind::ProfileNotAnalyzed })
        );

        let unused_export = findings
            .iter()
            .find(|finding| finding.subject_id == "symbol:unusedValue")
            .expect("unused TypeScript export");
        assert!(
            unused_export
                .blockers
                .iter()
                .all(|blocker| { blocker.kind != BlockerKind::ProfileNotAnalyzed })
        );
        assert!(
            unused_export
                .blockers
                .iter()
                .any(|blocker| { blocker.kind == BlockerKind::PublicSurface })
        );

        for subject in ["file:package.json", "file:tsconfig.json"] {
            let metadata = findings
                .iter()
                .find(|finding| finding.subject_id == subject)
                .expect("project metadata remains visible but blocked");
            assert_eq!(metadata.confidence, Confidence::Indeterminate);
            assert!(
                metadata
                    .blockers
                    .iter()
                    .any(|blocker| { blocker.kind == BlockerKind::EntryPoint })
            );
            assert!(
                metadata
                    .blockers
                    .iter()
                    .all(|blocker| { blocker.kind != BlockerKind::ProfileNotAnalyzed })
            );
        }
    }

    #[test]
    fn issue_437_go_package_usage_marks_all_source_files_in_imported_package() {
        let graph = snapshot(
            vec![profile("profile:go", "go", true)],
            vec![
                node(
                    "go:main",
                    "file",
                    "go",
                    "cmd/main.go",
                    json!({"package_name": "main", "package_path": "example.com/app/cmd"}),
                ),
                node(
                    "go:used",
                    "file",
                    "go",
                    "pkg/used.go",
                    json!({"package_path": "example.com/app/pkg"}),
                ),
                node(
                    "go:other",
                    "file",
                    "go",
                    "pkg/other.go",
                    json!({"package_path": "example.com/app/pkg"}),
                ),
                node(
                    "go:package-test",
                    "file",
                    "go",
                    "pkg/other_test.go",
                    json!({"package_path": "example.com/app/pkg", "test": true}),
                ),
                node(
                    "go:unused",
                    "file",
                    "go",
                    "unused/unused.go",
                    json!({"package_path": "example.com/app/unused"}),
                ),
                node(
                    "go:pkg",
                    "module",
                    "go",
                    "pkg",
                    json!({"package_path": "example.com/app/pkg"}),
                ),
                node(
                    "go:main-package",
                    "module",
                    "go",
                    "cmd",
                    json!({"package_name": "main", "package_path": "example.com/app/cmd"}),
                ),
                node(
                    "go:unused-package",
                    "module",
                    "go",
                    "unused",
                    json!({"package_path": "example.com/app/unused"}),
                ),
            ],
            vec![edge(
                "edge:import",
                "go:main",
                "go:pkg",
                "imports",
                "profile:go",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let findings = analyze_unused(&graph);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.kind == FindingKind::UnusedFile)
                .map(|finding| finding.subject_id.as_str())
                .collect::<Vec<_>>(),
            vec!["go:unused", "go:package-test"]
        );
        for subject in ["go:main", "go:used", "go:other"] {
            assert!(
                findings.iter().all(|finding| finding.subject_id != subject),
                "imported Go package file {subject} must not be reported unused"
            );
        }
    }

    #[test]
    fn issue_437_go_main_package_marks_every_production_file_but_not_test_files() {
        let graph = snapshot(
            vec![profile("profile:go", "go", true)],
            vec![
                node(
                    "go:entry-helper",
                    "file",
                    "go",
                    "cmd/bootstrap.go",
                    json!({"package_name": "main", "package_path": "example.com/app/cmd", "test": false}),
                ),
                node(
                    "go:entry-assembly",
                    "file",
                    "go",
                    "cmd/entry.s",
                    json!({
                        "assembly": true,
                        "package_path": "example.com/app/cmd",
                        "manifest_path": "cmd/go.mod"
                    }),
                ),
                node(
                    "go:entry-test",
                    "file",
                    "go",
                    "cmd/bootstrap_test.go",
                    json!({"package_name": "main", "package_path": "example.com/app/cmd", "test": true}),
                ),
                node(
                    "go:stale-main",
                    "file",
                    "go",
                    "stale/main.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd",
                        "module_path": "example.com/stale",
                        "manifest_path": "stale/go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:orphan-assembly",
                    "file",
                    "go",
                    "orphan/entry.s",
                    json!({
                        "assembly": true,
                        "package_path": "example.com/app/orphan",
                        "manifest_path": "go.mod"
                    }),
                ),
                node(
                    "go:ordinary",
                    "file",
                    "go",
                    "pkg/ordinary.go",
                    json!({"package_name": "pkg", "package_path": "example.com/app/pkg", "test": false}),
                ),
                node(
                    "go:entry-package",
                    "module",
                    "go",
                    "cmd",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd",
                        "module_path": "example.com/app",
                        "manifest_path": "cmd/go.mod"
                    }),
                ),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let findings = analyze_unused(&graph);
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "go:entry-helper"),
            "every production file in a Go main package is an entry surface"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject_id == "go:entry-test"),
            "worker-emitted test=true files remain separate from the production entry surface"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject_id == "go:ordinary")
        );
        for subject_id in ["go:stale-main", "go:orphan-assembly"] {
            let finding = findings
                .iter()
                .find(|finding| finding.subject_id == subject_id)
                .expect("unverified Go package scope remains visible");
            assert_eq!(finding.confidence, Confidence::Indeterminate);
            assert!(finding.blockers.iter().any(|blocker| {
                blocker.kind == BlockerKind::IncompleteCoverage
                    && blocker.detail.contains("missing or ambiguous")
            }));
        }
    }

    #[test]
    fn issue_437_go_inactive_main_file_is_not_marked_used_by_entry_semantics() {
        let profile_id = "profile:go-linux";
        let mut profile = profile(profile_id, "go", true);
        profile.environment = json!({
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "0",
            "GO_TAGS": ""
        });
        let mut build_edge = edge(
            "edge:windows-file",
            "go:normal-unit",
            "go:windows-file",
            "contains",
            profile_id,
        );
        build_edge.condition = json!({
            "op": "defined",
            "key": "go.build_tag:windows"
        });
        let graph = snapshot(
            vec![profile],
            vec![
                node(
                    "go:windows-file",
                    "file",
                    "go",
                    "cmd/windows.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd",
                        "build_constraint": "windows"
                    }),
                ),
                node(
                    "go:normal-file",
                    "file",
                    "go",
                    "cmd/main.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd"
                    }),
                ),
                node(
                    "go:inactive-helper",
                    "file",
                    "go",
                    "internal/windows.go",
                    json!({
                        "package_name": "helper",
                        "package_path": "example.com/app/internal",
                        "build_constraint": "windows"
                    }),
                ),
            ],
            vec![build_edge, {
                let mut edge = edge(
                    "edge:windows-helper",
                    "go:normal-unit",
                    "go:inactive-helper",
                    "contains",
                    profile_id,
                );
                edge.condition = json!({
                    "op": "defined",
                    "key": "go.build_tag:windows"
                });
                edge
            }],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&graph);
        let finding = findings
            .iter()
            .find(|finding| finding.subject_id == "go:windows-file")
            .expect("inactive Go file remains visible to unused analysis");
        assert_eq!(finding.confidence, Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker
                    .detail
                    .contains("inactive in every analyzed Go profile")
        }));
        let helper_finding = findings
            .iter()
            .find(|finding| finding.subject_id == "go:inactive-helper")
            .expect("inactive non-main Go file remains visible to unused analysis");
        assert_eq!(helper_finding.confidence, Confidence::Indeterminate);
        assert!(helper_finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker
                    .detail
                    .contains("inactive in every analyzed Go profile")
        }));
    }

    #[test]
    fn issue_437_go_unsupported_build_condition_is_indeterminate() {
        let profile_id = "profile:go-unknown";
        let mut build_edge = edge(
            "edge:unknown-file",
            "go:normal-unit",
            "go:unknown-file",
            "contains",
            profile_id,
        );
        build_edge.condition = json!({
            "op": "defined",
            "key": "go.build_tag:windows"
        });
        let graph = snapshot(
            vec![profile(profile_id, "go", true)],
            vec![node(
                "go:unknown-file",
                "file",
                "go",
                "cmd/windows.go",
                json!({
                    "package_name": "main",
                    "package_path": "example.com/app/cmd",
                    "build_constraint": "windows"
                }),
            )],
            vec![build_edge],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:unknown-file")
            .expect("unsupported Go condition remains visible");
        assert_eq!(finding.confidence, Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("unsupported or ambiguous")
        }));
    }

    #[test]
    fn issue_437_go_malformed_build_condition_fallback_is_indeterminate() {
        let profile_id = "profile:go-linux";
        let build_edge = edge(
            "edge:malformed-file",
            "go:normal-unit",
            "go:malformed-file",
            "contains",
            profile_id,
        );
        let mut profile = profile(profile_id, "go", true);
        profile.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let graph = snapshot(
            vec![profile],
            vec![node(
                "go:malformed-file",
                "file",
                "go",
                "cmd/malformed.go",
                json!({
                    "package_name": "main",
                    "package_path": "example.com/app/cmd",
                    "build_constraint": "linux && ("
                }),
            )],
            vec![build_edge],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:malformed-file")
            .expect("malformed Go condition remains visible");
        assert_eq!(finding.confidence, Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("unsupported or ambiguous")
        }));
    }

    #[test]
    fn issue_437_go_standard_goos_aliases_are_active() {
        for (goos, tag) in [
            ("android", "linux"),
            ("ios", "darwin"),
            ("illumos", "solaris"),
        ] {
            let mut profile = profile("profile:go", "go", true);
            profile.environment = json!({"GOOS": goos, "GOARCH": "amd64"});
            assert_eq!(
                evaluate_go_build_tag(&format!("go.build_tag:{tag}"), &profile),
                GoConditionState::True,
                "{goos} should define the {tag} build tag"
            );
        }
    }

    #[test]
    fn issue_437_go_condition_decisive_branch_overrides_unknown() {
        let mut go_profile = profile("profile:go", "go", true);
        go_profile.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let unknown = Condition::Defined {
            key: "go.build_tag:custom".to_owned(),
        };
        let false_and_unknown = Condition::All {
            conditions: vec![
                Condition::Defined {
                    key: "go.build_tag:windows".to_owned(),
                },
                unknown.clone(),
            ],
        };
        let true_or_unknown = Condition::Any {
            conditions: vec![
                Condition::Defined {
                    key: "go.build_tag:linux".to_owned(),
                },
                unknown,
            ],
        };
        let mut budget = HealthAnalysisBudget::new(64);
        let mut is_cancelled = || false;
        assert_eq!(
            evaluate_go_condition(
                &false_and_unknown,
                &go_profile,
                0,
                &mut budget,
                &mut is_cancelled,
            ),
            Ok(GoConditionState::False)
        );
        assert_eq!(
            evaluate_go_condition(
                &true_or_unknown,
                &go_profile,
                0,
                &mut budget,
                &mut is_cancelled,
            ),
            Ok(GoConditionState::True)
        );
        assert_eq!(
            combine_go_condition_states(vec![GoConditionState::Unknown, GoConditionState::True,]),
            GoConditionState::True
        );
    }

    #[test]
    fn issue_437_go_candidate_package_import_blocks_every_target_file() {
        let profile_id = "profile:go-candidate";
        let graph = snapshot(
            vec![profile(profile_id, "go", true)],
            vec![
                node(
                    "go:caller",
                    "file",
                    "go",
                    "cmd/main.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:package",
                    "module",
                    "go",
                    "pkg",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod"
                    }),
                ),
                node(
                    "go:file-a",
                    "file",
                    "go",
                    "pkg/a.go",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:file-b",
                    "file",
                    "go",
                    "pkg/b.go",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:stale-file",
                    "file",
                    "go",
                    "stale/pkg.go",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/stale",
                        "manifest_path": "stale/go.mod",
                        "test": false
                    }),
                ),
            ],
            vec![{
                let mut candidate = edge(
                    "edge:candidate-package",
                    "go:caller",
                    "go:package",
                    "imports",
                    profile_id,
                );
                candidate.resolution_status = "candidates".to_owned();
                candidate
            }],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&graph);
        for subject_id in ["go:file-a", "go:file-b", "go:stale-file"] {
            let finding = findings
                .iter()
                .find(|finding| finding.subject_id == subject_id)
                .expect("candidate package file remains visible");
            assert_eq!(finding.confidence, Confidence::Indeterminate);
            assert!(finding.blockers.iter().any(|blocker| {
                blocker.kind == BlockerKind::Candidate && blocker.detail.contains("is a candidate")
            }));
            if subject_id == "go:stale-file" {
                assert!(finding.blockers.iter().any(|blocker| {
                    blocker.kind == BlockerKind::IncompleteCoverage
                        && blocker.detail.contains("missing or ambiguous")
                }));
            }
        }
    }

    #[test]
    fn issue_437_go_imprecise_package_import_blocks_target_files() {
        let profile_id = "profile:go-imprecise";
        let mut import = edge(
            "edge:imprecise-package",
            "go:caller",
            "go:package",
            "imports",
            profile_id,
        );
        import.precision = "overapprox".to_owned();
        let graph = snapshot(
            vec![profile(profile_id, "go", true)],
            vec![
                node(
                    "go:caller",
                    "file",
                    "go",
                    "cmd/main.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/app/cmd",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:package",
                    "module",
                    "go",
                    "pkg",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod"
                    }),
                ),
                node(
                    "go:file",
                    "file",
                    "go",
                    "pkg/lib.go",
                    json!({
                        "package_name": "pkg",
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
            ],
            vec![import],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:file")
            .expect("imprecisely imported package file remains visible");
        assert_eq!(finding.confidence, Confidence::Indeterminate);
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::IncompleteCoverage
                && blocker.detail.contains("unresolved, imprecise")
        }));
    }

    #[test]
    fn issue_437_go_package_usage_keeps_same_package_path_scopes_separate() {
        let graph = snapshot(
            vec![profile("profile:go", "go", true)],
            vec![
                node(
                    "go:caller",
                    "file",
                    "go",
                    "caller/main.go",
                    json!({
                        "package_name": "main",
                        "package_path": "example.com/caller",
                        "module_path": "example.com/caller",
                        "manifest_path": "caller/go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:shared-a",
                    "module",
                    "go",
                    "shared-a",
                    json!({
                        "package_path": "example.com/shared",
                        "module_path": "example.com/first",
                        "manifest_path": "first/go.mod"
                    }),
                ),
                node(
                    "go:shared-b",
                    "module",
                    "go",
                    "shared-b",
                    json!({
                        "package_path": "example.com/shared",
                        "module_path": "example.com/second",
                        "manifest_path": "second/go.mod"
                    }),
                ),
                node(
                    "go:file-a",
                    "file",
                    "go",
                    "first/shared.go",
                    json!({
                        "package_name": "shared",
                        "package_path": "example.com/shared",
                        "module_path": "example.com/first",
                        "manifest_path": "first/go.mod",
                        "test": false
                    }),
                ),
                node(
                    "go:file-b",
                    "file",
                    "go",
                    "second/shared.go",
                    json!({
                        "package_name": "shared",
                        "package_path": "example.com/shared",
                        "module_path": "example.com/second",
                        "manifest_path": "second/go.mod",
                        "test": false
                    }),
                ),
            ],
            vec![edge(
                "edge:import-first",
                "go:caller",
                "go:shared-a",
                "imports",
                "profile:go",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let findings = analyze_unused(&graph);
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "go:file-a"),
            "the imported module scope marks its own package files used"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject_id == "go:file-b"),
            "a sibling module with the same package_path remains independently analyzable"
        );
    }

    #[test]
    fn issue_436_unused_health_probe_equivalent_file_is_detected() {
        const PROBE_PATH: &str = "workers/web/src/dogfood/unused-health-probe.ts";
        let graph = snapshot(
            vec![profile("profile:web", "web", true)],
            vec![
                node(
                    "file:workers/web/src/worker.ts",
                    "file",
                    "typescript",
                    "workers/web/src/worker.ts",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "file:workers/web/src/scanner.ts",
                    "file",
                    "typescript",
                    "workers/web/src/scanner.ts",
                    json!({"profile_id": "profile:web"}),
                ),
                node(
                    "file:probe",
                    "file",
                    "typescript",
                    PROBE_PATH,
                    json!({"profile_id": "profile:web"}),
                ),
            ],
            vec![edge(
                "edge:worker-scanner",
                "file:workers/web/src/worker.ts",
                "file:workers/web/src/scanner.ts",
                "imports",
                "profile:web",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let findings = analyze_unused(&graph);
        let probe = findings
            .iter()
            .find(|finding| {
                finding.kind == FindingKind::UnusedFile
                    && finding
                        .location
                        .as_ref()
                        .is_some_and(|location| location.path == PROBE_PATH)
            })
            .expect("probe-equivalent unreferenced file must produce unused-file");
        assert_eq!(probe.confidence, Confidence::Confirmed);
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "file:workers/web/src/scanner.ts"),
            "a referenced TypeScript file must not be reported unused"
        );
    }

    #[test]
    fn issue_423_syntax_coverage_is_probable_and_missing_language_profile_is_indeterminate() {
        let graph = snapshot(
            vec![profile("rust:lib", "rust", false)],
            vec![
                node("file:rust.rs", "file", "rust", "src/rust.rs", json!({})),
                node("file:go.go", "file", "go", "pkg/go.go", json!({})),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&graph);
        let rust = findings
            .iter()
            .find(|finding| finding.subject_id == "file:rust.rs")
            .expect("Rust finding");
        assert_eq!(rust.confidence, Confidence::Probable);
        assert!(rust.blockers.is_empty());

        let go = findings
            .iter()
            .find(|finding| finding.subject_id == "file:go.go")
            .expect("Go finding");
        assert_eq!(go.confidence, Confidence::Indeterminate);
        assert!(
            go.blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::ProfileNotAnalyzed)
        );
    }

    #[test]
    fn issue_423_missing_language_and_profiles_cannot_confirm_unused() {
        let mut subject = node("file:unknown", "file", "rust", "src/unknown.txt", json!({}));
        subject
            .properties
            .as_object_mut()
            .expect("node properties")
            .remove("language");
        let graph = snapshot(
            Vec::new(),
            vec![subject],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "file:unknown")
            .expect("unknown-language finding");
        assert_eq!(finding.confidence, Confidence::Indeterminate);
        assert!(
            finding
                .blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::ProfileNotAnalyzed)
        );
    }

    #[test]
    fn issue_423_unused_analysis_is_bounded_and_cancellable() {
        let graph = snapshot(
            vec![profile("rust:lib", "rust", true)],
            vec![node(
                "file:unused.rs",
                "file",
                "rust",
                "src/unused.rs",
                json!({}),
            )],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        assert_eq!(
            analyze_unused_cancellable(&graph, usize::MAX, 0, || false),
            Err(HealthAnalysisError::ResourceExhausted)
        );
        assert_eq!(
            analyze_unused_cancellable(&graph, usize::MAX, usize::MAX, || true),
            Err(HealthAnalysisError::Cancelled)
        );
    }

    #[test]
    fn issue_423_targetless_unresolved_sites_block_confirmation_and_internal_symbols_are_skipped() {
        let graph = snapshot(
            vec![profile("rust:lib", "rust", true)],
            vec![
                node("file:unused.rs", "file", "rust", "src/unused.rs", json!({})),
                node(
                    "symbol:private",
                    "symbol",
                    "typescript",
                    "src/private.ts",
                    json!({"name": "privateHelper", "exported": false}),
                ),
            ],
            Vec::new(),
            vec![SiteRecord {
                id: "site:unknown".to_owned(),
                source: "file:unused.rs".to_owned(),
                kind: "dynamic_import".to_owned(),
                specifier: None,
                profile_id: "rust:lib".to_owned(),
                resolution_status: "unresolved".to_owned(),
                precision: "overapprox".to_owned(),
                condition: json!({}),
                target_ids: Vec::new(),
                reason: Some("dynamic target".to_owned()),
            }],
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&graph);
        let file = findings
            .iter()
            .find(|finding| finding.subject_id == "file:unused.rs")
            .expect("unused file");
        assert_eq!(file.confidence, Confidence::Indeterminate);
        assert!(
            file.blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::Unresolved)
        );
        assert!(
            file.blockers
                .iter()
                .any(|blocker| blocker.kind == BlockerKind::DynamicLoading)
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "symbol:private")
        );
    }

    #[test]
    fn issue_423_cross_profile_reference_prevents_unused() {
        let graph = snapshot(
            vec![
                profile("profile:a", "rust", true),
                profile("profile:b", "rust", true),
            ],
            vec![
                node("file:used.rs", "file", "rust", "src/used.rs", json!({})),
                node("file:src.rs", "file", "rust", "src/src.rs", json!({})),
            ],
            vec![edge(
                "edge:b",
                "file:src.rs",
                "file:used.rs",
                "imports",
                "profile:b",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let findings = analyze_unused(&graph);
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject_id != "file:used.rs")
        );
    }

    #[test]
    fn issue_423_unanalyzed_profile_and_counterexamples_do_not_confirm() {
        let mut matrix = ProfileMatrixRecord::default();
        matrix
            .entries
            .push(depgraph_store::ProfileMatrixEntryRecord {
                id: "entry:rust".to_owned(),
                effective_input_id: "entry:rust".to_owned(),
                language: "rust".to_owned(),
                profile_ids: vec!["profile:a".to_owned(), "profile:missing".to_owned()],
                parent_profile_ids: Vec::new(),
                phases: vec!["semantic".to_owned()],
                condition_union: json!({}),
                phase_coverage: BTreeMap::new(),
                selection_reasons: Vec::new(),
                axis_conflicts: Vec::new(),
            });
        let mut candidate_edge = edge(
            "edge:candidate",
            "file:other.rs",
            "file:public.rs",
            "imports",
            "profile:a",
        );
        candidate_edge.resolution_status = "candidates".to_owned();
        let graph = snapshot(
            vec![profile("profile:a", "rust", false)],
            vec![
                node(
                    "file:public.rs",
                    "file",
                    "rust",
                    "src/public.rs",
                    json!({"exported": true}),
                ),
                node("file:other.rs", "file", "rust", "src/other.rs", json!({})),
                node(
                    "file:dynamic.rs",
                    "file",
                    "javascript",
                    "src/dynamic.js",
                    json!({"load_kind": "import()"}),
                ),
            ],
            vec![candidate_edge],
            vec![SiteRecord {
                id: "site:unresolved".to_owned(),
                source: "file:other.rs".to_owned(),
                kind: "import".to_owned(),
                specifier: Some("src/public.rs".to_owned()),
                profile_id: "profile:a".to_owned(),
                resolution_status: "unresolved".to_owned(),
                precision: "exact".to_owned(),
                condition: json!({}),
                target_ids: vec!["file:public.rs".to_owned()],
                reason: Some("ambiguous".to_owned()),
            }],
            vec![FileCoverageRecord {
                adapter: "rust".to_owned(),
                path: "src/public.rs".to_owned(),
                discovered_sites: 1,
                emitted_sites: 0,
                skipped_sites: 1,
                skipped: true,
                reason: Some("unsupported_syntax".to_owned()),
            }],
            matrix,
        );
        let findings = analyze_unused(&graph);
        for finding in &findings {
            assert_ne!(
                finding.confidence,
                Confidence::Confirmed,
                "{} was confirmed",
                finding.subject_id
            );
        }
        let public = findings
            .iter()
            .find(|finding| finding.subject_id == "file:public.rs")
            .expect("public file finding");
        let kinds = public
            .blockers
            .iter()
            .map(|blocker| blocker.kind)
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&BlockerKind::PublicSurface));
        assert!(kinds.contains(&BlockerKind::ProfileNotAnalyzed));
        assert!(
            kinds.contains(&BlockerKind::Candidate) || kinds.contains(&BlockerKind::Unresolved)
        );
        assert!(kinds.contains(&BlockerKind::CoverageOmission));
    }
}
