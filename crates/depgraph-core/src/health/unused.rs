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
    let (source, dynamic_site_ids) =
        GlobalSource::from_snapshot(snapshot, &mut budget, &mut is_cancelled)?;
    let global = GlobalIndex::build(&source, &mut budget, &mut is_cancelled)?;
    let local = LocalIndex::build(
        &global,
        &snapshot.nodes,
        &snapshot.edges,
        &snapshot.sites,
        dynamic_site_ids,
        &mut budget,
        &mut is_cancelled,
    )?;
    analyze_subjects(
        &global,
        &local,
        &snapshot.nodes,
        maximum_findings,
        &mut budget,
        &mut is_cancelled,
    )
}

fn analyze_subject<'a>(
    index: &'a GlobalIndex<'a>,
    local: &LocalIndex<'a>,
    node: &'a NodeRecord,
    kind: FindingKind,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<HealthFinding>, HealthAnalysisError> {
    if kind == FindingKind::UnusedExport && classify_surface(node).role == SurfaceRole::Internal {
        return Ok(None);
    }
    let incoming = local
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
    collect_site_blockers(index, local, &node.id, &mut blockers, budget, is_cancelled)?;
    collect_coverage_blockers(index, node, &mut blockers, budget, is_cancelled)?;
    if index.analysis_coverage_incomplete {
        blockers.push(FindingBlocker {
            kind: BlockerKind::IncompleteCoverage,
            detail: "one or more analysis units or dependency ranges were not analysed".to_owned(),
        });
    }
    let is_go_subject = node
        .properties
        .get("language")
        .and_then(serde_json::Value::as_str)
        == Some("go");
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
    for profile_id in &applicable.base.missing_ids {
        append_missing_profile_blockers(
            index,
            profile_id,
            is_go_subject,
            &mut blockers,
            budget,
            is_cancelled,
        )?;
    }
    if let Some(profile_id) = applicable.explicit_extra()
        && !index.profiles_by_id.contains_key(profile_id)
    {
        append_missing_profile_blockers(
            index,
            profile_id,
            is_go_subject,
            &mut blockers,
            budget,
            is_cancelled,
        )?;
    }
    let mut usage_profiles = BTreeSet::new();
    for edge in &usage {
        budget.step(is_cancelled)?;
        let profile_id = if is_go_subject {
            go_profile_representative(&index.go_profile_representatives, edge.profile_id.as_str())
        } else {
            edge.profile_id.as_str()
        };
        usage_profiles.insert(profile_id);
    }
    if kind == FindingKind::UnusedFile && is_go_subject {
        // The Go worker's import edge targets the package/module node, not an
        // arbitrary source file.  An exact package import therefore accounts
        // for every source file in that package for the matching profile.
        if let Some(package_profiles) = local.go_file_usage_profiles.get(node.id.as_str()) {
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
            && local.go_main_file_ids.contains(node.id.as_str())
            && let Some(active_profiles) = local.go_file_active_profiles.get(node.id.as_str())
        {
            usage_profiles.extend(active_profiles.iter().copied());
        }
        blockers.extend(
            local
                .go_file_blockers
                .get(node.id.as_str())
                .into_iter()
                .flatten()
                .cloned(),
        );
    }
    let mut unused_across_profiles = true;
    // Usage is sparse in the common case. Scan the profiles that actually
    // supplied definite usage evidence instead of visiting every applicable
    // profile, while still rejecting usage from missing profile records.
    for profile_id in &usage_profiles {
        budget.step(is_cancelled)?;
        if index.profiles_by_id.contains_key(profile_id) && applicable.contains(profile_id) {
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
    let profiles_complete = if is_go_subject {
        go_profiles_satisfy(
            index,
            &applicable,
            CompletenessKind::Semantic,
            budget,
            is_cancelled,
        )?
    } else {
        profiles_satisfy(
            index,
            &applicable,
            CompletenessKind::Semantic,
            budget,
            is_cancelled,
        )?
    };
    let profiles_have_minimum_coverage = if is_go_subject {
        go_profiles_satisfy(
            index,
            &applicable,
            CompletenessKind::Syntax,
            budget,
            is_cancelled,
        )?
    } else {
        profiles_satisfy(
            index,
            &applicable,
            CompletenessKind::Syntax,
            budget,
            is_cancelled,
        )?
    };
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

#[derive(Clone, Copy)]
struct ProfileCompleteness {
    semantic: bool,
    syntax: bool,
}

struct ApplicableProfileSet<'a> {
    // Keep the merged profile IDs sorted so a subject can use binary search
    // without materializing a per-subject set.
    ids: Vec<&'a str>,
    // Missing IDs are shared too. A subject still materializes the same
    // ProfileNotAnalyzed blockers when this list is non-empty, but complete
    // snapshots avoid probing every profile for every subject.
    missing_ids: Vec<&'a str>,
    completeness: ProfileCompleteness,
}

impl ApplicableProfileSet<'_> {
    fn contains(&self, profile_id: &str) -> bool {
        self.ids
            .binary_search_by(|candidate| (*candidate).cmp(profile_id))
            .is_ok()
    }
}

struct ApplicableProfiles<'a> {
    base: &'a ApplicableProfileSet<'a>,
    explicit: Option<&'a str>,
}

impl ApplicableProfiles<'_> {
    fn contains(&self, profile_id: &str) -> bool {
        self.base.contains(profile_id) || self.explicit == Some(profile_id)
    }

    fn explicit_extra(&self) -> Option<&str> {
        self.explicit
            .filter(|profile_id| !self.base.contains(profile_id))
    }

    fn is_empty(&self) -> bool {
        self.base.ids.is_empty() && self.explicit_extra().is_none()
    }
}

/// Snapshot-wide inputs of the unused analysis that do not depend on which
/// subjects are analysed.
///
/// Both the whole-snapshot path and the ranged path build one `GlobalIndex`
/// from the same inputs (profiles, matrix, coverage, Go module nodes, and the
/// edges/sites that target Go modules), so every subject sees identical
/// applicable-profile sets, condition groups, and package projections no
/// matter which execution range it belongs to.
pub(crate) struct GlobalIndex<'a> {
    profiles_by_id: HashMap<&'a str, &'a depgraph_store::ProfileRecord>,
    // Go analysis stages often produce distinct profile records with the
    // same environment and feature axes. Conditions only inspect those axes,
    // so keep stage IDs for provenance while sharing the expensive condition
    // evaluation through a deterministic representative profile.
    go_profile_representatives: HashMap<&'a str, &'a str>,
    go_condition_group_members: HashMap<&'a str, Vec<&'a str>>,
    go_condition_profile_ids: Vec<&'a str>,
    go_group_semantic_complete: HashMap<&'a str, bool>,
    go_group_syntax_coverage: HashMap<&'a str, bool>,
    applicable_profiles_by_language: HashMap<String, ApplicableProfileSet<'a>>,
    applicable_profiles_all: Option<ApplicableProfileSet<'a>>,
    // Package scopes and the package-level projections are global because a
    // Go package is compiled as one unit: a file's usage comes from imports
    // that target the package node, wherever the importing file lives.
    go_package_scopes_by_path: HashMap<&'a str, BTreeSet<GoPackageIdentity<'a>>>,
    go_main_package_scopes: HashSet<GoPackageIdentity<'a>>,
    go_package_usage_profiles: GoPackageProfileGroups<'a>,
    go_package_uncertain_profiles: GoPackageProfileGroups<'a>,
    go_package_candidate_profiles: GoPackageProfileGroups<'a>,
    go_candidates_by_path: HashMap<&'a str, GoProfilesByGroup<'a>>,
    targetless_candidate: bool,
    targetless_unresolved: bool,
    targetless_dynamic: bool,
    coverage_omitted_paths: HashSet<&'a str>,
    analysis_coverage_incomplete: bool,
}

/// The inbound side of one set of subjects: the whole snapshot for the
/// legacy path, or one execution range for the ranged path.
///
/// Every subject in the set must see all of its inbound edges and sites, no
/// matter where their sources live; range loading is keyed by target for
/// exactly that reason.
pub(crate) struct LocalIndex<'a> {
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
}

/// Snapshot-wide raw inputs of [`GlobalIndex::build`].
///
/// `edges` and `sites` may be supersets of the rows that matter (the whole
/// snapshot passes every edge and site; the store's ranged loader passes only
/// the edges that target Go module nodes and the candidate sites).
pub(crate) struct GlobalSource<'a> {
    pub(crate) scan_status: &'a str,
    pub(crate) coverage_reasons: &'a [String],
    pub(crate) profiles: &'a [depgraph_store::ProfileRecord],
    pub(crate) matrix_entries: &'a [depgraph_store::ProfileMatrixEntryRecord],
    /// Distinct `language` values of subject nodes; `None` marks subjects
    /// without a string language.
    pub(crate) subject_languages: Vec<Option<&'a str>>,
    pub(crate) go_module_nodes: Vec<&'a NodeRecord>,
    pub(crate) edges: &'a [EdgeRecord],
    pub(crate) sites: &'a [SiteRecord],
    pub(crate) targetless_candidate: bool,
    pub(crate) targetless_unresolved: bool,
    pub(crate) targetless_dynamic: bool,
    pub(crate) coverage_omitted_paths: Vec<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GoPackageIdentity<'a> {
    package_path: &'a str,
    module_path: Option<&'a str>,
    manifest_path: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct GoConditionKey {
    // Keep missing profile records distinct from a present profile whose
    // environment happens to be empty. Missing records must remain unknown.
    present: bool,
    environment: String,
    features: Vec<String>,
}

fn go_condition_key(profile: Option<&depgraph_store::ProfileRecord>) -> GoConditionKey {
    let Some(profile) = profile else {
        return GoConditionKey {
            present: false,
            environment: String::new(),
            features: Vec::new(),
        };
    };
    let mut features = profile.features.clone();
    features.sort_unstable();
    features.dedup();
    GoConditionKey {
        present: true,
        environment: depgraph_protocol::canonical_json(&profile.environment),
        features,
    }
}

fn go_profile_group_members<'a>(
    groups: &HashMap<&'a str, Vec<&'a str>>,
    representative: &'a str,
) -> Vec<&'a str> {
    groups
        .get(representative)
        .cloned()
        .unwrap_or_else(|| vec![representative])
}

fn go_profile_representative<'a>(
    representatives: &HashMap<&'a str, &'a str>,
    profile_id: &'a str,
) -> &'a str {
    representatives
        .get(profile_id)
        .copied()
        .unwrap_or(profile_id)
}

type GoProfilesByGroup<'a> = HashMap<&'a str, HashSet<&'a str>>;
type GoPackageProfileGroups<'a> = HashMap<GoPackageIdentity<'a>, GoProfilesByGroup<'a>>;

fn group_go_package_profiles<'a>(
    packages: HashMap<GoPackageIdentity<'a>, HashSet<&'a str>>,
    representatives: &HashMap<&'a str, &'a str>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<GoPackageProfileGroups<'a>, HealthAnalysisError> {
    let mut grouped = HashMap::new();
    for (package, profiles) in packages {
        budget.step(is_cancelled)?;
        let groups = grouped.entry(package).or_insert_with(HashMap::new);
        for profile_id in profiles {
            budget.step(is_cancelled)?;
            let representative = go_profile_representative(representatives, profile_id);
            groups
                .entry(representative)
                .or_insert_with(HashSet::new)
                .insert(profile_id);
        }
    }
    Ok(grouped)
}

#[derive(Default)]
struct GoConditionOverrides<'a> {
    profiles: HashMap<&'a str, GoConditionState>,
    true_count: usize,
    unknown_count: usize,
}

struct GoFileConditions<'a> {
    default: GoConditionState,
    // Only an actual contains edge can change the no-edge default. Keep those
    // exceptions by condition group without expanding every stage per file.
    overrides: HashMap<&'a str, GoConditionOverrides<'a>>,
}

impl<'a> GoFileConditions<'a> {
    fn build(
        has_build_constraint: bool,
        incoming: Option<&[&'a EdgeRecord]>,
        representatives: &HashMap<&'a str, &'a str>,
        profiles: &HashMap<&str, &depgraph_store::ProfileRecord>,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, HealthAnalysisError> {
        let default = if has_build_constraint {
            GoConditionState::Unknown
        } else {
            GoConditionState::True
        };
        let mut states = HashMap::<&str, (Vec<GoConditionState>, bool)>::new();
        // The cache is local to this file, so its retained size follows actual
        // incoming evidence. Equivalent stage conditions share evaluation.
        let mut cache = HashMap::<(&str, String), GoConditionState>::new();
        for edge in incoming.unwrap_or_default() {
            budget.step(is_cancelled)?;
            if edge.kind != "contains" {
                continue;
            }
            let profile_id = edge.profile_id.as_str();
            let Some(&representative) = representatives.get(profile_id) else {
                continue;
            };
            let key = (
                representative,
                depgraph_protocol::canonical_json(&edge.condition),
            );
            let state = if let Some(state) = cache.get(&key) {
                *state
            } else {
                let state = go_condition_state(
                    &edge.condition,
                    profile_id,
                    profiles,
                    budget,
                    is_cancelled,
                )?;
                cache.insert(key, state);
                state
            };
            let (conditions, fallback) = states.entry(profile_id).or_default();
            conditions.push(state);
            *fallback |= has_build_constraint && go_condition_is_always(&edge.condition);
        }
        let mut overrides = HashMap::<&str, GoConditionOverrides<'a>>::new();
        for (profile_id, (conditions, fallback)) in states {
            budget.step(is_cancelled)?;
            let state = if fallback {
                GoConditionState::Unknown
            } else {
                combine_go_condition_states(conditions)
            };
            if state == default {
                continue;
            }
            let group = overrides.entry(representatives[profile_id]).or_default();
            group.true_count += usize::from(state == GoConditionState::True);
            group.unknown_count += usize::from(state == GoConditionState::Unknown);
            group.profiles.insert(profile_id, state);
        }
        Ok(Self { default, overrides })
    }

    fn state(&self, representative: &str, profile_id: &str) -> GoConditionState {
        self.overrides
            .get(representative)
            .and_then(|group| group.profiles.get(profile_id))
            .copied()
            .unwrap_or(self.default)
    }

    fn group_has_state(&self, representative: &str, size: usize, wanted: GoConditionState) -> bool {
        let group = self.overrides.get(representative);
        if self.default == wanted {
            return group.map_or(0, |group| group.profiles.len()) < size;
        }
        group.is_some_and(|group| match wanted {
            GoConditionState::True => group.true_count > 0,
            GoConditionState::Unknown => group.unknown_count > 0,
            GoConditionState::False => {
                group.profiles.len() > group.true_count + group.unknown_count
            }
        })
    }

    fn has_usage(
        &self,
        representative: &str,
        usage: &HashSet<&str>,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<bool, HealthAnalysisError> {
        if usage.is_empty() {
            return Ok(false);
        }
        let Some(group) = self.overrides.get(representative) else {
            return Ok(self.default == GoConditionState::True);
        };
        if usage.len() < group.profiles.len() {
            for profile_id in usage {
                budget.step(is_cancelled)?;
                if self.state(representative, profile_id) == GoConditionState::True {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        let mut exceptional_usage = 0;
        for (profile_id, state) in &group.profiles {
            budget.step(is_cancelled)?;
            if usage.contains(profile_id) {
                if *state == GoConditionState::True {
                    return Ok(true);
                }
                exceptional_usage += 1;
            }
        }
        Ok(self.default == GoConditionState::True && exceptional_usage < usage.len())
    }

    fn add_unknown_blockers(
        &self,
        representative: &str,
        members: &[&str],
        node: &NodeRecord,
        blockers: &mut Vec<FindingBlocker>,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(), HealthAnalysisError> {
        if !self.group_has_state(representative, members.len(), GoConditionState::Unknown) {
            return Ok(());
        }
        if self.default == GoConditionState::Unknown {
            for profile_id in members {
                budget.step(is_cancelled)?;
                if self.state(representative, profile_id) == GoConditionState::Unknown {
                    blockers.push(go_incomplete_condition_blocker(node, profile_id));
                }
            }
        } else if let Some(group) = self.overrides.get(representative) {
            for (profile_id, state) in &group.profiles {
                budget.step(is_cancelled)?;
                if *state == GoConditionState::Unknown {
                    blockers.push(go_incomplete_condition_blocker(node, profile_id));
                }
            }
        }
        Ok(())
    }
}

impl<'a> GlobalSource<'a> {
    /// Derive the snapshot-wide inputs from an in-memory graph, charging one
    /// step per node, site, evidence record, and coverage row as the
    /// whole-snapshot index always did.
    pub(crate) fn from_snapshot(
        snapshot: &'a GraphSnapshot,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(Self, HashSet<&'a str>), HealthAnalysisError> {
        let mut subject_languages = BTreeSet::new();
        let mut go_module_nodes = Vec::new();
        for node in &snapshot.nodes {
            budget.step(is_cancelled)?;
            if matches!(node.kind.as_str(), "file" | "symbol" | "type") {
                subject_languages.insert(
                    node.properties
                        .get("language")
                        .and_then(serde_json::Value::as_str),
                );
            }
            if node.kind == "module"
                && node
                    .properties
                    .get("language")
                    .and_then(serde_json::Value::as_str)
                    == Some("go")
            {
                go_module_nodes.push(node);
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
        }
        let mut coverage_omitted_paths = Vec::new();
        for record in &snapshot.file_coverage {
            budget.step(is_cancelled)?;
            if record.skipped || record.reason.as_deref() == Some("unsupported_syntax") {
                coverage_omitted_paths.push(record.path.as_str());
            }
        }
        Ok((
            Self {
                scan_status: snapshot.scan.status.as_str(),
                coverage_reasons: snapshot.coverage.reasons.as_slice(),
                profiles: snapshot.profiles.as_slice(),
                matrix_entries: snapshot.profile_matrix.entries.as_slice(),
                subject_languages: subject_languages.into_iter().collect(),
                go_module_nodes,
                edges: snapshot.edges.as_slice(),
                sites: snapshot.sites.as_slice(),
                targetless_candidate,
                targetless_unresolved,
                targetless_dynamic,
                coverage_omitted_paths,
            },
            dynamic_site_ids,
        ))
    }
}

impl<'a> GlobalIndex<'a> {
    pub(crate) fn build(
        source: &GlobalSource<'a>,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, HealthAnalysisError> {
        let mut profiles_by_id = HashMap::new();
        let mut profile_ids_by_language = HashMap::<String, Vec<&str>>::new();
        let mut fixture_profile_ids = Vec::new();
        let mut all_profile_ids = Vec::new();
        for profile in source.profiles {
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
        for entry in source.matrix_entries {
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

        let mut go_condition_members_by_key = BTreeMap::<GoConditionKey, BTreeSet<&str>>::new();
        for profile_id in &go_profile_ids {
            budget.step(is_cancelled)?;
            let key = go_condition_key(profiles_by_id.get(profile_id).copied());
            go_condition_members_by_key
                .entry(key)
                .or_default()
                .insert(*profile_id);
        }
        let mut go_condition_profile_ids = Vec::new();
        let mut go_profile_representatives = HashMap::new();
        let mut go_condition_group_members = HashMap::new();
        let mut go_group_semantic_complete = HashMap::new();
        let mut go_group_syntax_coverage = HashMap::new();
        for members in go_condition_members_by_key.values() {
            let representative = *members
                .first()
                .expect("a Go condition group always has a profile");
            let members = members.iter().copied().collect::<Vec<_>>();
            for profile_id in &members {
                budget.step(is_cancelled)?;
                go_profile_representatives.insert(*profile_id, representative);
            }
            let semantic_complete = members.iter().all(|profile_id| {
                profiles_by_id
                    .get(profile_id)
                    .is_some_and(|profile| profile_is_semantically_complete(profile))
            });
            let syntax_coverage = members.iter().all(|profile_id| {
                profiles_by_id
                    .get(profile_id)
                    .is_some_and(|profile| profile_has_syntax_coverage(profile))
            });
            go_condition_profile_ids.push(representative);
            go_group_semantic_complete.insert(representative, semantic_complete);
            go_group_syntax_coverage.insert(representative, syntax_coverage);
            go_condition_group_members.insert(representative, members);
        }

        let mut go_package_identity_by_id = HashMap::<&str, GoPackageIdentity<'a>>::new();
        let mut go_package_scopes_by_path = HashMap::<&str, BTreeSet<GoPackageIdentity<'a>>>::new();
        let mut go_main_package_scopes = HashSet::<GoPackageIdentity<'a>>::new();
        let mut required_applicable_languages = BTreeSet::new();
        let mut needs_all_applicable_profiles = false;
        for language in &source.subject_languages {
            budget.step(is_cancelled)?;
            match language {
                Some(language) => {
                    required_applicable_languages
                        .insert(health_language_family(language).to_owned());
                }
                None => needs_all_applicable_profiles = true,
            }
        }
        for node in &source.go_module_nodes {
            budget.step(is_cancelled)?;
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
        let mut applicable_profiles_by_language = HashMap::new();
        for language in required_applicable_languages {
            let mut profile_ids = Vec::new();
            if language == "go" {
                profile_ids.extend(go_condition_profile_ids.iter().copied());
            } else {
                if let Some(ids) = profile_ids_by_language.get(&language) {
                    profile_ids.extend(ids.iter().copied());
                }
                if let Some(ids) = matrix_profile_ids_by_language.get(&language) {
                    profile_ids.extend(ids.iter().copied());
                }
            }
            profile_ids.extend(fixture_profile_ids.iter().copied());
            profile_ids.extend(fixture_matrix_profile_ids.iter().copied());
            let profile_set = build_applicable_profile_set(
                profile_ids,
                &profiles_by_id,
                &go_group_semantic_complete,
                &go_group_syntax_coverage,
                language == "go",
                budget,
                is_cancelled,
            )?;
            applicable_profiles_by_language.insert(language, profile_set);
        }
        let applicable_profiles_all = if needs_all_applicable_profiles {
            let mut profile_ids = Vec::new();
            profile_ids.extend(all_profile_ids.iter().copied());
            profile_ids.extend(all_matrix_profile_ids.iter().copied());
            Some(build_applicable_profile_set(
                profile_ids,
                &profiles_by_id,
                &go_group_semantic_complete,
                &go_group_syntax_coverage,
                false,
                budget,
                is_cancelled,
            )?)
        } else {
            None
        };
        let mut go_package_usage_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        let mut go_package_uncertain_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        let mut go_package_candidate_profiles =
            HashMap::<GoPackageIdentity<'a>, HashSet<&'a str>>::new();
        for edge in source.edges {
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
        for site in source.sites {
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
        let go_package_usage_profiles = group_go_package_profiles(
            go_package_usage_profiles,
            &go_profile_representatives,
            budget,
            is_cancelled,
        )?;
        let go_package_uncertain_profiles = group_go_package_profiles(
            go_package_uncertain_profiles,
            &go_profile_representatives,
            budget,
            is_cancelled,
        )?;
        let go_package_candidate_profiles = group_go_package_profiles(
            go_package_candidate_profiles,
            &go_profile_representatives,
            budget,
            is_cancelled,
        )?;
        // Ambiguous file ownership needs the union of candidate evidence from
        // every package scope with that path, preserving each stage identity.
        let mut go_candidates_by_path = HashMap::<&str, GoProfilesByGroup<'a>>::new();
        for (scope, groups) in &go_package_candidate_profiles {
            budget.step(is_cancelled)?;
            let path_groups = go_candidates_by_path.entry(scope.package_path).or_default();
            for (representative, profiles) in groups {
                budget.step(is_cancelled)?;
                let members = path_groups.entry(*representative).or_default();
                for profile_id in profiles {
                    budget.step(is_cancelled)?;
                    members.insert(*profile_id);
                }
            }
        }
        let analysis_coverage_incomplete = source.scan_status != "completed"
            || source.coverage_reasons.iter().any(|reason| {
                reason.starts_with("analysis-unit-")
                    || reason == "analysis-input-changed-during-scan"
            });
        Ok(Self {
            profiles_by_id,
            go_profile_representatives,
            go_condition_group_members,
            go_condition_profile_ids,
            go_group_semantic_complete,
            go_group_syntax_coverage,
            applicable_profiles_by_language,
            applicable_profiles_all,
            go_package_scopes_by_path,
            go_main_package_scopes,
            go_package_usage_profiles,
            go_package_uncertain_profiles,
            go_package_candidate_profiles,
            go_candidates_by_path,
            targetless_candidate: source.targetless_candidate,
            targetless_unresolved: source.targetless_unresolved,
            targetless_dynamic: source.targetless_dynamic,
            coverage_omitted_paths: source.coverage_omitted_paths.iter().copied().collect(),
            analysis_coverage_incomplete,
        })
    }

    pub(crate) const fn analysis_coverage_incomplete(&self) -> bool {
        self.analysis_coverage_incomplete
    }
}

impl<'a> LocalIndex<'a> {
    /// Index the inbound side of `subjects`.
    ///
    /// `edges` must contain every edge whose target is one of the subjects and
    /// `sites` every site that lists one of the subjects as a target; both may
    /// contain more. `dynamic_site_ids` are the sites carrying dynamic-import
    /// evidence among `sites`.
    pub(crate) fn build(
        global: &GlobalIndex<'a>,
        subjects: impl IntoIterator<Item = &'a NodeRecord>,
        edges: &'a [EdgeRecord],
        sites: &'a [SiteRecord],
        dynamic_site_ids: HashSet<&'a str>,
        budget: &mut HealthAnalysisBudget,
        is_cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Self, HealthAnalysisError> {
        let mut incoming = HashMap::<&str, Vec<&EdgeRecord>>::new();
        for edge in edges {
            budget.step(is_cancelled)?;
            incoming.entry(edge.target.as_str()).or_default().push(edge);
        }
        let mut sites_by_target = HashMap::<&str, Vec<&SiteRecord>>::new();
        for site in sites {
            budget.step(is_cancelled)?;
            for target_id in &site.target_ids {
                budget.step(is_cancelled)?;
                sites_by_target
                    .entry(target_id.as_str())
                    .or_default()
                    .push(site);
            }
        }

        let mut go_file_usage_profiles = HashMap::<&str, HashSet<&str>>::new();
        let mut go_file_blockers = HashMap::<&str, Vec<FindingBlocker>>::new();
        let mut go_file_active_profiles = HashMap::<&str, HashSet<&str>>::new();
        let mut go_main_file_ids = HashSet::<&str>::new();
        for node in subjects {
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
            let has_build_constraint = node
                .properties
                .get("build_constraint")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|constraint| !constraint.trim().is_empty());
            let conditions = GoFileConditions::build(
                has_build_constraint,
                incoming.get(node_id).map(Vec::as_slice),
                &global.go_profile_representatives,
                &global.profiles_by_id,
                budget,
                is_cancelled,
            )?;
            let blockers = go_file_blockers.entry(node_id).or_default();
            let mut eligible_groups = Vec::new();
            let mut active_groups = HashSet::new();
            for representative in &global.go_condition_profile_ids {
                budget.step(is_cancelled)?;
                let members = &global.go_condition_group_members[representative];
                let active = conditions.group_has_state(
                    representative,
                    members.len(),
                    GoConditionState::True,
                );
                let unknown = conditions.group_has_state(
                    representative,
                    members.len(),
                    GoConditionState::Unknown,
                );
                if active {
                    active_groups.insert(*representative);
                }
                if active || unknown {
                    eligible_groups.push(*representative);
                }
                conditions.add_unknown_blockers(
                    representative,
                    members,
                    node,
                    blockers,
                    budget,
                    is_cancelled,
                )?;
            }
            if has_build_constraint && eligible_groups.is_empty() {
                blockers.push(go_inactive_condition_blocker(node));
            }
            if !active_groups.is_empty() {
                go_file_active_profiles.insert(node_id, active_groups);
            }

            if node
                .properties
                .get("test")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                continue;
            }
            let Some(file_identity) = go_package_identity(node) else {
                continue;
            };
            let package_path = file_identity.package_path;
            let mut matching_scopes = Vec::new();
            if let Some(scopes) = global.go_package_scopes_by_path.get(package_path) {
                for scope in scopes {
                    budget.step(is_cancelled)?;
                    if go_package_scope_matches(file_identity, *scope) {
                        matching_scopes.push(*scope);
                    }
                }
            }
            if matching_scopes.len() != 1 {
                // Materialize stage IDs only when their unresolved scope is
                // part of the finding. Inactive stages cannot supply a blocker.
                for representative in eligible_groups {
                    budget.step(is_cancelled)?;
                    let candidates = global
                        .go_candidates_by_path
                        .get(package_path)
                        .and_then(|groups| groups.get(representative));
                    for profile_id in &global.go_condition_group_members[representative] {
                        budget.step(is_cancelled)?;
                        if conditions.state(representative, profile_id) == GoConditionState::False {
                            continue;
                        }
                        blockers.push(go_unresolved_package_scope_blocker(
                            package_path,
                            profile_id,
                        ));
                        if candidates.is_some_and(|profiles| profiles.contains(profile_id)) {
                            budget.step(is_cancelled)?;
                            blockers.push(go_candidate_package_blocker(package_path, profile_id));
                        }
                    }
                }
                continue;
            }
            let scope = matching_scopes[0];
            if global.go_main_package_scopes.contains(&scope) {
                go_main_file_ids.insert(node_id);
            }
            for representative in eligible_groups {
                budget.step(is_cancelled)?;
                if let Some(usage) = global
                    .go_package_usage_profiles
                    .get(&scope)
                    .and_then(|groups| groups.get(representative))
                    && conditions.has_usage(representative, usage, budget, is_cancelled)?
                {
                    go_file_usage_profiles
                        .entry(node_id)
                        .or_default()
                        .insert(representative);
                }
                if let Some(uncertain) = global
                    .go_package_uncertain_profiles
                    .get(&scope)
                    .and_then(|groups| groups.get(representative))
                {
                    for profile_id in uncertain {
                        budget.step(is_cancelled)?;
                        if conditions.state(representative, profile_id) != GoConditionState::False {
                            blockers.push(go_incomplete_package_usage_blocker(
                                package_path,
                                profile_id,
                            ));
                        }
                    }
                }
                if let Some(candidates) = global
                    .go_package_candidate_profiles
                    .get(&scope)
                    .and_then(|groups| groups.get(representative))
                {
                    for profile_id in candidates {
                        budget.step(is_cancelled)?;
                        if conditions.state(representative, profile_id) != GoConditionState::False {
                            blockers.push(go_candidate_package_blocker(package_path, profile_id));
                        }
                    }
                }
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
        })
    }
}

/// Analyse `subjects` against an already built global/local index pair.
///
/// Findings are returned sorted by id. The caller owns the budget so that the
/// whole-snapshot path and a single execution range charge the same steps.
pub(crate) fn analyze_subjects<'a>(
    global: &'a GlobalIndex<'a>,
    local: &LocalIndex<'a>,
    subjects: impl IntoIterator<Item = &'a NodeRecord>,
    maximum_findings: usize,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<HealthFinding>, HealthAnalysisError> {
    let mut findings = Vec::new();
    for node in subjects {
        budget.step(is_cancelled)?;
        let kind = match node.kind.as_str() {
            "file" => FindingKind::UnusedFile,
            "symbol" => FindingKind::UnusedExport,
            "type" => FindingKind::UnusedType,
            _ => continue,
        };
        if let Some(finding) = analyze_subject(global, local, node, kind, budget, is_cancelled)? {
            if findings.len() >= maximum_findings {
                return Err(HealthAnalysisError::ResourceExhausted);
            }
            findings.push(finding);
        }
    }
    budget.step(is_cancelled)?;
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(findings)
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

#[cfg(test)]
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
    index: &GlobalIndex<'_>,
    local: &LocalIndex<'_>,
    subject_id: &str,
    blockers: &mut Vec<FindingBlocker>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    for site in local.sites_by_target.get(subject_id).into_iter().flatten() {
        budget.step(is_cancelled)?;
        let dynamic = matches!(site.kind.as_str(), "dynamic_import" | "dynamic-load")
            || local.dynamic_site_ids.contains(site.id.as_str());
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
    index: &GlobalIndex<'_>,
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

fn applicable_profiles<'a>(
    index: &'a GlobalIndex<'a>,
    node: &'a NodeRecord,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<ApplicableProfiles<'a>, HealthAnalysisError> {
    let explicit_profile = node
        .properties
        .get("profile_id")
        .and_then(|value| value.as_str());
    let language = node
        .properties
        .get("language")
        .and_then(|value| value.as_str());
    let explicit = if let Some(profile_id) = explicit_profile {
        budget.step(is_cancelled)?;
        Some(if language == Some("go") {
            go_profile_representative(&index.go_profile_representatives, profile_id)
        } else {
            profile_id
        })
    } else {
        None
    };
    let base = match language.map(health_language_family) {
        Some(language) => index
            .applicable_profiles_by_language
            .get(language)
            .expect("a subject has an applicable profile set for its language"),
        None => index
            .applicable_profiles_all
            .as_ref()
            .expect("a subject without a language has an applicable profile set"),
    };
    Ok(ApplicableProfiles { base, explicit })
}

fn health_language_family(language: &str) -> &str {
    match language {
        "typescript" | "javascript" | "ts" | "tsx" | "js" | "jsx" | "astro" | "web" => "web",
        other => other,
    }
}

fn append_missing_profile_blockers<'a>(
    index: &GlobalIndex<'a>,
    profile_id: &'a str,
    is_go_subject: bool,
    blockers: &mut Vec<FindingBlocker>,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), HealthAnalysisError> {
    let missing_profiles = if is_go_subject {
        go_profile_group_members(&index.go_condition_group_members, profile_id)
    } else {
        vec![profile_id]
    };
    for missing_profile in missing_profiles {
        budget.step(is_cancelled)?;
        blockers.push(FindingBlocker {
            kind: BlockerKind::ProfileNotAnalyzed,
            detail: format!(
                "profile {missing_profile} is applicable but missing from the snapshot"
            ),
        });
    }
    Ok(())
}

fn sorted_unique_profile_ids(mut profile_ids: Vec<&str>) -> Vec<&str> {
    profile_ids.sort_unstable();
    profile_ids.dedup();
    profile_ids
}

#[derive(Clone, Copy)]
enum CompletenessKind {
    Semantic,
    Syntax,
}

impl ProfileCompleteness {
    fn satisfies(self, kind: CompletenessKind) -> bool {
        match kind {
            CompletenessKind::Semantic => self.semantic,
            CompletenessKind::Syntax => self.syntax,
        }
    }
}

fn direct_profile_completeness(
    profiles: &HashMap<&str, &depgraph_store::ProfileRecord>,
    profile_id: &str,
    kind: CompletenessKind,
) -> bool {
    profiles.get(profile_id).is_some_and(|profile| match kind {
        CompletenessKind::Semantic => profile_is_semantically_complete(profile),
        CompletenessKind::Syntax => profile_has_syntax_coverage(profile),
    })
}

fn go_profile_completeness(
    profiles: &HashMap<&str, &depgraph_store::ProfileRecord>,
    semantic_complete: &HashMap<&str, bool>,
    syntax_coverage: &HashMap<&str, bool>,
    profile_id: &str,
    kind: CompletenessKind,
) -> bool {
    let grouped = match kind {
        CompletenessKind::Semantic => semantic_complete.get(profile_id).copied(),
        CompletenessKind::Syntax => syntax_coverage.get(profile_id).copied(),
    };
    grouped
        .or_else(|| {
            profiles.get(profile_id).map(|profile| match kind {
                CompletenessKind::Semantic => profile_is_semantically_complete(profile),
                CompletenessKind::Syntax => profile_has_syntax_coverage(profile),
            })
        })
        .unwrap_or(false)
}

fn build_applicable_profile_set<'a>(
    profile_ids: Vec<&'a str>,
    profiles: &HashMap<&'a str, &'a depgraph_store::ProfileRecord>,
    go_group_semantic_complete: &HashMap<&'a str, bool>,
    go_group_syntax_coverage: &HashMap<&'a str, bool>,
    use_go_condition_groups: bool,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<ApplicableProfileSet<'a>, HealthAnalysisError> {
    let profile_ids = sorted_unique_profile_ids(profile_ids);
    let mut missing_ids = Vec::new();
    let mut completeness = ProfileCompleteness {
        semantic: true,
        syntax: true,
    };
    for profile_id in &profile_ids {
        budget.step(is_cancelled)?;
        if !profiles.contains_key(profile_id) {
            missing_ids.push(*profile_id);
        }
        let is_complete = |kind| {
            if use_go_condition_groups {
                go_profile_completeness(
                    profiles,
                    go_group_semantic_complete,
                    go_group_syntax_coverage,
                    profile_id,
                    kind,
                )
            } else {
                direct_profile_completeness(profiles, profile_id, kind)
            }
        };
        completeness.semantic &= is_complete(CompletenessKind::Semantic);
        completeness.syntax &= is_complete(CompletenessKind::Syntax);
    }
    Ok(ApplicableProfileSet {
        ids: profile_ids,
        missing_ids,
        completeness,
    })
}

fn profiles_satisfy(
    index: &GlobalIndex<'_>,
    applicable: &ApplicableProfiles<'_>,
    kind: CompletenessKind,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool, HealthAnalysisError> {
    if !applicable.base.completeness.satisfies(kind) {
        return Ok(false);
    }
    if let Some(profile_id) = applicable.explicit_extra() {
        budget.step(is_cancelled)?;
        return Ok(direct_profile_completeness(
            &index.profiles_by_id,
            profile_id,
            kind,
        ));
    }
    Ok(true)
}

fn go_profiles_satisfy(
    index: &GlobalIndex<'_>,
    applicable: &ApplicableProfiles<'_>,
    kind: CompletenessKind,
    budget: &mut HealthAnalysisBudget,
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<bool, HealthAnalysisError> {
    if !applicable.base.completeness.satisfies(kind) {
        return Ok(false);
    }
    if let Some(profile_id) = applicable.explicit_extra() {
        budget.step(is_cancelled)?;
        return Ok(go_profile_completeness(
            &index.profiles_by_id,
            &index.go_group_semantic_complete,
            &index.go_group_syntax_coverage,
            profile_id,
            kind,
        ));
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
    fn issue_467_same_go_condition_axes_share_budget_without_changing_finding() {
        let mut staged_profiles = Vec::new();
        for stage in ["syntax", "typed", "semantic"] {
            let mut staged = profile(&format!("go:{stage}"), "go", true);
            staged.environment = json!({
                "GOOS": "linux",
                "GOARCH": "amd64",
                "CGO_ENABLED": "0",
                "GO_TAGS": ""
            });
            staged.properties = json!({"analysis_stage": stage});
            staged_profiles.push(staged);
        }
        let graph = snapshot(
            staged_profiles,
            vec![node("go:unused", "file", "go", "pkg/unused.go", json!({}))],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        // This ceiling is deliberately below the old profile fanout while
        // leaving enough room for the single condition-group evaluation and
        // the ordinary finding construction. It exercises the same bounded
        // path used by the service health request.
        let findings = analyze_unused_cancellable(&graph, usize::MAX, 120, || false)
            .expect("equivalent Go stage profiles should share condition work");
        let finding = findings
            .iter()
            .find(|finding| finding.subject_id == "go:unused")
            .expect("unused Go file");
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.blockers.is_empty());
    }

    #[test]
    fn issue_467_go_condition_groups_keep_distinct_environment_axes() {
        let mut linux = profile("go:linux", "go", true);
        linux.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let mut windows = profile("go:windows", "go", true);
        windows.environment = json!({"GOOS": "windows", "GOARCH": "amd64"});
        let mut build_edge = edge(
            "edge:linux-condition",
            "go:unit",
            "go:file",
            "contains",
            "go:linux",
        );
        build_edge.condition = json!({"op":"eq","key":"GOOS","value":"linux"});
        let mut windows_edge = build_edge.clone();
        windows_edge.id = "edge:windows-condition".to_owned();
        windows_edge.profile_id = "go:windows".to_owned();
        windows_edge.condition = json!({"op":"eq","key":"GOOS","value":"windows"});
        let graph = snapshot(
            vec![linux, windows],
            vec![node("go:file", "file", "go", "pkg/file.go", json!({}))],
            vec![build_edge, windows_edge],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let mut budget = HealthAnalysisBudget::new(usize::MAX);
        let mut cancelled = || false;
        let (source, dynamic_site_ids) =
            GlobalSource::from_snapshot(&graph, &mut budget, &mut cancelled)
                .expect("synthetic Go snapshot sources");
        let index = GlobalIndex::build(&source, &mut budget, &mut cancelled)
            .expect("synthetic Go snapshot indexes");
        let local = LocalIndex::build(
            &index,
            &graph.nodes,
            &graph.edges,
            &graph.sites,
            dynamic_site_ids,
            &mut budget,
            &mut cancelled,
        )
        .expect("synthetic Go snapshot local index");
        assert_eq!(index.go_condition_group_members.len(), 2);
        let incoming = local
            .incoming
            .get("go:file")
            .expect("contains edges indexed");
        let linux_state = go_file_condition_state(
            &graph.nodes[0],
            "go:linux",
            Some(incoming),
            &index.profiles_by_id,
            &mut budget,
            &mut cancelled,
        )
        .expect("linux condition evaluates");
        let windows_state = go_file_condition_state(
            &graph.nodes[0],
            "go:windows",
            Some(incoming),
            &index.profiles_by_id,
            &mut budget,
            &mut cancelled,
        )
        .expect("windows condition evaluates");
        assert_eq!(linux_state, GoConditionState::True);
        assert_eq!(windows_state, GoConditionState::True);
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

    #[test]
    fn issue_467_stage_condition_mismatch_does_not_project_inactive_package_usage() {
        let mut first = profile("go:a", "go", true);
        first.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let mut second = profile("go:b", "go", true);
        second.environment = first.environment.clone();

        let mut first_contains = edge("edge:contains-a", "go:unit", "go:file", "contains", "go:a");
        first_contains.condition = json!({"op":"eq","key":"GOOS","value":"linux"});
        let mut second_contains = edge("edge:contains-b", "go:unit", "go:file", "contains", "go:b");
        second_contains.condition = json!({"op":"eq","key":"GOOS","value":"windows"});

        // The package import exists only for b. Since the file is inactive in b,
        // this must not be projected onto the active a stage.
        let package_import = edge(
            "edge:package-import-b",
            "go:caller",
            "go:package",
            "imports",
            "go:b",
        );
        let graph = snapshot(
            vec![first, second],
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
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod"
                    }),
                ),
                node(
                    "go:file",
                    "file",
                    "go",
                    "pkg/linux.go",
                    json!({
                        "package_path": "example.com/app/pkg",
                        "module_path": "example.com/app",
                        "manifest_path": "go.mod",
                        "test": false
                    }),
                ),
            ],
            vec![first_contains, second_contains, package_import],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:file")
            .expect("the file is unused in its only active stage");
        assert_eq!(finding.confidence, Confidence::Confirmed);
        assert!(finding.blockers.is_empty());
    }

    #[test]
    fn issue_467_missing_stage_contains_is_unknown_only_for_that_stage() {
        let mut first = profile("go:a", "go", true);
        first.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let mut second = profile("go:b", "go", true);
        second.environment = first.environment.clone();

        let mut first_contains = edge(
            "edge:contains-a-only",
            "go:unit",
            "go:file",
            "contains",
            "go:a",
        );
        first_contains.condition = json!({"op":"eq","key":"GOOS","value":"linux"});
        let graph = snapshot(
            vec![first, second],
            vec![node(
                "go:file",
                "file",
                "go",
                "pkg/linux.go",
                json!({"build_constraint": "linux-only"}),
            )],
            vec![first_contains],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:file")
            .expect("unused file remains visible");
        let condition_blockers = finding
            .blockers
            .iter()
            .filter(|blocker| {
                blocker.kind == BlockerKind::IncompleteCoverage
                    && blocker.detail.contains("Go build condition")
            })
            .collect::<Vec<_>>();
        assert_eq!(condition_blockers.len(), 1);
        assert!(condition_blockers[0].detail.contains("profile go:b"));
        assert!(!condition_blockers[0].detail.contains("profile go:a"));
    }

    #[test]
    fn issue_467_ambiguous_scope_candidate_keeps_nonrepresentative_stage_provenance() {
        let mut first = profile("go:a", "go", true);
        first.environment = json!({"GOOS": "linux", "GOARCH": "amd64"});
        let mut second = profile("go:b", "go", true);
        second.environment = first.environment.clone();

        let mut candidate = edge(
            "edge:candidate-b",
            "go:caller",
            "go:package-first",
            "imports",
            "go:b",
        );
        candidate.resolution_status = "candidates".to_owned();
        let graph = snapshot(
            vec![first, second],
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
                    "go:package-first",
                    "module",
                    "go",
                    "pkg-first",
                    json!({
                        "package_path": "example.com/app/shared",
                        "module_path": "example.com/first",
                        "manifest_path": "first/go.mod"
                    }),
                ),
                node(
                    "go:package-second",
                    "module",
                    "go",
                    "pkg-second",
                    json!({
                        "package_path": "example.com/app/shared",
                        "module_path": "example.com/second",
                        "manifest_path": "second/go.mod"
                    }),
                ),
                node(
                    "go:stale-file",
                    "file",
                    "go",
                    "pkg/stale.go",
                    json!({
                        "package_path": "example.com/app/shared",
                        "module_path": "example.com/stale",
                        "manifest_path": "stale/go.mod",
                        "test": false
                    }),
                ),
            ],
            vec![candidate],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:stale-file")
            .expect("ambiguous package scope remains visible");
        assert!(finding.blockers.iter().any(|blocker| {
            blocker.kind == BlockerKind::Candidate && blocker.detail.contains("profile go:b")
        }));
        assert!(finding.blockers.iter().all(|blocker| {
            blocker.kind != BlockerKind::Candidate || !blocker.detail.contains("profile go:a")
        }));
    }

    #[test]
    fn issue_467_missing_profile_records_keep_distinct_contains_provenance() {
        let mut matrix = ProfileMatrixRecord::default();
        matrix
            .entries
            .push(depgraph_store::ProfileMatrixEntryRecord {
                id: "entry:missing-go".to_owned(),
                effective_input_id: "entry:missing-go".to_owned(),
                language: "go".to_owned(),
                profile_ids: vec!["go:missing-a".to_owned(), "go:missing-b".to_owned()],
                parent_profile_ids: Vec::new(),
                phases: vec!["syntax".to_owned()],
                condition_union: json!({}),
                phase_coverage: BTreeMap::new(),
                selection_reasons: Vec::new(),
                axis_conflicts: Vec::new(),
            });
        let graph = snapshot(
            Vec::new(),
            vec![node("go:file", "file", "go", "pkg/file.go", json!({}))],
            vec![edge(
                "edge:missing-a-contains",
                "go:unit",
                "go:file",
                "contains",
                "go:missing-a",
            )],
            Vec::new(),
            Vec::new(),
            matrix,
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:file")
            .expect("missing profile proof must leave the unused candidate visible");
        assert_ne!(finding.confidence, Confidence::Confirmed);
        for profile_id in ["go:missing-a", "go:missing-b"] {
            assert!(finding.blockers.iter().any(|blocker| {
                blocker.kind == BlockerKind::ProfileNotAnalyzed
                    && blocker.detail.contains(profile_id)
            }));
        }
        let condition_blockers = finding
            .blockers
            .iter()
            .filter(|blocker| {
                blocker.kind == BlockerKind::IncompleteCoverage
                    && blocker.detail.contains("Go build condition")
            })
            .collect::<Vec<_>>();
        assert_eq!(condition_blockers.len(), 1);
        assert!(
            condition_blockers[0]
                .detail
                .contains("profile go:missing-a")
        );
        assert!(
            !condition_blockers[0]
                .detail
                .contains("profile go:missing-b")
        );
    }
    #[test]
    fn issue_467_many_stage_imports_share_package_projection_work() {
        let mut profiles = Vec::new();
        let mut imports = Vec::new();
        for index in 0..64 {
            let id = format!("go:stage-{index:02}");
            let mut stage = profile(&id, "go", true);
            stage.environment = json!({"GOOS":"linux", "GOARCH":"amd64"});
            profiles.push(stage);
            imports.push(edge(
                &format!("edge:import-{index}"),
                "go:caller",
                "go:package",
                "imports",
                &id,
            ));
        }
        let identity = json!({
            "package_path":"example.test/shared", "module_path":"example.test/shared",
            "manifest_path":"go.mod", "test":false
        });
        let mut nodes = vec![
            node("go:package", "module", "go", "pkg", identity.clone()),
            node("go:caller", "module", "go", "cmd", json!({})),
        ];
        for index in 0..128 {
            nodes.push(node(
                &format!("go:file-{index}"),
                "file",
                "go",
                &format!("pkg/file{index}.go"),
                identity.clone(),
            ));
        }
        let graph = snapshot(
            profiles,
            nodes,
            imports,
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        // The former file/profile traversal alone required 8,192 work steps.
        // Exact package usage now shares its group index across all 128 files.
        let findings = analyze_unused_cancellable(&graph, 128, 4_000, || false)
            .expect("equivalent stage imports must fit the bounded shared-work path");
        assert!(
            findings.is_empty(),
            "each production file is used by the package imports"
        );
    }

    #[test]
    fn issue_467_shared_applicable_profile_set_bounds_many_web_subjects() {
        let mut profiles = Vec::new();
        for index in 0..48 {
            profiles.push(profile(
                &format!("typescript:stage-{index:02}"),
                "typescript",
                true,
            ));
        }
        // Fixture profiles apply across language families and therefore remain
        // part of the shared web profile set.
        profiles.push(profile("fixture:shared", "fixture", true));

        let mut nodes = Vec::new();
        for index in 0..120 {
            let kind = match index % 3 {
                0 => "file",
                1 => "symbol",
                _ => "type",
            };
            let extra = if index == 0 {
                json!({"profile_id": "typescript:stage-00"})
            } else if kind == "file" {
                json!({})
            } else {
                json!({"exported": true})
            };
            nodes.push(node(
                &format!("web:subject-{index:03}"),
                kind,
                "typescript",
                &format!("src/subject-{index:03}.ts"),
                extra,
            ));
        }
        let graph = snapshot(
            profiles,
            nodes,
            vec![edge(
                "edge:one-used-profile",
                "web:subject-001",
                "web:subject-000",
                "imports",
                "typescript:stage-00",
            )],
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );

        // The old node/profile traversal spent roughly four profile passes per
        // subject. A shared set and completeness summary keep this public
        // many-profile fixture within the existing bounded-work contract.
        let findings = analyze_unused_cancellable(&graph, 128, 4_000, || false)
            .expect("many same-language profiles should use shared applicability work");
        assert_eq!(findings.len(), 119);
        assert!(findings.iter().all(|finding| {
            finding.subject_id != "web:subject-000"
                && finding
                    .blockers
                    .iter()
                    .all(|blocker| blocker.kind != BlockerKind::ProfileNotAnalyzed)
        }));
    }

    #[test]
    fn issue_467_condition_group_keeps_incomplete_stage_confidence() {
        let mut semantic = profile("go:semantic", "go", true);
        semantic.environment = json!({"GOOS":"linux", "GOARCH":"amd64"});
        let mut typed = profile("go:typed", "go", false);
        typed.environment = semantic.environment.clone();
        let graph = snapshot(
            vec![semantic, typed],
            vec![node("go:unused", "file", "go", "pkg/unused.go", json!({}))],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ProfileMatrixRecord::default(),
        );
        let finding = analyze_unused(&graph)
            .into_iter()
            .find(|finding| finding.subject_id == "go:unused")
            .expect("unused file remains visible");
        assert_eq!(finding.confidence, Confidence::Probable);
        assert!(finding.blockers.is_empty());
    }
}
