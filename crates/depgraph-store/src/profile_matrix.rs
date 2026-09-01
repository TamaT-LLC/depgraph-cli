use std::collections::{BTreeMap, BTreeSet};

use depgraph_protocol::{Condition, stable_id_from_value};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{DiagnosticRecord, EvidenceRecord, GraphSnapshot, ProfileRecord, SiteRecord};

pub const PROFILE_MATRIX_SCHEMA_VERSION: &str = "profile-matrix-v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PhaseCoverageRecord {
    pub profile_ids: Vec<String>,
    pub sites: u64,
    pub edges: u64,
    pub evidence: u64,
    pub resolved: u64,
    pub candidates: u64,
    pub external: u64,
    pub unresolved: u64,
    pub completeness: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileAxisConflictRecord {
    pub profile_id: String,
    pub parent_profile_id: String,
    pub fields: Vec<String>,
    pub diagnostic_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileMatrixEntryRecord {
    pub id: String,
    pub effective_input_id: String,
    pub language: String,
    pub profile_ids: Vec<String>,
    pub parent_profile_ids: Vec<String>,
    pub phases: Vec<String>,
    pub condition_union: Value,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
    pub selection_reasons: Vec<String>,
    pub axis_conflicts: Vec<ProfileAxisConflictRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileCorrelationRecord {
    pub id: String,
    pub effective_profile_id: String,
    pub source: String,
    pub kind: String,
    pub specifier: String,
    pub status: String,
    pub condition_union: Value,
    pub conditions_by_phase: BTreeMap<String, Value>,
    pub targets_by_phase: BTreeMap<String, Vec<String>>,
    pub resolutions_by_phase: BTreeMap<String, Vec<String>>,
    pub site_ids_by_phase: BTreeMap<String, Vec<String>>,
    pub edge_ids_by_phase: BTreeMap<String, Vec<String>>,
    pub difference_reasons: Vec<String>,
    pub diagnostic_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileMatrixRecord {
    pub schema_version: String,
    pub entries: Vec<ProfileMatrixEntryRecord>,
    pub correlations: Vec<ProfileCorrelationRecord>,
    pub phase_coverage: BTreeMap<String, PhaseCoverageRecord>,
    pub difference_counts: BTreeMap<String, u64>,
}

impl Default for ProfileMatrixRecord {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_MATRIX_SCHEMA_VERSION.to_owned(),
            entries: Vec::new(),
            correlations: Vec::new(),
            phase_coverage: BTreeMap::new(),
            difference_counts: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct PhaseCoverageBuilder {
    profile_ids: BTreeSet<String>,
    sites: u64,
    edges: u64,
    evidence: u64,
    resolved: u64,
    candidates: u64,
    external: u64,
    unresolved: u64,
    completeness: BTreeSet<String>,
}

impl PhaseCoverageBuilder {
    fn add_site(&mut self, site: &SiteRecord) {
        self.sites = self.sites.saturating_add(1);
        match site.resolution_status.as_str() {
            "resolved" => self.resolved = self.resolved.saturating_add(1),
            "candidates" => self.candidates = self.candidates.saturating_add(1),
            "external" => self.external = self.external.saturating_add(1),
            "unresolved" => self.unresolved = self.unresolved.saturating_add(1),
            _ => {}
        }
    }

    fn finish(self) -> PhaseCoverageRecord {
        PhaseCoverageRecord {
            profile_ids: self.profile_ids.into_iter().collect(),
            sites: self.sites,
            edges: self.edges,
            evidence: self.evidence,
            resolved: self.resolved,
            candidates: self.candidates,
            external: self.external,
            unresolved: self.unresolved,
            completeness: self.completeness.into_iter().collect(),
        }
    }
}

#[derive(Default)]
struct EntryBuilder {
    effective_input_id: String,
    language: String,
    profile_ids: BTreeSet<String>,
    parent_profile_ids: BTreeSet<String>,
    phases: BTreeSet<String>,
    conditions: Vec<Value>,
    phase_coverage: BTreeMap<String, PhaseCoverageBuilder>,
    selection_reasons: BTreeSet<String>,
    axis_conflicts: Vec<ProfileAxisConflictRecord>,
}

#[derive(Default)]
struct CorrelationBuilder {
    effective_profile_id: String,
    source: String,
    kind: String,
    specifier: String,
    conditions: BTreeMap<String, Vec<Value>>,
    targets: BTreeMap<String, BTreeSet<String>>,
    resolutions: BTreeMap<String, BTreeSet<String>>,
    site_ids: BTreeMap<String, BTreeSet<String>>,
    edge_ids: BTreeMap<String, BTreeSet<String>>,
}

pub fn declared_parent_profile_id(profile: &ProfileRecord) -> Option<&str> {
    profile
        .properties
        .get("parent_profile_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

pub fn declared_effective_input_id(profile: &ProfileRecord) -> Option<&str> {
    profile
        .properties
        .get("effective_input_id")
        .and_then(Value::as_str)
        .filter(|value| valid_effective_input_id(value))
}

pub fn canonical_effective_input_id(profile: &ProfileRecord) -> String {
    if declared_parent_profile_id(profile).is_some()
        && let Some(effective_input_id) = declared_effective_input_id(profile)
    {
        return effective_input_id.to_owned();
    }
    stable_id_from_value(
        "effective-input",
        &json!({
            "schema_version": PROFILE_MATRIX_SCHEMA_VERSION,
            "root_profile_id": profile.id,
        }),
    )
}

fn valid_effective_input_id(value: &str) -> bool {
    value
        .strip_prefix("effective-input:sha256:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

pub(crate) fn refresh_profile_matrix(snapshot: &mut GraphSnapshot, canonicalize_diagnostics: bool) {
    snapshot.diagnostics.retain(|diagnostic| {
        diagnostic
            .properties
            .get("profile_matrix_schema")
            .and_then(Value::as_str)
            != Some(PROFILE_MATRIX_SCHEMA_VERSION)
    });
    let retained_diagnostic_ids = snapshot
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.id.as_str())
        .collect::<BTreeSet<_>>();
    snapshot.evidence.retain(|evidence| {
        evidence.owner_type != "diagnostic"
            || retained_diagnostic_ids.contains(evidence.owner_id.as_str())
    });
    let retained_diagnostic_count = snapshot.diagnostics.len();
    let next_diagnostic_ordinal = snapshot
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.ordinal)
        .max()
        .unwrap_or(-1)
        .saturating_add(1);

    let matrix = build_profile_matrix(snapshot);
    append_matrix_diagnostics(snapshot, &matrix);
    snapshot.profile_matrix = matrix;
    if canonicalize_diagnostics {
        snapshot
            .diagnostics
            .sort_by(|left, right| left.id.cmp(&right.id));
        for (ordinal, diagnostic) in snapshot.diagnostics.iter_mut().enumerate() {
            diagnostic.ordinal = ordinal as i64;
        }
    } else {
        for (offset, diagnostic) in snapshot
            .diagnostics
            .iter_mut()
            .skip(retained_diagnostic_count)
            .enumerate()
        {
            diagnostic.ordinal = next_diagnostic_ordinal.saturating_add(offset as i64);
        }
    }
    snapshot.evidence.sort_by(|left, right| {
        left.owner_type
            .cmp(&right.owner_type)
            .then(left.owner_id.cmp(&right.owner_id))
            .then(left.ordinal.cmp(&right.ordinal))
    });
}

/// Rebuilds the derived profile-matrix view after a caller has selected a
/// deterministic graph subset for presentation or export.
pub fn refresh_profile_matrix_view(snapshot: &mut GraphSnapshot) {
    refresh_profile_matrix(snapshot, true);
}

fn build_profile_matrix(snapshot: &GraphSnapshot) -> ProfileMatrixRecord {
    let profiles = snapshot
        .profiles
        .iter()
        .map(|profile| (profile.id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut profile_effective = BTreeMap::<String, String>::new();
    for profile in &snapshot.profiles {
        let effective_input_id = declared_parent_profile_id(profile)
            .and_then(|parent| profiles.get(parent).copied())
            .map(canonical_effective_input_id)
            .unwrap_or_else(|| canonical_effective_input_id(profile));
        profile_effective.insert(profile.id.clone(), effective_input_id);
    }

    let mut entries = BTreeMap::<String, EntryBuilder>::new();
    let mut global_phase = BTreeMap::<String, PhaseCoverageBuilder>::new();
    for profile in &snapshot.profiles {
        let effective_input_id = profile_effective
            .get(&profile.id)
            .cloned()
            .unwrap_or_else(|| canonical_effective_input_id(profile));
        let entry = entries
            .entry(effective_input_id.clone())
            .or_insert_with(|| EntryBuilder {
                effective_input_id,
                language: canonical_language(&profile.language).to_owned(),
                ..EntryBuilder::default()
            });
        entry.profile_ids.insert(profile.id.clone());
        if let Some(parent) = declared_parent_profile_id(profile) {
            entry.parent_profile_ids.insert(parent.to_owned());
            entry
                .selection_reasons
                .insert("parent-effective-input".to_owned());
            if let Some(parent_profile) = profiles.get(parent).copied() {
                let fields = profile_axis_differences(profile, parent_profile);
                if !fields.is_empty() {
                    let diagnostic_id = stable_id_from_value(
                        "diagnostic",
                        &json!({
                            "code":"PROFILE_MATRIX_PROFILE_CONFLICT",
                            "profile_id":profile.id,
                            "parent_profile_id":parent,
                            "fields":fields,
                        }),
                    );
                    entry.axis_conflicts.push(ProfileAxisConflictRecord {
                        profile_id: profile.id.clone(),
                        parent_profile_id: parent.to_owned(),
                        fields,
                        diagnostic_id,
                    });
                }
            }
        } else {
            entry
                .selection_reasons
                .insert("direct-effective-input".to_owned());
        }
        for phase in profile_phases(profile) {
            entry.phases.insert(phase.clone());
            entry
                .phase_coverage
                .entry(phase.clone())
                .or_default()
                .profile_ids
                .insert(profile.id.clone());
            global_phase
                .entry(phase)
                .or_default()
                .profile_ids
                .insert(profile.id.clone());
        }
        if let Some(coverage) = &profile.coverage {
            for completeness in &coverage.completeness {
                if let Some(phase) = completeness_phase(completeness) {
                    entry
                        .phase_coverage
                        .entry(phase.to_owned())
                        .or_default()
                        .completeness
                        .insert(completeness.clone());
                    global_phase
                        .entry(phase.to_owned())
                        .or_default()
                        .completeness
                        .insert(completeness.clone());
                }
            }
        }
    }

    let evidence_phase = snapshot
        .evidence
        .iter()
        .filter(|evidence| matches!(evidence.owner_type.as_str(), "site" | "edge"))
        .fold(
            BTreeMap::<(String, String), (i64, String)>::new(),
            |mut map, evidence| {
                let phase = evidence_kind_phase(&evidence.kind).to_owned();
                let key = (evidence.owner_type.clone(), evidence.owner_id.clone());
                if map
                    .get(&key)
                    .is_none_or(|(ordinal, _)| evidence.ordinal < *ordinal)
                {
                    map.insert(key, (evidence.ordinal, phase));
                }
                map
            },
        );

    let mut correlations = BTreeMap::<String, CorrelationBuilder>::new();
    let mut site_correlations = BTreeMap::<String, String>::new();
    for site in &snapshot.sites {
        let phase = evidence_phase
            .get(&("site".to_owned(), site.id.clone()))
            .map(|(_, phase)| phase.as_str())
            .unwrap_or("static")
            .to_owned();
        let Some(effective_input_id) = profile_effective.get(&site.profile_id) else {
            continue;
        };
        let effective_profile_id = effective_profile_id(effective_input_id);
        let key = correlation_key(
            &effective_profile_id,
            &site.source,
            &site.kind,
            site.specifier.as_deref().unwrap_or_default(),
        );
        site_correlations.insert(site.id.clone(), key.clone());
        let correlation = correlations
            .entry(key)
            .or_insert_with(|| CorrelationBuilder {
                effective_profile_id: effective_profile_id.clone(),
                source: site.source.clone(),
                kind: site.kind.clone(),
                specifier: site.specifier.clone().unwrap_or_default(),
                ..CorrelationBuilder::default()
            });
        correlation
            .conditions
            .entry(phase.clone())
            .or_default()
            .push(canonical_condition(&site.condition));
        correlation
            .targets
            .entry(phase.clone())
            .or_default()
            .extend(site.target_ids.iter().cloned());
        correlation
            .resolutions
            .entry(phase.clone())
            .or_default()
            .insert(site.resolution_status.clone());
        correlation
            .site_ids
            .entry(phase.clone())
            .or_default()
            .insert(site.id.clone());
        if let Some(entry) = entries.get_mut(effective_input_id) {
            entry.phases.insert(phase.clone());
            entry.conditions.push(site.condition.clone());
            let coverage = entry.phase_coverage.entry(phase.clone()).or_default();
            coverage.profile_ids.insert(site.profile_id.clone());
            coverage.add_site(site);
        }
        let coverage = global_phase.entry(phase).or_default();
        coverage.profile_ids.insert(site.profile_id.clone());
        coverage.add_site(site);
    }

    for edge in &snapshot.edges {
        let phase = canonical_phase(&edge.phase).to_owned();
        if let Some(effective_input_id) = profile_effective.get(&edge.profile_id) {
            if let Some(entry) = entries.get_mut(effective_input_id) {
                entry.phases.insert(phase.clone());
                entry.conditions.push(edge.condition.clone());
                let coverage = entry.phase_coverage.entry(phase.clone()).or_default();
                coverage.profile_ids.insert(edge.profile_id.clone());
                coverage.edges = coverage.edges.saturating_add(1);
            }
            let coverage = global_phase.entry(phase.clone()).or_default();
            coverage.profile_ids.insert(edge.profile_id.clone());
            coverage.edges = coverage.edges.saturating_add(1);
        }
        if let Some(site_id) = edge.site_id.as_deref()
            && let Some(correlation_key) = site_correlations.get(site_id)
            && let Some(correlation) = correlations.get_mut(correlation_key)
        {
            correlation
                .edge_ids
                .entry(phase)
                .or_default()
                .insert(edge.id.clone());
        }
    }

    let owner_profiles = snapshot
        .sites
        .iter()
        .map(|site| (("site", site.id.as_str()), site.profile_id.as_str()))
        .chain(
            snapshot
                .edges
                .iter()
                .map(|edge| (("edge", edge.id.as_str()), edge.profile_id.as_str())),
        )
        .collect::<BTreeMap<_, _>>();
    for evidence in &snapshot.evidence {
        let Some(profile_id) =
            owner_profiles.get(&(evidence.owner_type.as_str(), evidence.owner_id.as_str()))
        else {
            continue;
        };
        let phase = evidence_kind_phase(&evidence.kind).to_owned();
        if let Some(effective_input_id) = profile_effective.get(*profile_id)
            && let Some(entry) = entries.get_mut(effective_input_id)
        {
            let coverage = entry.phase_coverage.entry(phase.clone()).or_default();
            coverage.profile_ids.insert((*profile_id).to_owned());
            coverage.evidence = coverage.evidence.saturating_add(1);
        }
        let coverage = global_phase.entry(phase).or_default();
        coverage.profile_ids.insert((*profile_id).to_owned());
        coverage.evidence = coverage.evidence.saturating_add(1);
    }

    let mut correlation_records = correlations
        .into_values()
        .map(finish_correlation)
        .collect::<Vec<_>>();
    correlation_records.sort_by(|left, right| left.id.cmp(&right.id));
    let correlations_by_entry = correlation_records.iter().fold(
        BTreeMap::<String, Vec<Value>>::new(),
        |mut map, correlation| {
            map.entry(correlation.effective_profile_id.clone())
                .or_default()
                .push(correlation.condition_union.clone());
            map
        },
    );

    let mut entry_records = entries
        .into_values()
        .map(|entry| {
            let id = effective_profile_id(&entry.effective_input_id);
            let mut axis_conflicts = entry.axis_conflicts;
            axis_conflicts.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
            let conditions = correlations_by_entry
                .get(&id)
                .cloned()
                .unwrap_or(entry.conditions);
            ProfileMatrixEntryRecord {
                id,
                effective_input_id: entry.effective_input_id,
                language: entry.language,
                profile_ids: entry.profile_ids.into_iter().collect(),
                parent_profile_ids: entry.parent_profile_ids.into_iter().collect(),
                phases: entry.phases.into_iter().collect(),
                condition_union: condition_union(&conditions),
                phase_coverage: entry
                    .phase_coverage
                    .into_iter()
                    .map(|(phase, coverage)| (phase, coverage.finish()))
                    .collect(),
                selection_reasons: entry.selection_reasons.into_iter().collect(),
                axis_conflicts,
            }
        })
        .collect::<Vec<_>>();
    entry_records.sort_by(|left, right| left.id.cmp(&right.id));

    let mut difference_counts = BTreeMap::new();
    for correlation in &correlation_records {
        *difference_counts
            .entry(correlation.status.clone())
            .or_insert(0_u64) += 1;
    }
    for status in ["matched", "additional", "conflict", "unobserved"] {
        difference_counts.entry(status.to_owned()).or_insert(0);
    }
    ProfileMatrixRecord {
        schema_version: PROFILE_MATRIX_SCHEMA_VERSION.to_owned(),
        entries: entry_records,
        correlations: correlation_records,
        phase_coverage: global_phase
            .into_iter()
            .map(|(phase, coverage)| (phase, coverage.finish()))
            .collect(),
        difference_counts,
    }
}

fn finish_correlation(builder: CorrelationBuilder) -> ProfileCorrelationRecord {
    let conditions_by_phase = builder
        .conditions
        .iter()
        .map(|(phase, conditions)| (phase.clone(), condition_union(conditions)))
        .collect::<BTreeMap<_, _>>();
    let predicted_phase = if builder.targets.contains_key("semantic") {
        Some("semantic")
    } else if builder.targets.contains_key("static") {
        Some("static")
    } else {
        None
    };
    let observed_phases = ["build", "runtime"]
        .into_iter()
        .filter(|phase| builder.targets.contains_key(*phase))
        .collect::<Vec<_>>();
    let mut differences = BTreeSet::new();
    let status = match (predicted_phase, observed_phases.is_empty()) {
        (None, false) => {
            differences.insert("observed_addition".to_owned());
            "additional"
        }
        (Some(_), true) => {
            differences.insert("not_observed".to_owned());
            "unobserved"
        }
        (None, true) => {
            differences.insert("not_observed".to_owned());
            "unobserved"
        }
        (Some(predicted), false) => {
            let expected_targets = builder.targets.get(predicted).cloned().unwrap_or_default();
            let expected_condition = conditions_by_phase.get(predicted);
            let expected_resolution = builder
                .resolutions
                .get(predicted)
                .cloned()
                .unwrap_or_default();
            for observed in observed_phases {
                if builder.targets.get(observed) != Some(&expected_targets) {
                    differences.insert("target_mismatch".to_owned());
                }
                if conditions_by_phase.get(observed) != expected_condition {
                    differences.insert("condition_mismatch".to_owned());
                }
                if builder.resolutions.get(observed) != Some(&expected_resolution) {
                    differences.insert("resolution_mismatch".to_owned());
                }
            }
            if differences.is_empty() {
                "matched"
            } else {
                "conflict"
            }
        }
    }
    .to_owned();
    if builder.targets.contains_key("static") && builder.targets.contains_key("semantic") {
        let static_condition = conditions_by_phase.get("static");
        let semantic_condition = conditions_by_phase.get("semantic");
        if builder.targets.get("static") != builder.targets.get("semantic")
            || static_condition != semantic_condition
        {
            differences.insert("semantic_refinement".to_owned());
        }
    }
    let id = correlation_key(
        &builder.effective_profile_id,
        &builder.source,
        &builder.kind,
        &builder.specifier,
    );
    let diagnostic_id = (status == "conflict").then(|| {
        stable_id_from_value(
            "diagnostic",
            &json!({"code":"BUILD_EVIDENCE_CONFLICT","correlation_id":id}),
        )
    });
    ProfileCorrelationRecord {
        id,
        effective_profile_id: builder.effective_profile_id,
        source: builder.source,
        kind: builder.kind,
        specifier: builder.specifier,
        status,
        condition_union: condition_union(
            &conditions_by_phase.values().cloned().collect::<Vec<_>>(),
        ),
        conditions_by_phase,
        targets_by_phase: builder
            .targets
            .into_iter()
            .map(|(phase, values)| (phase, values.into_iter().collect()))
            .collect(),
        resolutions_by_phase: builder
            .resolutions
            .into_iter()
            .map(|(phase, values)| (phase, values.into_iter().collect()))
            .collect(),
        site_ids_by_phase: builder
            .site_ids
            .into_iter()
            .map(|(phase, values)| (phase, values.into_iter().collect()))
            .collect(),
        edge_ids_by_phase: builder
            .edge_ids
            .into_iter()
            .map(|(phase, values)| (phase, values.into_iter().collect()))
            .collect(),
        difference_reasons: differences.into_iter().collect(),
        diagnostic_id,
    }
}

fn append_matrix_diagnostics(snapshot: &mut GraphSnapshot, matrix: &ProfileMatrixRecord) {
    for correlation in matrix
        .correlations
        .iter()
        .filter(|correlation| correlation.status == "conflict")
    {
        let Some(id) = correlation.diagnostic_id.clone() else {
            continue;
        };
        let site_ids = correlation
            .site_ids_by_phase
            .values()
            .flatten()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let build_run_ids = snapshot
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.owner_type == "site"
                    && site_ids.contains(evidence.owner_id.as_str())
                    && evidence.kind == "build"
            })
            .filter_map(|evidence| {
                evidence
                    .properties
                    .get("build_run_id")
                    .and_then(Value::as_str)
            })
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        snapshot.diagnostics.push(DiagnosticRecord {
            ordinal: 0,
            id: id.clone(),
            severity: "warning".to_owned(),
            code: "BUILD_EVIDENCE_CONFLICT".to_owned(),
            message: "observed dependency evidence conflicts with the selected static or semantic prediction".to_owned(),
            path: None,
            adapter: None,
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            properties: json!({
                "profile_correlation_id": correlation.id,
                "profile_matrix_schema": PROFILE_MATRIX_SCHEMA_VERSION,
                "effective_profile_id": correlation.effective_profile_id,
                "build_run_id": build_run_ids.iter().next(),
                "build_run_ids": build_run_ids,
                "difference_reasons": correlation.difference_reasons,
                "conditions_by_phase": correlation.conditions_by_phase,
                "targets_by_phase": correlation.targets_by_phase,
                "site_ids_by_phase": correlation.site_ids_by_phase,
                "phases": correlation.site_ids_by_phase.keys().collect::<Vec<_>>(),
            }),
        });
        append_correlation_evidence(snapshot, correlation, &id);
    }
    for entry in &matrix.entries {
        for conflict in &entry.axis_conflicts {
            snapshot.diagnostics.push(DiagnosticRecord {
                ordinal: 0,
                id: conflict.diagnostic_id.clone(),
                severity: "warning".to_owned(),
                code: "PROFILE_MATRIX_PROFILE_CONFLICT".to_owned(),
                message: "child profile effective axes conflict with its declared parent profile"
                    .to_owned(),
                path: None,
                adapter: None,
                start_line: None,
                start_column: None,
                end_line: None,
                end_column: None,
                properties: json!({
                    "effective_profile_id":entry.id,
                    "profile_matrix_schema": PROFILE_MATRIX_SCHEMA_VERSION,
                    "effective_input_id":entry.effective_input_id,
                    "profile_id":conflict.profile_id,
                    "parent_profile_id":conflict.parent_profile_id,
                    "fields":conflict.fields,
                }),
            });
            let matching = snapshot
                .evidence
                .iter()
                .filter(|evidence| {
                    evidence.kind == "build"
                        && evidence
                            .properties
                            .get("profile_id")
                            .and_then(Value::as_str)
                            == Some(conflict.profile_id.as_str())
                })
                .cloned()
                .collect::<Vec<_>>();
            append_owned_evidence(snapshot, matching, &conflict.diagnostic_id);
        }
    }
}

fn append_correlation_evidence(
    snapshot: &mut GraphSnapshot,
    correlation: &ProfileCorrelationRecord,
    diagnostic_id: &str,
) {
    let site_ids = correlation
        .site_ids_by_phase
        .values()
        .flatten()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let matching = snapshot
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.owner_type == "site" && site_ids.contains(evidence.owner_id.as_str())
        })
        .cloned()
        .collect::<Vec<_>>();
    append_owned_evidence(snapshot, matching, diagnostic_id);
}

fn append_owned_evidence(
    snapshot: &mut GraphSnapshot,
    evidence: Vec<EvidenceRecord>,
    diagnostic_id: &str,
) {
    let mut seen = BTreeSet::new();
    for mut item in evidence {
        let identity = serde_json::to_string(&json!({
            "kind":item.kind,
            "extractor":item.extractor,
            "extractor_version":item.extractor_version,
            "path":item.path,
            "start_line":item.start_line,
            "start_column":item.start_column,
            "end_line":item.end_line,
            "end_column":item.end_column,
            "detail":item.detail,
            "properties":item.properties,
        }))
        .unwrap_or_default();
        if !seen.insert(identity) {
            continue;
        }
        item.owner_type = "diagnostic".to_owned();
        item.owner_id = diagnostic_id.to_owned();
        item.ordinal = seen.len().saturating_sub(1) as i64;
        snapshot.evidence.push(item);
    }
}

fn profile_axis_differences(child: &ProfileRecord, parent: &ProfileRecord) -> Vec<String> {
    let mut fields = Vec::new();
    if canonical_language(&child.language) != canonical_language(&parent.language) {
        fields.push("language".to_owned());
    }
    if child.target.is_some() && child.target != parent.target {
        fields.push("target".to_owned());
    }
    let mut child_features = child.features.clone();
    let mut parent_features = parent.features.clone();
    child_features.sort();
    child_features.dedup();
    parent_features.sort();
    parent_features.dedup();
    if child_features != parent_features {
        fields.push("features".to_owned());
    }
    if effective_environment(&child.environment) != effective_environment(&parent.environment) {
        fields.push("environment".to_owned());
    }
    fields
}

fn effective_environment(environment: &Value) -> Value {
    let mut environment = environment.as_object().cloned().unwrap_or_default();
    environment.remove("phase");
    Value::Object(environment)
}

fn profile_phases(profile: &ProfileRecord) -> BTreeSet<String> {
    let mut phases = BTreeSet::new();
    if let Some(phase) = profile
        .properties
        .get("profile_phase")
        .and_then(Value::as_str)
    {
        phases.insert(canonical_phase(phase).to_owned());
    }
    if let Some(coverage) = &profile.coverage {
        for completeness in &coverage.completeness {
            if let Some(phase) = completeness_phase(completeness) {
                phases.insert(phase.to_owned());
            }
        }
    }
    phases
}

fn completeness_phase(completeness: &str) -> Option<&'static str> {
    match completeness {
        "syntax-complete" => Some("static"),
        "semantic-complete" => Some("semantic"),
        "build-observed" => Some("build"),
        "runtime-observed" => Some("runtime"),
        _ => None,
    }
}

fn evidence_kind_phase(kind: &str) -> &'static str {
    match kind {
        "semantic" => "semantic",
        "build" => "build",
        "runtime" => "runtime",
        _ => "static",
    }
}

fn canonical_phase(phase: &str) -> &'static str {
    match phase {
        "semantic" => "semantic",
        "build" => "build",
        "runtime" => "runtime",
        _ => "static",
    }
}

fn canonical_language(language: &str) -> &str {
    match language {
        "typescript" | "javascript" | "web" => "web",
        other => other,
    }
}

fn effective_profile_id(effective_input_id: &str) -> String {
    stable_id_from_value(
        "effective-profile",
        &json!({
            "schema_version": PROFILE_MATRIX_SCHEMA_VERSION,
            "effective_input_id": effective_input_id,
        }),
    )
}

fn correlation_key(
    effective_profile_id: &str,
    source: &str,
    kind: &str,
    specifier: &str,
) -> String {
    stable_id_from_value(
        "profile-correlation",
        &json!({
            "schema_version":PROFILE_MATRIX_SCHEMA_VERSION,
            "effective_profile_id":effective_profile_id,
            "source":source,
            "kind":kind,
            "specifier":specifier,
        }),
    )
}

fn canonical_condition(value: &Value) -> Value {
    serde_json::from_value::<Condition>(value.clone())
        .map(|condition| {
            serde_json::to_value(condition.canonicalize()).unwrap_or_else(|_| value.clone())
        })
        .unwrap_or_else(|_| value.clone())
}

fn condition_union(values: &[Value]) -> Value {
    let mut conditions = values
        .iter()
        .filter_map(|value| serde_json::from_value::<Condition>(value.clone()).ok())
        .map(|condition| condition.canonicalize())
        .collect::<Vec<_>>();
    conditions.sort_by_key(|condition| serde_json::to_string(condition).unwrap_or_default());
    conditions.dedup();
    let union = match conditions.len() {
        0 => Condition::default(),
        1 => conditions.pop().unwrap_or_default(),
        _ => Condition::Any { conditions }.canonicalize(),
    };
    serde_json::to_value(union).unwrap_or_else(|_| json!({"op":"all","conditions":[]}))
}

pub fn correlation_for_edge<'a>(
    matrix: &'a ProfileMatrixRecord,
    edge_id: &str,
) -> Option<&'a ProfileCorrelationRecord> {
    matrix.correlations.iter().find(|correlation| {
        correlation
            .edge_ids_by_phase
            .values()
            .any(|edges| edges.iter().any(|edge| edge == edge_id))
    })
}

pub fn correlation_for_site<'a>(
    matrix: &'a ProfileMatrixRecord,
    site_id: &str,
) -> Option<&'a ProfileCorrelationRecord> {
    matrix.correlations.iter().find(|correlation| {
        correlation
            .site_ids_by_phase
            .values()
            .any(|sites| sites.iter().any(|site| site == site_id))
    })
}

pub fn phase_coverage_for_effective_profile(
    matrix: &ProfileMatrixRecord,
    effective_profile_id: &str,
) -> BTreeMap<String, PhaseCoverageRecord> {
    matrix
        .entries
        .iter()
        .find(|entry| entry.id == effective_profile_id)
        .map(|entry| entry.phase_coverage.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoverageRecord, ScanRecord};

    #[test]
    fn base_refresh_preserves_diagnostic_emission_order_and_ordinals() {
        let diagnostic = |ordinal, id: &str| DiagnosticRecord {
            ordinal,
            id: id.to_owned(),
            severity: "warning".to_owned(),
            code: "FIXTURE".to_owned(),
            message: id.to_owned(),
            path: None,
            adapter: None,
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            properties: json!({}),
        };
        let mut snapshot = GraphSnapshot {
            scan: ScanRecord {
                id: "scan".to_owned(),
                root: "/fixture".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "now".to_owned(),
                completed_at: Some("now".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
                health_policy_config_digest: None,
                health_analyzer_version: None,
                health_finding_contract_version: None,
            },
            profiles: Vec::new(),
            nodes: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            evidence: Vec::new(),
            diagnostics: vec![diagnostic(4, "diagnostic:z"), diagnostic(9, "diagnostic:a")],
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: ProfileMatrixRecord::default(),
        };

        refresh_profile_matrix(&mut snapshot, false);
        assert_eq!(
            snapshot
                .diagnostics
                .iter()
                .map(|item| (item.id.as_str(), item.ordinal))
                .collect::<Vec<_>>(),
            [("diagnostic:z", 4), ("diagnostic:a", 9)]
        );

        refresh_profile_matrix(&mut snapshot, true);
        assert_eq!(
            snapshot
                .diagnostics
                .iter()
                .map(|item| (item.id.as_str(), item.ordinal))
                .collect::<Vec<_>>(),
            [("diagnostic:a", 0), ("diagnostic:z", 1)]
        );
    }
}
