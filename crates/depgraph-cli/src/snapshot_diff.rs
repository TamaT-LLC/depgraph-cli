#![cfg_attr(not(test), allow(dead_code))]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use anyhow::{Result, bail};
use depgraph_core::service::{
    ClosedChangedRecord, ClosedRecordDiff, SnapshotDiffCoverage, SnapshotDiffEdge,
    SnapshotDiffEvidence, SnapshotDiffNode, SnapshotDiffProfile, SnapshotDiffResult,
    SnapshotDiffSite,
};
use depgraph_store::{
    ChangedRecord, CoverageRecord, EdgeRecord, EvidenceRecord, GraphSnapshot, GraphSnapshotDiff,
    NodeRecord, NodeRename, ProfileRecord, RecordDiff, RenameConfidence, SiteRecord,
};
use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct DiffFilters {
    pub kind: Vec<String>,
    pub profile: Vec<String>,
    pub phase: Vec<String>,
    pub status: Vec<String>,
}

impl DiffFilters {
    pub(crate) fn new(
        kind: Vec<String>,
        profile: Vec<String>,
        phase: Vec<String>,
        status: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            kind: normalize_filter("kind", kind)?,
            profile: normalize_filter("profile", profile)?,
            phase: normalize_filter("phase", phase)?,
            status: normalize_filter("status", status)?,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.kind.is_empty()
            && self.profile.is_empty()
            && self.phase.is_empty()
            && self.status.is_empty()
    }

    pub(crate) fn apply(&self, diff: GraphSnapshotDiff) -> GraphSnapshotDiff {
        if self.is_empty() {
            return diff;
        }
        let GraphSnapshotDiff {
            schema_version,
            from_snapshot_id,
            to_snapshot_id,
            nodes,
            sites,
            edges,
            evidence,
            profiles,
            coverage: _,
            renames,
            rename_candidates,
        } = diff;
        let nodes = filter_records(nodes, |record| self.matches_node(record));
        let sites = filter_records(sites, |record| self.matches_site(record));
        let edges = filter_records(edges, |record| self.matches_edge(record));
        let profiles = filter_records(profiles, |record| self.matches_profile(record));
        let renames = renames
            .into_iter()
            .filter(|rename| self.matches_rename(rename))
            .collect::<Vec<_>>();
        let rename_candidates = rename_candidates
            .into_iter()
            .filter(|rename| self.matches_rename(rename))
            .collect::<Vec<_>>();
        let retained_owners =
            retained_evidence_owners(&nodes, &sites, &edges, &renames, &rename_candidates);
        let evidence = filter_records(evidence, |record| {
            retained_owners.contains(&(record.owner_type.clone(), record.owner_id.clone()))
        });
        GraphSnapshotDiff {
            schema_version,
            from_snapshot_id,
            to_snapshot_id,
            nodes,
            sites,
            edges,
            evidence,
            profiles,
            coverage: None,
            renames,
            rename_candidates,
        }
    }

    fn matches_node(&self, record: &NodeRecord) -> bool {
        matches_dimension(&self.kind, Some(&record.kind))
            && matches_dimension(&self.profile, None)
            && matches_dimension(&self.phase, None)
            && matches_dimension(&self.status, None)
    }

    fn matches_site(&self, record: &SiteRecord) -> bool {
        matches_dimension(&self.kind, Some(&record.kind))
            && matches_dimension(&self.profile, Some(&record.profile_id))
            && matches_dimension(&self.phase, None)
            && matches_dimension(&self.status, Some(&record.resolution_status))
    }

    fn matches_edge(&self, record: &EdgeRecord) -> bool {
        matches_dimension(&self.kind, Some(&record.kind))
            && matches_dimension(&self.profile, Some(&record.profile_id))
            && matches_dimension(&self.phase, Some(&record.phase))
            && matches_dimension(&self.status, Some(&record.resolution_status))
    }

    fn matches_profile(&self, record: &ProfileRecord) -> bool {
        matches_dimension(&self.kind, None)
            && matches_dimension(&self.profile, Some(&record.id))
            && matches_dimension(&self.phase, None)
            && matches_dimension(&self.status, None)
    }

    fn matches_rename(&self, record: &NodeRename) -> bool {
        matches_dimension(&self.kind, Some(&record.kind))
            && matches_dimension(&self.profile, None)
            && matches_dimension(&self.phase, None)
            && matches_dimension(&self.status, None)
    }
}

fn normalize_filter(name: &str, values: Vec<String>) -> Result<Vec<String>> {
    let mut output = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            bail!("diff {name} filter must not be empty");
        }
        output.insert(value.to_owned());
    }
    Ok(output.into_iter().collect())
}

fn matches_dimension(filter: &[String], value: Option<&String>) -> bool {
    filter.is_empty()
        || value.is_some_and(|value| {
            filter
                .binary_search_by(|item| item.as_str().cmp(value))
                .is_ok()
        })
}

fn filter_records<T>(mut records: RecordDiff<T>, matches: impl Fn(&T) -> bool) -> RecordDiff<T> {
    records.added.retain(&matches);
    records.removed.retain(&matches);
    records
        .changed
        .retain(|record| matches(&record.before) || matches(&record.after));
    records
}

fn retained_evidence_owners(
    nodes: &RecordDiff<NodeRecord>,
    sites: &RecordDiff<SiteRecord>,
    edges: &RecordDiff<EdgeRecord>,
    renames: &[NodeRename],
    rename_candidates: &[NodeRename],
) -> BTreeSet<(String, String)> {
    let mut owners = BTreeSet::new();
    add_record_owners(&mut owners, "node", nodes, |record| &record.id);
    add_record_owners(&mut owners, "site", sites, |record| &record.id);
    add_record_owners(&mut owners, "edge", edges, |record| &record.id);
    for rename in renames.iter().chain(rename_candidates) {
        owners.insert(("node".to_owned(), rename.old_id.clone()));
        owners.insert(("node".to_owned(), rename.new_id.clone()));
    }
    owners
}

fn add_record_owners<T>(
    owners: &mut BTreeSet<(String, String)>,
    owner_type: &str,
    records: &RecordDiff<T>,
    id: impl Fn(&T) -> &String,
) {
    for record in records.added.iter().chain(&records.removed) {
        owners.insert((owner_type.to_owned(), id(record).clone()));
    }
    for record in &records.changed {
        owners.insert((owner_type.to_owned(), id(&record.before).clone()));
        owners.insert((owner_type.to_owned(), id(&record.after).clone()));
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RecordChangeSummary {
    pub added: u64,
    pub removed: u64,
    pub changed: u64,
}

impl<T> From<&RecordDiff<T>> for RecordChangeSummary {
    fn from(records: &RecordDiff<T>) -> Self {
        Self {
            added: records.added.len() as u64,
            removed: records.removed.len() as u64,
            changed: records.changed.len() as u64,
        }
    }
}

impl RecordChangeSummary {
    fn total(self) -> u64 {
        self.added + self.removed + self.changed
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RenameSummary {
    pub confirmed: u64,
    pub candidates: u64,
    pub exact: u64,
    pub high: u64,
    pub medium: u64,
    pub ambiguous: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct DiffSummary {
    pub empty: bool,
    pub total_changes: u64,
    pub nodes: RecordChangeSummary,
    pub sites: RecordChangeSummary,
    pub edges: RecordChangeSummary,
    pub evidence: RecordChangeSummary,
    pub profiles: RecordChangeSummary,
    pub coverage_changed: bool,
    pub renames: RenameSummary,
}

impl DiffSummary {
    pub(crate) fn new(diff: &GraphSnapshotDiff) -> Self {
        let nodes = RecordChangeSummary::from(&diff.nodes);
        let sites = RecordChangeSummary::from(&diff.sites);
        let edges = RecordChangeSummary::from(&diff.edges);
        let evidence = RecordChangeSummary::from(&diff.evidence);
        let profiles = RecordChangeSummary::from(&diff.profiles);
        let renames = rename_summary(&diff.renames, &diff.rename_candidates);
        Self {
            empty: diff.is_empty(),
            total_changes: nodes.total()
                + sites.total()
                + edges.total()
                + evidence.total()
                + profiles.total()
                + u64::from(diff.coverage.is_some())
                + renames.confirmed,
            nodes,
            sites,
            edges,
            evidence,
            profiles,
            coverage_changed: diff.coverage.is_some(),
            renames,
        }
    }
}

fn rename_summary(renames: &[NodeRename], candidates: &[NodeRename]) -> RenameSummary {
    let mut summary = RenameSummary {
        confirmed: renames.len() as u64,
        candidates: candidates.len() as u64,
        ..RenameSummary::default()
    };
    for rename in renames.iter().chain(candidates) {
        match rename.confidence {
            RenameConfidence::Exact => summary.exact += 1,
            RenameConfidence::High => summary.high += 1,
            RenameConfidence::Medium => summary.medium += 1,
            RenameConfidence::Ambiguous => summary.ambiguous += 1,
        }
    }
    summary
}

#[derive(Default)]
struct EvidenceIndex<'a> {
    by_owner: BTreeMap<&'a str, BTreeMap<&'a str, &'a EvidenceRecord>>,
}

impl<'a> EvidenceIndex<'a> {
    fn new(snapshot: Option<&'a GraphSnapshot>) -> Self {
        let mut index = Self::default();
        if let Some(snapshot) = snapshot {
            for evidence in &snapshot.evidence {
                index
                    .by_owner
                    .entry(evidence.owner_type.as_str())
                    .or_default()
                    .entry(evidence.owner_id.as_str())
                    .or_insert(evidence);
            }
        }
        index
    }

    fn primary(&self, owner_type: &str, owner_id: &str) -> Option<&'a EvidenceRecord> {
        self.by_owner
            .get(owner_type)
            .and_then(|owners| owners.get(owner_id))
            .copied()
    }
}

pub(crate) fn render_human_diff(
    diff: &GraphSnapshotDiff,
    filters: &DiffFilters,
    from: Option<&GraphSnapshot>,
    to: Option<&GraphSnapshot>,
) -> String {
    let summary = DiffSummary::new(diff);
    let from_evidence = EvidenceIndex::new(from);
    let to_evidence = EvidenceIndex::new(to);
    let mut output = String::new();
    writeln!(
        output,
        "diff: {} -> {}",
        diff.from_snapshot_id, diff.to_snapshot_id
    )
    .expect("writing to String cannot fail");
    if !filters.is_empty() {
        writeln!(
            output,
            "filters: kind={} profile={} phase={} status={}",
            display_filter_values(&filters.kind),
            display_filter_values(&filters.profile),
            display_filter_values(&filters.phase),
            display_filter_values(&filters.status),
        )
        .expect("writing to String cannot fail");
    }
    writeln!(output, "empty: {}", summary.empty).expect("writing to String cannot fail");
    writeln!(output, "total changes: {}", summary.total_changes)
        .expect("writing to String cannot fail");
    write_summary_line(&mut output, "nodes", summary.nodes);
    write_summary_line(&mut output, "sites", summary.sites);
    write_summary_line(&mut output, "edges", summary.edges);
    write_summary_line(&mut output, "evidence", summary.evidence);
    write_summary_line(&mut output, "profiles", summary.profiles);
    writeln!(
        output,
        "coverage: {}",
        if !filters.is_empty() {
            "excluded by filters"
        } else if summary.coverage_changed {
            "changed"
        } else {
            "unchanged"
        }
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "renames: {} confirmed, {} candidates (exact={}, high={}, medium={}, ambiguous={})",
        summary.renames.confirmed,
        summary.renames.candidates,
        summary.renames.exact,
        summary.renames.high,
        summary.renames.medium,
        summary.renames.ambiguous,
    )
    .expect("writing to String cannot fail");

    write_node_changes(&mut output, &diff.nodes, &from_evidence, &to_evidence);
    write_site_changes(&mut output, &diff.sites, &from_evidence, &to_evidence);
    write_edge_changes(&mut output, &diff.edges, &from_evidence, &to_evidence);
    write_profile_changes(&mut output, &diff.profiles);
    write_coverage_change(&mut output, diff.coverage.as_ref());
    write_renames(&mut output, "renamed nodes", &diff.renames, "R");
    write_renames(
        &mut output,
        "rename candidates",
        &diff.rename_candidates,
        "?",
    );
    write_evidence_changes(&mut output, &diff.evidence);
    output
}

fn display_filter_values(values: &[String]) -> String {
    if values.is_empty() {
        "any".to_owned()
    } else {
        values.join(",")
    }
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(",")
    }
}

fn write_summary_line(output: &mut String, label: &str, summary: RecordChangeSummary) {
    writeln!(
        output,
        "{label}: +{} -{} ~{}",
        summary.added, summary.removed, summary.changed
    )
    .expect("writing to String cannot fail");
}

fn write_node_changes(
    output: &mut String,
    records: &RecordDiff<NodeRecord>,
    from_evidence: &EvidenceIndex<'_>,
    to_evidence: &EvidenceIndex<'_>,
) {
    if records.is_empty() {
        return;
    }
    output.push_str("node changes:\n");
    for record in &records.added {
        writeln!(
            output,
            "  + [{}] {} {:?}",
            record.kind, record.id, record.display_name
        )
        .expect("writing to String cannot fail");
        write_primary_evidence(output, "    ", to_evidence.primary("node", &record.id));
    }
    for record in &records.removed {
        writeln!(
            output,
            "  - [{}] {} {:?}",
            record.kind, record.id, record.display_name
        )
        .expect("writing to String cannot fail");
        write_primary_evidence(output, "    ", from_evidence.primary("node", &record.id));
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ [{}] {} fields={} {:?} -> {:?}",
            record.after.kind,
            record.id,
            record.changed_fields.join(","),
            record.before.display_name,
            record.after.display_name,
        )
        .expect("writing to String cannot fail");
        write_changed_primary_evidence(output, "node", &record.id, from_evidence, to_evidence);
    }
}

fn write_site_changes(
    output: &mut String,
    records: &RecordDiff<SiteRecord>,
    from_evidence: &EvidenceIndex<'_>,
    to_evidence: &EvidenceIndex<'_>,
) {
    if records.is_empty() {
        return;
    }
    output.push_str("site changes:\n");
    for record in &records.added {
        write_site(output, "+", record, None);
        write_primary_evidence(output, "    ", to_evidence.primary("site", &record.id));
    }
    for record in &records.removed {
        write_site(output, "-", record, None);
        write_primary_evidence(output, "    ", from_evidence.primary("site", &record.id));
    }
    for record in &records.changed {
        write_site(output, "~", &record.after, Some(&record.changed_fields));
        write_changed_primary_evidence(output, "site", &record.id, from_evidence, to_evidence);
    }
}

fn write_site(output: &mut String, marker: &str, record: &SiteRecord, fields: Option<&[String]>) {
    let fields = fields
        .map(|fields| format!(" fields={}", fields.join(",")))
        .unwrap_or_default();
    writeln!(
        output,
        "  {marker} [{}] {} source={} profile={} status={} targets={}{}",
        record.kind,
        record.id,
        record.source,
        record.profile_id,
        record.resolution_status,
        display_list(&record.target_ids),
        fields,
    )
    .expect("writing to String cannot fail");
}

fn write_edge_changes(
    output: &mut String,
    records: &RecordDiff<EdgeRecord>,
    from_evidence: &EvidenceIndex<'_>,
    to_evidence: &EvidenceIndex<'_>,
) {
    if records.is_empty() {
        return;
    }
    output.push_str("edge changes:\n");
    for record in &records.added {
        write_edge(output, "+", record, None);
        write_primary_evidence(output, "    ", to_evidence.primary("edge", &record.id));
    }
    for record in &records.removed {
        write_edge(output, "-", record, None);
        write_primary_evidence(output, "    ", from_evidence.primary("edge", &record.id));
    }
    for record in &records.changed {
        write_edge(output, "~", &record.after, Some(&record.changed_fields));
        write_changed_primary_evidence(output, "edge", &record.id, from_evidence, to_evidence);
    }
}

fn write_edge(output: &mut String, marker: &str, record: &EdgeRecord, fields: Option<&[String]>) {
    let fields = fields
        .map(|fields| format!(" fields={}", fields.join(",")))
        .unwrap_or_default();
    writeln!(
        output,
        "  {marker} [{}] {} {} -> {} phase={} profile={} status={}{}",
        record.kind,
        record.id,
        record.source,
        record.target,
        record.phase,
        record.profile_id,
        record.resolution_status,
        fields,
    )
    .expect("writing to String cannot fail");
}

fn write_profile_changes(output: &mut String, records: &RecordDiff<ProfileRecord>) {
    if records.is_empty() {
        return;
    }
    output.push_str("profile changes:\n");
    for record in &records.added {
        writeln!(output, "  + {} language={}", record.id, record.language)
            .expect("writing to String cannot fail");
    }
    for record in &records.removed {
        writeln!(output, "  - {} language={}", record.id, record.language)
            .expect("writing to String cannot fail");
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ {} language={} fields={}",
            record.id,
            record.after.language,
            record.changed_fields.join(","),
        )
        .expect("writing to String cannot fail");
    }
}

fn write_coverage_change(output: &mut String, coverage: Option<&ChangedRecord<CoverageRecord>>) {
    let Some(coverage) = coverage else {
        return;
    };
    output.push_str("coverage change:\n");
    writeln!(output, "  ~ fields={}", coverage.changed_fields.join(","))
        .expect("writing to String cannot fail");
    writeln!(output, "    before: {}", compact_coverage(&coverage.before))
        .expect("writing to String cannot fail");
    writeln!(output, "    after: {}", compact_coverage(&coverage.after))
        .expect("writing to String cannot fail");
}

fn compact_coverage(coverage: &CoverageRecord) -> String {
    format!(
        "files={}/{} skipped={} sites={} resolved={} candidates={} external={} unresolved={} unsupported={} completeness={} reasons={}",
        coverage.files_analyzed,
        coverage.files_discovered,
        coverage.files_skipped,
        coverage.dependency_sites,
        coverage.resolved,
        coverage.candidates,
        coverage.external,
        coverage.unresolved,
        coverage.unsupported_syntax,
        display_list(&coverage.completeness),
        display_list(&coverage.reasons),
    )
}

fn write_renames(output: &mut String, heading: &str, renames: &[NodeRename], marker: &str) {
    if renames.is_empty() {
        return;
    }
    writeln!(output, "{heading}:").expect("writing to String cannot fail");
    for rename in renames {
        writeln!(
            output,
            "  {marker} [{}; {}] {} -> {} fields={} reasons={}",
            rename.kind,
            rename_confidence(rename.confidence),
            rename.old_id,
            rename.new_id,
            rename.changed_fields.join(","),
            rename.reasons.join(","),
        )
        .expect("writing to String cannot fail");
        write_rename_evidence(output, "old", &rename.old_evidence);
        write_rename_evidence(output, "new", &rename.new_evidence);
    }
}

fn rename_confidence(confidence: RenameConfidence) -> &'static str {
    match confidence {
        RenameConfidence::Exact => "exact",
        RenameConfidence::High => "high",
        RenameConfidence::Medium => "medium",
        RenameConfidence::Ambiguous => "ambiguous",
    }
}

fn write_rename_evidence(
    output: &mut String,
    label: &str,
    evidence: &depgraph_store::NodeRenameEvidence,
) {
    if let Some(record) = evidence.records.first() {
        write_evidence(output, "    ", label, record);
    } else if let Some(path) = &evidence.source_path {
        writeln!(output, "    {label} evidence: {path}").expect("writing to String cannot fail");
    }
}

fn write_evidence_changes(output: &mut String, records: &RecordDiff<EvidenceRecord>) {
    if records.is_empty() {
        return;
    }
    output.push_str("evidence changes:\n");
    for record in &records.added {
        write_evidence(output, "  ", "+", record);
    }
    for record in &records.removed {
        write_evidence(output, "  ", "-", record);
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ {}:{}#{} fields={}",
            record.after.owner_type,
            record.after.owner_id,
            record.after.ordinal,
            record.changed_fields.join(","),
        )
        .expect("writing to String cannot fail");
        write_evidence(output, "    ", "before", &record.before);
        write_evidence(output, "    ", "after", &record.after);
    }
}

fn write_changed_primary_evidence(
    output: &mut String,
    owner_type: &str,
    owner_id: &str,
    from: &EvidenceIndex<'_>,
    to: &EvidenceIndex<'_>,
) {
    let before = from.primary(owner_type, owner_id);
    let after = to.primary(owner_type, owner_id);
    if before == after {
        write_primary_evidence(output, "    ", after);
        return;
    }
    if let Some(before) = before {
        write_evidence(output, "    ", "before evidence", before);
    }
    if let Some(after) = after {
        write_evidence(output, "    ", "after evidence", after);
    }
}

fn write_primary_evidence(output: &mut String, prefix: &str, evidence: Option<&EvidenceRecord>) {
    if let Some(evidence) = evidence {
        write_evidence(output, prefix, "evidence", evidence);
    }
}

fn write_evidence(output: &mut String, prefix: &str, label: &str, evidence: &EvidenceRecord) {
    let detail = evidence
        .detail
        .as_deref()
        .map(|detail| format!(" detail={detail:?}"))
        .unwrap_or_default();
    writeln!(
        output,
        "{prefix}{label}: {}:{}#{} [{} {}@{}] {}:{}:{}-{}:{}{}",
        evidence.owner_type,
        evidence.owner_id,
        evidence.ordinal,
        evidence.kind,
        evidence.extractor,
        evidence.extractor_version,
        evidence.path,
        evidence.start_line,
        evidence.start_column,
        evidence.end_line,
        evidence.end_column,
        detail,
    )
    .expect("writing to String cannot fail");
}

pub(crate) fn render_service_human_diff(diff: &SnapshotDiffResult) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "diff: {} -> {}",
        diff.from_snapshot_id, diff.to_snapshot_id
    )
    .expect("writing to String cannot fail");
    if !diff.filters.is_empty() {
        writeln!(
            output,
            "filters: kind={} profile={} phase={} status={}",
            display_filter_values(diff.filters.kinds()),
            display_filter_values(diff.filters.profiles()),
            display_filter_values(diff.filters.phases()),
            display_filter_values(diff.filters.statuses()),
        )
        .expect("writing to String cannot fail");
    }
    writeln!(output, "empty: {}", diff.summary.empty).expect("writing to String cannot fail");
    writeln!(output, "total changes: {}", diff.summary.total_changes)
        .expect("writing to String cannot fail");
    for (label, summary) in [
        ("nodes", diff.summary.nodes),
        ("sites", diff.summary.sites),
        ("edges", diff.summary.edges),
        ("evidence", diff.summary.evidence),
        ("profiles", diff.summary.profiles),
    ] {
        writeln!(
            output,
            "{label}: +{} -{} ~{}",
            summary.added, summary.removed, summary.changed
        )
        .expect("writing to String cannot fail");
    }
    writeln!(
        output,
        "coverage: {}",
        if !diff.filters.is_empty() {
            "excluded by filters"
        } else if diff.summary.coverage_changed {
            "changed"
        } else {
            "unchanged"
        }
    )
    .expect("writing to String cannot fail");
    writeln!(
        output,
        "renames: {} confirmed, {} candidates (exact={}, high={}, medium={}, ambiguous={})",
        diff.summary.renames.confirmed,
        diff.summary.renames.candidates,
        diff.summary.renames.exact,
        diff.summary.renames.high,
        diff.summary.renames.medium,
        diff.summary.renames.ambiguous,
    )
    .expect("writing to String cannot fail");

    write_service_nodes(&mut output, &diff.nodes);
    write_service_sites(&mut output, &diff.sites);
    write_service_edges(&mut output, &diff.edges);
    write_service_profiles(&mut output, &diff.profiles);
    write_service_coverage(&mut output, diff.coverage.as_ref());
    for (heading, marker, renames) in [
        ("renamed nodes", "R", diff.renames.as_slice()),
        ("rename candidates", "?", diff.rename_candidates.as_slice()),
    ] {
        if !renames.is_empty() {
            writeln!(output, "{heading}:").expect("writing to String cannot fail");
            for rename in renames {
                writeln!(
                    output,
                    "  {marker} [{}; {}] {} -> {} fields={}",
                    rename.kind,
                    rename_confidence(rename.confidence),
                    rename.old_id,
                    rename.new_id,
                    rename.changed_fields.join(","),
                )
                .expect("writing to String cannot fail");
            }
        }
    }
    write_service_evidence_changes(&mut output, &diff.evidence);
    output
}

fn write_service_nodes(output: &mut String, records: &ClosedRecordDiff<SnapshotDiffNode>) {
    if records.added.is_empty() && records.removed.is_empty() && records.changed.is_empty() {
        return;
    }
    output.push_str("node changes:\n");
    for (marker, values) in [("+", &records.added), ("-", &records.removed)] {
        for record in values {
            writeln!(
                output,
                "  {marker} [{}] {} {:?}",
                record.kind, record.id, record.display_name
            )
            .expect("writing to String cannot fail");
        }
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ [{}] {} fields={} {:?} -> {:?}",
            record.after.kind,
            record.id,
            record.changed_fields.join(","),
            record.before.display_name,
            record.after.display_name,
        )
        .expect("writing to String cannot fail");
    }
}

fn write_service_sites(output: &mut String, records: &ClosedRecordDiff<SnapshotDiffSite>) {
    if records.added.is_empty() && records.removed.is_empty() && records.changed.is_empty() {
        return;
    }
    output.push_str("site changes:\n");
    for (marker, values) in [("+", &records.added), ("-", &records.removed)] {
        for record in values {
            write_service_site(output, marker, record, &[]);
        }
    }
    for record in &records.changed {
        write_service_site(output, "~", &record.after, &record.changed_fields);
    }
}

fn write_service_site(
    output: &mut String,
    marker: &str,
    record: &SnapshotDiffSite,
    fields: &[String],
) {
    let fields = if fields.is_empty() {
        String::new()
    } else {
        format!(" fields={}", fields.join(","))
    };
    writeln!(
        output,
        "  {marker} [{}] {} source={} profile={} status={} targets={}{}",
        record.kind,
        record.id,
        record.source,
        record.profile_id,
        record.resolution_status,
        display_list(&record.target_ids),
        fields,
    )
    .expect("writing to String cannot fail");
}

fn write_service_edges(output: &mut String, records: &ClosedRecordDiff<SnapshotDiffEdge>) {
    if records.added.is_empty() && records.removed.is_empty() && records.changed.is_empty() {
        return;
    }
    output.push_str("edge changes:\n");
    for (marker, values) in [("+", &records.added), ("-", &records.removed)] {
        for record in values {
            write_service_edge(output, marker, record, &[]);
        }
    }
    for record in &records.changed {
        write_service_edge(output, "~", &record.after, &record.changed_fields);
    }
}

fn write_service_edge(
    output: &mut String,
    marker: &str,
    record: &SnapshotDiffEdge,
    fields: &[String],
) {
    let fields = if fields.is_empty() {
        String::new()
    } else {
        format!(" fields={}", fields.join(","))
    };
    writeln!(
        output,
        "  {marker} [{}] {} {} -> {} phase={} profile={} status={}{}",
        record.kind,
        record.id,
        record.source,
        record.target,
        record.phase,
        record.profile_id,
        record.resolution_status,
        fields,
    )
    .expect("writing to String cannot fail");
}

fn write_service_profiles(output: &mut String, records: &ClosedRecordDiff<SnapshotDiffProfile>) {
    if records.added.is_empty() && records.removed.is_empty() && records.changed.is_empty() {
        return;
    }
    output.push_str("profile changes:\n");
    for (marker, values) in [("+", &records.added), ("-", &records.removed)] {
        for record in values {
            writeln!(
                output,
                "  {marker} {} language={}",
                record.id, record.language
            )
            .expect("writing to String cannot fail");
        }
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ {} language={} fields={}",
            record.id,
            record.after.language,
            record.changed_fields.join(","),
        )
        .expect("writing to String cannot fail");
    }
}

fn write_service_coverage(
    output: &mut String,
    coverage: Option<&ClosedChangedRecord<SnapshotDiffCoverage>>,
) {
    let Some(coverage) = coverage else {
        return;
    };
    output.push_str("coverage change:\n");
    writeln!(output, "  ~ fields={}", coverage.changed_fields.join(","))
        .expect("writing to String cannot fail");
}

fn write_service_evidence_changes(
    output: &mut String,
    records: &ClosedRecordDiff<SnapshotDiffEvidence>,
) {
    if records.added.is_empty() && records.removed.is_empty() && records.changed.is_empty() {
        return;
    }
    output.push_str("evidence changes:\n");
    for (marker, values) in [("+", &records.added), ("-", &records.removed)] {
        for record in values {
            write_service_evidence(output, marker, record);
        }
    }
    for record in &records.changed {
        writeln!(
            output,
            "  ~ {}:{}#{} fields={}",
            record.after.owner_type,
            record.after.owner_id,
            record.after.ordinal,
            record.changed_fields.join(","),
        )
        .expect("writing to String cannot fail");
        write_service_evidence(output, "after", &record.after);
    }
}

fn write_service_evidence(output: &mut String, label: &str, evidence: &SnapshotDiffEvidence) {
    writeln!(
        output,
        "  {label} evidence: {}:{}#{} [{} {}@{}] {}:{}:{}-{}:{}",
        evidence.owner_type,
        evidence.owner_id,
        evidence.ordinal,
        evidence.kind,
        evidence.extractor,
        evidence.extractor_version,
        evidence.path,
        evidence.start_line,
        evidence.start_column,
        evidence.end_line,
        evidence.end_column,
    )
    .expect("writing to String cannot fail");
}

#[cfg(test)]
mod tests {
    use depgraph_store::{GraphSnapshotDiff, RenameConfidence};
    use serde_json::json;

    use super::*;

    fn node(id: &str, kind: &str) -> NodeRecord {
        NodeRecord {
            id: id.to_owned(),
            kind: kind.to_owned(),
            locator: id.to_owned(),
            display_name: id.to_owned(),
            properties: json!({}),
        }
    }

    fn edge(id: &str, profile: &str, phase: &str, status: &str) -> EdgeRecord {
        EdgeRecord {
            id: id.to_owned(),
            site_id: Some(format!("site:{id}")),
            source: "file:source".to_owned(),
            target: "file:target".to_owned(),
            kind: "imports".to_owned(),
            phase: phase.to_owned(),
            environment: "host".to_owned(),
            profile_id: profile.to_owned(),
            resolution_status: status.to_owned(),
            precision: "exact".to_owned(),
            condition: json!({"op":"all","conditions":[]}),
            generated: false,
        }
    }

    #[test]
    fn filters_are_sorted_deduplicated_and_strictly_scoped() -> Result<()> {
        let filters = DiffFilters::new(
            vec!["symbol".to_owned(), "symbol".to_owned()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?;
        assert_eq!(filters.kind, ["symbol"]);
        let mut diff = GraphSnapshotDiff::empty("from", "to");
        diff.nodes.added = vec![node("file:b", "file"), node("symbol:a", "symbol")];
        diff.edges.added = vec![edge("edge:a", "profile:a", "semantic", "resolved")];
        let filtered = filters.apply(diff);
        assert_eq!(filtered.nodes.added.len(), 1);
        assert_eq!(filtered.nodes.added[0].id, "symbol:a");
        assert!(filtered.edges.added.is_empty());

        let profile = DiffFilters::new(
            Vec::new(),
            vec!["profile:a".to_owned()],
            Vec::new(),
            Vec::new(),
        )?;
        let mut diff = GraphSnapshotDiff::empty("from", "to");
        diff.nodes.added.push(node("file:a", "file"));
        diff.edges.added = vec![
            edge("edge:b", "profile:b", "semantic", "resolved"),
            edge("edge:a", "profile:a", "semantic", "resolved"),
        ];
        let filtered = profile.apply(diff);
        assert!(filtered.nodes.added.is_empty());
        assert_eq!(filtered.edges.added[0].id, "edge:a");
        Ok(())
    }

    #[test]
    fn changed_records_match_before_or_after_and_summary_ignores_candidates_as_changes()
    -> Result<()> {
        let filters = DiffFilters::new(
            Vec::new(),
            Vec::new(),
            vec!["semantic".to_owned()],
            vec!["unresolved".to_owned()],
        )?;
        let mut diff = GraphSnapshotDiff::empty("from", "to");
        diff.edges.changed.push(ChangedRecord {
            id: "edge:a".to_owned(),
            changed_fields: vec!["phase".to_owned(), "resolution_status".to_owned()],
            before: edge("edge:a", "profile:a", "source", "resolved"),
            after: edge("edge:a", "profile:a", "semantic", "unresolved"),
        });
        let filtered = filters.apply(diff);
        assert_eq!(filtered.edges.changed.len(), 1);
        let summary = DiffSummary::new(&filtered);
        assert_eq!(summary.total_changes, 1);
        assert!(!summary.empty);
        Ok(())
    }

    #[test]
    fn human_output_contains_summary_rename_and_primary_evidence() {
        let mut diff = GraphSnapshotDiff::empty("snapshot:from", "snapshot:to");
        diff.edges
            .added
            .push(edge("edge:new", "profile:a", "semantic", "resolved"));
        let old = node("file:old", "file");
        let new = node("file:new", "file");
        diff.renames.push(NodeRename {
            kind: "file".to_owned(),
            old_id: old.id.clone(),
            new_id: new.id.clone(),
            confidence: RenameConfidence::Exact,
            reasons: vec!["same_content".to_owned()],
            changed_fields: vec!["id".to_owned()],
            before: old,
            after: new,
            old_evidence: depgraph_store::NodeRenameEvidence {
                node_id: "file:old".to_owned(),
                package_owner: None,
                content_hash: None,
                source_content_hash: None,
                semantic_fingerprint: None,
                canonical_identity: None,
                source_path: Some("src/old.ts".to_owned()),
                source_span: None,
                records: Vec::new(),
            },
            new_evidence: depgraph_store::NodeRenameEvidence {
                node_id: "file:new".to_owned(),
                package_owner: None,
                content_hash: None,
                source_content_hash: None,
                semantic_fingerprint: None,
                canonical_identity: None,
                source_path: Some("src/new.ts".to_owned()),
                source_span: None,
                records: Vec::new(),
            },
        });
        let mut to = depgraph_store::GraphSnapshot {
            scan: depgraph_store::ScanRecord {
                id: "attempt".to_owned(),
                root: "/portable/project".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "2026-07-23T00:00:00.000Z".to_owned(),
                completed_at: Some("2026-07-23T00:00:01.000Z".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: Some("revision".to_owned()),
            },
            nodes: Vec::new(),
            profiles: Vec::new(),
            sites: Vec::new(),
            edges: Vec::new(),
            diagnostics: Vec::new(),
            evidence: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        };
        to.evidence.push(EvidenceRecord {
            owner_type: "edge".to_owned(),
            owner_id: "edge:new".to_owned(),
            ordinal: 0,
            kind: "semantic".to_owned(),
            extractor: "fixture".to_owned(),
            extractor_version: "1.0".to_owned(),
            path: "src/new.ts".to_owned(),
            start_line: 2,
            start_column: 1,
            end_line: 2,
            end_column: 8,
            detail: Some("resolved import".to_owned()),
            properties: json!({}),
        });
        let rendered = render_human_diff(&diff, &DiffFilters::default(), None, Some(&to));
        assert!(rendered.contains("total changes: 2"));
        assert!(rendered.contains("evidence: edge:edge:new#0"));
        assert!(rendered.contains("R [file; exact] file:old -> file:new"));
        assert!(rendered.contains("old evidence: src/old.ts"));
    }
}
