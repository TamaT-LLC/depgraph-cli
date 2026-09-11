//! Bounded response selection and external sorting of compact finding IDs.
//! Finding bodies live only in the current range and the requested page.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Read, Write},
};

use tempfile::{NamedTempFile, TempDir, TempPath};

use super::{
    CancellationToken, CollectionIdentity, Confidence, DepgraphServiceError, DepgraphServiceResult,
    FindingKind, HealthFinding, HealthFindingGetRequest, HealthFindingsRequest,
    HealthRangeDiagnostics, MAX_HEALTH_BLOCKERS_PER_FINDING, MAX_HEALTH_EVIDENCE_PER_FINDING,
    MAX_HEALTH_FINDINGS, MAX_HEALTH_REMEDIATIONS_PER_FINDING, MAX_HEALTH_SUPPRESSIONS_PER_FINDING,
    bound_findings,
};
use crate::health::contract::CollectionDigestBuilder;

const MERGE_FAN_IN: usize = 16;
// Finding IDs are already limited to 160 bytes by the service contract.
// This also bounds a JSON-escaped ID and its selection bit when read back.
const MAX_ID_ROW_BYTES: usize = 1024;

#[derive(Clone, Copy)]
pub(super) enum FindingSelection<'a> {
    Summary(Option<&'a [FindingKind]>),
    List(&'a HealthFindingsRequest),
    Detail(&'a str),
}

pub(super) struct FindingCollector<'a> {
    selection: FindingSelection<'a>,
    ids: IdRuns,
    regular: BTreeMap<String, HealthFinding>,
    partial: BTreeMap<String, HealthFinding>,
    counts_by_kind: BTreeMap<String, u64>,
    counts_by_confidence: BTreeMap<String, u64>,
}

pub(super) struct CollectedFindings {
    pub(super) findings: Vec<HealthFinding>,
    pub(super) ids: SortedFindingIds,
    pub(super) counts_by_kind: BTreeMap<String, u64>,
    pub(super) counts_by_confidence: BTreeMap<String, u64>,
}

impl<'a> FindingCollector<'a> {
    pub(super) fn new(selection: FindingSelection<'a>) -> DepgraphServiceResult<Self> {
        Ok(Self {
            selection,
            ids: IdRuns {
                directory: TempDir::new().map_err(store_error)?,
                runs: Vec::new(),
            },
            regular: BTreeMap::new(),
            partial: BTreeMap::new(),
            counts_by_kind: BTreeMap::new(),
            counts_by_confidence: BTreeMap::new(),
        })
    }

    pub(super) fn add(
        &mut self,
        findings: Vec<HealthFinding>,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<()> {
        if findings.len() > MAX_HEALTH_FINDINGS {
            return Err(DepgraphServiceError::ResourceExhausted);
        }
        let mut ids = Vec::with_capacity(findings.len());
        for finding in findings {
            check_cancelled(cancellation)?;
            if !finding.kind.is_snapshot_scoped() {
                continue;
            }
            validate_fields(&finding)?;
            let summary_selected = match self.selection {
                FindingSelection::Summary(kinds) => {
                    kinds.is_none_or(|kinds| kinds.contains(&finding.kind))
                }
                _ => false,
            };
            ids.push((finding.id.clone(), summary_selected));
            if summary_selected {
                *self
                    .counts_by_kind
                    .entry(finding.kind.as_str().to_owned())
                    .or_default() += 1;
                *self
                    .counts_by_confidence
                    .entry(finding.confidence.as_str().to_owned())
                    .or_default() += 1;
            }
            match self.selection {
                FindingSelection::Summary(_) => {}
                FindingSelection::Detail(id) if finding.id == id => {
                    self.regular.insert(finding.id.clone(), finding);
                }
                FindingSelection::Detail(_) => {}
                FindingSelection::List(request) => {
                    let matches = (request.kinds.is_empty()
                        || request.kinds.contains(&finding.kind))
                        && (request.severities.is_empty()
                            || request.severities.contains(&finding.severity));
                    if !matches {
                        continue;
                    }
                    // Partial status is known only after all ranges finish.
                    // Keep a second bounded candidate page only when a
                    // confidence filter could change its membership.
                    if request.allow_partial
                        && !request.confidences.is_empty()
                        && request.confidences.contains(&Confidence::Indeterminate)
                    {
                        retain_first(&mut self.partial, finding.clone(), request.limit);
                    }
                    if request.confidences.is_empty()
                        || request.confidences.contains(&finding.confidence)
                    {
                        retain_first(&mut self.regular, finding, request.limit);
                    }
                }
            }
        }
        self.ids.add(ids)
    }

    pub(super) fn finish(
        mut self,
        diagnostics: &HealthRangeDiagnostics,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<CollectedFindings> {
        let ids = self.ids.finish(cancellation)?;
        let use_partial = diagnostics.partial
            && matches!(self.selection, FindingSelection::List(request) if !request.confidences.is_empty());
        let mut findings: Vec<_> = if use_partial {
            self.partial
        } else {
            self.regular
        }
        .into_values()
        .collect();
        if diagnostics.partial {
            crate::health::ranged::mark_partial(&mut findings, diagnostics);
            let total = self.counts_by_confidence.values().sum();
            self.counts_by_confidence.clear();
            if total > 0 {
                self.counts_by_confidence
                    .insert(Confidence::Indeterminate.as_str().to_owned(), total);
            }
        }
        Ok(CollectedFindings {
            findings: bound_findings(findings)?,
            ids,
            counts_by_kind: self.counts_by_kind,
            counts_by_confidence: self.counts_by_confidence,
        })
    }
}

fn retain_first(page: &mut BTreeMap<String, HealthFinding>, finding: HealthFinding, limit: usize) {
    if page.len() < limit
        || page
            .last_key_value()
            .is_some_and(|(last, _)| &finding.id < last)
    {
        page.insert(finding.id.clone(), finding);
        if page.len() > limit {
            page.pop_last();
        }
    }
}

fn validate_fields(finding: &HealthFinding) -> DepgraphServiceResult<()> {
    HealthFindingGetRequest::try_new(finding.id.clone())
        .map_err(|_| DepgraphServiceError::Integrity)?;
    if finding.evidence.len() > MAX_HEALTH_EVIDENCE_PER_FINDING
        || finding.remediations.len() > MAX_HEALTH_REMEDIATIONS_PER_FINDING
        || finding.suppressions.len() > MAX_HEALTH_SUPPRESSIONS_PER_FINDING
        || finding
            .blockers
            .iter()
            .map(|blocker| blocker.kind)
            .collect::<BTreeSet<_>>()
            .len()
            > MAX_HEALTH_BLOCKERS_PER_FINDING
    {
        return Err(DepgraphServiceError::ResourceExhausted);
    }
    // Preserve original blockers on candidate pages. Once partial status is
    // known, mark_partial followed by bound_findings keeps the legacy
    // fingerprint and blocker-compaction order exactly.
    Ok(())
}

type IdRow = (String, bool);

struct IdRun {
    path: TempPath,
    count: u64,
}
struct IdRuns {
    directory: TempDir,
    runs: Vec<IdRun>,
}

pub(super) struct SortedFindingIds {
    _directory: TempDir,
    run: Option<IdRun>,
}

impl IdRuns {
    fn add(&mut self, mut ids: Vec<IdRow>) -> DepgraphServiceResult<()> {
        if ids.is_empty() {
            return Ok(());
        }
        ids.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if ids.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(DepgraphServiceError::Integrity);
        }
        let mut file = NamedTempFile::new_in(self.directory.path()).map_err(store_error)?;
        {
            let mut writer = BufWriter::new(file.as_file_mut());
            for row in &ids {
                write_row(&mut writer, row)?;
            }
            writer.flush().map_err(store_error)?;
        }
        self.runs.push(IdRun {
            path: file.into_temp_path(),
            count: ids.len() as u64,
        });
        Ok(())
    }

    fn finish(
        mut self,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<SortedFindingIds> {
        while self.runs.len() > 1 {
            let mut previous = std::mem::take(&mut self.runs).into_iter();
            loop {
                let group: Vec<_> = previous.by_ref().take(MERGE_FAN_IN).collect();
                if group.is_empty() {
                    break;
                }
                self.runs.push(self.merge(group, cancellation)?);
            }
        }
        check_cancelled(cancellation)?;
        Ok(SortedFindingIds {
            run: self.runs.pop(),
            _directory: self.directory,
        })
    }

    fn merge(
        &self,
        mut runs: Vec<IdRun>,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<IdRun> {
        if runs.len() == 1 {
            return Ok(runs.pop().expect("one run"));
        }
        let expected: u64 = runs.iter().map(|run| run.count).sum();
        let mut readers: Vec<_> = runs
            .iter()
            .map(|run| File::open(&run.path).map(BufReader::new))
            .collect::<Result<_, _>>()
            .map_err(store_error)?;
        let mut heads = Vec::with_capacity(readers.len());
        let mut queue = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            let row = read_row(reader)?;
            if let Some((id, _)) = &row {
                queue.push(Reverse((id.clone(), index)));
            }
            heads.push(row);
        }
        let mut file = NamedTempFile::new_in(self.directory.path()).map_err(store_error)?;
        let mut count = 0;
        {
            let mut writer = BufWriter::new(file.as_file_mut());
            let mut last: Option<String> = None;
            while let Some(Reverse((id, index))) = queue.pop() {
                check_cancelled(cancellation)?;
                if last.as_ref().is_some_and(|last| last >= &id) {
                    return Err(DepgraphServiceError::Integrity);
                }
                let row = heads[index].take().ok_or(DepgraphServiceError::Integrity)?;
                write_row(&mut writer, &row)?;
                count += 1;
                last = Some(id);
                heads[index] = read_row(&mut readers[index])?;
                if let Some((id, _)) = &heads[index] {
                    queue.push(Reverse((id.clone(), index)));
                }
            }
            writer.flush().map_err(store_error)?;
        }
        if count != expected {
            return Err(DepgraphServiceError::Integrity);
        }
        Ok(IdRun {
            path: file.into_temp_path(),
            count,
        })
    }
}

impl SortedFindingIds {
    pub(super) fn digest(
        &self,
        identity: &CollectionIdentity,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<String> {
        let mut digest = CollectionDigestBuilder::new(identity);
        if let Some(run) = &self.run {
            let mut reader = BufReader::new(File::open(&run.path).map_err(store_error)?);
            let mut count = 0;
            let mut last = None;
            while let Some((id, selected)) = read_row(&mut reader)? {
                check_cancelled(cancellation)?;
                if last.as_ref().is_some_and(|last| last >= &id) {
                    return Err(DepgraphServiceError::Integrity);
                }
                if selected {
                    digest.push(&id);
                }
                last = Some(id);
                count += 1;
            }
            if count != run.count {
                return Err(DepgraphServiceError::Integrity);
            }
        }
        check_cancelled(cancellation)?;
        Ok(digest.finish())
    }
}

fn write_row(writer: &mut impl Write, row: &IdRow) -> DepgraphServiceResult<()> {
    serde_json::to_writer(&mut *writer, row).map_err(store_error)?;
    writer.write_all(b"\n").map_err(store_error)
}

fn read_row(reader: &mut BufReader<File>) -> DepgraphServiceResult<Option<IdRow>> {
    let mut bytes = Vec::new();
    let count = (&mut *reader)
        .take((MAX_ID_ROW_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(store_error)?;
    if count == 0 {
        return Ok(None);
    }
    if count > MAX_ID_ROW_BYTES || bytes.last() != Some(&b'\n') {
        return Err(DepgraphServiceError::Integrity);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| DepgraphServiceError::Integrity)
}

fn check_cancelled(cancellation: &CancellationToken) -> DepgraphServiceResult<()> {
    if cancellation.is_cancelled() {
        Err(DepgraphServiceError::Cancelled)
    } else {
        Ok(())
    }
}

fn store_error(error: impl Into<anyhow::Error>) -> DepgraphServiceError {
    DepgraphServiceError::store_operation(error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::contract::collection_digest;

    fn runs() -> IdRuns {
        IdRuns {
            directory: TempDir::new().unwrap(),
            runs: Vec::new(),
        }
    }

    fn identity() -> CollectionIdentity {
        CollectionIdentity {
            snapshot_ids: vec!["snapshot:b".into(), "snapshot:a".into()],
            manifest_digest: Some("sha256:policy".into()),
            changed_oid: None,
            changed_set_digest: None,
            churn_start_oid: None,
            churn_commit_limit: None,
            churn_path_filter: Vec::new(),
            hotspot_weights: None,
            partial_ranges: None,
        }
    }

    fn finding(index: usize) -> HealthFinding {
        use crate::health::contract::{FindingIdentity, finish_finding};
        let mut finding = finish_finding(
            FindingIdentity {
                kind: FindingKind::UnusedFile,
                subject_id: format!("file:{index}"),
                profile_scope: None,
                witness_key: serde_json::json!({"path": format!("{index}.rs")}),
            },
            "file",
            None,
            "unused",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            false,
            true,
        );
        finding.id = format!("finding:sha256:{index:064x}");
        finding.confidence = Confidence::Confirmed;
        finding
    }

    #[test]
    fn partial_confidence_page_matches_legacy_post_mark_filter_and_stays_bounded() {
        let token = CancellationToken::new();
        let request = HealthFindingsRequest::try_new(
            Vec::new(),
            Vec::new(),
            vec![Confidence::Indeterminate],
            3,
        )
        .unwrap()
        .with_allow_partial(true);
        let mut collector = FindingCollector::new(FindingSelection::List(&request)).unwrap();
        let mut oracle = Vec::new();
        for index in (0..50).rev() {
            let finding = finding(index);
            oracle.push(finding.clone());
            collector.add(vec![finding], &token).unwrap();
            assert!(collector.regular.len() <= request.limit);
            assert!(collector.partial.len() <= request.limit);
        }
        let mut diagnostics = HealthRangeDiagnostics::whole_snapshot(Vec::new(), 100);
        diagnostics.partial = true;
        diagnostics.ranges.total = 2;
        diagnostics.ranges.completed = 1;
        diagnostics.ranges.failed = 1;
        crate::health::ranged::mark_partial(&mut oracle, &diagnostics);
        let mut oracle = bound_findings(oracle).unwrap();
        oracle.sort_by(|left, right| left.id.cmp(&right.id));
        oracle.truncate(3);
        assert_eq!(
            collector.finish(&diagnostics, &token).unwrap().findings,
            oracle
        );

        let request =
            HealthFindingsRequest::try_new(Vec::new(), Vec::new(), vec![Confidence::Confirmed], 3)
                .unwrap()
                .with_allow_partial(true);
        let mut collector = FindingCollector::new(FindingSelection::List(&request)).unwrap();
        collector.add(vec![finding(0)], &token).unwrap();
        assert!(
            collector
                .finish(&diagnostics, &token)
                .unwrap()
                .findings
                .is_empty()
        );
    }

    #[test]
    fn external_digest_matches_legacy_for_empty_escaped_and_multi_pass_selected_ids() {
        let token = CancellationToken::new();
        let empty = runs().finish(&token).unwrap();
        assert_eq!(
            empty.digest(&identity(), &token).unwrap(),
            collection_digest(&identity(), &[])
        );
        let mut spool = runs();
        let mut selected = Vec::new();
        for index in (0..MERGE_FAN_IN * MERGE_FAN_IN + 1).rev() {
            let id = format!("finding:{index:05}:\"\\\n日本語");
            let include = index % 3 == 0;
            if include {
                selected.push(id.clone());
            }
            spool.add(vec![(id, include)]).unwrap();
        }
        let directory = spool.directory.path().to_owned();
        let sorted = spool.finish(&token).unwrap();
        assert_eq!(
            sorted.digest(&identity(), &token).unwrap(),
            collection_digest(&identity(), &selected)
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        drop(sorted);
        assert!(!directory.exists());
    }

    #[test]
    fn duplicates_are_rejected_even_when_unselected_in_different_merge_groups() {
        let mut spool = runs();
        for index in 0..MERGE_FAN_IN + 1 {
            spool
                .add(vec![(format!("finding:{index:05}"), false)])
                .unwrap();
        }
        spool.add(vec![("finding:00000".into(), false)]).unwrap();
        let directory = spool.directory.path().to_owned();
        assert!(matches!(
            spool.finish(&CancellationToken::new()),
            Err(DepgraphServiceError::Integrity)
        ));
        assert!(!directory.exists());
        assert!(matches!(
            runs().add(vec![("same".into(), true), ("same".into(), false)]),
            Err(DepgraphServiceError::Integrity)
        ));
    }

    #[test]
    fn cancelled_merge_removes_all_temporary_runs() {
        let mut spool = runs();
        spool.add(vec![("a".into(), true)]).unwrap();
        spool.add(vec![("b".into(), true)]).unwrap();
        let directory = spool.directory.path().to_owned();
        let token = CancellationToken::new();
        token.cancel();
        assert!(matches!(
            spool.finish(&token),
            Err(DepgraphServiceError::Cancelled)
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn digest_rejects_truncated_and_oversized_rows_and_missing_records() {
        for replacement in [
            b"[\"id\",true]".to_vec(),
            vec![b'x'; MAX_ID_ROW_BYTES + 1],
            Vec::new(),
        ] {
            let token = CancellationToken::new();
            let mut spool = runs();
            spool.add(vec![("id".into(), true)]).unwrap();
            let sorted = spool.finish(&token).unwrap();
            std::fs::write(&sorted.run.as_ref().unwrap().path, replacement).unwrap();
            assert!(matches!(
                sorted.digest(&identity(), &token),
                Err(DepgraphServiceError::Integrity)
            ));
        }
    }
}
