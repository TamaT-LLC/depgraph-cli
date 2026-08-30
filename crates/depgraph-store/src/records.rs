use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ProfileMatrixRecord;

/// Drop a JSON value without recursively descending through nested arrays or
/// objects.
///
/// `serde_json::Value` owns its children directly, so its derived destructor
/// follows a deeply nested value through the Rust call stack.  Values loaded
/// from JSON are protected by serde_json's parser recursion limit, but store
/// records are also assembled by importers, test fixtures, and callers of the
/// public snapshot API.  Keep the record destructors stack-safe for those
/// inputs as well.
pub(crate) fn drop_json_value_iteratively(value: Value) {
    enum Pending {
        Value(Value),
        Array(std::vec::IntoIter<Value>),
        Object(serde_json::map::IntoIter),
    }

    let mut pending = vec![Pending::Value(value)];
    while let Some(item) = pending.pop() {
        match item {
            Pending::Value(value) => match value {
                Value::Array(values) => pending.push(Pending::Array(values.into_iter())),
                Value::Object(values) => pending.push(Pending::Object(values.into_iter())),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            },
            Pending::Array(mut values) => {
                if let Some(value) = values.next() {
                    pending.push(Pending::Array(values));
                    pending.push(Pending::Value(value));
                }
            }
            Pending::Object(mut values) => {
                if let Some((_key, value)) = values.next() {
                    pending.push(Pending::Object(values));
                    pending.push(Pending::Value(value));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRecord {
    pub id: String,
    pub root: String,
    pub status: String,
    pub strict: bool,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub project_code_executed: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    /// Canonical policy identity used by the health analyzers for this scan.
    ///
    /// These fields are bound while a scan is staging.  They deliberately
    /// remain optional so stores created before schema 18 can be read and
    /// compared fail-closed rather than pretending to have provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_policy_config_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_analyzer_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_finding_contract_version: Option<String>,
}

/// Provenance tuple attached immutably to one staging scan.
///
/// The store treats these values as opaque, bounded identities.  Production
/// callers must supply the normalized `policy-config:sha256:<hex>` identity
/// and the constants exported by `depgraph-core`; keeping validation at the
/// store boundary prevents malformed rows from becoming trusted evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanHealthProvenance {
    pub policy_config_digest: String,
    pub analyzer_version: String,
    pub finding_contract_version: String,
}

pub type ScanAttemptRecord = ScanRecord;

#[derive(Debug)]
pub struct ValidatedScan {
    pub(crate) scan_id: String,
    pub(crate) mutation_count: i64,
}

pub(crate) struct FinishedScan {
    pub(crate) completed_snapshot_id: Option<String>,
    pub(crate) promoted: bool,
}

/// Immutable service authority and request identity recorded with an
/// operation-owned staging scan before graph ingestion begins.
pub struct ScanOperationStagingIdentity<'a> {
    pub operation_id: &'a str,
    pub repository_binding_digest: &'a [u8; 32],
    pub configuration_digest: &'a [u8; 32],
    pub cache_enabled: bool,
}

/// Complete proof supplied when recovering one operation-owned scan result.
pub struct ScanCompletionRecoveryIdentity<'a> {
    pub operation_id: &'a str,
    pub scan_id: &'a str,
    pub repository_root: &'a Path,
    pub repository_binding_digest: &'a [u8; 32],
    pub strict: bool,
    pub cache_enabled: bool,
    pub snapshot_id: &'a str,
    pub result_digest: &'a [u8; 32],
}

pub(crate) struct ScanOperationRecoveryBinding {
    pub(crate) operation_id: String,
    pub(crate) scan_id: String,
    pub(crate) repository_binding_digest: Vec<u8>,
    pub(crate) configuration_digest: Vec<u8>,
    pub(crate) strict: bool,
    pub(crate) cache_enabled: bool,
    pub(crate) base_snapshot_id: Option<String>,
    pub(crate) validated_mutation_count: Option<i64>,
    pub(crate) prospective_snapshot_id: Option<String>,
    pub(crate) result_digest: Option<Vec<u8>>,
    pub(crate) decision_authorization_digest: Option<Vec<u8>>,
    pub(crate) root: String,
    pub(crate) status: String,
    pub(crate) scan_strict: bool,
    pub(crate) parent_snapshot_id: Option<String>,
    pub(crate) mutation_count: i64,
}

pub(crate) struct LegacyRuntimeImportCandidate {
    pub(crate) import_id: String,
    pub(crate) created_at: String,
}

pub(crate) struct LegacyScanOperationCandidate {
    pub(crate) scan_id: String,
    pub(crate) strict: bool,
    pub(crate) parent_snapshot_id: Option<String>,
    pub(crate) validated_mutation_count: Option<i64>,
    pub(crate) prospective_snapshot_id: Option<String>,
    pub(crate) started_at: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PendingCancelledScanOperations {
    pub(crate) operation_ids: Vec<String>,
    pub(crate) more_work: bool,
    pub(crate) next_after_operation_id: Option<String>,
}

impl PendingCancelledScanOperations {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            operation_ids: Vec::new(),
            more_work: false,
            next_after_operation_id: None,
        }
    }

    #[must_use]
    pub fn operation_ids(&self) -> &[String] {
        &self.operation_ids
    }

    #[must_use]
    pub const fn more_work(&self) -> bool {
        self.more_work
    }

    #[must_use]
    pub fn next_after_operation_id(&self) -> Option<&str> {
        self.next_after_operation_id.as_deref()
    }

    #[must_use]
    pub fn into_operation_ids(self) -> Vec<String> {
        self.operation_ids
    }
}

#[derive(Debug)]
pub struct ValidatedScanSummary {
    pub coverage: CoverageRecord,
    pub diagnostics: Vec<DiagnosticRecord>,
}

#[derive(Debug)]
pub struct CompletedScanSnapshot {
    pub(crate) scan_id: String,
    pub(crate) snapshot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletedSnapshotRecord {
    pub id: String,
    pub source_kind: String,
    pub source_attempt_id: String,
    pub scan_id: String,
    pub build_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_import_id: Option<String>,
    #[serde(default)]
    pub runtime_session_ids: Vec<String>,
    pub parent_snapshot_id: Option<String>,
    pub source_revision: Option<String>,
    pub profile_ids: Vec<String>,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotIntegrityRecord {
    pub snapshot_id: String,
    pub valid: bool,
    pub expected_id: String,
    pub observed_id: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotNameRecord {
    pub name: String,
    pub snapshot_id: String,
    pub named_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSummaryRecord {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePage<T> {
    pub items: Vec<T>,
    pub total_items: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeTextMatch {
    Exact,
    Prefix,
    Contains,
}

impl NodeTextMatch {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Contains => "contains",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletedSnapshotDetails {
    pub snapshot: CompletedSnapshotRecord,
    pub names: Vec<String>,
    pub coverage: CoverageRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GarbageCollectionReport {
    pub scan_attempts_deleted: u64,
    pub build_attempts_deleted: u64,
    pub build_audits_deleted: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InterruptedAttemptRecovery {
    pub scan_attempt_ids: Vec<String>,
    pub build_attempt_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub kind: String,
    pub locator: String,
    pub display_name: String,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProfileRecord {
    pub id: String,
    pub language: String,
    pub toolchain: Option<Value>,
    pub command: Option<String>,
    pub target: Option<String>,
    pub features: Vec<String>,
    pub environment: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub properties: Value,
    pub coverage: Option<CoverageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SiteRecord {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub specifier: Option<String>,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub condition: Value,
    pub target_ids: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeRecord {
    pub id: String,
    pub site_id: Option<String>,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub phase: String,
    pub environment: String,
    pub profile_id: String,
    pub resolution_status: String,
    pub precision: String,
    pub condition: Value,
    pub generated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CoverageRecord {
    pub profiles: u64,
    pub files_discovered: u64,
    pub files_analyzed: u64,
    pub files_skipped: u64,
    pub dependency_sites: u64,
    pub resolved: u64,
    pub candidates: u64,
    pub external: u64,
    pub unresolved: u64,
    pub unsupported_syntax: u64,
    pub project_code_executed: bool,
    pub completeness: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiagnosticRecord {
    pub ordinal: i64,
    pub id: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub adapter: Option<String>,
    pub start_line: Option<u64>,
    pub start_column: Option<u64>,
    pub end_line: Option<u64>,
    pub end_column: Option<u64>,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub owner_type: String,
    pub owner_id: String,
    pub ordinal: i64,
    pub kind: String,
    pub extractor: String,
    pub extractor_version: String,
    pub path: String,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
    pub detail: Option<String>,
    pub properties: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCoverageRecord {
    pub adapter: String,
    pub path: String,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped_sites: u64,
    pub skipped: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterLogRecord {
    pub adapter: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticGroupSummaryRecord {
    pub severity: String,
    pub code: String,
    pub adapter: Option<String>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSampleSummaryRecord {
    pub id: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub adapter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticSummaryRecord {
    pub total: u64,
    pub groups: Vec<DiagnosticGroupSummaryRecord>,
    pub omitted_groups: u64,
    pub omitted_diagnostics: u64,
    pub samples: Vec<DiagnosticSampleSummaryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileCoverageSummaryRecord {
    pub adapter: String,
    pub files: u64,
    pub skipped_files: u64,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    pub skipped_sites: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterLogSummaryRecord {
    pub adapter: String,
    pub stderr_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanAttemptSummaryRecord {
    pub scan: ScanRecord,
    pub coverage: CoverageRecord,
    pub profile_count: u64,
    pub profiles_by_language: BTreeMap<String, u64>,
    pub package_instance_count: u64,
    pub file_coverage: Vec<FileCoverageSummaryRecord>,
    pub adapter_logs: Vec<AdapterLogSummaryRecord>,
    pub diagnostics: DiagnosticSummaryRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildAuditRecord {
    pub run_id: String,
    pub outcome: String,
    pub started_at: String,
    pub finished_at: String,
    pub audit: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildAttemptRecord {
    pub id: String,
    pub base_scan_id: String,
    pub base_snapshot_id: Option<String>,
    pub audit_run_id: String,
    pub status: String,
    pub observer: String,
    pub observer_version: String,
    pub profile_id: String,
    pub command_plan_digest: String,
    pub toolchain_executable_digest: String,
    pub environment_key_set_digest: String,
    pub validated_output_digest: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub(crate) struct BuildGraphDelta {
    pub(crate) profiles: Vec<ProfileRecord>,
    pub(crate) nodes: Vec<NodeRecord>,
    pub(crate) sites: Vec<SiteRecord>,
    pub(crate) edges: Vec<EdgeRecord>,
    pub(crate) evidence: Vec<EvidenceRecord>,
    pub(crate) diagnostics: Vec<DiagnosticRecord>,
    pub(crate) coverage: CoverageRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphSnapshot {
    /// Scan metadata, including optional schema-18 health provenance used to
    /// compare audit snapshots fail-closed.
    pub scan: ScanRecord,
    pub profiles: Vec<ProfileRecord>,
    pub nodes: Vec<NodeRecord>,
    pub sites: Vec<SiteRecord>,
    pub edges: Vec<EdgeRecord>,
    pub evidence: Vec<EvidenceRecord>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub file_coverage: Vec<FileCoverageRecord>,
    pub adapter_logs: Vec<AdapterLogRecord>,
    pub coverage: CoverageRecord,
    pub profile_matrix: ProfileMatrixRecord,
}

impl Drop for GraphSnapshot {
    fn drop(&mut self) {
        for mut profile in std::mem::take(&mut self.profiles) {
            if let Some(toolchain) = profile.toolchain.take() {
                drop_json_value_iteratively(toolchain);
            }
            drop_json_value_iteratively(std::mem::replace(&mut profile.environment, Value::Null));
            drop_json_value_iteratively(std::mem::replace(&mut profile.properties, Value::Null));
        }
        for mut node in std::mem::take(&mut self.nodes) {
            drop_json_value_iteratively(std::mem::replace(&mut node.properties, Value::Null));
        }
        for mut site in std::mem::take(&mut self.sites) {
            drop_json_value_iteratively(std::mem::replace(&mut site.condition, Value::Null));
        }
        for mut edge in std::mem::take(&mut self.edges) {
            drop_json_value_iteratively(std::mem::replace(&mut edge.condition, Value::Null));
        }
        for mut diagnostic in std::mem::take(&mut self.diagnostics) {
            drop_json_value_iteratively(std::mem::replace(&mut diagnostic.properties, Value::Null));
        }
        for mut evidence in std::mem::take(&mut self.evidence) {
            drop_json_value_iteratively(std::mem::replace(&mut evidence.properties, Value::Null));
        }
        let mut profile_matrix = std::mem::take(&mut self.profile_matrix);
        for mut entry in std::mem::take(&mut profile_matrix.entries) {
            drop_json_value_iteratively(std::mem::replace(&mut entry.condition_union, Value::Null));
        }
        for mut correlation in std::mem::take(&mut profile_matrix.correlations) {
            drop_json_value_iteratively(std::mem::replace(
                &mut correlation.condition_union,
                Value::Null,
            ));
            for (_phase, value) in std::mem::take(&mut correlation.conditions_by_phase) {
                drop_json_value_iteratively(value);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphTopology {
    pub nodes: Vec<GraphTopologyNode>,
    pub edges: Vec<GraphTopologyEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphTopologyNode {
    pub id: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphTopologyEdge {
    pub source: String,
    pub target: String,
}
