use crate::Condition;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type Properties = BTreeMap<String, Value>;

/// One node in the common property graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    /// Open string vocabulary; protocol v1 never changes the meaning of an
    /// existing kind, but compatible producers may introduce new kinds.
    pub kind: String,
    pub locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub properties: Properties,
}

/// A logical graph edge. Evidence is embedded on the wire and is split into
/// separate rows by the evidence store.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    pub phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub profile_id: String,
    pub condition: Condition,
    pub resolution_status: ResolutionStatus,
    pub precision: Precision,
    pub generated: bool,
    pub evidence: Vec<Evidence>,
}

/// The authoritative classification of a recognized dependency occurrence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DependencySite {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub specifier: String,
    pub resolution_status: ResolutionStatus,
    pub target_ids: Vec<String>,
    pub profile_id: String,
    pub condition: Condition,
    pub precision: Precision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub language: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub features: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub environment: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub properties: Properties,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub extractor: String,
    pub extractor_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default)]
    pub properties: Properties,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Source,
    Semantic,
    Build,
    Runtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Source,
    Semantic,
    Build,
    Runtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    Resolved,
    Candidates,
    External,
    Unresolved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    Exact,
    Overapprox,
    Heuristic,
    Observed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub id: String,
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_column: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub properties: Properties,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
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
    pub completeness: Vec<CompletenessLevel>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompletenessLevel {
    SyntaxComplete,
    SemanticComplete,
    BuildObserved,
    RuntimeObserved,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}
