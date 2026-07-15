use crate::{Coverage, DependencySite, Diagnostic, GraphEdge, GraphNode, Profile};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonFields {
    pub protocol_version: String,
    pub scan_id: String,
    pub adapter: String,
    pub adapter_version: String,
    pub seq: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProtocolEvent {
    ScanStarted(ScanStarted),
    ProfileDeclared(ProfileDeclared),
    NodeUpsert(NodeUpsert),
    EdgeUpsert(EdgeUpsert),
    DependencySite(DependencySiteEvent),
    Diagnostic(DiagnosticEvent),
    FileCompleted(FileCompleted),
    ProfileCompleted(ProfileCompleted),
    ScanCompleted(ScanCompleted),
}

macro_rules! event_struct {
    ($(#[$meta:meta])* $name:ident { $($fields:tt)* }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            #[serde(flatten)]
            pub common: CommonFields,
            $($fields)*
        }
    };
}

event_struct!(ScanStarted {
    pub root: String,
    pub project_code_executed: bool,
    pub safe_mode: bool,
});

event_struct!(ProfileDeclared {
    pub profile: Profile,
});

event_struct!(NodeUpsert {
    pub node: GraphNode,
});

event_struct!(EdgeUpsert {
    pub edge: GraphEdge,
});

event_struct!(DependencySiteEvent {
    pub site: DependencySite,
});

event_struct!(DiagnosticEvent {
    pub diagnostic: Diagnostic,
});

event_struct!(FileCompleted {
    pub path: String,
    pub discovered_sites: u64,
    pub emitted_sites: u64,
    /// Recognized sites that could not be emitted. Missing in older v1.0
    /// producers and therefore defaults to zero.
    #[serde(default)]
    pub skipped_sites: u64,
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
});

event_struct!(ProfileCompleted {
    pub profile_id: String,
    pub coverage: Coverage,
});

event_struct!(ScanCompleted {
    pub coverage: Coverage,
});

impl ProtocolEvent {
    #[must_use]
    pub fn common(&self) -> &CommonFields {
        match self {
            Self::ScanStarted(event) => &event.common,
            Self::ProfileDeclared(event) => &event.common,
            Self::NodeUpsert(event) => &event.common,
            Self::EdgeUpsert(event) => &event.common,
            Self::DependencySite(event) => &event.common,
            Self::Diagnostic(event) => &event.common,
            Self::FileCompleted(event) => &event.common,
            Self::ProfileCompleted(event) => &event.common,
            Self::ScanCompleted(event) => &event.common,
        }
    }

    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::ScanStarted(_) => "scan_started",
            Self::ProfileDeclared(_) => "profile_declared",
            Self::NodeUpsert(_) => "node_upsert",
            Self::EdgeUpsert(_) => "edge_upsert",
            Self::DependencySite(_) => "dependency_site",
            Self::Diagnostic(_) => "diagnostic",
            Self::FileCompleted(_) => "file_completed",
            Self::ProfileCompleted(_) => "profile_completed",
            Self::ScanCompleted(_) => "scan_completed",
        }
    }
}
