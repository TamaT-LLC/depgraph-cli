//! Versioned wire contracts shared by the depgraph core and language workers.
//!
//! Protocol version 1.0 is newline-delimited JSON. Every line is one
//! [`ProtocolEvent`], and every event carries the same routing metadata at the
//! top level. Unknown optional fields are intentionally accepted for forward
//! compatibility; unknown event names and malformed required fields are not.

mod condition;
mod event;
mod model;
mod stable_id;
mod validator;

pub use condition::Condition;
pub use event::{
    CommonFields, DependencySiteEvent, DiagnosticEvent, EdgeUpsert, FileCompleted, NodeUpsert,
    ProfileCompleted, ProfileDeclared, ProtocolEvent, ScanCompleted, ScanStarted,
};
pub use model::{
    CompletenessLevel, Coverage, DependencySite, Diagnostic, DiagnosticSeverity, Evidence,
    EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile, Properties, ResolutionStatus,
};
pub use stable_id::{StableIdInput, canonical_json, stable_id, stable_id_from_value};
pub use validator::{
    MAX_EVENT_LINE_BYTES, ProtocolError, ProtocolValidator, ValidatedProtocol, ValidationPolicy,
    validate_ndjson, validate_safe_ndjson, validate_safe_semantic_ndjson,
    validate_semantic_contract, validate_semantic_ndjson, validate_site_edge_invariants,
};

/// The only protocol version accepted by this crate.
pub const PROTOCOL_VERSION: &str = "1.0";

/// The bundled JSON Schema 2020-12 protocol contract.
pub const PROTOCOL_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-protocol-v1.schema.json"
));
