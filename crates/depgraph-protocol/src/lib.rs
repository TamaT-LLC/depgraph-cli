//! Versioned wire contracts shared by the depgraph core and language workers.
//!
//! Protocol version 1.0 is newline-delimited JSON. Every line is one
//! [`ProtocolEvent`], and every event carries the same routing metadata at the
//! top level. Unknown optional fields are intentionally accepted for forward
//! compatibility; unknown event names and malformed required fields are not.

mod condition;
mod cross_language;
mod delta;
mod event;
mod model;
mod stable_id;
mod validator;

pub use condition::Condition;
pub use cross_language::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_COMPLETENESS_VERSION,
    CROSS_LANGUAGE_CONTRACT_PROPERTY, CROSS_LANGUAGE_CONTRACT_VERSION,
    CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, CROSS_LANGUAGE_SCHEMA, CROSS_LANGUAGE_SCHEMA_PATH,
    CrossLanguageAdapterDelta, CrossLanguageCanonicalIdentity, CrossLanguageCapabilityStatus,
    CrossLanguageCompletenessLedger, CrossLanguageEvidenceProperties, CrossLanguageFormat,
    CrossLanguageFormatCoverage, CrossLanguageMappingKind, CrossLanguageNodeKind,
    CrossLanguageProfileIdentity, CrossLanguageRelationKind, build_cross_language_edge_id,
    build_cross_language_site_id, cross_language_graph_digest, cross_language_node_id,
    cross_language_profile_id, has_cross_language_claim, validate_cross_language_adapter_delta,
    validate_cross_language_contract, validate_cross_language_graph,
};
pub use delta::{
    CoverageDelete, CoverageUpsert, DELTA_CONTRACT_VERSION, DeltaBaseGraph, DeltaCompleted,
    DeltaCoverage, DeltaCoverageKey, DeltaEdgeUpsert, DeltaEvent, DeltaEvidenceKey,
    DeltaEvidenceOwner, DeltaEvidenceRecord, DeltaFileCoverage, DeltaNodeUpsert, DeltaScope,
    DeltaStarted, DeltaValidator, EdgeDelete, EvidenceDelete, EvidenceUpsert, NodeDelete,
    SiteDelete, SiteUpsert, ValidatedDelta, WORKER_DELTA_CAPABILITY,
    WORKER_DELTA_REQUEST_SCHEMA_VERSION, WorkerDeltaAnalysisMode, WorkerDeltaBaseGraph,
    WorkerDeltaFileChange, WorkerDeltaFileChangeKind, WorkerDeltaRequest, WorkerProtocolMode,
    build_delta_stable_id, delta_graph_digest, negotiate_worker_protocol, validate_delta_ndjson,
};
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
    build_edge_stable_id, build_site_stable_id, validate_build_contract, validate_build_ndjson,
    validate_ndjson, validate_safe_ndjson, validate_safe_semantic_ndjson,
    validate_semantic_contract, validate_semantic_graph, validate_semantic_ndjson,
    validate_site_edge_invariants,
};

/// The only protocol version accepted by this crate.
pub const PROTOCOL_VERSION: &str = "1.0";

/// The bundled JSON Schema 2020-12 protocol contract.
pub const PROTOCOL_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-protocol-v1.schema.json"
));
