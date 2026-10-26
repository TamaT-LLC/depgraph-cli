mod analysis_canonical;
mod analysis_checkpoint;
pub mod analysis_execution;
pub mod analysis_plan;
mod analysis_schedule;
pub mod analysis_split;
pub mod bounded_query;
pub mod bounded_query_execute;
pub mod bounded_query_plan;
pub mod bounded_query_type;
pub mod build;
pub mod build_evidence;
pub mod cache;
pub mod cancellation;
pub mod compiler_invocation;
pub mod compiler_mir;
pub mod compiler_pack;
pub mod compiler_precise;
pub mod compiler_precise_graph;
pub mod config;
pub mod cross_language;
pub mod daemon;
mod doctor;
pub mod edge_kind_selection;
pub mod export;
pub mod ffi;
pub mod ffi_link;
pub(crate) mod go_dependency_witness;
mod graphml;
pub mod graphql;
pub mod health;
pub mod http_operation_correlation;
pub mod impact;
pub mod import_evidence;
pub mod incremental;
pub mod openapi;
pub mod policy;
mod policy_engine;
pub mod profile_selection;
pub mod profile_selection_file;
pub mod profile_selection_go;
pub mod profile_selection_plan;
pub mod profile_selection_preview;
pub mod profile_selection_rank;
pub mod profile_selection_rust;
pub mod profile_selection_web;
pub mod protobuf;
pub mod query;
mod release_compatibility;
mod release_health;
pub(crate) mod repository_inventory;
pub mod runtime_trace;
pub mod rust_build_observer;
pub mod scan;
pub mod service;
mod service_agent;
mod service_artifacts;
mod service_bounded;
mod service_build;
mod service_graph;
mod service_health;
mod service_lifecycle;
mod service_limits;
mod service_repository;
mod service_snapshot;
mod service_store_write;
pub mod symbol_rollup;
pub mod worker;
mod worker_memory;
mod worker_progress;
mod worker_web_semantic;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use depgraph_store::Store;

const MAX_EXECUTABLE_SYMLINK_DEPTH: usize = 40;

pub(crate) fn canonicalize_executable(path: &Path, description: &str) -> Result<PathBuf> {
    if let Some(release_root) = executable_release_root(path, description)?
        && std::fs::symlink_metadata(&release_root)
            .ok()
            .is_some_and(|metadata| metadata.file_type().is_symlink())
        && release_root.join("release-manifest.json").is_file()
    {
        anyhow::bail!(
            "failed to canonicalize {description}: release root must be a non-symlink directory"
        );
    }
    path.canonicalize()
        .with_context(|| format!("failed to canonicalize {description}"))
}

fn executable_release_root(path: &Path, description: &str) -> Result<Option<PathBuf>> {
    let mut executable = path.to_path_buf();
    for depth in 0..=MAX_EXECUTABLE_SYMLINK_DEPTH {
        let metadata = std::fs::symlink_metadata(&executable).with_context(|| {
            format!("failed to inspect {description} while resolving its symlink chain")
        })?;
        if !metadata.file_type().is_symlink() {
            let Some(bin) = executable.parent() else {
                return Ok(None);
            };
            return Ok(bin.parent().map(Path::to_path_buf));
        }
        if depth == MAX_EXECUTABLE_SYMLINK_DEPTH {
            anyhow::bail!(
                "failed to canonicalize {description}: executable symlink chain exceeds {MAX_EXECUTABLE_SYMLINK_DEPTH} links"
            );
        }
        let target = std::fs::read_link(&executable).with_context(|| {
            format!("failed to read {description} while resolving its symlink chain")
        })?;
        executable = if target.is_absolute() {
            target
        } else {
            let Some(parent) = executable.parent() else {
                return Ok(None);
            };
            parent.join(target)
        };
    }
    unreachable!("the executable symlink loop always returns or fails at the configured limit")
}

pub use bounded_query::{
    BOUNDED_QUERY_CONTRACT_VERSION, BOUNDED_QUERY_CREDENTIAL_POLICY_VERSION, EntityExpression,
    Expression, FieldReference, Literal, MAX_QUERY_AST_NODES, MAX_QUERY_BYTES, MAX_QUERY_DEPTH,
    MAX_QUERY_EXISTENTIAL_PREDICATES, MAX_QUERY_EXPRESSION_NESTING, MAX_QUERY_LIMIT,
    MAX_QUERY_LIST_LITERALS, MAX_QUERY_PROJECTIONS, MAX_QUERY_TOKENS, MatchClause, NodePattern,
    OrderItem, Projection, QuantifierKind, QuantifierPredicate, QueryAst, QueryDiagnostic,
    QueryDirection, QueryFailureClass, QueryOrigin, RelationshipPattern, ReturnClause,
    ScalarOperator, ScalarPredicate, SortDirection, parse_bounded_query, parse_bounded_query_bytes,
    parse_bounded_query_file, read_bounded_query_file, read_bounded_repository_file,
};
pub use bounded_query_execute::{
    BOUNDED_QUERY_RESULT_SCHEMA_VERSION, BoundedQueryExecutionError, BoundedQueryExecutionMetrics,
    BoundedQueryExecutionOptions, BoundedQueryExecutionResult, BoundedQueryResult,
    bounded_query_result_digest, execute_bounded_query, execute_bounded_query_with_options,
};
pub use bounded_query_plan::{
    BOUNDED_QUERY_LIMIT_VERSION, BOUNDED_QUERY_PLAN_SCHEMA_VERSION,
    BOUNDED_QUERY_STATISTICS_VERSION, BoundedQueryLimits, BoundedQueryOperatorKind,
    BoundedQueryOperatorPlan, BoundedQueryPlan, BoundedQueryPlanningError,
    BoundedQueryPlanningResult, BoundedQueryResourceBounds, ClosedFieldByteBounds,
    QueryAdmissionReason, QueryCardinalityInputs, SnapshotCardinalityStatistics,
    bounded_query_graph_digest, bounded_query_plan_digest, canonical_bounded_query_plan_json,
    collect_bounded_query_statistics, plan_bounded_query, plan_bounded_query_with_limits,
    plan_bounded_query_with_statistics, redacted_typed_query_shape,
};
pub use bounded_query_type::{
    BOUNDED_QUERY_TYPE_CONTRACT_VERSION, BindingDefinition, EntityType, FIELD_REGISTRY,
    FieldDefinition, QueryType, ScalarType, TypedEntityExpression, TypedExpression,
    TypedFieldReference, TypedMatchClause, TypedNodePattern, TypedOrderItem, TypedProjection,
    TypedQuery, TypedQueryAst, TypedReturnClause, TypedScalarPredicate,
    canonical_typed_query_ast_json, field_registry, parse_and_type_check_bounded_query,
    type_check_bounded_query, typed_query_ast_digest,
};
pub use build::{
    ASTRO_BUILD_CAPABILITY, ASTRO_BUILD_OBSERVATION_SCHEMA, ASTRO_BUILD_OBSERVER,
    ASTRO_BUILD_OBSERVER_VERSION, BUILD_SUPERVISOR_VERSION, BuildAudit, BuildExecutionOutcome,
    BuildExecutionPlan, BuildExecutionRequest, BuildIsolation, BuildOutcomeKind,
    BuildSourceMutationAudit, BuildSourceMutationDiagnostic, BuildSourceMutationStatus,
    NEXT_BUILD_CAPABILITY, NEXT_BUILD_OBSERVATION_SCHEMA, NEXT_BUILD_OBSERVER,
    NEXT_BUILD_OBSERVER_VERSION, NetworkIsolation, TANSTACK_ROUTER_BUILD_CAPABILITY,
    TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA, TANSTACK_ROUTER_BUILD_OBSERVER,
    TANSTACK_ROUTER_BUILD_OBSERVER_VERSION, TANSTACK_START_BUILD_CAPABILITY,
    TANSTACK_START_BUILD_OBSERVATION_SCHEMA, TANSTACK_START_BUILD_OBSERVER,
    TANSTACK_START_BUILD_OBSERVER_VERSION, WEB_BUILD_OBSERVER_VERSION, WebBuildAdapter,
    WebBuildObservation, compiler_precise_cache_hit_audit, create_build_execution_request,
    create_compiler_precise_invocation_request, create_compiler_precise_unit_graph_request,
    execute_build_request, execute_build_request_with_cancellation, prepare_build_cache_input,
    prepare_compiler_precise_cache_input, supervise_build, supervise_build_with_cancellation,
    validate_build_cache_source, validate_compiler_precise_cache_input,
};
pub use build_evidence::{
    stage_build_evidence, validate_build_evidence, validate_framework_build_evidence_contract,
    web_build_protocol_ndjson,
};
pub use cross_language::validate_cross_language_worker_protocol;
pub use ffi::{
    FFI_CAPABILITY, FFI_FORMAT_VERSION, MAX_FFI_DECLARATIONS, MAX_FFI_FILE_BYTES, MAX_FFI_FILES,
    MAX_FFI_TOTAL_BYTES, scan_ffi_repository,
};
pub use ffi_link::{
    FFI_LINK_CAPABILITY, FFI_LINK_OBSERVATION_SCHEMA, FFI_LINK_OBSERVATION_SCHEMA_PATH,
    FFI_LINK_OBSERVATION_SCHEMA_VERSION, FFI_LINK_OBSERVER, FFI_LINK_OBSERVER_VERSION,
    FfiLinkObservation, FfiObservedLink, collect_supervised_ffi_link_observation,
    correlate_ffi_link_observation, validate_ffi_link_observation,
};
pub const FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION: &str = "framework-build-graph-v1";
pub const FRAMEWORK_BUILD_GATE_CONTRACT_VERSION: &str =
    "dynamic-framework-evidence-release-gate-v1";
pub const FRAMEWORK_BUILD_CONVERTER_ARTIFACT: &str = "libexec/depgraph-web-build-evidence.mjs";
pub const RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION: &str = "rust-src-data-tree-v1";
pub const RUST_SYSROOT_TOOLCHAIN_VERSION: &str = "1.93.1";
pub const RUST_SYSROOT_TOOLCHAIN_COMMIT: &str = "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
pub const RUST_SYSROOT_COMPONENT_NAME: &str = "rust-stdlib-source";
pub const RUST_SYSROOT_COMPONENT_VERSION: &str =
    "1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf";
pub const RUST_SYSROOT_COMPONENT_ROOT: &str = "libexec/rust-sysroot";
pub const RUST_SYSROOT_SOURCE_LAYOUT: &str = "rustup-rust-src-library-v1";
pub const RUST_SYSROOT_LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
pub const RUST_SYSROOT_SBOM_PACKAGE_NAME: &str = "rust-stdlib-source";
pub const BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION: &str = "bounded-query-release-smoke-v1";
pub const BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH: &str = "queries/bounded-query-smoke-v1.query";
pub const BOUNDED_QUERY_RELEASE_SMOKE_QUERY: &str =
    include_str!("../../../queries/bounded-query-smoke-v1.query");
pub const CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION: &str = "cross-language-release-smoke-v1";
pub const CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH: &str =
    "fixtures/cross-language-release-smoke-v1.json";
pub const CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE: &str =
    include_str!("../../../fixtures/cross-language-release-smoke-v1.json");
pub use cache::{
    BuildCacheInput, COMPILER_PRECISE_CACHE_CONTRACT_VERSION,
    COMPILER_PRECISE_CACHE_ENTRY_SCHEMA_VERSION, CompilerPreciseCacheInput,
    CompilerPreciseCachedEvidence, build_cache_key, compiler_precise_cache_key,
    validate_build_cache_input, validate_compiler_precise_cached_evidence,
};
pub use cancellation::CancellationToken;
pub use compiler_invocation::{
    COMPILER_INVOCATION_LEDGER_SCHEMA, COMPILER_INVOCATION_LEDGER_SCHEMA_PATH,
    COMPILER_INVOCATION_LEDGER_SCHEMA_VERSION, COMPILER_INVOCATION_RECORD_SCHEMA,
    COMPILER_INVOCATION_RECORD_SCHEMA_PATH, COMPILER_INVOCATION_RECORD_SCHEMA_VERSION,
    COMPILER_PRECISE_INVOCATION_ADAPTER, COMPILER_PRECISE_INVOCATION_ADAPTER_VERSION,
    RustCompilerFailureContext, RustCompilerInvocation, RustCompilerInvocationLedger,
    compiler_invocation_attempt_digest, compiler_invocation_entry_digest,
    compiler_invocation_ledger_digest, diagnose_compiler_invocation_failure,
    validate_compiler_invocation_ledger, validate_compiler_invocation_ledger_identity,
    validate_compiler_invocation_unit_graph,
};
pub use compiler_mir::{
    COMPILER_PRECISE_MIR_LEDGER_SCHEMA, COMPILER_PRECISE_MIR_LEDGER_SCHEMA_PATH,
    COMPILER_PRECISE_MIR_LEDGER_SCHEMA_VERSION, COMPILER_PRECISE_MIR_SCHEMA,
    COMPILER_PRECISE_MIR_SCHEMA_PATH, COMPILER_PRECISE_MIR_SCHEMA_VERSION, RustCompilerCall,
    RustCompilerCallEvidence, RustCompilerCallReason, RustCompilerCallRelation,
    RustCompilerCallResolution, RustCompilerGenericArgument, RustCompilerGenericArgumentKind,
    RustCompilerMirBlock, RustCompilerMirBody, RustCompilerMirBodyKind, RustCompilerMirConstant,
    RustCompilerMirDefinition, RustCompilerMirLedger, RustCompilerMirLocal,
    RustCompilerMirOperation, RustCompilerMirPlace, RustCompilerMirProjection, RustCompilerMirSpan,
    RustCompilerMirType, RustCompilerMirUnit, RustCompilerMirUnsupported, RustCompilerMonoInstance,
    RustCompilerMonoInstanceKind, compiler_mir_ledger_digest, compiler_mir_unit_digest,
    validate_compiler_mir_directory, validate_compiler_mir_ledger_identity,
};
pub use compiler_pack::{
    COMPILER_PACK_CHANNEL_MANIFEST, COMPILER_PACK_CHANNEL_MANIFEST_SHA256,
    COMPILER_PACK_DISTRIBUTION, COMPILER_PACK_FALLBACK_POLICY,
    COMPILER_PACK_LICENSE_INVENTORY_PATH, COMPILER_PACK_MANIFEST_PATH,
    COMPILER_PACK_MANIFEST_SCHEMA, COMPILER_PACK_MANIFEST_SCHEMA_PATH,
    COMPILER_PACK_MANIFEST_SCHEMA_VERSION, COMPILER_PACK_PROVENANCE_PATH,
    COMPILER_PACK_RELEASE_CONTRACT_VERSION, COMPILER_PACK_RUST_RELEASE, COMPILER_PACK_RUSTC_COMMIT,
    COMPILER_PACK_SBOM_PATH, COMPILER_PACK_SUPPORTED_TARGETS, COMPILER_PACK_TOOLCHAIN_CHANNEL,
    COMPILER_PACK_WRAPPER_PROTOCOL_VERSION, COMPILER_PRECISE_CONTRACT_VERSION,
    CompilerPackArtifact, CompilerPackAttestation, CompilerPackBuildComponent,
    CompilerPackBuildSpec, CompilerPackComponent, CompilerPackFile, CompilerPackManifest,
    CompilerPackProtocol, CompilerPackRequirement, CompilerPackToolchain, VerifiedCompilerPack,
    build_compiler_pack, compiler_pack_host_target, read_compiler_pack_build_spec,
    read_compiler_pack_requirement, verify_compiler_pack,
};
pub use compiler_precise::{
    COMPILER_PRECISE_UNIT_GRAPH_ADAPTER, COMPILER_PRECISE_UNIT_GRAPH_ADAPTER_VERSION,
    COMPILER_PRECISE_UNIT_GRAPH_SCHEMA, COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_PATH,
    COMPILER_PRECISE_UNIT_GRAPH_SCHEMA_VERSION, NEUTRAL_CARGO_CONFIG_SCHEMA_VERSION,
    NeutralCargoConfig, RustCargoDependency, RustCargoProfile, RustCargoStrip, RustCargoTarget,
    RustCargoUnit, RustCargoUnitGraph, compiler_unit_graph_digest, install_neutral_cargo_config,
    project_neutral_cargo_config, validate_cargo_unit_graph,
    validate_cargo_unit_graph_with_cargo_home,
};
pub use compiler_precise_graph::{
    COMPILER_PRECISE_GRAPH_CAPABILITY, COMPILER_PRECISE_GRAPH_CONTRACT_VERSION,
    compiler_precise_graph_events, compiler_precise_graph_ndjson, compiler_precise_profile_id,
};
pub use config::{Config, DaemonConfig, default_store_path, init_config};
pub use daemon::{
    DAEMON_INCREMENTAL_TRACE_SCHEMA_VERSION, DAEMON_STATUS_SCHEMA_VERSION, DaemonAttempt,
    DaemonHandle, DaemonIncrementalTrace, DaemonPhase, DaemonScanFuture, DaemonScanOutcome,
    DaemonScanRequest, DaemonScanRunner, DaemonStatus, EventCoalescer, IncrementalWorkerExecutor,
    IncrementalWorkerFuture, IncrementalWorkerOutcome, IncrementalWorkerTrace,
    RepositoryScanRunner, StoreLockGuard, WatchIgnoreRules, WatchPathKind, WatchedPath,
    acquire_store_writer_lock, coalesce_incremental_changes, start_daemon_with_runner,
    start_repository_daemon,
};
pub use depgraph_store::GraphSnapshot;
/// Lets a long-lived read server reuse verified seals and the reconstructed
/// completed snapshot while the store files are unchanged (Issue #599).
pub use depgraph_store::enable_read_cache;
pub use edge_kind_selection::{
    DEFAULT_STRUCTURAL_EDGE_SELECTION, EdgeKindFilter, EdgeKindFilterError,
    MAX_DEPENDENCY_EDGE_KIND_BYTES, MAX_DEPENDENCY_EDGE_KINDS, STRUCTURAL_EDGE_KINDS,
    StructuralEdgeSelection, is_structural_edge_kind,
};
pub use export::{
    ExportFormat, export, export_filtered, export_graphml_filtered_to_writer, filter_snapshot,
};
pub use graphml::GRAPHML_SCHEMA_VERSION;
pub use graphql::{
    GRAPHQL_CAPABILITY, GRAPHQL_FORMAT_VERSION, GRAPHQL_REPOSITORY_MAPPING_CAPABILITY,
    GRAPHQL_REPOSITORY_MAPPING_SCHEMA_VERSION, MAX_GRAPHQL_DEFINITIONS, MAX_GRAPHQL_DEPTH,
    MAX_GRAPHQL_FILE_BYTES, MAX_GRAPHQL_FILES, MAX_GRAPHQL_SELECTIONS, MAX_GRAPHQL_TOKENS,
    MAX_GRAPHQL_TOTAL_BYTES, scan_graphql_repository,
};
pub use health::{
    BaselineFindingRecord, BaselineTransition, BlockerKind, CollectionIdentity, Confidence,
    DEFAULT_HOTSPOT_WEIGHTS, FindingBlocker, FindingEvidenceRef, FindingIdentity, FindingKind,
    FindingKindScope, FindingSuppression, HEALTH_ANALYZER_VERSION, HEALTH_FINDING_CONTRACT_VERSION,
    HOTSPOT_SUBJECT_KINDS, HealthFinding, HealthFindingDetail, HealthGateConfig,
    HealthGateDecision, HotspotFindingScores, HotspotLayerScore, HotspotLayerScores, HotspotScores,
    HotspotWeights, Remediation, Severity, SourceLocation, classify_baseline_transition,
    collection_digest, evaluate_health_gate, finding_fingerprint, finding_id,
};
pub use http_operation_correlation::{
    HTTP_OPERATION_CORRELATION_VERSION, HttpOperationCorrelationOutcome,
    HttpOperationCorrelationResult, correlate_http_operations,
};
pub use impact::{
    CHANGED_SET_IMPACT_MODE, ChangedNodeMapping, ChangedSetImpactNode, ChangedSetImpactResult,
    GitChange, GitChangedSet, IMPACT_QUERY_CACHE_SCHEMA_VERSION, ImpactDiagnostic, ImpactFilters,
    ImpactNode, ImpactResult, UNMAPPED_REASON_DELETED, UNMAPPED_REASON_NOT_IN_SNAPSHOT,
    UnmappedChange, impact, impact_changed_set, impact_query_cache_key, map_changed_set,
    read_git_changed_set,
};
pub use incremental::{
    INCREMENTAL_PLAN_SCHEMA_VERSION, IncrementalChangeKind, IncrementalFileChange,
    IncrementalInvalidationMode, IncrementalInvalidationPlan, IncrementalInvalidationReason,
    plan_incremental_invalidation, snapshot_profile_plan_id,
};
pub use openapi::{
    MAX_OPENAPI_DEPTH, MAX_OPENAPI_DOCUMENT_BYTES, MAX_OPENAPI_DOCUMENTS,
    MAX_OPENAPI_REFERENCE_DEPTH, MAX_OPENAPI_REFERENCES, MAX_OPENAPI_SCALAR_BYTES,
    MAX_OPENAPI_TOTAL_BYTES, MAX_OPENAPI_VALUES, OPENAPI_CAPABILITY,
    OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION, scan_openapi_repository,
};
pub use policy::{
    AppliedPolicySuppression, POLICY_RESULT_SCHEMA_VERSION, POLICY_SCHEMA, POLICY_SCHEMA_VERSION,
    PolicyAnnotation, PolicyAnnotationLevel, PolicyCondition, PolicyConfig, PolicyEntity,
    PolicyEvidenceRequirement, PolicyEvidenceSpan, PolicyMatchKind, PolicyPathStep, PolicyPattern,
    PolicyProfileFilter, PolicyResult, PolicyResultSummary, PolicyRule, PolicyRuleKind,
    PolicySelector, PolicySelectorCardinality, PolicySelectorField, PolicySelectorKind,
    PolicySelectorPattern, PolicySelectorScope, PolicySeverity, PolicySuppression,
    PolicySuppressionScope, PolicyThreshold, PolicyViolation, PublicApiChange, PublicApiChangeKind,
    policy_annotations, render_github_annotations,
};
pub use policy_engine::{evaluate_policy, evaluate_policy_diff};
pub use profile_selection::{
    CandidateDiscoveryReason, CanonicalProfileAxes, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
    DEFAULT_PROFILE_SELECTION_LIMIT_VERSION, DEFAULT_PROFILE_SELECTION_SCHEMA,
    DEFAULT_PROFILE_SELECTION_SCHEMA_PATH, DefaultProfileSelectionPlan, GoCallGraph, GoHostContext,
    GoProfileAxes, MAX_AUTOMATIC_PROFILE_CANDIDATES, MAX_AUTOMATIC_PROFILE_CANDIDATES_PER_LANGUAGE,
    MAX_SELECTED_ROOT_PROFILES, ProfileAxis, ProfileAxisCapability, ProfileCandidateCoverage,
    ProfileCandidateEvidence, ProfileCandidateEvidenceKind, ProfileCandidateKind,
    ProfileCandidateRecord, ProfileDiscoveryLedger, ProfileExclusionReason, ProfileHostContext,
    ProfileLanguage, ProfileOmissionReason, ProfileOmittedLedger, ProfilePolicyExclusion,
    ProfileRankEvidence, ProfileSelectedLedger, ProfileSelectedReason, ProfileSelectionInput,
    ProfileSelectionLimits, ProfileSelectionMode, ProfileSelectionProfile,
    ProfileSelectionRepository, ProfileSelectionSummary, RepositorySizeClass, RustHostContext,
    RustProfileAxes, RustProfileMode, WebEnvironment, WebProfileAxes, WebProfileMode,
    canonical_profile_id, canonical_profile_selection_json, canonical_profile_selection_plan_id,
    profile_candidate_id, profile_exclusion_id, profile_selection_input_digest,
    validate_profile_selection_plan,
};
pub use profile_selection_file::{
    EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA, EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA_PATH,
    ExplicitProfileSelectionFile, ValidatedExplicitProfileSelection,
    parse_explicit_profile_selection_file, plan_explicit_profile_selection,
    read_explicit_profile_selection_file, validate_explicit_profile_selection_capabilities,
};
pub use profile_selection_go::{
    GO_PROFILE_PLANNING_VERSION, GoAutomaticBoundaryKind, GoConstraintTarget,
    GoPlatformEvidenceKind, GoProfileAvailability, GoProfileCandidateGenerationResult,
    GoProfilePlanningInput, GoRejectedProfileDeclaration, GoStaticProfileEvidence,
    GoTagDeclaration, GoTargetDeclaration, generate_go_profile_candidates,
};
pub use profile_selection_plan::{
    DEFAULT_LARGE_PROFILE_CAP, DEFAULT_MEDIUM_PROFILE_CAP, DEFAULT_SMALL_PROFILE_CAP,
    DEFAULT_TINY_PROFILE_CAP, LARGE_BUILD_UNIT_THRESHOLD, LARGE_SOURCE_FILE_THRESHOLD,
    MEDIUM_BUILD_UNIT_THRESHOLD, MEDIUM_SOURCE_FILE_THRESHOLD, PROFILE_SELECTION_INVENTORY_VERSION,
    ProfileCandidateDiscoveryResult, ProfilePlanningBuildUnit, ProfilePlanningBuildUnitKind,
    ProfilePlanningFile, ProfilePlanningFileKind, ProfilePlanningInventory,
    ProfileSelectionInputContext, SMALL_BUILD_UNIT_THRESHOLD, SMALL_SOURCE_FILE_THRESHOLD,
    TINY_BUILD_UNIT_THRESHOLD, TINY_SOURCE_FILE_THRESHOLD, bound_profile_candidate_discovery,
    build_profile_selection_input, canonical_profile_planning_inventory,
    classify_profile_selection_repository, default_profile_selection_limits,
    profile_planning_build_unit_id, profile_selection_inventory_digest,
};
pub use profile_selection_preview::{
    LegacyProfileConfigMigration, LegacyProfileMigrationStatus, ProfileToolchainGuidance,
    RepositoryProfilePlanPreview, build_repository_profile_planning_inventory,
    migrate_legacy_profile_config, plan_repository_profiles,
};
pub use profile_selection_rank::{
    AutomaticProfileSelectionRequest, ProfileMatrixIncompleteReason, ProfileSelectionDoctorStatus,
    plan_automatic_profile_selection, profile_selection_doctor_status,
    profile_selection_human_summary,
};
pub use profile_selection_rust::{
    RUST_PROFILE_PLANNING_VERSION, RustAutomaticBoundaryKind, RustProfileAlternativeDeclaration,
    RustProfileAvailability, RustProfileCandidateGenerationResult, RustProfilePlanningInput,
    RustRejectedProfileDeclaration, RustRootFeatureDeclaration, RustStaticProfileEvidence,
    RustTargetDeclaration, generate_rust_profile_candidates,
};
pub use protobuf::{
    MAX_PROTOBUF_DEPTH, MAX_PROTOBUF_DESCRIPTOR_BYTES, MAX_PROTOBUF_DESCRIPTOR_FILES,
    MAX_PROTOBUF_FILE_BYTES, MAX_PROTOBUF_FILES, MAX_PROTOBUF_TOKENS, MAX_PROTOBUF_TOTAL_BYTES,
    PROTOBUF_CAPABILITY, PROTOBUF_DESCRIPTOR_SUFFIX, PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION,
    scan_protobuf_repository,
};
pub use query::{
    BoundedTraversalResult, CycleLevel, CycleResult, DEFAULT_INTERACTIVE_QUERY_MAX_BYTES,
    DEFAULT_INTERACTIVE_QUERY_MAX_ITEMS, DEFAULT_INTERACTIVE_QUERY_MAX_TRAVERSAL, GraphQueryFilter,
    INTERACTIVE_QUERY_PAGE_CONTRACT_VERSION, InteractiveQueryPage, InteractiveQueryPageRequest,
    InteractiveQuerySummary, MAX_INTERACTIVE_QUERY_BYTES, MAX_INTERACTIVE_QUERY_ITEMS,
    MAX_INTERACTIVE_QUERY_TRAVERSAL, QueryCountGroup, QueryCountSummary, QueryPageDiagnostic,
    SelectorFailure, SelectorFailureKind, TraversalPageItem, TraversalResult, UnresolvedResult,
    WhyResult, cycles, cycles_from_topology, paginate_interactive_query, render_condition,
    resolve_selector, traversal_page_items, traversal_summary, traverse, traverse_bounded_filtered,
    traverse_filtered, unresolved, unresolved_summary, validate_interactive_query_bounds, why,
    why_filtered,
};
pub use runtime_trace::{
    MatchedRuntimeTraceLocator, RUNTIME_COLLECTOR_CONTRACT_VERSION, RUNTIME_COLLECTOR_SCHEMA,
    RUNTIME_TRACE_MAX_BYTES, RUNTIME_TRACE_MAX_EVENTS, RUNTIME_TRACE_SCHEMA,
    RUNTIME_TRACE_SCHEMA_VERSION, RuntimeHttpObservation, RuntimeHttpOperationFormat, RuntimeTrace,
    RuntimeTraceEnvironment, RuntimeTraceEvent, RuntimeTraceLocator, RuntimeTraceMatchStatus,
    RuntimeTraceProfile, RuntimeTraceProfileMatch, RuntimeTraceRedaction, RuntimeTraceRepository,
    RuntimeTraceSession, RuntimeTraceSummary, ValidatedRuntimeTrace, ValidatedRuntimeTraceEvent,
    match_runtime_trace, read_runtime_trace, runtime_session_delta, validate_runtime_trace,
};
pub use rust_build_observer::{
    RUST_BUILD_CAPABILITY, RUST_BUILD_OBSERVATION_SCHEMA, RUST_BUILD_OBSERVER,
    RUST_BUILD_OBSERVER_VERSION, RustBuildObservation, rust_build_protocol_events,
    rust_build_protocol_ndjson,
};
pub use scan::{
    ScanCacheMode, ScanOutcome, run_scan, run_scan_with_cache_mode,
    run_scan_with_cache_mode_and_cancellation,
};
pub use service::{
    ChangedSetImpactRequest, ChangedSetImpactServiceResult, CyclesRequest, CyclesResult,
    DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES, DEFAULT_SERVICE_MAX_OUTPUT_BYTES,
    DEFAULT_SERVICE_MAX_PAGE_ITEMS, DEFAULT_SERVICE_PAGE_ITEMS, DEPGRAPH_SERVICE_LIMITS_VERSION,
    DependenciesRequest, DependenciesResult, DependencyDirection, DepgraphCapability,
    DepgraphCapabilitySet, DepgraphMutatingContext, DepgraphMutatingUseCase,
    DepgraphMutatingUseCaseKind, DepgraphResourceLimit, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceConfigurationError, DepgraphServiceError, DepgraphServiceErrorCategory,
    DepgraphServiceLimit, DepgraphServiceLimits, DepgraphServiceResult, DoctorRequest,
    DoctorResponse, ExplainPathRequest, ExplainPathResult, HealthAuditReadScope,
    HealthAuditRequest, HealthAuditResult, HealthCoverageOverview, HealthFindingGetRequest,
    HealthFindingsRequest, HealthFindingsResult, HealthHotspotsRequest, HealthHotspotsResult,
    HealthSummaryRequest, HealthSummaryResult, ImpactRequest, ImpactServiceResult,
    OpenedRepositoryFile, PartialSnapshotMetadata, PinnedHealthSnapshot, ProfilePlanRequest,
    RepositoryFileError, RepositoryPathError, RepositoryPathSelector, RepositoryRelativePath,
    RequestReadStore, RequestReadStoreFactory, ResolvedSnapshotId, SnapshotLocator,
    SnapshotReadRequest, UnresolvedRequest, UnresolvedServiceResult,
};

pub use doctor::{
    CompilerPackAvailabilityHealth, CompilerPreciseHealth, CompilerPreciseProfileHealth,
    DoctorDiagnosticRoot, DoctorReport, DoctorSummaryReport, ScanHealth, ScanHealthSummary,
    WorkerHealth, compiler_pack_availability, doctor, doctor_cancellable, doctor_for_root,
    doctor_for_root_cancellable, doctor_summary, doctor_summary_cancellable,
    doctor_summary_for_root, doctor_summary_for_root_cancellable,
};
pub use release_compatibility::{
    BoundedQueryReleaseCompatibilityHealth, CompilerPreciseReleaseCompatibilityHealth,
    CrossLanguageCapabilityHealth, CrossLanguageReleaseCompatibilityHealth,
    CrossLanguageSchemaHealth, FrameworkBuildCapabilityHealth,
    ProfileSelectionReleaseCompatibilityHealth, ReleaseCompatibilityHealth,
    RustSysrootCompatibilityHealth, bounded_query_release_compatibility_contract,
    compiler_precise_release_compatibility_contract, cross_language_release_compatibility_contract,
    framework_build_capability_contract, profile_selection_release_compatibility_contract,
    release_compatibility_contract, rust_sysroot_compatibility_contract,
};
pub use release_health::ReleaseHealth;
pub(crate) use release_health::verify_release_compatibility;

pub fn open_store(path: &Path) -> Result<Store> {
    Store::open(path)
}

pub fn open_store_read_only(path: &Path) -> Result<Store> {
    Store::open_read_only(path)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn executable_symlink_chain_fails_closed_beyond_the_explicit_limit() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        use super::canonicalize_executable;

        let temp = tempfile::tempdir()?;
        let executable = temp.path().join("depgraph");
        std::fs::write(&executable, b"test executable")?;
        let mut target = executable;
        for index in 0..=super::MAX_EXECUTABLE_SYMLINK_DEPTH {
            let alias = temp.path().join(format!("depgraph-alias-{index}"));
            symlink(&target, &alias)?;
            target = alias;
        }

        let error = canonicalize_executable(&target, "test depgraph executable")
            .expect_err("an overlong executable symlink chain must fail closed");
        assert!(error.to_string().contains("symlink chain exceeds 40 links"));
        Ok(())
    }
}

mod web_declarations;
