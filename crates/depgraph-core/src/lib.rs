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
pub mod export;
pub mod ffi;
pub mod ffi_link;
pub mod github_settings;
mod graphml;
pub mod graphql;
pub mod health;
pub mod http_operation_correlation;
pub mod impact;
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
pub mod public_history_audit;
pub mod public_migration_rehearsal;
pub mod public_provenance_audit;
pub mod public_readiness;
pub mod query;
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
pub mod worker;
mod worker_web_semantic;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use depgraph_store::{
    AdapterLogRecord, AdapterLogSummaryRecord, CACHE_CONTRACT_VERSION, CacheEntryCounts,
    CacheEventRecord, CoverageRecord, DiagnosticRecord, DiagnosticSummaryRecord,
    FileCoverageRecord, FileCoverageSummaryRecord, IMPACT_QUERY_CACHE_CONTRACT_VERSION,
    ProfileMatrixRecord, ProfileRecord, SNAPSHOT_DIFF_SCHEMA_VERSION, STORE_SCHEMA_VERSION, Store,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
pub use public_history_audit::{
    FinalizedPublicHistoryAudit, MAX_PUBLIC_AUDIT_REFS, MAX_PUBLIC_AUDIT_SOURCE_BYTES,
    MAX_PUBLIC_AUDIT_SOURCES, MAX_PUBLIC_AUDIT_TOTAL_BYTES, PUBLIC_AUDIT_SOURCE_KINDS,
    PUBLIC_HISTORY_AUDIT_FINAL_SCHEMA_VERSION, PUBLIC_HISTORY_AUDIT_SCHEMA_VERSION,
    PUBLIC_SECRET_SCANNER_NAME, PUBLIC_SECRET_SCANNER_VERSION, PublicAuditCredentialAction,
    PublicAuditFinding, PublicAuditFindingState, PublicAuditPurgeAction, PublicAuditRefInput,
    PublicAuditRemediationAttestation, PublicAuditSourceInput, PublicAuditSourceKind,
    PublicHistoryAuditInput, PublicHistoryAuditReport, audit_public_history,
    finalize_public_history_audit, public_audit_remediation_attestation_digest,
    public_secret_scanner_identity,
};
pub use public_migration_rehearsal::{
    AnonymousPublicSurfaceSmoke, PUBLIC_MIGRATION_CHECKPOINT_VERIFIER_NAME,
    PUBLIC_MIGRATION_CHECKPOINT_VERIFIER_VERSION, PUBLIC_MIGRATION_PHASES,
    PUBLIC_MIGRATION_PRODUCTION_REPOSITORY, PUBLIC_MIGRATION_REHEARSAL_INPUT_SCHEMA_VERSION,
    PUBLIC_MIGRATION_REHEARSAL_MODE, PUBLIC_MIGRATION_REHEARSAL_REPORT_SCHEMA_VERSION,
    PublicMigrationCheckpointEvidence, PublicMigrationCleanup, PublicMigrationContainment,
    PublicMigrationEvidence, PublicMigrationEvidenceKind, PublicMigrationNoGoReason,
    PublicMigrationPhase, PublicMigrationRehearsalInput, PublicMigrationRehearsalReport,
    PublicMigrationStep, PublicMigrationStepOutcome, PublicMigrationWriteDisposition,
    canonical_public_migration_rehearsal_digest, evaluate_public_migration_rehearsal,
    public_migration_checkpoint_evidence_digest, public_migration_checkpoint_verifier_identity,
};
pub use public_provenance_audit::{
    MAX_PUBLIC_PROVENANCE_ASSETS, MAX_PUBLIC_PROVENANCE_DEPENDENCIES, PUBLIC_LICENSE_POLICY_NAME,
    PUBLIC_LICENSE_POLICY_VERSION, PUBLIC_PROVENANCE_EVALUATION_SCHEMA_VERSION,
    PUBLIC_PROVENANCE_REVIEW_SCHEMA_VERSION, PUBLIC_RELEASE_TARGETS,
    PUBLIC_VULNERABILITY_SCANNER_NAME, PUBLIC_VULNERABILITY_SCANNER_VERSION, PublicAssetAuditInput,
    PublicAssetEvidence, PublicAssetKind, PublicDependencyAuditInput, PublicDependencyEcosystem,
    PublicDependencyEvidence, PublicLicensePolicyState, PublicProvenanceAuditInput,
    PublicProvenanceEvaluation, PublicProvenanceExpectedState, PublicProvenanceFinding,
    PublicProvenanceFindingReason, PublicProvenanceRejectionReason, PublicProvenanceReviewPackage,
    PublicProvenanceState, PublicTargetAuditInput, PublicTargetEvidence,
    PublicVulnerabilitySeverity, build_public_provenance_review_package,
    evaluate_public_provenance_review, public_license_policy_identity,
    public_vulnerability_scanner_identity,
};
pub use public_readiness::{
    PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION, PUBLIC_READINESS_FINAL_APPROVAL_ROLES,
    PUBLIC_READINESS_GATE_IDS, PUBLIC_READINESS_REPOSITORY, PUBLIC_READINESS_ROLES,
    PUBLIC_READINESS_SCHEMA_VERSION, PUBLIC_READINESS_VERIFIER_MODE, PublicReadinessApproval,
    PublicReadinessBundle, PublicReadinessDecision, PublicReadinessEvaluation,
    PublicReadinessEvidence, PublicReadinessEvidenceManifest, PublicReadinessExpectedState,
    PublicReadinessFindingSummary, PublicReadinessGate, PublicReadinessRecord,
    PublicReadinessRejectionReason, PublicReadinessToolIdentity, canonical_public_readiness_digest,
    evaluate_public_readiness, public_readiness_approval_statement_digest,
    public_readiness_evidence_digest, public_readiness_evidence_input_digest,
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
    RepositoryScanRunner, WatchIgnoreRules, WatchPathKind, WatchedPath, acquire_store_writer_lock,
    coalesce_incremental_changes, start_daemon_with_runner, start_repository_daemon,
};
pub use depgraph_store::GraphSnapshot;
pub use export::{
    ExportFormat, export, export_filtered, export_graphml_filtered_to_writer, filter_snapshot,
};
pub use github_settings::{
    GITHUB_SETTINGS_DESIRED_SCHEMA_VERSION, GITHUB_SETTINGS_EVALUATION_SCHEMA_VERSION,
    GITHUB_SETTINGS_REPOSITORY, GITHUB_SETTINGS_VERIFIER_MODE, GITHUB_SETTINGS_VERIFIER_NAME,
    GITHUB_SETTINGS_VERIFIER_VERSION, GitHubRedactedPrincipal, GitHubRedactedSurface,
    GitHubRequiredCheck, GitHubRuleset, GitHubRulesetEnforcement, GitHubRulesetTarget,
    GitHubSecuritySettings, GitHubSettingsApiSnapshot, GitHubSettingsCollectionStatus,
    GitHubSettingsDrift, GitHubSettingsDriftReason, GitHubSettingsEvaluation, GitHubSettingsState,
    canonical_github_settings_digest, evaluate_github_settings, github_settings_verifier_identity,
    parse_github_settings_desired,
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
    HealthFinding, HealthFindingDetail, HealthGateConfig, HealthGateDecision, HotspotFindingScores,
    HotspotLayerScore, HotspotLayerScores, HotspotScores, HotspotWeights, Remediation, Severity,
    SourceLocation, classify_baseline_transition, collection_digest, evaluate_health_gate,
    finding_fingerprint, finding_id,
};
pub use http_operation_correlation::{
    HTTP_OPERATION_CORRELATION_VERSION, HttpOperationCorrelationOutcome,
    HttpOperationCorrelationResult, correlate_http_operations,
};
pub use impact::{
    ChangedNodeMapping, GitChange, GitChangedSet, IMPACT_QUERY_CACHE_SCHEMA_VERSION,
    ImpactDiagnostic, ImpactFilters, ImpactNode, ImpactResult, impact, impact_query_cache_key,
    map_changed_set, read_git_changed_set,
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
    TraversalPageItem, TraversalResult, UnresolvedResult, WhyResult, cycles, cycles_from_topology,
    paginate_interactive_query, render_condition, resolve_selector, traversal_page_items,
    traversal_summary, traverse, traverse_bounded_filtered, traverse_filtered, unresolved,
    unresolved_summary, validate_interactive_query_bounds, why, why_filtered,
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
    CyclesRequest, CyclesResult, DEFAULT_SERVICE_MAX_INLINE_INPUT_BYTES,
    DEFAULT_SERVICE_MAX_OUTPUT_BYTES, DEFAULT_SERVICE_MAX_PAGE_ITEMS, DEFAULT_SERVICE_PAGE_ITEMS,
    DEPGRAPH_SERVICE_LIMITS_VERSION, DependenciesRequest, DependenciesResult, DependencyDirection,
    DepgraphCapability, DepgraphCapabilitySet, DepgraphMutatingContext, DepgraphMutatingUseCase,
    DepgraphMutatingUseCaseKind, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceConfigurationError, DepgraphServiceError, DepgraphServiceErrorCategory,
    DepgraphServiceLimit, DepgraphServiceLimits, DepgraphServiceResult, DoctorRequest,
    DoctorResponse, ExplainPathRequest, ExplainPathResult, HealthAuditReadScope,
    HealthAuditRequest, HealthAuditResult, HealthCoverageOverview, HealthFindingGetRequest,
    HealthFindingsRequest, HealthFindingsResult, HealthHotspotsRequest, HealthHotspotsResult,
    HealthSummaryRequest, HealthSummaryResult, ImpactRequest, ImpactServiceResult,
    OpenedRepositoryFile, PinnedHealthSnapshot, ProfilePlanRequest, RepositoryFileError,
    RepositoryPathError, RepositoryPathSelector, RepositoryRelativePath, RequestReadStore,
    RequestReadStoreFactory, ResolvedSnapshotId, SnapshotLocator, SnapshotReadRequest,
    UnresolvedRequest, UnresolvedServiceResult,
};

use worker::{
    AdapterKind, RUST_BACKEND_KIND, RUST_BACKEND_REVISION, RUST_BACKEND_SALSA_VERSION,
    RUST_BACKEND_VERSION, is_security_error, locate_worker,
    probe_toolchain_version_with_cancellation, probe_worker_version_with_cancellation,
    validate_worker_launch_policy, verify_release_artifact, verify_release_runtime_component,
    verify_rust_release_handshake, verify_web_release_handshake, verify_web_semantic_compatibility,
};

#[derive(Debug, Clone, Serialize)]
pub struct WorkerHealth {
    pub adapter: String,
    pub available: bool,
    pub command: Option<String>,
    pub version: Option<String>,
    pub protocol: Option<String>,
    pub integrity: String,
    pub error: Option<String>,
    pub root_launch_allowed: bool,
    pub root_launch_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DoctorDiagnosticRoot {
    pub path: String,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHealth {
    pub scan_id: String,
    pub status: String,
    pub root: String,
    pub project_code_executed: bool,
    pub coverage: CoverageRecord,
    pub profiles: Vec<ProfileRecord>,
    pub file_coverage: Vec<FileCoverageRecord>,
    pub adapter_logs: Vec<AdapterLogRecord>,
    pub detected_packages: BTreeMap<String, String>,
    pub diagnostics: Vec<DiagnosticRecord>,
    pub profile_matrix: ProfileMatrixRecord,
    pub cache_events: Vec<CacheEventRecord>,
    pub compiler_precise: Option<CompilerPreciseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHealthSummary {
    pub scan_id: String,
    pub status: String,
    pub root: String,
    pub project_code_executed: bool,
    pub coverage: CoverageRecord,
    pub profile_count: u64,
    pub profiles_by_language: BTreeMap<String, u64>,
    pub package_instance_count: u64,
    pub file_coverage: Vec<FileCoverageSummaryRecord>,
    pub adapter_logs: Vec<AdapterLogSummaryRecord>,
    pub diagnostics: DiagnosticSummaryRecord,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPreciseHealth {
    pub status: String,
    pub phase: String,
    pub precision: String,
    pub profiles: Vec<CompilerPreciseProfileHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPreciseProfileHealth {
    pub profile_id: String,
    pub target: Option<String>,
    pub compiler_pack_manifest_sha256: Option<String>,
    pub unit_graph_digest: Option<String>,
    pub invocation_ledger_digest: Option<String>,
    pub mir_ledger_digest: Option<String>,
    pub cargo_units: u64,
    pub typed_mir_bodies: u64,
    pub compiler_instances: u64,
    pub compiler_calls: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompilerPackAvailabilityHealth {
    pub status: String,
    pub host_target: Option<String>,
    pub requirement_path: Option<String>,
    pub pack_root: Option<String>,
    pub manifest_sha256: Option<String>,
    pub archive_asset: Option<String>,
    pub checksum_asset: Option<String>,
    pub requirement_asset: Option<String>,
    pub smoke_asset: Option<String>,
    pub release_page: &'static str,
    pub fallback_policy: &'static str,
    pub diagnostic: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub diagnostic_root: DoctorDiagnosticRoot,
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
    pub cache_contract_version: u32,
    pub cache_entries: CacheEntryCounts,
    pub impact_query_cache_contract_version: u32,
    pub impact_query_cache_entries: u64,
    pub recent_cache_events: Vec<CacheEventRecord>,
    pub toolchains: BTreeMap<String, String>,
    pub supported_baselines: BTreeMap<String, String>,
    pub toolchain_remediation: BTreeMap<String, String>,
    pub workers: Vec<WorkerHealth>,
    pub compiler_pack: CompilerPackAvailabilityHealth,
    pub latest_attempt: Option<ScanHealth>,
    pub latest_successful_scan_id: Option<String>,
    pub release: Option<ReleaseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorSummaryReport {
    pub report_kind: &'static str,
    pub detail_command: &'static str,
    pub diagnostic_root: DoctorDiagnosticRoot,
    pub protocol_version: &'static str,
    pub graph_schema_version: &'static str,
    pub store_schema_version: i64,
    pub cache_contract_version: u32,
    pub cache_entries: CacheEntryCounts,
    pub impact_query_cache_contract_version: u32,
    pub impact_query_cache_entries: u64,
    pub recent_cache_events: Vec<CacheEventRecord>,
    pub toolchains: BTreeMap<String, String>,
    pub supported_baselines: BTreeMap<String, String>,
    pub toolchain_remediation: BTreeMap<String, String>,
    pub workers: Vec<WorkerHealth>,
    pub compiler_pack: CompilerPackAvailabilityHealth,
    pub latest_attempt: Option<ScanHealthSummary>,
    pub latest_successful_scan_id: Option<String>,
    pub release: Option<ReleaseHealth>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseHealth {
    pub version: String,
    pub target: String,
    pub schema_version: String,
    pub compatibility: ReleaseCompatibilityHealth,
    pub compatibility_integrity: String,
    pub license_expression: String,
    pub core_integrity: String,
    pub schema_integrity: String,
    pub runtime_integrity: BTreeMap<String, String>,
    pub runtime_requirements: BTreeMap<String, String>,
}

pub fn compiler_pack_availability(
    requirement_path: Option<&Path>,
) -> CompilerPackAvailabilityHealth {
    const RELEASE_PAGE: &str = "https://github.com/TamaT-LLC/depgraph-cli/releases";
    let Some(host_target) = compiler_pack_host_target() else {
        return CompilerPackAvailabilityHealth {
            status: "unsupported-host".to_owned(),
            host_target: None,
            requirement_path: requirement_path.map(|path| path.to_string_lossy().into_owned()),
            pack_root: None,
            manifest_sha256: None,
            archive_asset: None,
            checksum_asset: None,
            requirement_asset: None,
            smoke_asset: None,
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: format!(
                "no first-party compiler pack is published for {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            ),
            remediation:
                "use one of the five supported hosts; depgraph will not fall back to rustup, PATH, system, or project compilers"
                    .to_owned(),
        };
    };
    let version = env!("CARGO_PKG_VERSION");
    let name = format!("depgraph-compiler-pack-{version}-{host_target}");
    let archive_asset = format!(
        "{name}.{}",
        if host_target.ends_with("windows-msvc") {
            "zip"
        } else {
            "tar.gz"
        }
    );
    let checksum_asset = format!("{archive_asset}.sha256");
    let requirement_asset = format!("{name}.requirement.json");
    let smoke_asset = format!("{name}.smoke.json");
    let install = format!(
        "download {archive_asset}, {checksum_asset}, {requirement_asset}, and {smoke_asset} from a depgraph {version} release at {RELEASE_PAGE}; verify the checksum, extract the archive next to the requirement, then run `depgraph doctor --compiler-pack-requirement {requirement_asset}`"
    );
    let Some(requirement_path) = requirement_path else {
        return CompilerPackAvailabilityHealth {
            status: "unconfigured".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: None,
            pack_root: None,
            manifest_sha256: None,
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: "no compiler-pack requirement was supplied to doctor".to_owned(),
            remediation: install,
        };
    };
    let requirement_display = requirement_path.to_string_lossy().into_owned();
    let inspected = read_compiler_pack_requirement(requirement_path).and_then(|requirement| {
        if requirement.host != host_target || requirement.target != host_target {
            anyhow::bail!(
                "compiler pack requirement targets {}/{} instead of current host {host_target}",
                requirement.host,
                requirement.target
            );
        }
        verify_compiler_pack(&requirement)
    });
    match inspected {
        Ok(pack) => CompilerPackAvailabilityHealth {
            status: "available".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: Some(requirement_display.clone()),
            pack_root: Some(pack.root.to_string_lossy().into_owned()),
            manifest_sha256: Some(pack.attestation.manifest_sha256),
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: "the exact current-host compiler pack is verified and available".to_owned(),
            remediation: format!(
                "run compiler-precise resolve with `--compiler-pack-requirement {requirement_display}`"
            ),
        },
        Err(error) => CompilerPackAvailabilityHealth {
            status: "unavailable".to_owned(),
            host_target: Some(host_target.to_owned()),
            requirement_path: Some(requirement_display),
            pack_root: None,
            manifest_sha256: None,
            archive_asset: Some(archive_asset),
            checksum_asset: Some(checksum_asset),
            requirement_asset: Some(requirement_asset),
            smoke_asset: Some(smoke_asset),
            release_page: RELEASE_PAGE,
            fallback_policy: COMPILER_PACK_FALLBACK_POLICY,
            diagnostic: format!("compiler pack verification failed: {error:#}"),
            remediation: install,
        },
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrameworkBuildCapabilityHealth {
    pub framework: String,
    pub observer: String,
    pub observer_version: String,
    pub observation_schema: String,
    pub capability: String,
    pub observer_runtime_artifact: String,
    pub converter_runtime_artifact: String,
}

pub fn framework_build_capability_contract() -> Vec<FrameworkBuildCapabilityHealth> {
    [
        (
            "astro",
            ASTRO_BUILD_OBSERVER,
            ASTRO_BUILD_OBSERVER_VERSION,
            ASTRO_BUILD_OBSERVATION_SCHEMA,
            ASTRO_BUILD_CAPABILITY,
            "libexec/astro-build-integration.mjs",
        ),
        (
            "next",
            NEXT_BUILD_OBSERVER,
            NEXT_BUILD_OBSERVER_VERSION,
            NEXT_BUILD_OBSERVATION_SCHEMA,
            NEXT_BUILD_CAPABILITY,
            "libexec/next-build-adapter.mjs",
        ),
        (
            "tanstack-router",
            TANSTACK_ROUTER_BUILD_OBSERVER,
            TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
            TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA,
            TANSTACK_ROUTER_BUILD_CAPABILITY,
            "libexec/tanstack-router-build-observer.mjs",
        ),
        (
            "tanstack-start",
            TANSTACK_START_BUILD_OBSERVER,
            TANSTACK_START_BUILD_OBSERVER_VERSION,
            TANSTACK_START_BUILD_OBSERVATION_SCHEMA,
            TANSTACK_START_BUILD_CAPABILITY,
            "libexec/tanstack-start-build-observer.mjs",
        ),
    ]
    .into_iter()
    .map(
        |(
            framework,
            observer,
            observer_version,
            observation_schema,
            capability,
            observer_runtime_artifact,
        )| FrameworkBuildCapabilityHealth {
            framework: framework.to_owned(),
            observer: observer.to_owned(),
            observer_version: observer_version.to_owned(),
            observation_schema: observation_schema.to_owned(),
            capability: capability.to_owned(),
            observer_runtime_artifact: observer_runtime_artifact.to_owned(),
            converter_runtime_artifact: FRAMEWORK_BUILD_CONVERTER_ARTIFACT.to_owned(),
        },
    )
    .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustSysrootCompatibilityHealth {
    pub contract_version: String,
    pub toolchain_version: String,
    pub toolchain_commit: String,
    pub component_name: String,
    pub component_version: String,
    pub component_root: String,
    pub source_layout: String,
    pub license_expression: String,
    pub sbom_package_name: String,
}

pub fn rust_sysroot_compatibility_contract() -> RustSysrootCompatibilityHealth {
    RustSysrootCompatibilityHealth {
        contract_version: RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION.to_owned(),
        toolchain_version: RUST_SYSROOT_TOOLCHAIN_VERSION.to_owned(),
        toolchain_commit: RUST_SYSROOT_TOOLCHAIN_COMMIT.to_owned(),
        component_name: RUST_SYSROOT_COMPONENT_NAME.to_owned(),
        component_version: RUST_SYSROOT_COMPONENT_VERSION.to_owned(),
        component_root: RUST_SYSROOT_COMPONENT_ROOT.to_owned(),
        source_layout: RUST_SYSROOT_SOURCE_LAYOUT.to_owned(),
        license_expression: RUST_SYSROOT_LICENSE_EXPRESSION.to_owned(),
        sbom_package_name: RUST_SYSROOT_SBOM_PACKAGE_NAME.to_owned(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibilityHealth {
    pub worker_protocol_version: String,
    pub store_schema_version: i64,
    pub operation_journal_schema_version: i64,
    pub mcp_tool_contract_version: String,
    pub mcp_operation_contract_version: String,
    pub minimum_migratable_store_schema_version: i64,
    pub previous_release_version: String,
    pub previous_release_store_schema_version: i64,
    pub stable_release_gate_contract_version: String,
    pub stable_release_version: String,
    pub stable_upgrade_source_version: String,
    pub stable_upgrade_source_store_schema_version: i64,
    pub stable_upgrade_source_fixture_path: String,
    pub stable_upgrade_source_fixture_sha256: String,
    pub cache_contract_version: u32,
    pub snapshot_diff_schema_version: String,
    pub incremental_plan_schema_version: String,
    pub daemon_status_schema_version: String,
    pub policy_schema_version: String,
    pub policy_result_schema_version: String,
    pub framework_build_graph_contract_version: String,
    pub framework_build_gate_contract_version: String,
    pub framework_build_capabilities: Vec<FrameworkBuildCapabilityHealth>,
    pub rust_sysroot: RustSysrootCompatibilityHealth,
    pub runtime_trace_schema_version: String,
    pub runtime_collector_contract_version: String,
    pub graphml_schema_version: String,
    pub packaged_smoke_contract: String,
    pub bounded_query: BoundedQueryReleaseCompatibilityHealth,
    pub profile_selection: ProfileSelectionReleaseCompatibilityHealth,
    pub cross_language: CrossLanguageReleaseCompatibilityHealth,
    pub compiler_precise: CompilerPreciseReleaseCompatibilityHealth,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPreciseReleaseCompatibilityHealth {
    pub release_contract_version: String,
    pub distribution: String,
    pub supported_targets: Vec<String>,
    pub compiler_contract_version: String,
    pub manifest_schema_version: String,
    pub toolchain_channel: String,
    pub rust_release: String,
    pub rustc_commit: String,
    pub channel_manifest: String,
    pub channel_manifest_sha256: String,
    pub wrapper_protocol_version: String,
    pub mir_schema_version: String,
    pub query_capabilities: Vec<String>,
    pub fallback_policy: String,
}

pub fn compiler_precise_release_compatibility_contract() -> CompilerPreciseReleaseCompatibilityHealth
{
    CompilerPreciseReleaseCompatibilityHealth {
        release_contract_version: COMPILER_PACK_RELEASE_CONTRACT_VERSION.to_owned(),
        distribution: COMPILER_PACK_DISTRIBUTION.to_owned(),
        supported_targets: COMPILER_PACK_SUPPORTED_TARGETS
            .iter()
            .map(|target| (*target).to_owned())
            .collect(),
        compiler_contract_version: COMPILER_PRECISE_CONTRACT_VERSION.to_owned(),
        manifest_schema_version: COMPILER_PACK_MANIFEST_SCHEMA_VERSION.to_owned(),
        toolchain_channel: COMPILER_PACK_TOOLCHAIN_CHANNEL.to_owned(),
        rust_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
        channel_manifest: COMPILER_PACK_CHANNEL_MANIFEST.to_owned(),
        channel_manifest_sha256: COMPILER_PACK_CHANNEL_MANIFEST_SHA256.to_owned(),
        wrapper_protocol_version: COMPILER_PACK_WRAPPER_PROTOCOL_VERSION.to_owned(),
        mir_schema_version: COMPILER_PRECISE_MIR_SCHEMA_VERSION.to_owned(),
        query_capabilities: vec![
            "monomorphized_call_graph".to_owned(),
            "typed_mir".to_owned(),
        ],
        fallback_policy: COMPILER_PACK_FALLBACK_POLICY.to_owned(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundedQueryReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub language_contract_version: String,
    pub type_contract_version: String,
    pub statistics_version: String,
    pub plan_schema_version: String,
    pub limit_version: String,
    pub result_schema_version: String,
    pub fixture_path: String,
    pub fixture_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub selection_contract_version: String,
    pub limit_version: String,
    pub inventory_version: String,
    pub rust_planning_version: String,
    pub go_planning_version: String,
    pub web_planning_version: String,
    pub automatic_schema_path: String,
    pub automatic_schema_sha256: String,
    pub explicit_schema_path: String,
    pub explicit_schema_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageCapabilityHealth {
    pub surface: String,
    pub capability: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageSchemaHealth {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub contract_version: String,
    pub completeness_version: String,
    pub fixture_path: String,
    pub fixture_sha256: String,
    pub capabilities: Vec<CrossLanguageCapabilityHealth>,
    pub schemas: Vec<CrossLanguageSchemaHealth>,
}

pub fn cross_language_release_compatibility_contract() -> CrossLanguageReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    let digest = |contents: &str| {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(contents.as_bytes()))
        )
    };
    CrossLanguageReleaseCompatibilityHealth {
        release_smoke_contract_version: CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION.to_owned(),
        contract_version: depgraph_protocol::CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: depgraph_protocol::CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        fixture_path: CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH.to_owned(),
        fixture_sha256: digest(CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE),
        capabilities: vec![
            CrossLanguageCapabilityHealth {
                surface: "common".to_owned(),
                capability: depgraph_protocol::CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "ffi-link".to_owned(),
                capability: FFI_LINK_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "ffi-static".to_owned(),
                capability: FFI_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "graphql-mapping".to_owned(),
                capability: GRAPHQL_REPOSITORY_MAPPING_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "graphql-source".to_owned(),
                capability: GRAPHQL_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "http-runtime".to_owned(),
                capability: HTTP_OPERATION_CORRELATION_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "openapi-generated".to_owned(),
                capability: OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "openapi-source".to_owned(),
                capability: OPENAPI_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "protobuf-generated".to_owned(),
                capability: PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "protobuf-source".to_owned(),
                capability: PROTOBUF_CAPABILITY.to_owned(),
            },
        ],
        schemas: vec![
            CrossLanguageSchemaHealth {
                path: depgraph_protocol::CROSS_LANGUAGE_SCHEMA_PATH.to_owned(),
                sha256: digest(depgraph_protocol::CROSS_LANGUAGE_SCHEMA),
            },
            CrossLanguageSchemaHealth {
                path: FFI_LINK_OBSERVATION_SCHEMA_PATH.to_owned(),
                sha256: digest(FFI_LINK_OBSERVATION_SCHEMA),
            },
            CrossLanguageSchemaHealth {
                path: "schemas/depgraph-runtime-trace-v1.schema.json".to_owned(),
                sha256: digest(RUNTIME_TRACE_SCHEMA),
            },
        ],
    }
}

pub fn profile_selection_release_compatibility_contract()
-> ProfileSelectionReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    ProfileSelectionReleaseCompatibilityHealth {
        release_smoke_contract_version: "profile-selection-release-smoke-v1".to_owned(),
        selection_contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        limit_version: DEFAULT_PROFILE_SELECTION_LIMIT_VERSION.to_owned(),
        inventory_version: PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
        rust_planning_version: RUST_PROFILE_PLANNING_VERSION.to_owned(),
        go_planning_version: GO_PROFILE_PLANNING_VERSION.to_owned(),
        web_planning_version: profile_selection_web::WEB_PROFILE_PLANNING_VERSION.to_owned(),
        automatic_schema_path: DEFAULT_PROFILE_SELECTION_SCHEMA_PATH.to_owned(),
        automatic_schema_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(DEFAULT_PROFILE_SELECTION_SCHEMA.as_bytes()))
        ),
        explicit_schema_path: EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA_PATH.to_owned(),
        explicit_schema_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA.as_bytes()
            ))
        ),
    }
}

pub fn bounded_query_release_compatibility_contract() -> BoundedQueryReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    BoundedQueryReleaseCompatibilityHealth {
        release_smoke_contract_version: BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION.to_owned(),
        language_contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
        type_contract_version: BOUNDED_QUERY_TYPE_CONTRACT_VERSION.to_owned(),
        statistics_version: BOUNDED_QUERY_STATISTICS_VERSION.to_owned(),
        plan_schema_version: BOUNDED_QUERY_PLAN_SCHEMA_VERSION.to_owned(),
        limit_version: BOUNDED_QUERY_LIMIT_VERSION.to_owned(),
        result_schema_version: BOUNDED_QUERY_RESULT_SCHEMA_VERSION.to_owned(),
        fixture_path: BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH.to_owned(),
        fixture_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(BOUNDED_QUERY_RELEASE_SMOKE_QUERY.as_bytes()))
        ),
    }
}

pub fn release_compatibility_contract() -> ReleaseCompatibilityHealth {
    ReleaseCompatibilityHealth {
        worker_protocol_version: depgraph_protocol::PROTOCOL_VERSION.to_owned(),
        store_schema_version: STORE_SCHEMA_VERSION,
        operation_journal_schema_version: 5,
        mcp_tool_contract_version: "depgraph-mcp-tools-v1".to_owned(),
        mcp_operation_contract_version: "depgraph-operation-v1".to_owned(),
        minimum_migratable_store_schema_version: 1,
        previous_release_version: "0.5.3".to_owned(),
        previous_release_store_schema_version: 17,
        stable_release_gate_contract_version: "stable-release-gate-v2".to_owned(),
        stable_release_version: "0.5.4".to_owned(),
        stable_upgrade_source_version: "0.4.0-rc.6".to_owned(),
        stable_upgrade_source_store_schema_version: 13,
        stable_upgrade_source_fixture_path: "xtask/fixtures/v0.4.0-rc.6-store-v13.sql".to_owned(),
        stable_upgrade_source_fixture_sha256:
            "sha256:43fe0dda73d03be9b8fff2ed9ff8ce888ad96e41e78335a1117646475c937150".to_owned(),
        cache_contract_version: CACHE_CONTRACT_VERSION,
        snapshot_diff_schema_version: SNAPSHOT_DIFF_SCHEMA_VERSION.to_owned(),
        incremental_plan_schema_version: INCREMENTAL_PLAN_SCHEMA_VERSION.to_owned(),
        daemon_status_schema_version: DAEMON_STATUS_SCHEMA_VERSION.to_owned(),
        policy_schema_version: POLICY_SCHEMA_VERSION.to_owned(),
        policy_result_schema_version: POLICY_RESULT_SCHEMA_VERSION.to_owned(),
        framework_build_graph_contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION.to_owned(),
        framework_build_gate_contract_version: FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
        framework_build_capabilities: framework_build_capability_contract(),
        rust_sysroot: rust_sysroot_compatibility_contract(),
        runtime_trace_schema_version: RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
        runtime_collector_contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
        graphml_schema_version: GRAPHML_SCHEMA_VERSION.to_owned(),
        packaged_smoke_contract: "stable-v0.5.0-packaged-smoke-v1".to_owned(),
        bounded_query: bounded_query_release_compatibility_contract(),
        profile_selection: profile_selection_release_compatibility_contract(),
        cross_language: cross_language_release_compatibility_contract(),
        compiler_precise: compiler_precise_release_compatibility_contract(),
    }
}

#[derive(Debug)]
enum DoctorWorkerLocation {
    Ready(worker::WorkerSpec),
    Unavailable(String),
}

#[derive(Debug)]
struct DoctorWorkerPreflight {
    locations: Vec<(AdapterKind, DoctorWorkerLocation)>,
    suppress_probes: bool,
}

fn preflight_doctor_workers(
    adapters: impl IntoIterator<Item = AdapterKind>,
    mut locate: impl FnMut(AdapterKind) -> Result<worker::WorkerSpec>,
) -> DoctorWorkerPreflight {
    let mut locations = Vec::new();
    let mut suppress_probes = false;

    for adapter in adapters {
        let location = match locate(adapter) {
            Ok(spec) => DoctorWorkerLocation::Ready(spec),
            Err(error) => {
                let error = format!("{error:#}");
                suppress_probes |= is_security_error(&error);
                DoctorWorkerLocation::Unavailable(error)
            }
        };
        locations.push((adapter, location));
    }

    DoctorWorkerPreflight {
        locations,
        suppress_probes,
    }
}

fn worker_root_launch_policy(spec: &worker::WorkerSpec, root: &Path) -> (bool, Option<String>) {
    match validate_worker_launch_policy(spec, root) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    }
}

fn evaluated_worker_health(
    adapter: AdapterKind,
    spec: worker::WorkerSpec,
    root: &Path,
    version: Result<String>,
) -> WorkerHealth {
    let (root_launch_allowed, root_launch_error) = worker_root_launch_policy(&spec, root);
    let reported_version = version.as_deref().ok();
    let protocol = reported_version
        .and_then(parse_worker_handshake)
        .map(|(_, _, protocol)| protocol.to_owned());
    let integrity = worker_integrity(adapter, &spec.artifact_path, reported_version);
    let error = version
        .as_ref()
        .err()
        .map(ToString::to_string)
        .or_else(|| integrity.strip_prefix("error: ").map(ToOwned::to_owned));
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available: error.is_none(),
        command: Some(spec.display),
        version: version.ok(),
        protocol,
        integrity,
        error,
        root_launch_allowed,
        root_launch_error,
    }
}

fn suppressed_worker_health(
    adapter: AdapterKind,
    spec: worker::WorkerSpec,
    root: &Path,
) -> WorkerHealth {
    let (root_launch_allowed, root_launch_error) = worker_root_launch_policy(&spec, root);
    WorkerHealth {
        adapter: adapter.name().to_owned(),
        available: false,
        command: Some(spec.display),
        version: None,
        protocol: None,
        integrity: worker_integrity(adapter, &spec.artifact_path, None),
        error: Some(
            "worker probe suppressed because another adapter failed release security verification"
                .to_owned(),
        ),
        root_launch_allowed,
        root_launch_error,
    }
}

async fn doctor_workers(root: &Path, cancellation: &CancellationToken) -> Vec<WorkerHealth> {
    let preflight = preflight_doctor_workers(
        [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
        locate_worker,
    );
    let mut workers = Vec::new();
    for (adapter, location) in preflight.locations {
        workers.push(match location {
            DoctorWorkerLocation::Ready(spec) if preflight.suppress_probes => {
                suppressed_worker_health(adapter, spec, root)
            }
            DoctorWorkerLocation::Ready(spec) => {
                let version = worker_artifact_version(&spec, cancellation).await;
                evaluated_worker_health(adapter, spec, root, version)
            }
            DoctorWorkerLocation::Unavailable(error) => WorkerHealth {
                adapter: adapter.name().to_owned(),
                available: false,
                command: None,
                version: None,
                protocol: None,
                integrity: "unavailable".to_owned(),
                error: Some(error.clone()),
                root_launch_allowed: false,
                root_launch_error: Some(format!(
                    "root launch policy was not evaluated because the worker is unavailable: {error}"
                )),
            },
        });
    }
    workers
}

async fn worker_artifact_version(
    spec: &worker::WorkerSpec,
    cancellation: &CancellationToken,
) -> Result<String> {
    let probe_root = tempfile::Builder::new()
        .prefix("depgraph-doctor-worker-probe-")
        .tempdir()
        .context("failed to create a neutral worker health probe root")?;
    worker_version_cancellable(spec, probe_root.path(), cancellation).await
}

fn default_doctor_diagnostic_root(store: &Store) -> Result<(PathBuf, &'static str)> {
    if let Some(scan_id) = store.latest_attempt_id()?
        && let Some(scan) = store.scan(&scan_id)?
    {
        let root = PathBuf::from(scan.root);
        if !root.is_absolute() {
            anyhow::bail!("stored diagnostic root is not absolute");
        }
        return Ok((root, "latest-attempt"));
    }
    Ok((
        std::env::current_dir()?.canonicalize()?,
        "current-working-directory",
    ))
}

fn normalize_doctor_diagnostic_root(
    root: &Path,
    source: &'static str,
) -> (PathBuf, DoctorDiagnosticRoot) {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let diagnostic_root = DoctorDiagnosticRoot {
        path: root.to_string_lossy().into_owned(),
        source,
    };
    (root, diagnostic_root)
}

pub async fn doctor(store: &Store) -> Result<DoctorReport> {
    doctor_cancellable(store, &CancellationToken::new()).await
}

pub async fn doctor_cancellable(
    store: &Store,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    let (root, source) = default_doctor_diagnostic_root(store)?;
    doctor_with_diagnostic_root(store, &root, source, cancellation).await
}

pub async fn doctor_for_root(store: &Store, root: &Path) -> Result<DoctorReport> {
    doctor_for_root_cancellable(store, root, &CancellationToken::new()).await
}

pub async fn doctor_for_root_cancellable(
    store: &Store,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    doctor_with_diagnostic_root(store, root, "explicit", cancellation).await
}

async fn doctor_with_diagnostic_root(
    store: &Store,
    root: &Path,
    source: &'static str,
    cancellation: &CancellationToken,
) -> Result<DoctorReport> {
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let (root, diagnostic_root) = normalize_doctor_diagnostic_root(root, source);
    let workers = doctor_workers(&root, cancellation).await;
    let latest_attempt = store
        .latest_attempt_id()?
        .map(|scan_id| {
            let snapshot = store.load_snapshot(&scan_id)?;
            let compiler_profiles = snapshot
                .profiles
                .iter()
                .filter(|profile| {
                    profile
                        .properties
                        .get("compiler_precise_contract")
                        .and_then(Value::as_str)
                        == Some(COMPILER_PRECISE_CONTRACT_VERSION)
                        && profile
                            .properties
                            .get("profile_phase")
                            .and_then(Value::as_str)
                            == Some("build")
                })
                .map(|profile| {
                    let string_property = |name: &str| {
                        profile
                            .properties
                            .get(name)
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    };
                    let count_property = |name: &str| {
                        profile
                            .properties
                            .get(name)
                            .and_then(Value::as_u64)
                            .unwrap_or(0)
                    };
                    CompilerPreciseProfileHealth {
                        profile_id: profile.id.clone(),
                        target: profile.target.clone(),
                        compiler_pack_manifest_sha256: string_property(
                            "compiler_pack_manifest_sha256",
                        ),
                        unit_graph_digest: string_property("unit_graph_digest"),
                        invocation_ledger_digest: string_property("invocation_ledger_digest"),
                        mir_ledger_digest: string_property("mir_ledger_digest"),
                        cargo_units: count_property("cargo_unit_count"),
                        typed_mir_bodies: count_property("typed_mir_body_count"),
                        compiler_instances: count_property("compiler_instance_count"),
                        compiler_calls: count_property("compiler_call_count"),
                    }
                })
                .collect::<Vec<_>>();
            let compiler_precise =
                (!compiler_profiles.is_empty()).then_some(CompilerPreciseHealth {
                    status: "promoted".to_owned(),
                    phase: "build".to_owned(),
                    precision: "observed".to_owned(),
                    profiles: compiler_profiles,
                });
            let detected_packages = snapshot
                .nodes
                .iter()
                .filter(|node| node.kind == "package_instance")
                .filter_map(|node| {
                    let name = node.properties.get("name")?.as_str()?;
                    let version = node.properties.get("version")?.as_str()?;
                    Some((name.to_owned(), version.to_owned()))
                })
                .collect();
            Ok::<_, anyhow::Error>(ScanHealth {
                scan_id: scan_id.clone(),
                status: snapshot.scan.status,
                root: snapshot.scan.root,
                project_code_executed: snapshot.scan.project_code_executed,
                coverage: snapshot.coverage,
                profiles: snapshot.profiles,
                file_coverage: snapshot.file_coverage,
                adapter_logs: snapshot.adapter_logs,
                detected_packages,
                diagnostics: snapshot.diagnostics,
                profile_matrix: snapshot.profile_matrix,
                cache_events: store.cache_events_for_scan(&scan_id)?,
                compiler_precise,
            })
        })
        .transpose()?;
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let toolchains = toolchain_versions(&root, cancellation).await;
    let toolchain_remediation = doctor_toolchain_remediation(&toolchains);
    Ok(DoctorReport {
        diagnostic_root,
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
        cache_contract_version: CACHE_CONTRACT_VERSION,
        cache_entries: store.cache_entry_counts()?,
        impact_query_cache_contract_version: IMPACT_QUERY_CACHE_CONTRACT_VERSION,
        impact_query_cache_entries: store.impact_query_cache_entry_count()?,
        recent_cache_events: store.recent_cache_events(20)?,
        toolchains,
        supported_baselines: doctor_supported_baselines(),
        toolchain_remediation,
        workers,
        compiler_pack: compiler_pack_availability(None),
        latest_attempt,
        latest_successful_scan_id: store.latest_successful_id()?,
        release: release_health()?,
    })
}

pub async fn doctor_summary(store: &Store) -> Result<DoctorSummaryReport> {
    doctor_summary_cancellable(store, &CancellationToken::new()).await
}

pub async fn doctor_summary_cancellable(
    store: &Store,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    let (root, source) = default_doctor_diagnostic_root(store)?;
    doctor_summary_with_diagnostic_root(store, &root, source, cancellation).await
}

pub async fn doctor_summary_for_root(store: &Store, root: &Path) -> Result<DoctorSummaryReport> {
    doctor_summary_for_root_cancellable(store, root, &CancellationToken::new()).await
}

pub async fn doctor_summary_for_root_cancellable(
    store: &Store,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    doctor_summary_with_diagnostic_root(store, root, "explicit", cancellation).await
}

async fn doctor_summary_with_diagnostic_root(
    store: &Store,
    root: &Path,
    source: &'static str,
    cancellation: &CancellationToken,
) -> Result<DoctorSummaryReport> {
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let (root, diagnostic_root) = normalize_doctor_diagnostic_root(root, source);
    let workers = doctor_workers(&root, cancellation).await;
    let latest_attempt = store
        .latest_attempt_id()?
        .map(|scan_id| {
            let summary = store.scan_attempt_summary(&scan_id)?;
            Ok::<_, anyhow::Error>(ScanHealthSummary {
                scan_id,
                status: summary.scan.status,
                root: summary.scan.root,
                project_code_executed: summary.scan.project_code_executed,
                coverage: summary.coverage,
                profile_count: summary.profile_count,
                profiles_by_language: summary.profiles_by_language,
                package_instance_count: summary.package_instance_count,
                file_coverage: summary.file_coverage,
                adapter_logs: summary.adapter_logs,
                diagnostics: summary.diagnostics,
            })
        })
        .transpose()?;
    if cancellation.is_cancelled() {
        anyhow::bail!("doctor cancelled");
    }
    let toolchains = toolchain_versions(&root, cancellation).await;
    let toolchain_remediation = doctor_toolchain_remediation(&toolchains);
    Ok(DoctorSummaryReport {
        report_kind: "summary",
        detail_command: "depgraph doctor --details",
        diagnostic_root,
        protocol_version: "1.0",
        graph_schema_version: "1.0",
        store_schema_version: store.schema_version()?,
        cache_contract_version: CACHE_CONTRACT_VERSION,
        cache_entries: store.cache_entry_counts()?,
        impact_query_cache_contract_version: IMPACT_QUERY_CACHE_CONTRACT_VERSION,
        impact_query_cache_entries: store.impact_query_cache_entry_count()?,
        recent_cache_events: store.recent_cache_events(20)?,
        toolchains,
        supported_baselines: doctor_supported_baselines(),
        toolchain_remediation,
        workers,
        compiler_pack: compiler_pack_availability(None),
        latest_attempt,
        latest_successful_scan_id: store.latest_successful_id()?,
        release: release_health()?,
    })
}

fn doctor_supported_baselines() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("rust".to_owned(), "1.93.1".to_owned()),
        ("go".to_owned(), "1.26.1".to_owned()),
        ("node".to_owned(), "24.18.0".to_owned()),
        ("pnpm".to_owned(), "10.33.0".to_owned()),
        ("typescript".to_owned(), "7.0.2".to_owned()),
    ])
}

async fn worker_version_cancellable(
    spec: &worker::WorkerSpec,
    root: &Path,
    cancellation: &CancellationToken,
) -> Result<String> {
    let version = probe_worker_version_with_cancellation(spec, root, cancellation).await?;
    let expected_name = format!("depgraph-{}-worker", spec.adapter.name());
    let Some((name, _, protocol)) = parse_worker_handshake(&version) else {
        anyhow::bail!("worker reports a malformed version handshake: {version}");
    };
    if name != expected_name || protocol != "1.0" {
        anyhow::bail!("worker reports an incompatible protocol: {version}");
    }
    Ok(version)
}

fn parse_worker_handshake(handshake: &str) -> Option<(&str, &str, &str)> {
    let (identity, details) = handshake.split_once(" (protocol ")?;
    let details = details.strip_suffix(')')?;
    let protocol = details.split_once(';').map_or(details, |(value, _)| value);
    let mut identity = identity.split_whitespace();
    let name = identity.next()?;
    let version = identity.next()?;
    if identity.next().is_some() || name.is_empty() || version.is_empty() || protocol.is_empty() {
        return None;
    }
    Some((name, version, protocol))
}

#[derive(Deserialize)]
struct ReleaseManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    compatibility: ReleaseCompatibilityHealth,
    target: String,
    license_expression: String,
    project_licenses: Vec<ReleaseArtifact>,
    core: ReleaseArtifact,
    schema: ReleaseArtifact,
    query_fixture: ReleaseArtifact,
    cross_language_fixture: ReleaseArtifact,
    cross_language_schemas: Vec<ReleaseArtifact>,
    #[serde(default)]
    runtime_artifacts: Vec<ReleaseArtifact>,
    #[serde(default)]
    runtime_components: Vec<ReleaseRuntimeComponent>,
    #[serde(default)]
    runtime_requirements: BTreeMap<String, String>,
    workers: Vec<ReleaseWorker>,
}

#[derive(Deserialize)]
struct ReleaseArtifact {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseRuntimeComponent {
    name: String,
    version: String,
    kind: String,
    root: String,
    entrypoint: Option<String>,
    license: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseWorker {
    adapter: String,
    version: String,
    #[serde(default)]
    backend: Option<ReleaseWorkerBackend>,
    #[serde(default)]
    semantic: Option<ReleaseWebSemanticAttestation>,
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
struct ReleaseWorkerBackend {
    kind: String,
    version: String,
    revision: String,
    salsa_version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWebSemanticAttestation {
    typescript_version: String,
    capabilities: Vec<String>,
    runtime_components: Vec<String>,
    runtime_artifacts: Vec<String>,
}

fn worker_integrity(
    adapter: AdapterKind,
    artifact: &Path,
    reported_version: Option<&str>,
) -> String {
    let (manifest_path, manifest) = match load_release_manifest() {
        Ok(Some(release)) => release,
        Ok(None) => return "development-unverified".to_owned(),
        Err(error) => return format!("error: {error:#}"),
    };
    if manifest.protocol_version != "1.0" {
        return format!(
            "error: release manifest protocol {} is incompatible",
            manifest.protocol_version
        );
    }
    if manifest.release_version != env!("CARGO_PKG_VERSION") {
        return format!(
            "error: release manifest version {} does not match core {}",
            manifest.release_version,
            env!("CARGO_PKG_VERSION")
        );
    }
    if let Err(error) = verify_release_compatibility(&manifest.compatibility) {
        return format!("error: {error:#}");
    }
    let Some(entry) = manifest
        .workers
        .iter()
        .find(|entry| entry.adapter == adapter.name())
    else {
        return format!("error: {} is absent from release manifest", adapter.name());
    };
    if adapter == AdapterKind::Rust {
        let Some(backend) = &entry.backend else {
            return "error: Rust worker backend attestation is missing".to_owned();
        };
        if backend.kind != RUST_BACKEND_KIND
            || backend.version != RUST_BACKEND_VERSION
            || backend.revision != RUST_BACKEND_REVISION
            || backend.salsa_version != RUST_BACKEND_SALSA_VERSION
        {
            return "error: Rust worker backend attestation does not match core".to_owned();
        }
        if let Some(reported) = reported_version
            && let Err(error) = verify_rust_release_handshake(
                reported,
                &entry.version,
                &backend.kind,
                &backend.version,
                &backend.revision,
                &backend.salsa_version,
            )
        {
            return format!("error: {error:#}");
        }
    } else if entry.backend.is_some() {
        return format!(
            "error: {} worker unexpectedly declares a Rust backend attestation",
            adapter.name()
        );
    }
    if adapter == AdapterKind::Web {
        let Some(semantic) = &entry.semantic else {
            return "error: Web worker semantic attestation is missing".to_owned();
        };
        if let Err(error) = verify_web_semantic_compatibility(
            &semantic.typescript_version,
            &semantic.capabilities,
            &semantic.runtime_components,
            &semantic.runtime_artifacts,
        ) {
            return format!("error: {error:#}");
        }
        if let Some(reported) = reported_version
            && let Err(error) = verify_web_release_handshake(
                reported,
                &entry.version,
                &semantic.typescript_version,
                &semantic.capabilities,
            )
        {
            return format!("error: {error:#}");
        }
    } else if entry.semantic.is_some() {
        return format!(
            "error: {} worker unexpectedly declares a Web semantic attestation",
            adapter.name()
        );
    }
    if let Some(reported) = reported_version {
        let actual = parse_worker_handshake(reported)
            .map(|(_, version, _)| version)
            .unwrap_or_default();
        if actual != entry.version {
            return format!(
                "error: worker version {actual} does not match release manifest {}",
                entry.version
            );
        }
    }
    let root = manifest_path.parent().unwrap_or(Path::new("."));
    let expected_path = match verify_release_artifact(
        root,
        &entry.path,
        &entry.sha256,
        &format!("{} worker", adapter.name()),
    ) {
        Ok(path) => path,
        Err(error) => return format!("error: {error:#}"),
    };
    let actual_path = artifact
        .canonicalize()
        .unwrap_or_else(|_| artifact.to_path_buf());
    if expected_path != actual_path {
        return format!(
            "error: manifest path {} does not match {}",
            expected_path.display(),
            actual_path.display()
        );
    }
    "verified".to_owned()
}

fn parse_release_manifest(path: &Path) -> Result<ReleaseManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read release manifest {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("invalid release manifest {}", path.display()))
}

fn load_release_manifest() -> Result<Option<(PathBuf, ReleaseManifest)>> {
    let executable =
        std::env::current_exe().context("failed to locate the running depgraph executable")?;
    let parent = executable
        .parent()
        .context("running depgraph executable has no parent directory")?;
    for candidate in [
        parent.join("release-manifest.json"),
        parent.join("../release-manifest.json"),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                return Ok(Some((
                    candidate.clone(),
                    parse_release_manifest(&candidate)?,
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect release manifest candidate {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    Ok(None)
}

fn release_health() -> Result<Option<ReleaseHealth>> {
    let Some((manifest_path, manifest)) = load_release_manifest()? else {
        return Ok(None);
    };
    let root = manifest_path.parent().unwrap_or(Path::new("."));
    let executable =
        std::env::current_exe().context("failed to locate the running depgraph executable")?;
    let query_fixture_integrity = if manifest.query_fixture.path
        != BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH
        || format!("sha256:{}", manifest.query_fixture.sha256)
            != manifest.compatibility.bounded_query.fixture_sha256
    {
        "error: bounded query fixture identity does not match the compatibility contract".to_owned()
    } else {
        artifact_integrity(root, &manifest.query_fixture, None)
    };
    let mut runtime_integrity: BTreeMap<String, String> = manifest
        .project_licenses
        .iter()
        .map(|artifact| {
            (
                format!("project-license:{}", artifact.path),
                artifact_integrity(root, artifact, None),
            )
        })
        .chain(manifest.runtime_artifacts.iter().map(|artifact| {
            (
                artifact.path.clone(),
                artifact_integrity(root, artifact, None),
            )
        }))
        .collect();
    runtime_integrity.insert("bounded-query-contract".to_owned(), query_fixture_integrity);
    let cross_language_contract = cross_language_release_compatibility_contract();
    let cross_language_fixture_integrity = if manifest.cross_language_fixture.path
        != cross_language_contract.fixture_path
        || format!("sha256:{}", manifest.cross_language_fixture.sha256)
            != cross_language_contract.fixture_sha256
    {
        "error: cross-language fixture identity does not match the compatibility contract"
            .to_owned()
    } else {
        artifact_integrity(root, &manifest.cross_language_fixture, None)
    };
    runtime_integrity.insert(
        "cross-language-contract-fixture".to_owned(),
        cross_language_fixture_integrity,
    );
    let declared_cross_language_schemas = manifest
        .cross_language_schemas
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    for expected in cross_language_contract.schemas {
        let integrity = declared_cross_language_schemas
            .get(expected.path.as_str())
            .filter(|artifact| format!("sha256:{}", artifact.sha256) == expected.sha256)
            .map_or_else(
                || "error: missing or incompatible cross-language schema".to_owned(),
                |artifact| artifact_integrity(root, artifact, None),
            );
        runtime_integrity.insert(
            format!("cross-language-schema:{}", expected.path),
            integrity,
        );
    }
    for component in &manifest.runtime_components {
        let key = format!("component:{}@{}", component.name, component.version);
        let integrity = match verify_release_runtime_component(
            root,
            &worker::ReleaseRuntimeComponentAttestation {
                name: &component.name,
                version: &component.version,
                kind: &component.kind,
                root: &component.root,
                entrypoint: component.entrypoint.as_deref(),
                license: &component.license,
                sha256: &component.sha256,
            },
        ) {
            Ok(()) => "verified".to_owned(),
            Err(error) => format!("error: {error:#}"),
        };
        runtime_integrity.insert(key, integrity);
    }
    let compatibility_integrity = verify_release_compatibility(&manifest.compatibility)
        .map(|()| "verified".to_owned())
        .unwrap_or_else(|error| format!("error: {error:#}"));
    Ok(Some(ReleaseHealth {
        version: manifest.release_version,
        target: manifest.target,
        schema_version: manifest.schema_version,
        compatibility: manifest.compatibility,
        compatibility_integrity,
        license_expression: manifest.license_expression,
        core_integrity: artifact_integrity(root, &manifest.core, Some(&executable)),
        schema_integrity: artifact_integrity(root, &manifest.schema, None),
        runtime_integrity,
        runtime_requirements: manifest.runtime_requirements,
    }))
}

pub(crate) fn verify_release_compatibility(
    compatibility: &ReleaseCompatibilityHealth,
) -> Result<()> {
    let expected = release_compatibility_contract();
    if compatibility != &expected {
        anyhow::bail!(
            "release compatibility metadata does not match the core contract: expected {expected:?}, found {compatibility:?}"
        );
    }
    Ok(())
}

fn artifact_integrity(root: &Path, artifact: &ReleaseArtifact, expected: Option<&Path>) -> String {
    let path = match verify_release_artifact(root, &artifact.path, &artifact.sha256, "artifact") {
        Ok(path) => path,
        Err(error) => return format!("error: {error:#}"),
    };
    if let Some(expected) = expected {
        let expected = expected
            .canonicalize()
            .unwrap_or_else(|_| expected.to_path_buf());
        if path != expected {
            return format!(
                "error: manifest path {} does not match {}",
                path.display(),
                expected.display()
            );
        }
    }
    "verified".to_owned()
}

async fn toolchain_versions(
    root: &Path,
    cancellation: &CancellationToken,
) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for (name, command, argument) in [
        ("rust", "rustc", "--version"),
        ("go", "go", "version"),
        ("node", "node", "--version"),
    ] {
        if cancellation.is_cancelled() {
            break;
        }
        let version =
            probe_toolchain_version_with_cancellation(command, argument, root, cancellation)
                .await
                .ok()
                .unwrap_or_else(|| "unavailable".to_owned());
        versions.insert(name.to_owned(), version);
    }
    versions
}

fn doctor_toolchain_remediation(toolchains: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut remediation = BTreeMap::new();
    if toolchains
        .get("rust")
        .is_none_or(|version| !version.starts_with("rustc 1.93.1 "))
    {
        remediation.insert(
            "rust".to_owned(),
            "safe HIR automatically selects an already-installed verified Rust 1.93.1 pair; if it is unavailable, run `rustup toolchain install 1.93.1 --profile minimal --component rust-src`; depgraph never installs or switches toolchains automatically"
                .to_owned(),
        );
    }
    remediation
}

pub fn open_store(path: &Path) -> Result<Store> {
    Store::open(path)
}

pub fn open_store_read_only(path: &Path) -> Result<Store> {
    Store::open_read_only(path)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        path::{Path, PathBuf},
    };

    use super::{
        AdapterKind, DoctorWorkerLocation, FRAMEWORK_BUILD_CONVERTER_ARTIFACT,
        FRAMEWORK_BUILD_GATE_CONTRACT_VERSION, STORE_SCHEMA_VERSION,
        default_doctor_diagnostic_root, doctor_toolchain_remediation, evaluated_worker_health,
        framework_build_capability_contract, parse_release_manifest, parse_worker_handshake,
        preflight_doctor_workers, release_compatibility_contract, suppressed_worker_health,
        verify_release_compatibility, worker,
    };

    fn test_worker_spec(adapter: AdapterKind) -> worker::WorkerSpec {
        let path = PathBuf::from(format!("/tmp/depgraph-{}-worker", adapter.name()));
        worker::WorkerSpec {
            adapter,
            program: OsString::from(&path),
            leading_args: Vec::new(),
            display: path.display().to_string(),
            artifact_path: path,
            runtime_requirement: None,
            expected_version: None,
            release_attested: false,
            attested_rust_sysroot: None,
        }
    }

    #[test]
    fn doctor_explains_the_installed_baseline_path_for_a_newer_host() {
        let newer = BTreeMap::from([(
            "rust".to_owned(),
            "rustc 1.97.1 (8bab26f4f 2026-07-14)".to_owned(),
        )]);
        let remediation = doctor_toolchain_remediation(&newer);
        let rust = remediation.get("rust").expect("Rust remediation");
        assert!(rust.contains("automatically selects"));
        assert!(
            rust.contains("rustup toolchain install 1.93.1 --profile minimal --component rust-src")
        );
        assert!(rust.contains("never installs or switches"));

        let baseline = BTreeMap::from([(
            "rust".to_owned(),
            "rustc 1.93.1 (01f6ddf75 2026-02-11)".to_owned(),
        )]);
        assert!(doctor_toolchain_remediation(&baseline).is_empty());
    }

    #[test]
    fn worker_handshake_requires_an_exact_protocol_token() {
        assert_eq!(
            parse_worker_handshake("depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2)"),
            Some(("depgraph-web-worker", "0.1.0", "1.0"))
        );
        assert_eq!(
            parse_worker_handshake("depgraph-go-worker 0.1.0 (protocol 1.00)"),
            Some(("depgraph-go-worker", "0.1.0", "1.00"))
        );
        assert_eq!(parse_worker_handshake("depgraph-go-worker 0.1.0"), None);
    }

    #[test]
    fn release_compatibility_contract_rejects_drift() {
        let compatible = release_compatibility_contract();
        verify_release_compatibility(&compatible).unwrap();
        assert_eq!(compatible.worker_protocol_version, "1.0");
        assert_eq!(compatible.store_schema_version, STORE_SCHEMA_VERSION);
        assert_eq!(compatible.operation_journal_schema_version, 5);
        assert_eq!(
            compatible.mcp_tool_contract_version,
            "depgraph-mcp-tools-v1"
        );
        assert_eq!(
            compatible.mcp_operation_contract_version,
            "depgraph-operation-v1"
        );
        assert_eq!(compatible.stable_release_version, "0.5.4");
        assert_eq!(compatible.previous_release_version, "0.5.3");
        assert_eq!(compatible.previous_release_store_schema_version, 17);
        assert_eq!(compatible.stable_upgrade_source_version, "0.4.0-rc.6");
        assert_eq!(compatible.stable_upgrade_source_store_schema_version, 13);

        let mut drifted = compatible.clone();
        drifted.store_schema_version += 1;
        assert!(
            verify_release_compatibility(&drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut journal_drifted = compatible.clone();
        journal_drifted.operation_journal_schema_version += 1;
        assert!(verify_release_compatibility(&journal_drifted).is_err());

        let mut mcp_drifted = compatible.clone();
        mcp_drifted.mcp_tool_contract_version = "depgraph-mcp-tools-v2".to_owned();
        assert!(verify_release_compatibility(&mcp_drifted).is_err());

        let mut collector_drifted = compatible.clone();
        collector_drifted.runtime_collector_contract_version = "runtime-collector-v2".to_owned();
        assert!(
            verify_release_compatibility(&collector_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut profile_selection_drifted = compatible.clone();
        profile_selection_drifted
            .profile_selection
            .selection_contract_version = "default-profile-selection-v2".to_owned();
        assert!(
            verify_release_compatibility(&profile_selection_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut framework_build_drifted = compatible;
        framework_build_drifted.framework_build_graph_contract_version =
            "framework-build-graph-v2".to_owned();
        assert!(
            verify_release_compatibility(&framework_build_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut framework_capability_drifted = release_compatibility_contract();
        framework_capability_drifted.framework_build_capabilities[0].observer_version =
            "9.9.9".to_owned();
        assert!(
            verify_release_compatibility(&framework_capability_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut rust_sysroot_drifted = release_compatibility_contract();
        rust_sysroot_drifted.rust_sysroot.toolchain_commit =
            "0000000000000000000000000000000000000000".to_owned();
        assert!(
            verify_release_compatibility(&rust_sysroot_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut query_drifted = release_compatibility_contract();
        query_drifted.bounded_query.result_schema_version = "bounded-query-result-v2".to_owned();
        assert!(
            verify_release_compatibility(&query_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );

        let mut cross_language_drifted = release_compatibility_contract();
        cross_language_drifted.cross_language.capabilities.pop();
        assert!(
            verify_release_compatibility(&cross_language_drifted)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }

    #[test]
    fn framework_build_release_gate_pins_every_dynamic_capability() {
        let capabilities = framework_build_capability_contract();
        assert_eq!(
            capabilities
                .iter()
                .map(|capability| capability.framework.as_str())
                .collect::<Vec<_>>(),
            ["astro", "next", "tanstack-router", "tanstack-start"]
        );
        assert!(capabilities.iter().all(|capability| {
            capability.converter_runtime_artifact == FRAMEWORK_BUILD_CONVERTER_ARTIFACT
                && capability.observer_runtime_artifact.starts_with("libexec/")
                && capability.observer_version.contains('.')
                && (capability.observation_schema.ends_with("-v1")
                    || capability.observation_schema.ends_with("-v2"))
        }));
        assert_eq!(
            release_compatibility_contract().framework_build_gate_contract_version,
            FRAMEWORK_BUILD_GATE_CONTRACT_VERSION
        );
    }

    #[test]
    fn stale_release_manifest_is_an_explicit_parse_error() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("release-manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "release_version": "0.2.0-rc.1",
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "target": "legacy-target",
                "license_expression": "MIT OR Apache-2.0",
                "project_licenses": [],
                "core": {"path": "bin/depgraph", "sha256": "legacy"},
                "schema": {"path": "schemas/depgraph-protocol-v1.schema.json", "sha256": "legacy"},
                "workers": [],
            }))?,
        )?;

        let error = match parse_release_manifest(&manifest_path) {
            Ok(_) => panic!("stale manifest unexpectedly parsed"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(message.contains("invalid release manifest"));
        assert!(message.contains("missing field `compatibility`"));
        Ok(())
    }

    #[test]
    fn late_security_failure_suppresses_every_successful_doctor_probe() {
        let mut visited = Vec::new();
        let preflight = preflight_doctor_workers(
            [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
            |adapter| {
                visited.push(adapter);
                if adapter == AdapterKind::Web {
                    anyhow::bail!("security policy violation: late Web release manifest mismatch");
                }
                Ok(test_worker_spec(adapter))
            },
        );

        assert_eq!(
            visited,
            vec![AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web]
        );
        assert!(preflight.suppress_probes);
        assert_eq!(
            preflight
                .locations
                .iter()
                .filter(|(_, location)| matches!(location, DoctorWorkerLocation::Ready(_)))
                .count(),
            2
        );

        for (adapter, location) in preflight.locations {
            if let DoctorWorkerLocation::Ready(spec) = location {
                let health = suppressed_worker_health(adapter, spec, Path::new("/tmp"));
                assert!(!health.available);
                assert!(health.command.is_some());
                assert!(health.version.is_none());
                assert!(health.protocol.is_none());
                assert!(
                    health.integrity == "development-unverified"
                        || health.integrity.starts_with("error: ")
                );
                assert!(
                    health
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains("probe suppressed"))
                );
            }
        }
    }

    #[test]
    fn worker_artifact_health_is_independent_from_root_confinement_for_every_adapter() {
        let source_root = tempfile::tempdir().expect("source root");
        let unrelated_root = tempfile::tempdir().expect("unrelated root");
        for adapter in [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web] {
            let artifact = source_root
                .path()
                .join(format!("depgraph-{}-worker", adapter.name()));
            std::fs::write(&artifact, b"fixture").expect("worker artifact");
            let spec = worker::WorkerSpec {
                adapter,
                program: OsString::from(&artifact),
                leading_args: Vec::new(),
                display: artifact.display().to_string(),
                artifact_path: artifact,
                runtime_requirement: None,
                expected_version: None,
                release_attested: false,
                attested_rust_sysroot: None,
            };
            let version = format!(
                "depgraph-{}-worker {} (protocol 1.0)",
                adapter.name(),
                env!("CARGO_PKG_VERSION")
            );
            let blocked = evaluated_worker_health(
                adapter,
                spec.clone(),
                source_root.path(),
                Ok(version.clone()),
            );
            let allowed =
                evaluated_worker_health(adapter, spec, unrelated_root.path(), Ok(version));

            assert!(blocked.available);
            assert_eq!(blocked.protocol.as_deref(), Some("1.0"));
            assert!(blocked.error.is_none());
            assert!(!blocked.root_launch_allowed);
            assert!(
                blocked
                    .root_launch_error
                    .as_deref()
                    .is_some_and(|error| error.contains("inside the scan root"))
            );
            assert!(allowed.available);
            assert_eq!(allowed.protocol.as_deref(), Some("1.0"));
            assert!(allowed.root_launch_allowed);
            assert!(allowed.root_launch_error.is_none());
            assert_eq!(blocked.version, allowed.version);
            assert_eq!(blocked.integrity, allowed.integrity);
        }
    }

    #[test]
    fn doctor_diagnostic_root_prefers_the_latest_attempt_and_has_a_cwd_fallback()
    -> anyhow::Result<()> {
        let mut store = depgraph_store::Store::open_in_memory()?;
        let (fallback, fallback_source) = default_doctor_diagnostic_root(&store)?;
        assert_eq!(fallback_source, "current-working-directory");
        assert_eq!(fallback, std::env::current_dir()?.canonicalize()?);

        let root = tempfile::tempdir()?;
        store.start_scan("diagnostic-root", root.path(), false)?;
        let (selected, selected_source) = default_doctor_diagnostic_root(&store)?;
        assert_eq!(selected_source, "latest-attempt");
        assert_eq!(selected, root.path());
        Ok(())
    }

    #[test]
    fn non_security_unavailability_keeps_successful_doctor_probes_enabled() {
        let preflight = preflight_doctor_workers(
            [AdapterKind::Rust, AdapterKind::Go, AdapterKind::Web],
            |adapter| {
                if adapter == AdapterKind::Go {
                    anyhow::bail!("Go worker is unavailable");
                }
                Ok(test_worker_spec(adapter))
            },
        );

        assert!(!preflight.suppress_probes);
        assert_eq!(
            preflight
                .locations
                .iter()
                .filter(|(_, location)| matches!(location, DoctorWorkerLocation::Ready(_)))
                .count(),
            2
        );
        assert!(matches!(
            &preflight.locations[1],
            (AdapterKind::Go, DoctorWorkerLocation::Unavailable(error))
                if error == "Go worker is unavailable"
        ));
    }
}
