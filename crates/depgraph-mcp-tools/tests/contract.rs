use std::num::NonZeroU32;

use depgraph_mcp_tools::{
    AcceptedOperationStatus, AgentBuildOutcome, AgentCapability, AgentChangedSince,
    AgentCompletedSnapshot, AgentCondition, AgentContext, AgentCorrelationDifference,
    AgentCorrelationStatus, AgentCoverage, AgentCurrentSnapshot, AgentCycle, AgentCycleLevel,
    AgentDaemonStatus, AgentDependenciesResponse, AgentDependencyDirection, AgentEdge, AgentError,
    AgentErrorCategory, AgentErrorCode, AgentErrorDetails, AgentEvidence, AgentEvidenceKind,
    AgentExportOutcome, AgentGraphExportFormat, AgentGraphExportResponse, AgentImpact,
    AgentImpactResponse, AgentLocator, AgentNamedSnapshot, AgentNode, AgentNodeSummary,
    AgentOperation, AgentOperationStatus, AgentPathResponse, AgentPathStep, AgentPhase,
    AgentPolicyAnnotation, AgentPolicyApiChange, AgentPolicyEvaluationResponse,
    AgentPolicyViolation, AgentPrecision, AgentQueryRow, AgentRemediation,
    AgentRepositoryInitOutcome, AgentResolutionStatus, AgentResourceLimit, AgentRuntimeOutcome,
    AgentRuntimeValidationResponse, AgentScanOutcome, AgentSite, AgentSnapshot,
    AgentSnapshotDiffResponse, AgentSourcePosition, AgentSourceSpan, AgentUnresolved,
    CommonRequest, ContractBuildError, Cursor, DurableSubmitResult, ErrorEnvelope,
    LogicalRepositoryId, MAX_AGENT_CHANGED_FIELDS, MAX_AGENT_CONDITION_BYTES,
    MAX_AGENT_CORRELATION_REASONS, MAX_AGENT_CYCLE_NODES, MAX_AGENT_PHASES, MAX_AGENT_QUERY_VALUES,
    MAX_PAGE_BYTES, MAX_PAGE_ITEMS, MAX_TASK_TTL_MS, MIN_TASK_TTL_MS, OperationAccepted,
    OperationRecoveryTools, Page, PageByteLimit, PageRequest, PageSize,
    PortableTerminalOutputContract, RepositoryRelativePath, SnapshotId, SnapshotSelector,
    SuccessEnvelope, TASK_POLL_INTERVAL_MS, TaskAccepted, TasksNegotiation, canonical_json_bytes,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::Digest as _;

const OPERATION_ID: &str = "op_0123456789abcdef0123456789abcdef";
const SNAPSHOT_ID: &str =
    "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn parse<T>(value: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().expect("sample scalar must be valid")
}

fn source_span() -> AgentSourceSpan {
    AgentSourceSpan::new(
        parse("src/lib.rs"),
        AgentSourcePosition::new(
            NonZeroU32::new(1).expect("non-zero"),
            NonZeroU32::new(2).expect("non-zero"),
        ),
        AgentSourcePosition::new(
            NonZeroU32::new(3).expect("non-zero"),
            NonZeroU32::new(4).expect("non-zero"),
        ),
    )
    .expect("ordered source span")
}

fn evidence() -> AgentEvidence {
    AgentEvidence::new(
        AgentEvidenceKind::Semantic,
        parse("rust-analyzer"),
        parse("0.0.330"),
        Some(source_span()),
    )
}

fn node() -> AgentNode {
    AgentNode::new(
        parse("node:src"),
        parse("module"),
        parse("repo://src/lib.rs"),
        Some(parse("crate::lib")),
        Some(parse("src/lib.rs")),
    )
}

fn node_summary() -> AgentNodeSummary {
    AgentNodeSummary::new(
        parse("node:src"),
        parse("module"),
        parse("repo://src/lib.rs"),
        parse("crate::lib"),
    )
}

fn query_row() -> AgentQueryRow {
    serde_json::from_value(json!({
        "values":[
            {"kind":"text","value":"node:src"},
            {"kind":"node","node_id":"node:dependency"}
        ]
    }))
    .expect("representative bounded query row")
}

fn runtime_validation() -> AgentRuntimeValidationResponse {
    serde_json::from_value(json!({
        "schema_version":"1.0",
        "profile_match":{"status":"resolved","parent_profile_id":"profile:fixture"},
        "summary":{
            "events":1,
            "resolved_targets":1,
            "external_targets":0,
            "unresolved_targets":0,
            "redacted_values":1
        },
        "events":{
            "items":[{
                "id":"runtime-event:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sequence":1,
                "dependency_kind":"imports",
                "source":{"status":"resolved","node_id":"node:src"},
                "target":{"status":"resolved","node_id":"node:dependency"},
                "count":1
            }],
            "returned_items":1,
            "total_items":1,
            "complete":true
        }
    }))
    .expect("representative runtime validation")
}

fn completed_snapshot() -> AgentCompletedSnapshot {
    serde_json::from_value(json!({
        "snapshot_id": SNAPSHOT_ID,
        "names": ["baseline"],
        "status": "completed",
        "source_kind": "scan",
        "source_attempt_id": "scan:fixture",
        "scan_id": "scan:fixture",
        "runtime_session_ids": [],
        "profile_ids": ["profile:default"],
        "source_revision": "revision-1",
        "created_at": "2026-08-06T00:00:00.000Z",
        "coverage": {
            "profiles": 1,
            "files_discovered": 1,
            "files_analyzed": 1,
            "files_skipped": 0,
            "dependency_sites": 0,
            "resolved": 0,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": []
        }
    }))
    .expect("representative completed snapshot")
}

fn build_outcome() -> AgentBuildOutcome {
    serde_json::from_value(json!({
        "build_id": "build:fixture",
        "status": "completed",
        "project_execution": "executed",
        "project_code_executed": true,
        "isolation_strength": "best_effort",
        "network_isolation": "best_effort",
        "source_non_mutation_guaranteed": false,
        "mutation_diagnostics": ["best_effort_isolation_does_not_prevent_source_mutation"],
        "snapshot_id": SNAPSHOT_ID,
        "host_risk": {
            "human_confirmation_required": true,
            "acknowledgement_is_not_authorization": true,
            "source_mutation_possible": true,
            "network_access_possible": true
        }
    }))
    .expect("representative build outcome")
}

#[test]
fn portable_terminal_output_is_deserialized_only_by_its_originating_tool_contract() {
    let repository_id: LogicalRepositoryId = parse("repo-1");
    let daemon_status: AgentDaemonStatus = serde_json::from_value(json!({
        "schema_version": "depgraph-daemon-v1",
        "phase": "stopped",
        "started_at": "2026-08-08T00:00:00.000Z",
        "stopped_at": "2026-08-08T00:00:01.000Z",
        "debounce_milliseconds": 0,
        "pending_change_count": 0,
        "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
    }))
    .unwrap();
    let envelope = SuccessEnvelope::new(repository_id, None, daemon_status);
    let value = serde_json::to_value(&envelope).unwrap();

    let daemon =
        PortableTerminalOutputContract::for_originating_tool("daemon_start_submit").unwrap();
    let daemon_start = json!({
        "contract_version": "depgraph-mcp-tools-v1",
        "repository_id": "repo-1",
        "result": {"action": "start", "phase": "running"}
    });
    assert!(daemon.deserialize(daemon_start).is_ok());
    assert!(daemon.deserialize(value.clone()).is_err());
    let daemon_stop = PortableTerminalOutputContract::for_originating_tool("daemon_stop").unwrap();
    assert!(
        daemon_stop
            .deserialize(json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repo-1",
                "result": {"action": "stop", "phase": "stopped"}
            }))
            .is_ok()
    );
    assert!(
        daemon_stop
            .deserialize(json!({
                "contract_version": "depgraph-mcp-tools-v1",
                "repository_id": "repo-1",
                "result": {"action": "start", "phase": "running"}
            }))
            .is_err()
    );
    let scan = PortableTerminalOutputContract::for_originating_tool("scan_submit").unwrap();
    let scan_outcome: AgentScanOutcome = serde_json::from_value(json!({
        "scan_id": "scan:fixture",
        "status": "completed",
        "project_code_executed": false,
        "cache": {"hits": 1, "misses": 2},
        "coverage": {
            "profiles": 1,
            "files_discovered": 1,
            "files_analyzed": 1,
            "files_skipped": 0,
            "dependency_sites": 0,
            "resolved": 0,
            "candidates": 0,
            "external": 0,
            "unresolved": 0,
            "unsupported_syntax": 0,
            "project_code_executed": false,
            "completeness": ["syntax-complete"],
            "reasons": []
        }
    }))
    .unwrap();
    assert_eq!(scan_outcome.cache().hits(), 1);
    assert_eq!(scan_outcome.cache().misses(), 2);
    let scan_envelope =
        SuccessEnvelope::new(parse("repo-1"), Some(parse(SNAPSHOT_ID)), scan_outcome);
    assert!(
        scan.deserialize(serde_json::to_value(&scan_envelope).unwrap())
            .is_ok()
    );
    let mut unsafe_scan = serde_json::to_value(&scan_envelope).unwrap();
    unsafe_scan["result"]["project_code_executed"] = json!(true);
    assert!(scan.deserialize(unsafe_scan).is_err());
    let mut snapshotless_scan = serde_json::to_value(&scan_envelope).unwrap();
    snapshotless_scan
        .as_object_mut()
        .unwrap()
        .remove("snapshot_id");
    assert!(scan.deserialize(snapshotless_scan).is_err());

    let runtime_outcome: AgentRuntimeOutcome = serde_json::from_value(json!({
        "import_id":"runtime-import:fixture",
        "session_id":"runtime-session:fixture",
        "snapshot_id":SNAPSHOT_ID,
        "status":"completed",
        "deduplicated":false
    }))
    .unwrap();
    let runtime_envelope =
        SuccessEnvelope::new(parse("repo-1"), Some(parse(SNAPSHOT_ID)), runtime_outcome);
    let runtime =
        PortableTerminalOutputContract::for_originating_tool("runtime_trace_import_submit")
            .unwrap();
    assert!(
        runtime
            .deserialize(serde_json::to_value(&runtime_envelope).unwrap())
            .is_ok()
    );
    let mut mismatched_runtime = serde_json::to_value(&runtime_envelope).unwrap();
    mismatched_runtime["snapshot_id"] = json!(format!("snapshot:sha256:{}", "b".repeat(64)));
    assert!(runtime.deserialize(mismatched_runtime).is_err());
    assert!(
        scan.deserialize(serde_json::to_value(runtime_envelope).unwrap())
            .is_err()
    );

    let mut mismatched_envelope = value;
    mismatched_envelope["snapshot_id"] = json!(SNAPSHOT_ID);
    assert!(daemon.deserialize(mismatched_envelope).is_err());
    let mut unknown_field = serde_json::to_value(&envelope).unwrap();
    unknown_field["result"]["raw_journal_payload"] = json!(true);
    assert!(daemon.deserialize(unknown_field).is_err());
    assert!(daemon.deserialize(json!({"arbitrary": true})).is_err());
}

#[test]
fn resolve_build_outcome_requires_explicit_host_risk_and_enforced_guarantees() {
    let valid = serde_json::to_value(build_outcome()).unwrap();
    let outcome: AgentBuildOutcome = serde_json::from_value(valid.clone()).unwrap();
    assert!(outcome.project_code_executed());
    assert!(!outcome.source_non_mutation_guaranteed());
    assert!(outcome.host_risk().human_confirmation_required());
    assert!(outcome.host_risk().acknowledgement_is_not_authorization());

    let contract = PortableTerminalOutputContract::for_originating_tool("resolve_build_submit")
        .expect("resolve_build_submit has a closed terminal contract");
    let envelope = SuccessEnvelope::new(parse("repo-1"), Some(parse(SNAPSHOT_ID)), outcome);
    assert!(
        contract
            .deserialize(serde_json::to_value(&envelope).unwrap())
            .is_ok()
    );

    let mut mismatched_snapshot = serde_json::to_value(&envelope).unwrap();
    mismatched_snapshot["snapshot_id"] = json!(format!("snapshot:sha256:{}", "b".repeat(64)));
    assert!(contract.deserialize(mismatched_snapshot).is_err());

    let mut false_confirmation = valid.clone();
    false_confirmation["host_risk"]["human_confirmation_required"] = json!(false);
    assert!(serde_json::from_value::<AgentBuildOutcome>(false_confirmation).is_err());

    let mut acknowledgement_as_authority = valid.clone();
    acknowledgement_as_authority["host_risk"]["acknowledgement_is_not_authorization"] =
        json!(false);
    assert!(serde_json::from_value::<AgentBuildOutcome>(acknowledgement_as_authority).is_err());

    let mut false_guarantee = valid.clone();
    false_guarantee["source_non_mutation_guaranteed"] = json!(true);
    assert!(serde_json::from_value::<AgentBuildOutcome>(false_guarantee).is_err());

    let mut missing_best_effort_diagnostic = valid;
    missing_best_effort_diagnostic["mutation_diagnostics"] = json!([]);
    assert!(serde_json::from_value::<AgentBuildOutcome>(missing_best_effort_diagnostic).is_err());
}

#[test]
fn agent_export_outcome_revalidates_its_closed_public_shape() {
    let digest = "a".repeat(64);
    let outcome = AgentExportOutcome::new(
        "artifacts/graph.json",
        AgentGraphExportFormat::Json,
        42,
        &digest,
    )
    .expect("representative file export outcome is valid");
    assert_eq!(
        serde_json::to_value(&outcome).unwrap(),
        json!({
            "output_path": "artifacts/graph.json",
            "format": "json",
            "output_bytes": 42,
            "content_sha256": digest,
        })
    );

    assert!(
        AgentExportOutcome::new(
            "/private/graph.json",
            AgentGraphExportFormat::Json,
            42,
            "a".repeat(64),
        )
        .is_err()
    );
    assert!(
        AgentExportOutcome::new(
            "graph.json",
            AgentGraphExportFormat::Json,
            0,
            "a".repeat(64),
        )
        .is_err()
    );
    assert!(
        AgentExportOutcome::new(
            "graph.json",
            AgentGraphExportFormat::Json,
            42,
            "A".repeat(64),
        )
        .is_err()
    );
    for invalid in [
        json!({"output_path":"../graph.json","format":"json","output_bytes":42,"content_sha256":"a".repeat(64)}),
        json!({"output_path":"graph.json","format":"yaml","output_bytes":42,"content_sha256":"a".repeat(64)}),
        json!({"output_path":"graph.json","format":"json","output_bytes":42,"content_sha256":"a".repeat(64),"temporary_path":"/private/stage"}),
    ] {
        assert!(serde_json::from_value::<AgentExportOutcome>(invalid).is_err());
    }
}

#[test]
fn repository_write_outcome_schemas_match_runtime_invariants() {
    let init = serde_json::to_value(schemars::schema_for!(AgentRepositoryInitOutcome)).unwrap();
    assert_eq!(
        init["properties"]["output_path"]["const"],
        json!(".depgraph.toml")
    );

    let export = serde_json::to_value(schemars::schema_for!(AgentExportOutcome)).unwrap();
    assert_eq!(export["properties"]["output_bytes"]["minimum"], json!(1));
}

#[test]
fn export_file_terminal_output_is_bound_to_its_closed_originating_contract() {
    let outcome = AgentExportOutcome::new(
        "artifacts/graph.json",
        AgentGraphExportFormat::Json,
        42,
        "a".repeat(64),
    )
    .unwrap();
    let envelope = SuccessEnvelope::new(parse("repo-1"), Some(parse(SNAPSHOT_ID)), outcome);
    let contract = PortableTerminalOutputContract::for_originating_tool("export_file")
        .expect("export_file has a closed terminal contract");

    assert!(
        contract
            .deserialize(serde_json::to_value(&envelope).unwrap())
            .is_ok()
    );
    let mut snapshotless = serde_json::to_value(&envelope).unwrap();
    snapshotless.as_object_mut().unwrap().remove("snapshot_id");
    assert!(contract.deserialize(snapshotless).is_err());
    let mut extra = serde_json::to_value(envelope).unwrap();
    extra["result"]["content"] = json!("raw graph must stay private");
    assert!(contract.deserialize(extra).is_err());
}

#[test]
fn repository_init_outcome_contains_only_the_fixed_relative_config_path() {
    let outcome = AgentRepositoryInitOutcome::new(".depgraph.toml").unwrap();
    assert_eq!(
        serde_json::to_value(&outcome).unwrap(),
        json!({"output_path": ".depgraph.toml"})
    );
    assert!(AgentRepositoryInitOutcome::new("nested/.depgraph.toml").is_err());
    assert!(AgentRepositoryInitOutcome::new("/private/.depgraph.toml").is_err());
    assert!(
        serde_json::from_value::<AgentRepositoryInitOutcome>(json!({
            "output_path": ".depgraph.toml",
            "root": "/private/repository"
        }))
        .is_err()
    );
}

fn context() -> AgentContext {
    AgentContext::new(
        parse("repo-1"),
        vec![AgentCapability::Read],
        AgentCurrentSnapshot::available(completed_snapshot()),
    )
    .expect("representative context")
}

fn named_snapshot() -> AgentNamedSnapshot {
    AgentNamedSnapshot::new(
        parse("baseline"),
        parse("2026-08-06T00:00:01.000Z"),
        completed_snapshot(),
    )
}

fn site() -> AgentSite {
    AgentSite::new(
        parse("site:import-1"),
        parse("node:src"),
        parse("import"),
        parse("crate::dependency"),
        AgentResolutionStatus::Resolved,
        parse("profile:default"),
        vec![parse("node:dependency")],
        Some(source_span()),
        vec![evidence()],
    )
    .expect("bounded site")
}

fn edge() -> AgentEdge {
    AgentEdge::new(
        parse("edge:import-1"),
        parse("node:src"),
        parse("node:dependency"),
        parse("imports"),
        AgentPhase::Semantic,
        AgentResolutionStatus::Resolved,
        AgentPrecision::Exact,
        parse("profile:default"),
        Some(parse("site:import-1")),
        Some(parse("cfg(test)")),
        vec![evidence()],
    )
    .expect("bounded edge")
}

#[test]
fn agent_edge_accepts_a_rendered_condition_larger_than_an_agent_label() {
    let values: Vec<Value> = (0..40)
        .map(|index| Value::String(format!("enabled-{index:02}")))
        .collect();
    let condition = depgraph_core::query::render_condition(&json!({
        "op": "in",
        "key": "feature",
        "values": values,
    }));
    assert!(condition.len() > depgraph_mcp_tools::MAX_AGENT_LABEL_BYTES);

    AgentEdge::new_with_condition(
        parse("edge:long-condition"),
        parse("node:src"),
        parse("node:dependency"),
        parse("imports"),
        AgentPhase::Semantic,
        AgentResolutionStatus::Resolved,
        AgentPrecision::Exact,
        parse("profile:default"),
        None,
        Some(parse(&condition)),
        vec![],
    )
    .expect("valid persisted conditions must not be constrained by label length");
}

#[test]
fn agent_condition_enforces_the_routable_utf8_byte_boundary() {
    assert!(AgentCondition::parse("x".repeat(MAX_AGENT_CONDITION_BYTES)).is_ok());
    assert!(AgentCondition::parse("é".repeat(MAX_AGENT_CONDITION_BYTES / 2)).is_ok());
    assert!(AgentCondition::parse("x".repeat(MAX_AGENT_CONDITION_BYTES + 1)).is_err());
    assert!(AgentCondition::parse("feature\u{0085}enabled").is_err());
}

#[test]
fn agent_edge_legacy_constructor_accepts_agent_labels() {
    AgentEdge::new(
        parse("edge:legacy-condition"),
        parse("node:src"),
        parse("node:dependency"),
        parse("imports"),
        AgentPhase::Semantic,
        AgentResolutionStatus::Resolved,
        AgentPrecision::Exact,
        parse("profile:default"),
        None,
        Some(parse("true")),
        vec![],
    )
    .expect("the original AgentLabel constructor remains source-compatible");
}

fn unresolved_site() -> AgentSite {
    AgentSite::new(
        parse("site:unresolved-1"),
        parse("node:src"),
        parse("import"),
        parse("crate::missing"),
        AgentResolutionStatus::Unresolved,
        parse("profile:default"),
        vec![parse("node:dependency")],
        Some(source_span()),
        vec![evidence()],
    )
    .expect("bounded unresolved site")
}

fn dependency_node() -> AgentNode {
    AgentNode::new(
        parse("node:dependency"),
        parse("module"),
        parse("repo://src/dependency.rs"),
        Some(parse("crate::dependency")),
        Some(parse("src/dependency.rs")),
    )
}

fn path_step() -> AgentPathStep {
    AgentPathStep::new(node(), edge(), dependency_node()).expect("connected path step")
}

fn impact() -> AgentImpact {
    AgentImpact::new(node(), 0, parse("node:src"), Vec::new()).expect("sample impact")
}

fn impact_response() -> AgentImpactResponse {
    AgentImpactResponse::new(
        node(),
        true,
        None,
        Page::new(vec![impact()], 1, true, None).expect("sample impact page"),
    )
    .expect("consistent impact response")
}

fn cycle() -> AgentCycle {
    AgentCycle::new(
        AgentCycleLevel::File,
        vec![
            parse("node:src"),
            parse("node:dependency"),
            parse("node:src"),
        ],
    )
    .expect("sample cycle")
}

fn unresolved() -> AgentUnresolved {
    AgentUnresolved::new(
        unresolved_site(),
        vec![AgentPhase::Source, AgentPhase::Semantic],
        Some(parse("profile:default")),
        Some(AgentCorrelationStatus::Unobserved),
        vec![AgentCorrelationDifference::NotObserved],
    )
    .expect("sample unresolved site")
}

fn operation() -> OperationAccepted {
    OperationAccepted::new(parse(OPERATION_ID))
}

fn error() -> AgentError {
    AgentError::new(
        AgentErrorCode::OperationNotReady,
        true,
        AgentRemediation::PollOperation,
        Some(AgentErrorDetails::Operation {
            operation_id: parse(OPERATION_ID),
        }),
    )
}

fn assert_unknown_field_rejected<T>(case: &str, mut value: Value)
where
    T: DeserializeOwned,
{
    value
        .as_object_mut()
        .expect("representative value must be an object")
        .insert("unexpected".to_owned(), Value::Bool(true));
    let error = serde_json::from_value::<T>(value)
        .err()
        .unwrap_or_else(|| panic!("{case} accepted an unknown field"));
    let message = error.to_string();
    assert!(
        message.contains("unknown field") || message.contains("did not match any variant"),
        "{case} failed for the wrong reason: {error}"
    );
}

#[test]
fn serde_rejects_unknown_fields_for_every_object_and_tagged_enum_branch() {
    assert_unknown_field_rejected::<CommonRequest>(
        "CommonRequest",
        json!({"contract_version":"depgraph-mcp-tools-v1","repository_id":"repo-1"}),
    );
    assert_unknown_field_rejected::<SnapshotSelector>(
        "SnapshotSelector::Current",
        json!({"kind":"current"}),
    );
    assert_unknown_field_rejected::<SnapshotSelector>(
        "SnapshotSelector::Name",
        json!({"kind":"name","name":"baseline"}),
    );
    assert_unknown_field_rejected::<SnapshotSelector>(
        "SnapshotSelector::Id",
        json!({"kind":"id","snapshot_id":SNAPSHOT_ID}),
    );
    assert_unknown_field_rejected::<PageRequest>(
        "PageRequest",
        json!({"max_items":100,"max_bytes":1048576}),
    );
    assert_unknown_field_rejected::<AgentSourcePosition>(
        "AgentSourcePosition",
        json!({"line":1,"column":2}),
    );
    assert_unknown_field_rejected::<AgentSourceSpan>(
        "AgentSourceSpan",
        json!({"path":"src/lib.rs","start":{"line":1,"column":2},"end":{"line":3,"column":4}}),
    );
    assert_unknown_field_rejected::<AgentEvidence>(
        "AgentEvidence",
        serde_json::to_value(evidence()).expect("serialize evidence"),
    );
    assert_unknown_field_rejected::<AgentNode>(
        "AgentNode",
        serde_json::to_value(node()).expect("serialize node"),
    );
    assert_unknown_field_rejected::<AgentNodeSummary>(
        "AgentNodeSummary",
        serde_json::to_value(node_summary()).expect("serialize node summary"),
    );
    assert_unknown_field_rejected::<AgentCoverage>(
        "AgentCoverage",
        serde_json::to_value(completed_snapshot()).expect("serialize snapshot")["coverage"].clone(),
    );
    assert_unknown_field_rejected::<AgentCompletedSnapshot>(
        "AgentCompletedSnapshot",
        serde_json::to_value(completed_snapshot()).expect("serialize completed snapshot"),
    );
    assert_unknown_field_rejected::<AgentNamedSnapshot>(
        "AgentNamedSnapshot",
        serde_json::to_value(named_snapshot()).expect("serialize named snapshot"),
    );
    assert_unknown_field_rejected::<AgentContext>(
        "AgentContext",
        serde_json::to_value(context()).expect("serialize context"),
    );
    assert_unknown_field_rejected::<AgentSite>(
        "AgentSite",
        serde_json::to_value(site()).expect("serialize site"),
    );
    assert_unknown_field_rejected::<AgentEdge>(
        "AgentEdge",
        serde_json::to_value(edge()).expect("serialize edge"),
    );
    assert_unknown_field_rejected::<AgentPathStep>(
        "AgentPathStep",
        serde_json::to_value(path_step()).expect("serialize path step"),
    );
    assert_unknown_field_rejected::<AgentDependenciesResponse>(
        "AgentDependenciesResponse",
        serde_json::to_value(
            AgentDependenciesResponse::new(
                node(),
                AgentDependencyDirection::Outgoing,
                false,
                true,
                1,
                Page::new(vec![edge()], 1, true, None).expect("complete dependency page"),
            )
            .expect("dependency response"),
        )
        .expect("serialize dependency response"),
    );
    assert_unknown_field_rejected::<AgentPathResponse>(
        "AgentPathResponse",
        serde_json::to_value(
            AgentPathResponse::new(node(), dependency_node(), true, 1, vec![path_step()])
                .expect("path response"),
        )
        .expect("serialize path response"),
    );
    assert_unknown_field_rejected::<AgentImpact>(
        "AgentImpact",
        serde_json::to_value(impact()).expect("serialize impact"),
    );
    assert_unknown_field_rejected::<AgentImpactResponse>(
        "AgentImpactResponse",
        serde_json::to_value(impact_response()).expect("serialize impact response"),
    );
    assert_unknown_field_rejected::<AgentCycle>(
        "AgentCycle",
        serde_json::to_value(cycle()).expect("serialize cycle"),
    );
    assert_unknown_field_rejected::<AgentUnresolved>(
        "AgentUnresolved",
        serde_json::to_value(unresolved()).expect("serialize unresolved"),
    );
    assert_unknown_field_rejected::<AgentChangedSince>(
        "AgentChangedSince",
        json!({
            "requested_ref":"HEAD",
            "resolved_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "merge_base":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "head":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "changed_paths":1,
            "mapped_nodes":1
        }),
    );
    assert_unknown_field_rejected::<AgentSnapshot>(
        "AgentSnapshot::Available",
        json!({"availability":"available","snapshot_id":SNAPSHOT_ID,"name":"baseline"}),
    );
    assert_unknown_field_rejected::<AgentSnapshot>(
        "AgentSnapshot::Unavailable",
        json!({"availability":"unavailable"}),
    );
    assert_unknown_field_rejected::<Page<AgentNode>>(
        "Page<AgentNode>",
        json!({"items":[],"returned_items":0,"total_items":0,"complete":true}),
    );
    assert_unknown_field_rejected::<SuccessEnvelope<AgentNode>>(
        "SuccessEnvelope<AgentNode>",
        json!({"contract_version":"depgraph-mcp-tools-v1","repository_id":"repo-1","snapshot_id":SNAPSHOT_ID,"result":serde_json::to_value(node()).expect("serialize node")}),
    );
    assert_unknown_field_rejected::<AgentErrorDetails>(
        "AgentErrorDetails::RequiredCapability",
        json!({"kind":"required_capability","capability":"read"}),
    );
    assert_unknown_field_rejected::<AgentErrorDetails>(
        "AgentErrorDetails::ResourceLimit",
        json!({"kind":"resource_limit","limit":"page_items","maximum":1000}),
    );
    assert_unknown_field_rejected::<AgentErrorDetails>(
        "AgentErrorDetails::Operation",
        json!({"kind":"operation","operation_id":OPERATION_ID}),
    );
    assert_unknown_field_rejected::<AgentError>(
        "AgentError",
        serde_json::to_value(error()).expect("serialize error"),
    );
    assert_unknown_field_rejected::<ErrorEnvelope>(
        "ErrorEnvelope",
        serde_json::to_value(ErrorEnvelope::new(parse("repo-1"), error()))
            .expect("serialize error envelope"),
    );
    assert_unknown_field_rejected::<OperationRecoveryTools>(
        "OperationRecoveryTools",
        json!({"status":"operation_get","result":"operation_result","cancel":"operation_cancel"}),
    );
    assert_unknown_field_rejected::<OperationAccepted>(
        "OperationAccepted",
        serde_json::to_value(operation()).expect("serialize operation"),
    );
    assert_unknown_field_rejected::<TaskAccepted>(
        "TaskAccepted",
        json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1700000000000_u64,"updatedAtMs":1700000000100_u64,"pollIntervalMs":TASK_POLL_INTERVAL_MS,"ttlMs":MIN_TASK_TTL_MS}),
    );
    assert_unknown_field_rejected::<DurableSubmitResult>(
        "DurableSubmitResult::Baseline",
        serde_json::to_value(operation()).expect("serialize operation"),
    );
    assert_unknown_field_rejected::<DurableSubmitResult>(
        "DurableSubmitResult::Task",
        json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1700000000000_u64,"updatedAtMs":1700000000100_u64,"pollIntervalMs":TASK_POLL_INTERVAL_MS,"ttlMs":MIN_TASK_TTL_MS}),
    );
}

#[test]
fn dependency_and_path_contracts_validate_topology_and_completion_state() {
    let dependency_page = Page::new(vec![edge()], 1, true, None).expect("complete edge page");
    let response = AgentDependenciesResponse::new(
        node(),
        AgentDependencyDirection::Outgoing,
        false,
        true,
        1,
        dependency_page,
    )
    .expect("consistent dependencies response");
    let value = serde_json::to_value(response).expect("serialize response");
    assert_eq!(
        value,
        json!({
            "root": serde_json::to_value(node()).expect("root"),
            "direction": "outgoing",
            "transitive": false,
            "traversal_complete": true,
            "traversed_edges": 1,
            "edges": {
                "items": [serde_json::to_value(edge()).expect("edge")],
                "returned_items": 1,
                "total_items": 1,
                "complete": true
            }
        })
    );

    let found = AgentPathResponse::new(node(), dependency_node(), true, 1, vec![path_step()])
        .expect("connected found path");
    assert_eq!(
        serde_json::to_value(found).expect("serialize path")["path_found"],
        true
    );
    assert!(
        AgentPathResponse::new(node(), dependency_node(), false, 1, vec![path_step()]).is_err(),
        "an unreachable response must never contain partial path steps"
    );
    assert!(
        AgentPathResponse::new(node(), dependency_node(), true, 1, Vec::new()).is_err(),
        "different endpoints require a non-empty found path"
    );

    let wrong_target = AgentNode::new(
        parse("node:wrong"),
        parse("module"),
        parse("repo://src/wrong.rs"),
        None,
        None,
    );
    assert!(AgentPathStep::new(node(), edge(), wrong_target).is_err());
}

#[test]
fn issue_303_closed_results_reject_unknown_enums_and_unbounded_shapes() {
    assert_eq!(
        AgentImpact::new(node(), 0, parse("node:dependency"), Vec::new()),
        Err(ContractBuildError::PathTopology)
    );
    assert_eq!(
        AgentImpactResponse::new(
            node(),
            true,
            None,
            Page::new(Vec::new(), 0, true, None).expect("empty page"),
        ),
        Err(ContractBuildError::ImpactState)
    );
    assert_eq!(
        AgentUnresolved::new(
            unresolved_site(),
            Vec::new(),
            None,
            Some(AgentCorrelationStatus::Unobserved),
            Vec::new(),
        ),
        Err(ContractBuildError::UnresolvedState)
    );
    assert!(
        serde_json::from_value::<AgentCycle>(json!({
            "level":"directory",
            "node_ids":["node:src","node:src"]
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AgentCycle>(json!({
            "level":"file",
            "node_ids":["node:src","node:dependency"]
        }))
        .is_err(),
        "a cycle must close at its starting node"
    );
    assert_eq!(
        AgentCycle::new(
            AgentCycleLevel::File,
            vec![parse("node:src"), parse("node:dependency")]
        ),
        Err(ContractBuildError::CycleTopology)
    );
    assert_eq!(
        AgentCycle::new(
            AgentCycleLevel::File,
            vec![parse("node:src"); MAX_AGENT_CYCLE_NODES + 1]
        ),
        Err(ContractBuildError::TooManyCycleNodes)
    );

    let unresolved_value = serde_json::to_value(unresolved()).expect("serialize unresolved");
    let mut invalid_status = unresolved_value.clone();
    invalid_status["correlation_status"] = json!("maybe");
    assert!(serde_json::from_value::<AgentUnresolved>(invalid_status).is_err());
    let mut invalid_reason = unresolved_value;
    invalid_reason["observed_difference_reasons"] = json!(["private_reason"]);
    assert!(serde_json::from_value::<AgentUnresolved>(invalid_reason).is_err());
    assert_eq!(
        AgentUnresolved::new(
            site(),
            Vec::new(),
            None,
            None,
            vec![AgentCorrelationDifference::NotObserved; MAX_AGENT_CORRELATION_REASONS + 1],
        ),
        Err(ContractBuildError::TooManyCorrelationReasons)
    );
    assert!(
        AgentUnresolved::new(
            unresolved_site(),
            vec![AgentPhase::Source; MAX_AGENT_PHASES],
            None,
            None,
            Vec::new(),
        )
        .is_ok()
    );
    assert_eq!(
        AgentUnresolved::new(
            unresolved_site(),
            vec![AgentPhase::Source; MAX_AGENT_PHASES + 1],
            None,
            None,
            Vec::new(),
        ),
        Err(ContractBuildError::TooManyPhases)
    );
}

#[test]
fn issue_304_query_and_runtime_dtos_reject_forged_shapes_and_counts() {
    assert!(serde_json::from_value::<AgentQueryRow>(json!({"values":[]})).is_err());
    let too_wide = json!({
        "values": (0..=MAX_AGENT_QUERY_VALUES)
            .map(|_| json!({"kind":"null"}))
            .collect::<Vec<_>>()
    });
    assert!(serde_json::from_value::<AgentQueryRow>(too_wide).is_err());
    assert!(
        serde_json::from_value::<AgentQueryRow>(json!({
            "values":[{
                "kind":"path",
                "path_id":"query-path:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "depth":2,
                "direction":"forward",
                "node_ids":["node:a","node:b"],
                "edge_ids":["edge:a"]
            }]
        }))
        .is_err()
    );

    let valid = json!({
        "schema_version":"1.0",
        "profile_match":{"status":"resolved","parent_profile_id":"profile:fixture"},
        "summary":{
            "events":1,
            "resolved_targets":1,
            "external_targets":0,
            "unresolved_targets":0,
            "redacted_values":1
        },
        "events":{
            "items":[{
                "id":"runtime-event:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sequence":1,
                "dependency_kind":"imports",
                "source":{"status":"resolved","node_id":"node:a"},
                "target":{"status":"resolved","node_id":"node:b"},
                "count":1
            }],
            "returned_items":1,
            "total_items":1,
            "complete":true
        }
    });
    assert!(serde_json::from_value::<AgentRuntimeValidationResponse>(valid.clone()).is_ok());

    let mut missing_resolved_node = valid.clone();
    missing_resolved_node["events"]["items"][0]["target"] = json!({"status":"resolved"});
    assert!(
        serde_json::from_value::<AgentRuntimeValidationResponse>(missing_resolved_node).is_err()
    );
    let mut unresolved_with_node = valid.clone();
    unresolved_with_node["events"]["items"][0]["target"] =
        json!({"status":"unresolved","node_id":"node:b"});
    assert!(
        serde_json::from_value::<AgentRuntimeValidationResponse>(unresolved_with_node).is_err()
    );
    let mut summary_mismatch = valid.clone();
    summary_mismatch["summary"]["resolved_targets"] = json!(0);
    assert!(serde_json::from_value::<AgentRuntimeValidationResponse>(summary_mismatch).is_err());
    let mut page_mismatch = valid;
    page_mismatch["summary"]["events"] = json!(2);
    assert!(serde_json::from_value::<AgentRuntimeValidationResponse>(page_mismatch).is_err());
}

#[test]
fn issue_305_artifact_dtos_reject_unbounded_or_forged_wire_values() {
    let digest = "a".repeat(64);
    let snapshot_diff = json!({
        "schema_version":"depgraph-snapshot-diff-service-v1",
        "from_snapshot_id":SNAPSHOT_ID,
        "to_snapshot_id":SNAPSHOT_ID,
        "total_changes":0,
        "empty":true,
        "changes":[],
        "collection_digest":format!("snapshot-diff-collection:sha256:{digest}")
    });
    assert!(serde_json::from_value::<AgentSnapshotDiffResponse>(snapshot_diff.clone()).is_ok());
    for (field, value) in [
        ("schema_version", json!("1.0")),
        (
            "from_snapshot_id",
            json!(format!("snapshot:sha256:{}", "A".repeat(64))),
        ),
        ("collection_digest", json!(digest.clone())),
    ] {
        let mut invalid = snapshot_diff.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<AgentSnapshotDiffResponse>(invalid).is_err(),
            "snapshot diff accepted invalid {field}"
        );
    }
    let mut oversized_fields = snapshot_diff.clone();
    oversized_fields["total_changes"] = json!(1);
    oversized_fields["empty"] = json!(false);
    oversized_fields["changes"] = json!([{
        "record_type":"node",
        "change_type":"changed",
        "id":"node:a",
        "changed_fields":(0..=MAX_AGENT_CHANGED_FIELDS)
            .map(|index| format!("field_{index:03}"))
            .collect::<Vec<_>>()
    }]);
    assert!(
        serde_json::from_value::<AgentSnapshotDiffResponse>(oversized_fields).is_err(),
        "snapshot diff accepted an oversized changed_fields vector"
    );

    let policy = json!({
        "from_snapshot_id":SNAPSHOT_ID,
        "to_snapshot_id":SNAPSHOT_ID,
        "result_id":format!("policy-evaluation:sha256:{digest}"),
        "policy_config_digest":format!("policy-config:sha256:{digest}"),
        "passed":true,
        "exit_code":0,
        "api_changes":[],
        "violations":[],
        "annotations":[],
        "summary":{"errors":0,"warnings":0,"suppressed":0},
        "collection_digest":format!("policy-evaluation-collection:sha256:{digest}")
    });
    assert!(serde_json::from_value::<AgentPolicyEvaluationResponse>(policy.clone()).is_ok());
    for (field, value) in [
        (
            "result_id",
            json!(format!("policy-evaluation:sha256:{}", "0".repeat(63))),
        ),
        (
            "policy_config_digest",
            json!(format!("other:sha256:{digest}")),
        ),
        ("exit_code", json!(2)),
    ] {
        let mut invalid = policy.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<AgentPolicyEvaluationResponse>(invalid).is_err(),
            "policy response accepted invalid {field}"
        );
    }
    assert!(
        serde_json::from_value::<AgentPolicyViolation>(json!({
            "id":format!("policy-violation:sha256:{digest}"),
            "rule_id":"rule-a",
            "severity":"fatal",
            "message":"bounded message",
            "source_id":"node:a",
            "target_id":"node:b",
            "suppressed":false
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<AgentPolicyApiChange>(json!({
            "id":format!("policy-api-change:sha256:{digest}"),
            "rule_id":"rule-a",
            "kind":"added",
            "breaking":true,
            "changed_fields":[],
            "after_id":"node:b"
        }))
        .is_err(),
        "compatible addition accepted a forged breaking flag"
    );
    assert!(
        serde_json::from_value::<AgentPolicyAnnotation>(json!({
            "violation_id":format!("policy-violation:sha256:{digest}"),
            "rule_id":"rule-a",
            "level":"warning",
            "path":"../private.rs",
            "start_line":1,
            "start_column":1,
            "end_line":1,
            "end_column":2,
            "title":"policy warning",
            "message":"bounded message"
        }))
        .is_err()
    );

    let content = "{}";
    let content_digest = format!("{:x}", sha2::Sha256::digest(content.as_bytes()));
    let graph_export = json!({
        "schema_version":"depgraph-graph-export-service-v1",
        "snapshot_id":SNAPSHOT_ID,
        "format":"json",
        "media_type":"application/json",
        "content":content,
        "content_sha256":content_digest,
        "output_bytes":2,
        "node_count":0,
        "edge_count":0
    });
    assert!(serde_json::from_value::<AgentGraphExportResponse>(graph_export.clone()).is_ok());
    for (field, value) in [
        ("media_type", json!("text/vnd.graphviz")),
        ("content_sha256", json!(digest)),
        ("output_bytes", json!(3)),
        ("node_count", json!(50_001)),
    ] {
        let mut invalid = graph_export.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<AgentGraphExportResponse>(invalid).is_err(),
            "graph export accepted invalid {field}"
        );
    }
}

#[test]
fn issue_300_public_node_projection_has_exactly_four_fields() {
    let value = serde_json::to_value(node_summary()).expect("serialize node summary");
    let mut fields = value
        .as_object()
        .expect("node summary is an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, ["display_name", "id", "kind", "locator"]);
    assert!(value.get("properties").is_none());
    assert!(value.get("path").is_none());
    assert!(value.get("repository_path").is_none());
}

#[test]
fn issue_300_current_snapshot_unavailable_is_a_success_shape() {
    let value = serde_json::to_value(
        AgentContext::new(
            parse("repo-1"),
            vec![AgentCapability::Read],
            AgentCurrentSnapshot::unavailable(),
        )
        .expect("empty context"),
    )
    .expect("serialize context");
    assert_eq!(value["snapshot"], json!({"available": false}));
    assert!(value.to_string().find('/').is_none());
}

#[test]
fn closed_dto_prohibition_corpus_rejects_arbitrary_and_sensitive_fields() {
    for forbidden in [
        json!({"metadata":{"owner":"agent"}}),
        json!({"properties":{"arbitrary":true}}),
        json!({"root":"/checkout"}),
        json!({"store_path":"/var/lib/depgraph/store"}),
    ] {
        let mut value = serde_json::to_value(node()).expect("serialize node");
        value
            .as_object_mut()
            .expect("node object")
            .extend(forbidden.as_object().expect("forbidden object").clone());
        assert!(
            serde_json::from_value::<AgentNode>(value).is_err(),
            "AgentNode accepted forbidden field {forbidden}"
        );
    }

    for field in ["detail", "raw", "raw_evidence_detail", "stderr"] {
        let mut value = serde_json::to_value(evidence()).expect("serialize evidence");
        value
            .as_object_mut()
            .expect("evidence object")
            .insert(field.to_owned(), json!("raw compiler output"));
        assert!(
            serde_json::from_value::<AgentEvidence>(value).is_err(),
            "AgentEvidence accepted forbidden field {field}"
        );
    }
}

#[test]
fn agent_locator_is_a_repository_relative_locator_not_an_absolute_path_escape_hatch() {
    assert_eq!(
        AgentLocator::parse("repo://src/lib.rs")
            .expect("repository-relative locator")
            .as_str(),
        "repo://src/lib.rs"
    );
    assert!(AgentLocator::parse("crate::dependency").is_ok());
    assert!(AgentLocator::parse("@scope/package").is_ok());

    for invalid in [
        "repo:///Users/alice/private",
        "repo://../private",
        "repo://C:/Windows/win.ini",
        "custom:/absolute/path",
        "custom:C:/Windows/win.ini",
        "custom:C:\\Windows\\win.ini",
        "custom://server/share",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "C:secret",
        "custom:C:secret",
        "//server/share",
        "\\\\server\\share",
        "custom:file:/etc/passwd",
        "file:src/lib.rs",
        "opaque\nsecret",
        "repo://src\tsecret/lib.rs",
    ] {
        assert!(
            AgentLocator::parse(invalid).is_err(),
            "AgentLocator accepted non-portable locator {invalid:?}"
        );
        assert!(
            serde_json::from_value::<AgentLocator>(json!(invalid)).is_err(),
            "AgentLocator Serde accepted non-portable locator {invalid:?}"
        );
    }
}

#[test]
fn option_a_negotiation_preserves_baseline_and_uses_one_identity() {
    let accepted = operation();
    let baseline = DurableSubmitResult::negotiated(
        accepted.clone(),
        TasksNegotiation::Baseline,
        0,
        u64::MAX,
        0,
    )
    .expect("baseline does not require task timing");
    assert!(matches!(baseline, DurableSubmitResult::Baseline(_)));
    assert_eq!(baseline.operation_id().as_str(), OPERATION_ID);

    let task = DurableSubmitResult::negotiated(
        accepted,
        TasksNegotiation::Tasks,
        1_700_000_000_000,
        1_700_000_000_100,
        MIN_TASK_TTL_MS,
    )
    .expect("valid task timing");
    let DurableSubmitResult::Task(task) = task else {
        panic!("Tasks negotiation returned the baseline branch");
    };
    assert_eq!(task.task_id().as_str(), OPERATION_ID);
    assert_eq!(task.operation_id().as_str(), OPERATION_ID);
    assert_eq!(task.created_at_ms(), 1_700_000_000_000);
    assert_eq!(task.updated_at_ms(), 1_700_000_000_100);
    assert_eq!(task.ttl_ms(), MIN_TASK_TTL_MS);

    let recovery = operation().recovery().clone();
    assert_eq!(
        recovery.status(),
        depgraph_mcp_tools::BaselineOperationTool::OperationGet
    );
    assert_eq!(
        recovery.result(),
        depgraph_mcp_tools::BaselineOperationTool::OperationResult
    );
    assert_eq!(
        recovery.cancel(),
        depgraph_mcp_tools::BaselineOperationTool::OperationCancel
    );
}

#[test]
fn operation_and_task_wire_invariants_fail_closed() {
    let mut baseline = serde_json::to_value(operation()).expect("serialize operation");
    baseline["status"] = json!("working");
    assert!(serde_json::from_value::<OperationAccepted>(baseline).is_err());

    let mut recovery = serde_json::to_value(operation()).expect("serialize operation");
    recovery["recovery"]["status"] = json!("operation_result");
    assert!(serde_json::from_value::<OperationAccepted>(recovery).is_err());

    let valid_task = json!({"resultType":"task","taskId":OPERATION_ID,"status":"working","createdAtMs":1000,"updatedAtMs":1001,"pollIntervalMs":TASK_POLL_INTERVAL_MS,"ttlMs":MIN_TASK_TTL_MS});
    assert!(serde_json::from_value::<TaskAccepted>(valid_task.clone()).is_ok());
    for invalid in [
        ("pollIntervalMs", json!(TASK_POLL_INTERVAL_MS + 1)),
        ("ttlMs", json!(MIN_TASK_TTL_MS - 1)),
        ("ttlMs", json!(MAX_TASK_TTL_MS + 1)),
        ("updatedAtMs", json!(999)),
        ("updatedAtMs", json!(1000 + MIN_TASK_TTL_MS + 1)),
    ] {
        let mut task = valid_task.clone();
        task[invalid.0] = invalid.1;
        assert!(
            serde_json::from_value::<TaskAccepted>(task).is_err(),
            "TaskAccepted accepted invalid {}",
            invalid.0
        );
    }
}

#[test]
fn agent_operation_is_closed_and_validates_status_progress_and_timestamps() {
    let valid = json!({
        "operation_id": OPERATION_ID,
        "status": "running",
        "progress": {"completed_units": 2, "total_units": 4},
        "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1100},
        "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
    });
    let operation = serde_json::from_value::<AgentOperation>(valid.clone()).unwrap();
    assert_eq!(operation.operation_id().as_str(), OPERATION_ID);
    assert_eq!(operation.status(), AgentOperationStatus::Running);
    assert_eq!(operation.progress().completed_units(), 2);
    assert_eq!(operation.progress().total_units(), 4);
    assert_eq!(operation.timestamps().created_at_ms(), 1000);
    assert_eq!(operation.timestamps().updated_at_ms(), 1100);
    assert_eq!(operation.timestamps().terminal_at_ms(), None);
    assert_eq!(operation.retention().execution_deadline_ms(), 2000);
    assert_eq!(operation.retention().retain_until_ms(), 3000);

    let mut unknown = valid.clone();
    unknown["journal"] = json!({"lease": "must-not-be-public"});
    assert!(serde_json::from_value::<AgentOperation>(unknown).is_err());

    for invalid in [
        json!({
            "operation_id": OPERATION_ID,
            "status": "completed",
            "progress": {"completed_units": 3, "total_units": 4},
            "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1100, "terminal_at_ms": 1100},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }),
        json!({
            "operation_id": OPERATION_ID,
            "status": "failed",
            "progress": {"completed_units": 2, "total_units": 4},
            "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1100},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }),
        json!({
            "operation_id": OPERATION_ID,
            "status": "running",
            "progress": {"completed_units": 2, "total_units": 4},
            "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1100, "terminal_at_ms": 1100},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }),
        json!({
            "operation_id": OPERATION_ID,
            "status": "running",
            "progress": {"completed_units": 5, "total_units": 4},
            "timestamps": {"created_at_ms": 1000, "updated_at_ms": 1100},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }),
        json!({
            "operation_id": OPERATION_ID,
            "status": "running",
            "progress": {"completed_units": 2, "total_units": 4},
            "timestamps": {"created_at_ms": 1200, "updated_at_ms": 1100},
            "retention": {"execution_deadline_ms": 2000, "retain_until_ms": 3000}
        }),
    ] {
        assert!(serde_json::from_value::<AgentOperation>(invalid).is_err());
    }
}

#[test]
fn typed_error_category_is_derived_and_deserialization_cannot_forge_it() {
    let cases = [
        (AgentErrorCode::InvalidArgument, AgentErrorCategory::Input),
        (
            AgentErrorCode::InvalidRepositoryPath,
            AgentErrorCategory::Input,
        ),
        (
            AgentErrorCode::SnapshotNotFound,
            AgentErrorCategory::NotFound,
        ),
        (AgentErrorCode::SnapshotMismatch, AgentErrorCategory::Input),
        (
            AgentErrorCode::SnapshotWorktreeMismatch,
            AgentErrorCategory::Input,
        ),
        (AgentErrorCode::QueryRejected, AgentErrorCategory::Resource),
        (AgentErrorCode::CursorInvalid, AgentErrorCategory::Input),
        (AgentErrorCode::CursorMismatch, AgentErrorCategory::Input),
        (
            AgentErrorCode::CapabilityDenied,
            AgentErrorCategory::Authorization,
        ),
        (AgentErrorCode::NotFound, AgentErrorCategory::NotFound),
        (AgentErrorCode::Conflict, AgentErrorCategory::Conflict),
        (
            AgentErrorCode::ResourceExhausted,
            AgentErrorCategory::Resource,
        ),
        (AgentErrorCode::OperationNotReady, AgentErrorCategory::State),
        (
            AgentErrorCode::IdempotencyConflict,
            AgentErrorCategory::Conflict,
        ),
        (AgentErrorCode::Cancelled, AgentErrorCategory::Cancelled),
        (
            AgentErrorCode::IntegrityFailure,
            AgentErrorCategory::Integrity,
        ),
        (AgentErrorCode::Internal, AgentErrorCategory::Internal),
    ];
    for (code, category) in cases {
        assert_eq!(code.category(), category);
        assert_eq!(
            AgentError::new(code, false, AgentRemediation::ContactOperator, None).category(),
            category
        );
    }

    let mut forged = serde_json::to_value(error()).expect("serialize error");
    forged["category"] = json!("internal");
    assert!(serde_json::from_value::<AgentError>(forged).is_err());

    let details = [
        AgentErrorDetails::RequiredCapability {
            capability: AgentCapability::RepositoryWrite,
        },
        AgentErrorDetails::ResourceLimit {
            limit: AgentResourceLimit::PageItems,
            maximum: u64::from(MAX_PAGE_ITEMS),
        },
        AgentErrorDetails::Operation {
            operation_id: parse(OPERATION_ID),
        },
    ];
    for detail in details {
        let round_trip = serde_json::from_value::<AgentErrorDetails>(
            serde_json::to_value(&detail).expect("serialize typed details"),
        )
        .expect("deserialize typed details");
        assert_eq!(round_trip, detail);
    }
}

#[test]
fn page_bounds_counts_and_cursor_invariants_fail_closed() {
    assert_eq!(PageSize::default().get(), 100);
    assert_eq!(PageByteLimit::default().get(), 1_048_576);
    assert_eq!(PageSize::new(1).expect("minimum").get(), 1);
    assert_eq!(
        PageSize::new(MAX_PAGE_ITEMS).expect("maximum").get(),
        MAX_PAGE_ITEMS
    );
    assert_eq!(PageSize::new(0), Err(ContractBuildError::PageSize));
    assert_eq!(
        PageSize::new(MAX_PAGE_ITEMS + 1),
        Err(ContractBuildError::PageSize)
    );
    assert_eq!(
        PageByteLimit::new(0),
        Err(ContractBuildError::PageByteLimit)
    );
    assert_eq!(
        PageByteLimit::new(MAX_PAGE_BYTES + 1),
        Err(ContractBuildError::PageByteLimit)
    );

    let maximum = vec![(); usize::from(MAX_PAGE_ITEMS)];
    assert_eq!(
        Page::new(maximum, u64::from(MAX_PAGE_ITEMS), true, None)
            .expect("maximum page")
            .returned_items(),
        MAX_PAGE_ITEMS
    );
    assert_eq!(
        Page::new(vec![(); usize::from(MAX_PAGE_ITEMS) + 1], 2_000, true, None),
        Err(ContractBuildError::TooManyPageItems)
    );
    assert_eq!(
        Page::new(vec![(), ()], 1, true, None),
        Err(ContractBuildError::PageTotal)
    );
    assert_eq!(
        Page::<()>::new(vec![], 0, true, Some(parse("next"))),
        Err(ContractBuildError::CompletePageCursor)
    );
    assert_eq!(
        Page::<()>::new(vec![], 1, false, None),
        Err(ContractBuildError::IncompletePageCursor)
    );
    assert_eq!(
        Page::<()>::new(vec![], 1, false, Some(parse("next")))
            .expect("incomplete page with cursor")
            .next_cursor()
            .expect("continuation cursor")
            .as_str(),
        "next"
    );

    let count_mismatch = json!({"items":[null],"returned_items":0,"total_items":1,"complete":true});
    assert!(serde_json::from_value::<Page<()>>(count_mismatch).is_err());
    let complete_cursor =
        json!({"items":[],"returned_items":0,"total_items":1,"complete":true,"next_cursor":"next"});
    assert!(serde_json::from_value::<Page<()>>(complete_cursor).is_err());
    let incomplete_without_cursor =
        json!({"items":[],"returned_items":0,"total_items":1,"complete":false});
    assert!(serde_json::from_value::<Page<()>>(incomplete_without_cursor).is_err());

    let request = PageRequest::new(
        PageSize::new(25).expect("page size"),
        PageByteLimit::new(4_096).expect("page bytes"),
        Some(parse("cursor_1~part-2")),
    );
    assert_eq!(request.max_items().get(), 25);
    assert_eq!(request.max_bytes().get(), 4_096);
    assert_eq!(
        request.cursor().expect("cursor").as_str(),
        "cursor_1~part-2"
    );
    for invalid in ["", "has/slash", "has=padding", "white space"] {
        assert!(
            Cursor::parse(invalid).is_err(),
            "cursor {invalid:?} was accepted"
        );
    }
}

#[test]
fn repository_paths_reject_non_portable_and_escaping_forms() {
    for valid in ["src/lib.rs", ".git/config", "console", "com10.log"] {
        assert!(
            RepositoryRelativePath::parse(valid).is_ok(),
            "portable path {valid:?} was rejected"
        );
    }
    let invalid = [
        ("POSIX absolute", "/etc/passwd"),
        ("dot traversal", "./src/lib.rs"),
        ("parent traversal", "src/../secret"),
        ("bare parent", ".."),
        ("backslash", r"src\lib.rs"),
        ("Windows drive absolute", "C:/Windows/win.ini"),
        ("Windows drive relative", "C:Windows/win.ini"),
        ("Windows drive backslash", r"C:\Windows\win.ini"),
        ("UNC", r"\\server\share\file"),
        ("verbatim UNC", r"\\?\UNC\server\share\file"),
        ("ADS", "public.txt:private"),
        ("nested ADS", "nested/public.txt:private"),
        ("reserved CON", "CON"),
        ("reserved NUL extension", "nested/nul.txt"),
        ("reserved COM", "nested/Com1.log"),
        ("reserved LPT", "nested/LPT9"),
    ];
    for (case, path) in invalid {
        assert!(
            RepositoryRelativePath::parse(path).is_err(),
            "{case} path {path:?} was accepted"
        );
        assert!(
            serde_json::from_value::<RepositoryRelativePath>(json!(path)).is_err(),
            "{case} path {path:?} crossed serde"
        );
    }
}

fn contract_samples() -> Value {
    let repository_id: LogicalRepositoryId = parse("repo-1");
    let snapshot_id: SnapshotId = parse(SNAPSHOT_ID);
    let agent_operation = AgentOperation::new(
        parse(OPERATION_ID),
        AgentOperationStatus::Running,
        1,
        2,
        1_700_000_000_000,
        1_700_000_000_100,
        None,
        1_700_000_060_000,
        1_700_604_860_000,
    )
    .expect("sample Agent operation");
    let page = Page::new(vec![node()], 2, false, Some(parse("cursor-2"))).expect("sample page");
    let success = SuccessEnvelope::new(repository_id.clone(), Some(snapshot_id.clone()), node());
    let error_envelope = ErrorEnvelope::new(repository_id.clone(), error());
    let baseline = DurableSubmitResult::baseline(operation());
    let task = DurableSubmitResult::negotiated(
        operation(),
        TasksNegotiation::Tasks,
        1_700_000_000_000,
        1_700_000_000_100,
        MIN_TASK_TTL_MS,
    )
    .expect("sample task");
    json!({
        "agent_dependencies_response": AgentDependenciesResponse::new(
            node(),
            AgentDependencyDirection::Outgoing,
            false,
            true,
            1,
            Page::new(vec![edge()], 1, true, None).expect("sample dependency page"),
        ).expect("sample dependency response"),
        "agent_build_outcome": build_outcome(),
        "agent_edge": edge(),
        "agent_evidence": evidence(),
        "agent_impact": impact(),
        "agent_impact_response": impact_response(),
        "agent_cycle": cycle(),
        "agent_unresolved": unresolved(),
        "agent_node": node(),
        "agent_node_summary": node_summary(),
        "agent_operation": agent_operation,
        "agent_path_response": AgentPathResponse::new(
            node(), dependency_node(), true, 1, vec![path_step()]
        ).expect("sample path response"),
        "agent_path_step": path_step(),
        "agent_query_row": query_row(),
        "agent_runtime_validation": runtime_validation(),
        "agent_context": context(),
        "agent_named_snapshot": named_snapshot(),
        "agent_site": site(),
        "agent_snapshot": AgentSnapshot::available(snapshot_id, Some(parse("baseline"))),
        "common_request": CommonRequest::new(repository_id.clone()),
        "durable_submit_baseline": baseline,
        "durable_submit_task": task,
        "error_envelope": error_envelope,
        "page": page,
        "page_request": PageRequest::new(
            PageSize::new(25).expect("sample page size"),
            PageByteLimit::new(4096).expect("sample byte limit"),
            Some(parse("cursor-1")),
        ),
        "snapshot_selectors": [
            SnapshotSelector::parse("current").expect("current selector"),
            SnapshotSelector::parse("baseline").expect("name selector"),
            SnapshotSelector::parse(SNAPSHOT_ID).expect("id selector"),
        ],
        "source_span": source_span(),
        "success_envelope": success,
    })
}

#[test]
fn canonical_contract_samples_match_the_golden_exactly() {
    let actual = canonical_json_bytes(&contract_samples()).expect("canonical samples");
    if std::env::var_os("DEPGRAPH_UPDATE_CONTRACT_GOLDEN").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/depgraph-mcp-tools-v1.contract.golden.json"
            ),
            &actual,
        )
        .expect("update contract golden");
    }
    let expected = include_bytes!("fixtures/depgraph-mcp-tools-v1.contract.golden.json");
    assert_eq!(
        std::str::from_utf8(&actual).expect("canonical JSON is UTF-8"),
        std::str::from_utf8(expected).expect("golden JSON is UTF-8")
    );
    assert!(
        !expected.ends_with(b"\n"),
        "canonical golden has no trailing LF"
    );
}

#[test]
fn accepted_operation_status_is_the_closed_queued_value() {
    let value = serde_json::to_value(AcceptedOperationStatus::Queued).expect("serialize status");
    assert_eq!(value, json!("queued"));
}
