use std::num::NonZeroU32;

use depgraph_mcp_tools::{
    AcceptedOperationStatus, AgentCapability, AgentCompletedSnapshot, AgentContext, AgentCoverage,
    AgentCurrentSnapshot, AgentDependenciesResponse, AgentDependencyDirection, AgentEdge,
    AgentError, AgentErrorCategory, AgentErrorCode, AgentErrorDetails, AgentEvidence,
    AgentEvidenceKind, AgentLocator, AgentNamedSnapshot, AgentNode, AgentNodeSummary,
    AgentPathResponse, AgentPathStep, AgentPhase, AgentPrecision, AgentRemediation,
    AgentResolutionStatus, AgentResourceLimit, AgentSite, AgentSnapshot, AgentSourcePosition,
    AgentSourceSpan, CommonRequest, ContractBuildError, Cursor, DurableSubmitResult, ErrorEnvelope,
    LogicalRepositoryId, MAX_PAGE_BYTES, MAX_PAGE_ITEMS, MAX_TASK_TTL_MS, MIN_TASK_TTL_MS,
    OperationAccepted, OperationRecoveryTools, Page, PageByteLimit, PageRequest, PageSize,
    RepositoryRelativePath, SnapshotId, SnapshotSelector, SuccessEnvelope, TASK_POLL_INTERVAL_MS,
    TaskAccepted, TasksNegotiation, canonical_json_bytes,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

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
        "agent_edge": edge(),
        "agent_evidence": evidence(),
        "agent_node": node(),
        "agent_node_summary": node_summary(),
        "agent_path_response": AgentPathResponse::new(
            node(), dependency_node(), true, 1, vec![path_step()]
        ).expect("sample path response"),
        "agent_path_step": path_step(),
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
