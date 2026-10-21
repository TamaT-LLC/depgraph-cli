use std::io;

use depgraph_core::{DepgraphCapability, DepgraphServiceError, RepositoryFileError};
use depgraph_mcp_tools::{
    AgentCapability, AgentContext, AgentCurrentSnapshot, AgentDependenciesOutput,
    AgentDependenciesResponse, AgentDependencyDetail, AgentDependencyDirection, AgentEdge,
    AgentErrorCode, AgentGraphExportFormat, AgentGraphExportMediaType, AgentGraphExportResponse,
    AgentNode, AgentSnapshot, CanonicalResponseMapper, CursorKey, DependencyProjectionRequest,
    LogicalRepositoryId, MAX_PAGE_BYTES, OperationAccepted, Page, PageByteLimit, PageRequest,
    PageSize, PaginationContext, SnapshotId, SuccessEnvelope, project_dependency_items_cancellable,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const SNAPSHOT_ID: &str =
    "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn cursor_key() -> CursorKey {
    CursorKey::from_bytes([0x42; 32])
}

#[test]
fn issue_300_closed_context_is_accepted_by_the_public_mapper() {
    let context = AgentContext::new(
        repository_id(),
        vec![AgentCapability::Read],
        AgentCurrentSnapshot::unavailable(),
    )
    .expect("valid context");
    let mapped =
        CanonicalResponseMapper::success(&SuccessEnvelope::new(repository_id(), None, context))
            .expect("closed context is a public result");
    let structured = mapped.result().structured_content.as_ref().unwrap();
    assert_eq!(
        structured["result"]["snapshot"],
        json!({"available": false})
    );
}

fn item(id: u32, label: &str) -> AgentNode {
    AgentNode::new(
        format!("node-{id}").parse().expect("valid node ID"),
        "module".parse().expect("valid node kind"),
        format!("src/module-{id}.rs")
            .parse()
            .expect("valid locator"),
        Some(label.parse().expect("valid display name")),
        Some(
            format!("src/module-{id}.rs")
                .parse()
                .expect("valid repository path"),
        ),
    )
}

fn repository_id() -> LogicalRepositoryId {
    "repo-1".parse().expect("valid repository ID")
}

fn snapshot_id() -> SnapshotId {
    SNAPSHOT_ID.parse().expect("valid snapshot ID")
}

fn text_content(result: &rmcp::model::CallToolResult) -> &str {
    assert_eq!(result.content.len(), 1, "exactly one content block");
    &result.content[0]
        .as_text()
        .expect("the sole content block must be text")
        .text
}

#[test]
fn canonical_mapper_keeps_structured_content_and_single_text_content_byte_identical() {
    let envelope = SuccessEnvelope::new(
        repository_id(),
        Some(snapshot_id()),
        AgentSnapshot::unavailable(),
    );

    let mapped = CanonicalResponseMapper::success(&envelope).expect("map success response");
    let result = mapped.result();
    let structured = result
        .structured_content
        .as_ref()
        .expect("structured content");
    let canonical_structured =
        depgraph_mcp_tools::canonical_json_bytes(structured).expect("canonical structured content");

    assert_eq!(text_content(result).as_bytes(), canonical_structured);
    assert_eq!(mapped.output_bytes(), canonical_structured.len());
    assert_eq!(result.is_error, Some(false));
}

#[test]
fn graph_export_mapper_preserves_export_file_remediation_after_envelope_overflow() {
    let content = "x".repeat(MAX_PAGE_BYTES as usize);
    let content_sha256 = format!("{:x}", Sha256::digest(content.as_bytes()));
    let export = AgentGraphExportResponse::try_new(
        depgraph_core::service::GRAPH_EXPORT_SERVICE_SCHEMA_VERSION,
        SNAPSHOT_ID,
        AgentGraphExportFormat::Json,
        AgentGraphExportMediaType::Json,
        content,
        &content_sha256,
        u64::from(MAX_PAGE_BYTES),
        1,
        0,
    )
    .expect("valid maximum-size export DTO");
    let envelope = SuccessEnvelope::new(repository_id(), Some(snapshot_id()), export);

    let mapped = CanonicalResponseMapper::export_success(&envelope)
        .expect("oversized export maps to a bounded typed error");
    let structured = mapped
        .result()
        .structured_content
        .as_ref()
        .expect("structured error content");

    assert_eq!(mapped.result().is_error, Some(true));
    assert_eq!(structured["error"]["code"], "RESOURCE_EXHAUSTED");
    assert_eq!(structured["error"]["remediation"], "export_file");
    assert!(structured.get("result").is_none());
}

#[test]
fn accepted_response_uses_the_same_canonical_mapper_contract() {
    let accepted = OperationAccepted::new(
        "op_0123456789abcdef0123456789abcdef"
            .parse()
            .expect("valid operation ID"),
    );
    let envelope = SuccessEnvelope::new(repository_id(), Some(snapshot_id()), accepted);

    let mapped = CanonicalResponseMapper::success(&envelope).expect("map accepted response");
    let result = mapped.result();
    let structured = result
        .structured_content
        .as_ref()
        .expect("structured accepted content");

    assert_eq!(result.is_error, Some(false));
    assert_eq!(
        text_content(result).as_bytes(),
        depgraph_mcp_tools::canonical_json_bytes(structured).expect("canonical accepted content")
    );
}

#[test]
fn service_errors_map_to_closed_redacted_tool_errors() {
    let cases = [
        (
            DepgraphServiceError::CapabilityDenied {
                required: DepgraphCapability::StoreWrite,
            },
            AgentErrorCode::CapabilityDenied,
        ),
        (
            DepgraphServiceError::InvalidInput,
            AgentErrorCode::InvalidArgument,
        ),
        (
            DepgraphServiceError::SnapshotWorktreeMismatch,
            AgentErrorCode::SnapshotWorktreeMismatch,
        ),
        (
            DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::NotFound,
            },
            AgentErrorCode::NotFound,
        ),
        (
            DepgraphServiceError::RepositoryFile {
                reason: RepositoryFileError::Unavailable {
                    source: io::Error::other(
                        "worker stderr: Bearer top-secret at /Users/private/store.sqlite",
                    ),
                },
            },
            AgentErrorCode::Internal,
        ),
        (
            DepgraphServiceError::ResourceExhausted,
            AgentErrorCode::ResourceExhausted,
        ),
        (
            DepgraphServiceError::QueryRejected,
            AgentErrorCode::QueryRejected,
        ),
        (
            DepgraphServiceError::Integrity,
            AgentErrorCode::IntegrityFailure,
        ),
    ];

    for (source, expected_code) in cases {
        let mapped = CanonicalResponseMapper::service_error(repository_id(), &source)
            .expect("map service error");
        let result = mapped.result();
        let structured = result
            .structured_content
            .as_ref()
            .expect("structured error content");
        let error = structured
            .get("error")
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .expect("typed error code");

        assert_eq!(error, serde_json::to_value(expected_code).unwrap());
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            text_content(result).as_bytes(),
            depgraph_mcp_tools::canonical_json_bytes(structured)
                .expect("canonical structured error")
        );
        let disclosure = text_content(result).to_ascii_lowercase();
        for forbidden in ["top-secret", "bearer", "/users/", "worker stderr"] {
            assert!(
                !disclosure.contains(forbidden),
                "tool error disclosed forbidden marker {forbidden}: {disclosure}"
            );
        }
    }
}

fn mapped_error(source: &DepgraphServiceError) -> Value {
    let mapped =
        CanonicalResponseMapper::service_error(repository_id(), source).expect("map service error");
    mapped.result().structured_content.as_ref().unwrap()["error"].clone()
}

#[test]
fn issue_565_resource_limits_name_the_bound_the_work_and_the_argument() {
    use depgraph_core::DepgraphResourceLimit;

    let raisable = mapped_error(&DepgraphServiceError::resource_limit(
        DepgraphResourceLimit::MaxTraversal,
        50_000,
        Some(50_000),
    ));
    assert_eq!(
        raisable,
        json!({
            "code": "RESOURCE_EXHAUSTED",
            "category": "resource",
            "retryable": false,
            "remediation": "increase_limit",
            "details": {
                "kind": "resource_limit",
                "limit": "traversal_items",
                "maximum": 50_000,
                "observed": 50_000,
                "argument": "max_traversal"
            }
        })
    );
    // At the argument's ceiling only narrowing helps.
    let ceiling = mapped_error(&DepgraphServiceError::resource_limit(
        DepgraphResourceLimit::MaxTraversal,
        1_000_000,
        Some(1_000_000),
    ));
    assert_eq!(ceiling["remediation"], "narrow_query");
    assert_eq!(ceiling["details"]["argument"], "max_traversal");
    // Fixed bounds that no argument widens only ask for narrowing.
    for (limit, name) in [
        (
            DepgraphResourceLimit::AdjacencyEdgeInspection,
            "snapshot_edges",
        ),
        (
            DepgraphResourceLimit::PreprocessingWorkItems,
            "preprocessing_work_items",
        ),
    ] {
        let fixed = mapped_error(&DepgraphServiceError::resource_limit(
            limit, 1_000_000, None,
        ));
        assert_eq!(fixed["remediation"], "narrow_query");
        assert_eq!(fixed["details"]["limit"], name);
        assert!(fixed["details"].get("argument").is_none(), "{fixed}");
        assert!(fixed["details"].get("observed").is_none(), "{fixed}");
    }
    // The unclassified variant keeps its v1 shape without details.
    assert!(
        mapped_error(&DepgraphServiceError::ResourceExhausted)
            .get("details")
            .is_none()
    );
}

#[test]
fn issue_617_unresolved_and_cycle_limits_and_out_of_range_arguments_are_named() {
    use depgraph_core::DepgraphResourceLimit;

    // Unresolved listing reports how many sites matched; a larger
    // max_traversal succeeds while that count fits under the ceiling.
    assert_eq!(
        mapped_error(&DepgraphServiceError::resource_limit(
            DepgraphResourceLimit::MaxTraversal,
            50_000,
            Some(61_234),
        )),
        json!({
            "code": "RESOURCE_EXHAUSTED",
            "category": "resource",
            "retryable": false,
            "remediation": "increase_limit",
            "details": {
                "kind": "resource_limit",
                "limit": "traversal_items",
                "maximum": 50_000,
                "observed": 61_234,
                "argument": "max_traversal"
            }
        })
    );
    // More matches than the ceiling admits: raising cannot help.
    let beyond = mapped_error(&DepgraphServiceError::resource_limit(
        DepgraphResourceLimit::MaxTraversal,
        50_000,
        Some(1_000_001),
    ));
    assert_eq!(beyond["remediation"], "narrow_query");
    assert_eq!(beyond["details"]["argument"], "max_traversal");
    // The cycle search does not know the total edge visits it needs.
    let cycles = mapped_error(&DepgraphServiceError::resource_limit(
        DepgraphResourceLimit::MaxTraversal,
        50_000,
        None,
    ));
    assert_eq!(cycles["remediation"], "increase_limit");
    assert!(cycles["details"].get("observed").is_none(), "{cycles}");

    let out_of_range = DepgraphServiceError::ArgumentOutOfRange {
        argument: "max_traversal",
        minimum: 1,
        maximum: 1_000_000,
    };
    assert_eq!(
        mapped_error(&out_of_range),
        json!({
            "code": "INVALID_ARGUMENT",
            "category": "input",
            "retryable": false,
            "remediation": "correct_input",
            "details": {
                "kind": "argument",
                "argument": "max_traversal",
                "reason": "out_of_range",
                "minimum": 1,
                "maximum": 1_000_000
            }
        })
    );
    // Argument details without a range keep their previous wire shape.
    assert_eq!(
        serde_json::to_value(depgraph_mcp_tools::AgentErrorDetails::argument(
            Some("limit"),
            depgraph_mcp_tools::AgentArgumentReason::OutOfRange,
        ))
        .unwrap(),
        json!({"kind": "argument", "argument": "limit", "reason": "out_of_range"})
    );
}

#[test]
fn issue_581_impact_health_and_artifact_limits_are_named() {
    use depgraph_core::DepgraphResourceLimit;

    // Bounds an argument widens ask for increase_limit below its ceiling.
    for (limit, name, argument, maximum, ceiling) in [
        (
            DepgraphResourceLimit::ImpactNodes,
            "impact_nodes",
            "max_nodes",
            10_000,
            1_000_000,
        ),
        (
            DepgraphResourceLimit::ImpactEdges,
            "impact_edges",
            "max_edges",
            50_000,
            1_000_000,
        ),
        (
            DepgraphResourceLimit::ExportNodes,
            "export_nodes",
            "max_nodes",
            10,
            50_000,
        ),
        (
            DepgraphResourceLimit::ExportEdges,
            "export_edges",
            "max_edges",
            10,
            100_000,
        ),
    ] {
        let raisable = mapped_error(&DepgraphServiceError::resource_limit(
            limit,
            maximum,
            Some(maximum + 1),
        ));
        assert_eq!(
            raisable,
            json!({
                "code": "RESOURCE_EXHAUSTED",
                "category": "resource",
                "retryable": false,
                "remediation": "increase_limit",
                "details": {
                    "kind": "resource_limit",
                    "limit": name,
                    "maximum": maximum,
                    "observed": maximum + 1,
                    "argument": argument
                }
            })
        );
        let at_ceiling = mapped_error(&DepgraphServiceError::resource_limit(limit, ceiling, None));
        assert_eq!(at_ceiling["remediation"], "narrow_query", "{name}");
        assert_eq!(at_ceiling["details"]["argument"], argument, "{name}");
    }
    // Fixed service bounds only ask for narrowing.
    for (limit, name) in [
        (DepgraphResourceLimit::ImpactPathSteps, "impact_path_steps"),
        (DepgraphResourceLimit::ChangedPaths, "changed_paths"),
        (DepgraphResourceLimit::HealthFindings, "health_findings"),
        (
            DepgraphResourceLimit::HealthFindingItems,
            "health_finding_items",
        ),
        (DepgraphResourceLimit::HealthManifests, "health_manifests"),
        (DepgraphResourceLimit::InputBytes, "input_bytes"),
        (DepgraphResourceLimit::ArtifactItems, "artifact_items"),
        (
            DepgraphResourceLimit::ArtifactWorkItems,
            "artifact_work_items",
        ),
        (DepgraphResourceLimit::OutputBytes, "output_bytes"),
    ] {
        let fixed = mapped_error(&DepgraphServiceError::resource_limit(limit, 10_000, None));
        assert_eq!(fixed["code"], "RESOURCE_EXHAUSTED", "{name}");
        assert_eq!(fixed["remediation"], "narrow_query", "{name}");
        assert_eq!(
            fixed["details"],
            json!({"kind": "resource_limit", "limit": name, "maximum": 10_000})
        );
    }
}

#[test]
fn issue_565_unclassified_graph_query_errors_stay_detail_free_and_unreflected() {
    let error = mapped_error(&DepgraphServiceError::graph_query(
        io::Error::other("selector \"path:/Users/private/secret.rs\" is weird").into(),
    ));
    assert_eq!(
        error,
        json!({
            "code": "INVALID_ARGUMENT",
            "category": "input",
            "retryable": false,
            "remediation": "correct_input"
        })
    );
}

#[test]
fn mapper_redacts_sensitive_strings_from_closed_success_dtos() {
    for sensitive in [
        "MATCH (n) WHERE n.password = 'top-secret' RETURN n",
        "WITH 'top-secret' AS credential RETURN credential",
        "CREATE (n {token: 'top-secret'})",
        "CALL db.labels()",
        "EXPLAIN SELECT * FROM credentials",
        "/* audit */ SELECT * FROM credentials",
        "g.V().has('password', 'top-secret')",
        r#"feature == \"ghp_examplecredential\""#,
        "C:/private/key",
        concat!("file", ":///Users/alice/private.db"),
        r"\Windows\System32\config\SAM",
        r"\\server\share\secret",
        "//server/share/secret",
        "x-api-key: top-secret",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    ] {
        let unsafe_envelope =
            SuccessEnvelope::new(repository_id(), Some(snapshot_id()), item(1, sensitive));

        let mapped =
            CanonicalResponseMapper::success(&unsafe_envelope).expect("map redacted success");
        let text = text_content(mapped.result()).to_ascii_lowercase();

        assert!(
            !text.contains(&sensitive.to_ascii_lowercase()),
            "success disclosed forbidden value {sensitive}: {text}"
        );
        assert!(text.contains("[redacted]"));
    }
}

#[test]
fn cursor_is_bound_to_tool_snapshot_filter_and_contract() {
    let items = vec![item(1, "one"), item(2, "two")];
    let first_request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(4096).unwrap(),
        None,
    );
    let context = PaginationContext::new(
        &cursor_key(),
        "agent_nodes_find",
        repository_id(),
        snapshot_id(),
        &json!({"kinds":["module"],"filter":"src"}),
    )
    .expect("pagination context");
    let first = context
        .paginate(&items, &first_request)
        .expect("first page");
    let cursor = first.next_cursor().expect("continuation cursor").clone();
    assert_eq!(cursor.as_str().split('.').count(), 2);
    assert!(
        !cursor.as_str().contains(".1."),
        "offset must not be exposed"
    );

    let mut tampered = cursor.as_str().as_bytes().to_vec();
    let last = tampered.last_mut().expect("non-empty cursor");
    *last = if *last == b'a' { b'b' } else { b'a' };
    let tampered = String::from_utf8(tampered)
        .expect("ASCII cursor")
        .parse()
        .expect("tampered token still satisfies scalar grammar");
    let tampered_request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(4096).unwrap(),
        Some(tampered),
    );
    let error = context
        .paginate(&items, &tampered_request)
        .expect_err("authenticated cursor tampering must fail");
    assert_eq!(error.code(), AgentErrorCode::CursorMismatch);

    for mismatched in [
        PaginationContext::new(
            &CursorKey::from_bytes([0x24; 32]),
            "agent_nodes_find",
            repository_id(),
            snapshot_id(),
            &json!({"kinds":["module"],"filter":"src"}),
        )
        .unwrap(),
        PaginationContext::new(
            &cursor_key(),
            "agent_edges_list",
            repository_id(),
            snapshot_id(),
            &json!({"kinds":["module"],"filter":"src"}),
        )
        .unwrap(),
        PaginationContext::new(
            &cursor_key(),
            "agent_nodes_find",
            repository_id(),
            "snapshot:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .unwrap(),
            &json!({"kinds":["module"],"filter":"src"}),
        )
        .unwrap(),
        PaginationContext::new(
            &cursor_key(),
            "agent_nodes_find",
            repository_id(),
            snapshot_id(),
            &json!({"kinds":["function"],"filter":"src"}),
        )
        .unwrap(),
    ] {
        let request = PageRequest::new(
            PageSize::new(1).unwrap(),
            PageByteLimit::new(4096).unwrap(),
            Some(cursor.clone()),
        );
        let error = mismatched
            .paginate(&items, &request)
            .expect_err("mismatched cursor must fail without data");
        assert_eq!(error.code(), AgentErrorCode::CursorMismatch);
    }

    let mut changed_items = items.clone();
    changed_items[1] = item(2, "changed-between-pages");
    let changed_request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(4096).unwrap(),
        Some(cursor.clone()),
    );
    let error = context
        .paginate(&changed_items, &changed_request)
        .expect_err("result-set changes under the same snapshot must fail");
    assert_eq!(error.code(), AgentErrorCode::CursorMismatch);

    let forged_contract_cursor = cursor
        .as_str()
        .replacen("v1.", "v2.", 1)
        .parse()
        .expect("closed cursor grammar accepts version token");
    let request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(4096).unwrap(),
        Some(forged_contract_cursor),
    );
    let error = context
        .paginate(&items, &request)
        .expect_err("different contract cursor must fail");
    assert_eq!(error.code(), AgentErrorCode::CursorMismatch);
}

#[test]
fn malformed_cursor_and_too_small_empty_page_fail_closed() {
    let context = PaginationContext::new(
        &cursor_key(),
        "agent_nodes_find",
        repository_id(),
        snapshot_id(),
        &json!({"filter":null}),
    )
    .expect("pagination context");
    let malformed = "not-a-bound-cursor".parse().expect("valid cursor scalar");
    let malformed_request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(4096).unwrap(),
        Some(malformed),
    );
    let error = context
        .paginate::<AgentNode>(&[], &malformed_request)
        .expect_err("malformed cursor must fail");
    assert_eq!(error.code(), AgentErrorCode::CursorInvalid);

    let tiny_request = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(1).unwrap(),
        None,
    );
    let error = context
        .paginate::<AgentNode>(&[], &tiny_request)
        .expect_err("empty success envelope must honor byte limit");
    assert_eq!(error.code(), AgentErrorCode::ResourceExhausted);
}

#[test]
fn item_and_byte_bounded_pages_reassemble_the_canonical_full_result() {
    let items: Vec<AgentNode> = (0..9)
        .map(|id| item(id, &format!("item-{id}-{}", "x".repeat(48))))
        .collect();
    let context = PaginationContext::new(
        &cursor_key(),
        "agent_nodes_find",
        repository_id(),
        snapshot_id(),
        &json!({"kinds":[],"filter":null}),
    )
    .expect("pagination context");
    let mut cursor = None;
    let mut reassembled = Vec::new();
    let mut page_count = 0;

    loop {
        let request = PageRequest::new(
            PageSize::new(3).unwrap(),
            PageByteLimit::new(700).unwrap(),
            cursor,
        );
        let page = context.paginate(&items, &request).expect("bounded page");
        let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            repository_id(),
            Some(snapshot_id()),
            page.clone(),
        ))
        .expect("map page");

        assert!(page.returned_items() <= 3);
        assert!(mapped.output_bytes() <= 700);
        reassembled.extend_from_slice(page.items());
        page_count += 1;
        if page.complete() {
            break;
        }
        cursor = Some(page.next_cursor().expect("incomplete page cursor").clone());
    }

    assert!(page_count > 1);
    assert_eq!(reassembled, items);
    assert_eq!(
        depgraph_mcp_tools::canonical_json_bytes(&reassembled).unwrap(),
        depgraph_mcp_tools::canonical_json_bytes(&items).unwrap()
    );
}

#[test]
fn ten_item_page_projection_accounts_for_returned_item_digit_growth_exactly() {
    let items = (0..10)
        .map(|id| item(id, &format!("item-{id}-{}", "x".repeat(200))))
        .collect::<Vec<_>>();
    let context = PaginationContext::new(
        &cursor_key(),
        "agent_nodes_find",
        repository_id(),
        snapshot_id(),
        &json!({"kinds":[],"filter":null}),
    )
    .expect("pagination context");
    let generous = PageRequest::new(
        PageSize::new(10).expect("ten item page"),
        PageByteLimit::new(16 * 1024).expect("generous byte limit"),
        None,
    );
    let baseline = context
        .paginate(&items, &generous)
        .expect("ten items fit the generous page");
    assert_eq!(baseline.returned_items(), 10);
    let baseline_mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
        repository_id(),
        Some(snapshot_id()),
        baseline,
    ))
    .expect("baseline page maps");
    let exact_bytes = u32::try_from(baseline_mapped.output_bytes()).expect("page bytes fit u32");

    let exact_request = PageRequest::new(
        PageSize::new(10).expect("ten item page"),
        PageByteLimit::new(exact_bytes).expect("exact byte limit"),
        None,
    );
    let exact_page = context
        .paginate(&items, &exact_request)
        .expect("the exact projected ten-item envelope fits");
    assert_eq!(exact_page.returned_items(), 10);
    let exact_mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
        repository_id(),
        Some(snapshot_id()),
        exact_page,
    ))
    .expect("accepted exact page must map successfully");
    assert_eq!(exact_mapped.output_bytes(), exact_bytes as usize);

    let one_lower = PageRequest::new(
        PageSize::new(10).expect("ten item page"),
        PageByteLimit::new(exact_bytes - 1).expect("one-lower byte limit"),
        None,
    );
    match context.paginate(&items, &one_lower) {
        Ok(page) => {
            assert!(page.returned_items() < 10);
            let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id(),
                Some(snapshot_id()),
                page,
            ))
            .expect("smaller accepted page must still map");
            assert!(mapped.output_bytes() < exact_bytes as usize);
        }
        Err(error) => assert_eq!(error.code(), AgentErrorCode::ResourceExhausted),
    }
}

// Issue #542: output granularity of graph_dependencies_list / graph_dependents_list.

struct DependencyFixtureEdge<'a> {
    id: &'a str,
    source: (&'a str, Option<&'a str>),
    target: (&'a str, Option<&'a str>),
    kind: &'a str,
    precision: &'a str,
    site_id: Option<&'a str>,
    evidence: usize,
}

fn dependency_fixture_node(id: &str, path: Option<&str>) -> Value {
    let properties = path.map_or_else(|| json!({}), |path| json!({"path": path}));
    json!({
        "id": id,
        "kind": "module",
        "locator": format!("id:{id}"),
        "display_name": id,
        "properties": properties
    })
}

fn dependency_fixture_item(
    edge: &DependencyFixtureEdge,
) -> depgraph_core::query::TraversalPageItem {
    let evidence = (0..edge.evidence)
        .map(|ordinal| {
            json!({
                "owner_type": "edge",
                "owner_id": edge.id,
                "ordinal": ordinal,
                "kind": "semantic",
                "extractor": "fixture",
                "extractor_version": "1.0",
                "path": "src/a.rs",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "detail": null,
                "properties": {}
            })
        })
        .collect::<Vec<_>>();
    serde_json::from_value(json!({
        "source": dependency_fixture_node(edge.source.0, edge.source.1),
        "target": dependency_fixture_node(edge.target.0, edge.target.1),
        "step": {
            "edge": {
                "id": edge.id,
                "site_id": edge.site_id,
                "source": edge.source.0,
                "target": edge.target.0,
                "kind": edge.kind,
                "phase": "semantic",
                "environment": "host",
                "profile_id": "profile:default",
                "resolution_status": "resolved",
                "precision": edge.precision,
                "condition": {"op": "all", "conditions": []},
                "generated": false
            },
            "condition_text": "all",
            "evidence": evidence,
            "effective_profile_id": null,
            "correlation_status": null,
            "observed_difference_reasons": [],
            "phase_coverage": {}
        }
    }))
    .expect("valid dependency traversal item")
}

/// Four traversal edges: two share the same file pair and kind (`edge:1`, `edge:3`),
/// one differs only in kind (`edge:2`) and one targets a node without a repository path.
fn dependency_fixture_items() -> Vec<depgraph_core::query::TraversalPageItem> {
    [
        DependencyFixtureEdge {
            id: "edge:1",
            source: ("node:a", Some("src/a.rs")),
            target: ("node:b", Some("src/b.rs")),
            kind: "imports",
            precision: "exact",
            site_id: Some("site:1"),
            evidence: 2,
        },
        DependencyFixtureEdge {
            id: "edge:2",
            source: ("node:a", Some("src/a.rs")),
            target: ("node:b", Some("src/b.rs")),
            kind: "calls",
            precision: "heuristic",
            site_id: None,
            evidence: 0,
        },
        DependencyFixtureEdge {
            id: "edge:3",
            source: ("symbol:a", Some("src/a.rs")),
            target: ("node:b", Some("src/b.rs")),
            kind: "imports",
            precision: "exact",
            site_id: Some("site:3"),
            evidence: 1,
        },
        DependencyFixtureEdge {
            id: "edge:4",
            source: ("node:b", Some("src/b.rs")),
            target: ("node:x", None),
            kind: "imports",
            precision: "exact",
            site_id: None,
            evidence: 1,
        },
    ]
    .iter()
    .map(dependency_fixture_item)
    .collect()
}

fn dependency_root() -> AgentNode {
    AgentNode::new(
        "node:a".parse().expect("valid root ID"),
        "module".parse().expect("valid kind"),
        "id:node:a".parse().expect("valid locator"),
        None,
        Some("src/a.rs".parse().expect("valid path")),
    )
}

fn dependency_pagination(normalized: &Value) -> PaginationContext {
    PaginationContext::new(
        &cursor_key(),
        "graph_dependencies_list",
        repository_id(),
        snapshot_id(),
        normalized,
    )
    .expect("dependency pagination context")
}

fn project_fixture(
    detail: AgentDependencyDetail,
    page: &PageRequest,
    pagination: &PaginationContext,
) -> Result<AgentDependenciesOutput, depgraph_mcp_tools::AgentError> {
    project_items(&dependency_fixture_items(), detail, page, pagination)
}

/// Twenty edges with distinct file pairs, large enough that one-item pages (which carry a
/// continuation cursor) stay below the complete response for every detail.
fn many_dependency_items() -> Vec<depgraph_core::query::TraversalPageItem> {
    (0..20)
        .map(|index| {
            let id = format!("edge:{index:02}");
            let node = format!("node:s{index:02}");
            let path = format!("src/s{index:02}.rs");
            dependency_fixture_item(&DependencyFixtureEdge {
                id: &id,
                source: (&node, Some(&path)),
                target: ("node:b", Some("src/b.rs")),
                kind: "imports",
                precision: "exact",
                site_id: None,
                evidence: 1,
            })
        })
        .collect()
}

fn project_items(
    items: &[depgraph_core::query::TraversalPageItem],
    detail: AgentDependencyDetail,
    page: &PageRequest,
    pagination: &PaginationContext,
) -> Result<AgentDependenciesOutput, depgraph_mcp_tools::AgentError> {
    project_dependency_items_cancellable(
        dependency_root(),
        items,
        u64::try_from(items.len()).unwrap(),
        DependencyProjectionRequest::new(AgentDependencyDirection::Outgoing, true, detail),
        pagination,
        page,
        &depgraph_core::CancellationToken::new(),
    )
}

fn large_page() -> PageRequest {
    PageRequest::new(
        PageSize::new(100).unwrap(),
        PageByteLimit::new(MAX_PAGE_BYTES).unwrap(),
        None,
    )
}

fn mapped_bytes<T: depgraph_mcp_tools::PublicToolResult>(result: T) -> Vec<u8> {
    let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
        repository_id(),
        Some(snapshot_id()),
        result,
    ))
    .expect("dependency response maps");
    text_content(mapped.result()).as_bytes().to_vec()
}

#[test]
fn issue_542_full_detail_is_byte_identical_to_the_legacy_edge_projection() {
    let pagination = dependency_pagination(&json!({"selector": "id:node:a"}));
    let full = project_fixture(AgentDependencyDetail::Full, &large_page(), &pagination)
        .expect("full projection");
    let AgentDependenciesOutput::Full(full) = full else {
        panic!("full detail must keep the legacy response shape");
    };

    let legacy_edges = dependency_fixture_items()
        .iter()
        .map(|item| AgentEdge::try_from(&item.step).expect("legacy edge projection"))
        .collect::<Vec<_>>();
    let legacy = AgentDependenciesResponse::new(
        dependency_root(),
        AgentDependencyDirection::Outgoing,
        true,
        true,
        4,
        Page::new(legacy_edges, 4, true, None).expect("legacy page"),
    )
    .expect("legacy response");
    assert_eq!(full, legacy);
    let full_bytes = mapped_bytes(AgentDependenciesOutput::Full(full));
    assert_eq!(full_bytes, mapped_bytes(legacy));
    let full_value: Value = serde_json::from_slice(&full_bytes).unwrap();
    assert!(full_value["result"].get("detail").is_none());
    assert!(full_value["result"].get("common").is_none());
    assert_eq!(
        full_value["result"]["edges"]["items"][0]["evidence"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn issue_542_summary_detail_hoists_shared_edge_fields_into_common_once() {
    let pagination = dependency_pagination(&json!({"selector": "id:node:a", "detail": "summary"}));
    let summary = project_fixture(AgentDependencyDetail::Summary, &large_page(), &pagination)
        .expect("summary projection");
    assert_eq!(summary.detail(), AgentDependencyDetail::Summary);
    let bytes = mapped_bytes(summary);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let result = &value["result"];
    assert_eq!(result["detail"], "summary");
    assert_eq!(result["root"]["id"], "node:a");
    assert_eq!(result["traversed_edges"], 4);
    assert_eq!(
        result["common"],
        json!({
            "phase": "semantic",
            "resolution_status": "resolved",
            "profile_id": "profile:default",
            "condition": "all"
        }),
        "precision differs across edges, so it stays per edge"
    );
    let items = result["edges"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    assert_eq!(
        items[0],
        json!({
            "id": "edge:1",
            "source_id": "node:a",
            "target_id": "node:b",
            "kind": "imports",
            "precision": "exact",
            "site_id": "site:1",
            "evidence_count": 2
        })
    );
    assert_eq!(items[1]["precision"], "heuristic");
    assert_eq!(items[1]["evidence_count"], 0);
    assert!(items[1].get("site_id").is_none());
    for item in items {
        for hoisted in [
            "phase",
            "resolution_status",
            "profile_id",
            "condition",
            "evidence",
        ] {
            assert!(item.get(hoisted).is_none(), "{hoisted} repeated in {item}");
        }
    }
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.matches("profile:default").count(), 1);
    assert_eq!(text.matches("\"semantic\"").count(), 1);

    let full_pagination = dependency_pagination(&json!({"selector": "id:node:a"}));
    let full = project_fixture(AgentDependencyDetail::Full, &large_page(), &full_pagination)
        .expect("full projection");
    assert!(text.len() < mapped_bytes(full).len());
}

#[test]
fn issue_542_paths_detail_returns_unique_paths_and_kinds_only() {
    let pagination = dependency_pagination(&json!({"selector": "id:node:a", "detail": "paths"}));
    let paths = project_fixture(AgentDependencyDetail::Paths, &large_page(), &pagination)
        .expect("paths projection");
    assert_eq!(paths.detail(), AgentDependencyDetail::Paths);
    let value: Value = serde_json::from_slice(&mapped_bytes(paths)).unwrap();
    let result = &value["result"];
    assert_eq!(result["detail"], "paths");
    assert_eq!(result["traversed_edges"], 4);
    assert!(result.get("edges").is_none());
    assert_eq!(
        result["paths"],
        json!({
            "items": [
                {"source_path": "src/a.rs", "target_path": "src/b.rs", "kind": "imports"},
                {"source_path": "src/a.rs", "target_path": "src/b.rs", "kind": "calls"},
                {"source_path": "src/b.rs", "target_id": "node:x", "kind": "imports"}
            ],
            "returned_items": 3,
            "total_items": 3,
            "complete": true
        })
    );
}

#[test]
fn issue_542_byte_budget_pages_every_detail_and_reassembles_the_complete_result() {
    let items = many_dependency_items();
    for (detail, field) in [
        (AgentDependencyDetail::Full, "edges"),
        (AgentDependencyDetail::Summary, "edges"),
        (AgentDependencyDetail::Paths, "paths"),
    ] {
        let pagination = dependency_pagination(&json!({"selector": "id:node:a", "detail": detail}));
        let complete = project_items(&items, detail, &large_page(), &pagination).expect("complete");
        let complete_bytes = mapped_bytes(complete);
        let complete_value: Value = serde_json::from_slice(&complete_bytes).unwrap();
        let expected_items = complete_value["result"][field]["items"].clone();
        let expected_count = expected_items.as_array().unwrap().len();

        // The largest one-item page is the smallest budget that always makes progress;
        // it is below the complete response, so the byte budget alone must split pages.
        let mut budget = 0_usize;
        let mut single_cursor = None;
        loop {
            let request = PageRequest::new(
                PageSize::new(1).unwrap(),
                PageByteLimit::new(MAX_PAGE_BYTES).unwrap(),
                single_cursor.take(),
            );
            let page = project_items(&items, detail, &request, &pagination).expect("one-item page");
            let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id(),
                Some(snapshot_id()),
                page,
            ))
            .unwrap();
            budget = budget.max(mapped.output_bytes());
            let value: Value = serde_json::from_str(text_content(mapped.result())).unwrap();
            match value["result"][field].get("next_cursor") {
                Some(next) => single_cursor = Some(next.as_str().unwrap().parse().unwrap()),
                None => break,
            }
        }
        assert!(budget < complete_bytes.len(), "{detail:?}");
        let budget = u32::try_from(budget).unwrap();
        let mut collected = Vec::new();
        let mut cursor = None;
        let mut pages = 0;
        loop {
            let request = PageRequest::new(
                PageSize::new(100).unwrap(),
                PageByteLimit::new(budget).unwrap(),
                cursor.clone(),
            );
            let page = project_items(&items, detail, &request, &pagination).expect("page");
            let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
                repository_id(),
                Some(snapshot_id()),
                page,
            ))
            .unwrap();
            assert!(
                mapped.output_bytes() <= budget as usize,
                "{detail:?} over budget"
            );
            pages += 1;
            let value: Value = serde_json::from_str(text_content(mapped.result())).unwrap();
            let page = &value["result"][field];
            assert!(page["returned_items"].as_u64().unwrap() >= 1);
            collected.extend(page["items"].as_array().unwrap().iter().cloned());
            match page.get("next_cursor") {
                Some(next) => cursor = Some(next.as_str().unwrap().parse().unwrap()),
                None => break,
            }
        }
        assert!(pages > 1, "{detail:?} was not split by the byte budget");
        assert_eq!(collected.len(), expected_count, "{detail:?}");
        assert_eq!(Value::Array(collected), expected_items, "{detail:?}");
    }
}

#[test]
fn issue_542_cursor_from_one_detail_is_rejected_by_another() {
    let first_page = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(MAX_PAGE_BYTES).unwrap(),
        None,
    );
    let full_pagination = dependency_pagination(&json!({"selector": "id:node:a"}));
    let AgentDependenciesOutput::Full(full) =
        project_fixture(AgentDependencyDetail::Full, &first_page, &full_pagination).unwrap()
    else {
        panic!("full shape");
    };
    let cursor = full.edges().next_cursor().unwrap().clone();
    let paths_pagination =
        dependency_pagination(&json!({"selector": "id:node:a", "detail": "paths"}));
    let resumed = PageRequest::new(
        PageSize::new(1).unwrap(),
        PageByteLimit::new(MAX_PAGE_BYTES).unwrap(),
        Some(cursor),
    );
    let error = project_fixture(AgentDependencyDetail::Paths, &resumed, &paths_pagination)
        .expect_err("cursor bound to another detail");
    assert_eq!(error.code(), AgentErrorCode::CursorMismatch);
}
