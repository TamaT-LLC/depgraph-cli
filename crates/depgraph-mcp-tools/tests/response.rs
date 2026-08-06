use std::io;

use depgraph_core::{DepgraphCapability, DepgraphServiceError, RepositoryFileError};
use depgraph_mcp_tools::{
    AgentCapability, AgentContext, AgentCurrentSnapshot, AgentErrorCode, AgentNode, AgentSnapshot,
    CanonicalResponseMapper, CursorKey, LogicalRepositoryId, OperationAccepted, PageByteLimit,
    PageRequest, PageSize, PaginationContext, SnapshotId, SuccessEnvelope,
};
use serde_json::{Value, json};

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
