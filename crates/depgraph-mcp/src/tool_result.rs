//! Adapter from the transport-neutral [`MappedToolResult`] to rmcp's
//! [`CallToolResult`].

use depgraph_agent_contract::MappedToolResult;
use rmcp::model::{CallToolResult, ContentBlock};

/// Builds the MCP tool result for a canonical mapped response.
pub trait IntoCallToolResult {
    /// Returns a result whose structured content is the canonical value, whose
    /// sole content block is its canonical JSON text, and whose `is_error` is
    /// always set.
    fn into_result(self) -> CallToolResult;
}

impl IntoCallToolResult for MappedToolResult {
    fn into_result(self) -> CallToolResult {
        let (structured_content, text, is_error) = self.into_parts();
        let mut result = CallToolResult::structured(structured_content);
        result.content = vec![ContentBlock::text(text)];
        result.is_error = Some(is_error);
        result
    }
}

#[cfg(test)]
mod tests {
    use depgraph_agent_contract::{
        AgentSnapshot, CanonicalResponseMapper, LogicalRepositoryId, SnapshotId, SuccessEnvelope,
        canonical_json_bytes,
    };
    use depgraph_core::DepgraphServiceError;

    use super::*;

    fn repository_id() -> LogicalRepositoryId {
        "repo-1".parse().expect("valid repository ID")
    }

    fn assert_call_tool_result(mapped: MappedToolResult, expected_is_error: bool) {
        let structured = mapped.structured_content().clone();
        let text = mapped.text().to_owned();
        let output_bytes = mapped.output_bytes();
        let result = mapped.into_result();

        assert_eq!(result.structured_content.as_ref(), Some(&structured));
        assert_eq!(result.content.len(), 1, "exactly one content block");
        let block_text = &result.content[0]
            .as_text()
            .expect("the sole content block must be text")
            .text;
        assert_eq!(block_text, &text);
        assert_eq!(
            block_text.as_bytes(),
            canonical_json_bytes(&structured).expect("canonical structured content")
        );
        assert_eq!(block_text.len(), output_bytes);
        assert_eq!(result.is_error, Some(expected_is_error));
    }

    #[test]
    fn success_maps_to_structured_and_single_text_content() {
        let snapshot_id: SnapshotId =
            "snapshot:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .expect("valid snapshot ID");
        let mapped = CanonicalResponseMapper::success(&SuccessEnvelope::new(
            repository_id(),
            Some(snapshot_id),
            AgentSnapshot::unavailable(),
        ))
        .expect("map success response");
        assert_call_tool_result(mapped, false);
    }

    #[test]
    fn error_maps_to_error_flagged_result() {
        let mapped = CanonicalResponseMapper::service_error(
            repository_id(),
            &DepgraphServiceError::InvalidInput,
        )
        .expect("map service error");
        assert_call_tool_result(mapped, true);
    }
}
