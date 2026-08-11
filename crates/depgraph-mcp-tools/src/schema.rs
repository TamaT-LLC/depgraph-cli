use std::{borrow::Cow, fmt::Write as _};

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    AgentChangedSince, AgentCompletedSnapshot, AgentContext, AgentCorrelationDifference,
    AgentCorrelationStatus, AgentCoverage, AgentCurrentSnapshot, AgentCycle, AgentCycleLevel,
    AgentDaemonControlOutcome, AgentDaemonStatus, AgentDependenciesResponse, AgentDoctor,
    AgentEdge, AgentEvidence, AgentGraphExportResponse, AgentImpact, AgentImpactResponse,
    AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentOperation, AgentPathResponse,
    AgentPathStep, AgentPolicyEvaluationResponse, AgentProfilePlan, AgentQueryRow, AgentQueryValue,
    AgentRepositoryInitOutcome, AgentRuntimeOutcome, AgentRuntimeTraceEvent,
    AgentRuntimeValidationResponse, AgentScanOutcome, AgentSite, AgentSnapshot,
    AgentSnapshotDiffResponse, AgentUnresolved, CommonRequest, DurableSubmitResult, ErrorEnvelope,
    OperationAccepted, Page, PageRequest, PortableTerminalOutput, SnapshotSelector,
    SuccessEnvelope, TaskAccepted,
};

pub const MCP_TOOLS_SCHEMA_ID: &str =
    "https://github.com/TamaT-LLC/depgraph-cli/schemas/depgraph-mcp-tools-v1.schema.json";

struct McpToolsV1Schema;

impl JsonSchema for McpToolsV1Schema {
    fn schema_name() -> Cow<'static, str> {
        "depgraph-mcp-tools-v1".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::McpToolsV1Schema").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let contracts = vec![
            generator.subschema_for::<CommonRequest>(),
            generator.subschema_for::<SnapshotSelector>(),
            generator.subschema_for::<PageRequest>(),
            generator.subschema_for::<Page<AgentNode>>(),
            generator.subschema_for::<Page<AgentNodeSummary>>(),
            generator.subschema_for::<Page<AgentNamedSnapshot>>(),
            generator.subschema_for::<Page<AgentSite>>(),
            generator.subschema_for::<Page<AgentEdge>>(),
            generator.subschema_for::<Page<AgentEvidence>>(),
            generator.subschema_for::<Page<AgentSnapshot>>(),
            generator.subschema_for::<Page<AgentImpact>>(),
            generator.subschema_for::<Page<AgentCycle>>(),
            generator.subschema_for::<Page<AgentUnresolved>>(),
            generator.subschema_for::<Page<AgentQueryRow>>(),
            generator.subschema_for::<Page<AgentRuntimeTraceEvent>>(),
            generator.subschema_for::<SuccessEnvelope<AgentNode>>(),
            generator.subschema_for::<SuccessEnvelope<AgentContext>>(),
            generator.subschema_for::<SuccessEnvelope<AgentCompletedSnapshot>>(),
            generator.subschema_for::<SuccessEnvelope<AgentProfilePlan>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDaemonStatus>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDaemonControlOutcome>>(),
            generator.subschema_for::<SuccessEnvelope<AgentScanOutcome>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDoctor>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDependenciesResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentPathResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentImpactResponse>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentCycle>>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentUnresolved>>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentQueryRow>>>(),
            generator.subschema_for::<SuccessEnvelope<AgentRuntimeValidationResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentRuntimeOutcome>>(),
            generator.subschema_for::<SuccessEnvelope<AgentRepositoryInitOutcome>>(),
            generator.subschema_for::<SuccessEnvelope<AgentSnapshotDiffResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentPolicyEvaluationResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentGraphExportResponse>>(),
            generator.subschema_for::<SuccessEnvelope<AgentOperation>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentNode>>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentNodeSummary>>>(),
            generator.subschema_for::<SuccessEnvelope<Page<AgentNamedSnapshot>>>(),
            generator.subschema_for::<ErrorEnvelope>(),
            generator.subschema_for::<OperationAccepted>(),
            generator.subschema_for::<TaskAccepted>(),
            generator.subschema_for::<DurableSubmitResult>(),
            generator.subschema_for::<PortableTerminalOutput>(),
            generator.subschema_for::<AgentNode>(),
            generator.subschema_for::<AgentNodeSummary>(),
            generator.subschema_for::<AgentCoverage>(),
            generator.subschema_for::<AgentCompletedSnapshot>(),
            generator.subschema_for::<AgentNamedSnapshot>(),
            generator.subschema_for::<AgentCurrentSnapshot>(),
            generator.subschema_for::<AgentContext>(),
            generator.subschema_for::<AgentSite>(),
            generator.subschema_for::<AgentEdge>(),
            generator.subschema_for::<AgentEvidence>(),
            generator.subschema_for::<AgentPathStep>(),
            generator.subschema_for::<AgentDependenciesResponse>(),
            generator.subschema_for::<AgentPathResponse>(),
            generator.subschema_for::<AgentCycleLevel>(),
            generator.subschema_for::<AgentCycle>(),
            generator.subschema_for::<AgentCorrelationStatus>(),
            generator.subschema_for::<AgentCorrelationDifference>(),
            generator.subschema_for::<AgentUnresolved>(),
            generator.subschema_for::<AgentChangedSince>(),
            generator.subschema_for::<AgentImpact>(),
            generator.subschema_for::<AgentImpactResponse>(),
            generator.subschema_for::<AgentQueryValue>(),
            generator.subschema_for::<AgentQueryRow>(),
            generator.subschema_for::<AgentRuntimeTraceEvent>(),
            generator.subschema_for::<AgentRuntimeValidationResponse>(),
            generator.subschema_for::<AgentRuntimeOutcome>(),
            generator.subschema_for::<AgentRepositoryInitOutcome>(),
            generator.subschema_for::<AgentSnapshotDiffResponse>(),
            generator.subschema_for::<AgentPolicyEvaluationResponse>(),
            generator.subschema_for::<AgentGraphExportResponse>(),
            generator.subschema_for::<AgentOperation>(),
            generator.subschema_for::<AgentScanOutcome>(),
            generator.subschema_for::<AgentDaemonControlOutcome>(),
            generator.subschema_for::<AgentSnapshot>(),
        ];
        json_schema!({
            "$id": MCP_TOOLS_SCHEMA_ID,
            "title": "depgraph MCP Agent tools v1 contract catalog",
            "description": "Closed common request, response, pagination, Agent DTO, and durable operation contracts. Consumers select the applicable schema from $defs.",
            "anyOf": contracts
        })
    }
}

#[must_use]
pub fn mcp_tools_v1_schema() -> Schema {
    SchemaSettings::draft2020_12()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<McpToolsV1Schema>()
}

pub fn canonical_json_bytes<T>(value: &T) -> Result<Vec<u8>, CanonicalJsonError>
where
    T: Serialize + ?Sized,
{
    let value = serde_json::to_value(value)?;
    Ok(depgraph_protocol::canonical_json(&value).into_bytes())
}

pub fn canonical_json_sha256<T>(value: &T) -> Result<String, CanonicalJsonError>
where
    T: Serialize + ?Sized,
{
    canonical_json_bytes(value).map(|bytes| lowercase_sha256(&bytes))
}

#[must_use]
pub fn canonical_schema_bytes() -> Vec<u8> {
    canonical_json_bytes(&mcp_tools_v1_schema())
        .expect("a schemars Schema is always JSON serializable")
}

#[must_use]
pub fn canonical_schema_sha256() -> String {
    lowercase_sha256(&canonical_schema_bytes())
}

#[derive(Debug, thiserror::Error)]
#[error("value could not be serialized as canonical JSON")]
pub struct CanonicalJsonError {
    #[from]
    source: serde_json::Error,
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
