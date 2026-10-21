use std::{borrow::Cow, fmt::Write as _};

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    AgentBuildOutcome, AgentChangedSince, AgentCompletedSnapshot, AgentContext, AgentContextDetail,
    AgentContextOutput, AgentContextSummary, AgentCorrelationDifference, AgentCorrelationStatus,
    AgentCoverage, AgentCurrentSnapshot, AgentCycle, AgentCycleLevel, AgentDaemonControlOutcome,
    AgentDaemonStatus, AgentDependenciesOutput, AgentDependenciesResponse,
    AgentDependenciesSummaryResponse, AgentDependencyDetail, AgentDependencyPath,
    AgentDependencyPathsResponse, AgentDoctor, AgentEdge, AgentEdgeCommon, AgentEdgeDetail,
    AgentEdgeSummary, AgentEdgesOutput, AgentEdgesSummaryResponse, AgentEvidence,
    AgentGraphExportResponse, AgentHealthAudit, AgentHealthFinding, AgentHealthFindingDetail,
    AgentHealthFindingsPage, AgentHealthHotspots, AgentHealthSummary, AgentImpact,
    AgentImpactResponse, AgentNamedSnapshot, AgentNode, AgentNodeSummary, AgentOperation,
    AgentPathOutput, AgentPathPathsResponse, AgentPathResponse, AgentPathStep,
    AgentPathSummaryResponse, AgentPolicyEvaluationResponse, AgentProfilePlan, AgentQueryRow,
    AgentQueryValue, AgentRepositoryInitOutcome, AgentRepositoryList, AgentRepositorySummary,
    AgentRuntimeOutcome, AgentRuntimeTraceEvent, AgentRuntimeValidationResponse, AgentScanOutcome,
    AgentScanOutcomeV2, AgentSite, AgentSnapshot, AgentSnapshotDiffResponse, AgentUnresolved,
    CommonRequest, DurableSubmitResult, ErrorEnvelope, OperationAccepted, Page, PageRequest,
    PortableTerminalOutput, SnapshotSelector, SuccessEnvelope, TaskAccepted,
};

pub const MCP_TOOLS_SCHEMA_ID: &str =
    "https://github.com/TamaT-LLC/depgraph-cli/schemas/depgraph-mcp-tools-v1.schema.json";
pub const AGENT_SCAN_OUTCOME_V2_SCHEMA_ID: &str =
    "https://github.com/TamaT-LLC/depgraph-cli/schemas/depgraph-agent-scan-outcome-v2.schema.json";

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
            generator.subschema_for::<SuccessEnvelope<AgentRepositoryList>>(),
            generator.subschema_for::<SuccessEnvelope<AgentCompletedSnapshot>>(),
            generator.subschema_for::<SuccessEnvelope<AgentProfilePlan>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDaemonStatus>>(),
            generator.subschema_for::<SuccessEnvelope<AgentDaemonControlOutcome>>(),
            generator.subschema_for::<SuccessEnvelope<AgentBuildOutcome>>(),
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
            generator.subschema_for::<SuccessEnvelope<AgentHealthSummary>>(),
            generator.subschema_for::<SuccessEnvelope<AgentHealthFindingsPage>>(),
            generator.subschema_for::<SuccessEnvelope<AgentHealthFindingDetail>>(),
            generator.subschema_for::<SuccessEnvelope<AgentHealthAudit>>(),
            generator.subschema_for::<SuccessEnvelope<AgentHealthHotspots>>(),
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
            generator.subschema_for::<AgentRepositorySummary>(),
            generator.subschema_for::<AgentRepositoryList>(),
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
            generator.subschema_for::<AgentHealthSummary>(),
            generator.subschema_for::<AgentHealthFindingsPage>(),
            generator.subschema_for::<AgentHealthFindingDetail>(),
            generator.subschema_for::<AgentHealthAudit>(),
            generator.subschema_for::<AgentHealthHotspots>(),
            generator.subschema_for::<Page<AgentHealthFinding>>(),
            generator.subschema_for::<AgentHealthFinding>(),
            generator.subschema_for::<AgentOperation>(),
            generator.subschema_for::<AgentScanOutcome>(),
            generator.subschema_for::<AgentDaemonControlOutcome>(),
            generator.subschema_for::<AgentBuildOutcome>(),
            generator.subschema_for::<AgentSnapshot>(),
            generator.subschema_for::<SuccessEnvelope<AgentDependenciesOutput>>(),
            generator.subschema_for::<AgentDependenciesOutput>(),
            generator.subschema_for::<AgentDependenciesSummaryResponse>(),
            generator.subschema_for::<AgentDependencyPathsResponse>(),
            generator.subschema_for::<AgentEdgeCommon>(),
            generator.subschema_for::<AgentEdgeSummary>(),
            generator.subschema_for::<AgentDependencyPath>(),
            generator.subschema_for::<AgentDependencyDetail>(),
            generator.subschema_for::<SuccessEnvelope<AgentEdgesOutput>>(),
            generator.subschema_for::<AgentEdgesOutput>(),
            generator.subschema_for::<AgentEdgesSummaryResponse>(),
            generator.subschema_for::<AgentEdgeDetail>(),
            generator.subschema_for::<SuccessEnvelope<AgentPathOutput>>(),
            generator.subschema_for::<AgentPathOutput>(),
            generator.subschema_for::<AgentPathSummaryResponse>(),
            generator.subschema_for::<AgentPathPathsResponse>(),
            generator.subschema_for::<SuccessEnvelope<AgentContextOutput>>(),
            generator.subschema_for::<AgentContextOutput>(),
            generator.subschema_for::<AgentContextSummary>(),
            generator.subschema_for::<AgentContextDetail>(),
            generator.subschema_for::<crate::AgentEdgesImportsResponse>(),
            generator.subschema_for::<crate::AgentImportGroup>(),
            generator.subschema_for::<SuccessEnvelope<Page<crate::AgentFanInItem>>>(),
            generator.subschema_for::<Page<crate::AgentFanInItem>>(),
            generator.subschema_for::<crate::AgentFanInItem>(),
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
    let mut schema = SchemaSettings::draft2020_12()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<McpToolsV1Schema>();
    standardize_schema(&mut schema);
    schema
}

/// `format` values that JSON Schema 2020-12 defines. Validators such as Ajv
/// warn about every other value (Issue #568).
pub const STANDARD_JSON_SCHEMA_FORMATS: &[&str] = &[
    "date-time",
    "date",
    "time",
    "duration",
    "email",
    "idn-email",
    "hostname",
    "idn-hostname",
    "ipv4",
    "ipv6",
    "uri",
    "uri-reference",
    "iri",
    "iri-reference",
    "uuid",
    "uri-template",
    "json-pointer",
    "relative-json-pointer",
    "regex",
];

/// Inclusive range of the Rust integer formats schemars emits.
fn integer_format_range(format: &str) -> Option<(serde_json::Number, serde_json::Number)> {
    let unsigned = |maximum: u64| Some((0_u64.into(), maximum.into()));
    let signed = |minimum: i64, maximum: i64| Some((minimum.into(), maximum.into()));
    match format {
        "uint8" => unsigned(u8::MAX.into()),
        "uint16" => unsigned(u16::MAX.into()),
        "uint32" => unsigned(u32::MAX.into()),
        "uint64" | "uint" => unsigned(u64::MAX),
        "int8" => signed(i8::MIN.into(), i8::MAX.into()),
        "int16" => signed(i16::MIN.into(), i16::MAX.into()),
        "int32" => signed(i32::MIN.into(), i32::MAX.into()),
        "int64" | "int" => signed(i64::MIN, i64::MAX),
        _ => None,
    }
}

/// Replaces the non-standard integer `format` values schemars derives from
/// Rust integer types (`uint32`, `uint64`, ...) with the equivalent
/// `minimum` / `maximum` bounds. A bound that is already present is kept,
/// because a hand-written or `NonZero` bound is at least as tight as the type
/// range, so the set of accepted values does not change (Issue #568).
pub fn standardize_integer_formats(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            let range = object
                .get("format")
                .and_then(serde_json::Value::as_str)
                .and_then(integer_format_range);
            if let Some((minimum, maximum)) = range {
                object.remove("format");
                object
                    .entry("minimum")
                    .or_insert(serde_json::Value::Number(minimum));
                object
                    .entry("maximum")
                    .or_insert(serde_json::Value::Number(maximum));
            }
            for child in object.values_mut() {
                standardize_integer_formats(child);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                standardize_integer_formats(item);
            }
        }
        _ => {}
    }
}

fn standardize_schema(schema: &mut Schema) {
    let mut value = serde_json::to_value(&*schema).expect("a schemars Schema is JSON");
    standardize_integer_formats(&mut value);
    *schema = Schema::try_from(value).expect("a standardized schema stays a schema");
}

/// Standalone schema for the additive scan outcome projection.  It is kept
/// outside the v1 catalog so regenerating the legacy catalog cannot silently
/// change the closed completed-only tool contract.
#[must_use]
pub fn agent_scan_outcome_v2_schema() -> Schema {
    let mut schema = SchemaSettings::draft2020_12()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<AgentScanOutcomeV2>();
    standardize_schema(&mut schema);
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "$id".to_owned(),
            serde_json::Value::String(AGENT_SCAN_OUTCOME_V2_SCHEMA_ID.to_owned()),
        );
        object.insert(
            "title".to_owned(),
            serde_json::Value::String("depgraph agent scan outcome v2".to_owned()),
        );
    }
    schema
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
