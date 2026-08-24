use std::collections::BTreeSet;

use depgraph_protocol::{
    Condition, EvidenceKind, Phase, Precision, ProtocolEvent, ResolutionStatus, ValidatedProtocol,
    validate_semantic_contract,
};
use serde_json::Value;

use crate::worker::TYPESCRIPT_COMPILER_VERSION;

pub(crate) const TYPESCRIPT_ANALYSIS_MODE_PROPERTY: &str = "typescript_analysis_mode";
pub(crate) const TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH: &str = "semantic-definition-graph";
pub(crate) const TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH: &str = "semantic-import-type-graph";
pub(crate) const TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH: &str =
    "semantic-import-type-call-graph";
pub(crate) const TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY: &str = "typescript_semantic_graph_emission";
pub(crate) const TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1: &str = "definition-graph-v1";
pub(crate) const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1: &str =
    "definition-import-type-graph-v1";
pub(crate) const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1: &str =
    "definition-import-type-call-graph-v1";
pub(crate) const TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2: &str =
    "definition-import-type-call-graph-v2";
pub(crate) const TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY: &str = "typescript_semantic_site_count";
pub(crate) const TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY: &str =
    "typescript_semantic_call_site_count";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY: &str =
    "web_framework_semantic_capability";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1: &str = "framework-semantic-graph-v1";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY: &str = "web_framework_semantic_status";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY: &str =
    "web_framework_semantic_extractor_version";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION: &str = "0.1.0";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY: &str =
    "web_framework_semantic_node_count";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY: &str =
    "web_framework_semantic_site_count";
pub(crate) const WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY: &str =
    "web_framework_semantic_edge_count";
pub(crate) const WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY: &str =
    "web_framework_completeness_capability";
pub(crate) const WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1: &str =
    "framework-semantic-completeness-v1";
pub(crate) const WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY: &str =
    "web_framework_completeness_status";
pub(crate) const WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY: &str =
    "web_framework_completeness_issue_count";
pub(crate) const WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY: &str =
    "web_framework_completeness_ledger";
pub(crate) const TYPESCRIPT_SEMANTIC_EXTRACTOR: &str = "typescript-native-typechecker";
pub(crate) const TYPESCRIPT_SEMANTIC_BACKEND: &str = "typescript-native-compiler";
pub(crate) const TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM: &str =
    "typescript-closed-local-call-flow-v1";
pub(crate) const TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM: &str =
    "typescript-closed-local-fresh-instance-flow-v1";
pub(crate) const TYPESCRIPT_PROJECT_STATUS_PROPERTY: &str = "typescript_project_model_status";
pub(crate) const TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY: &str = "typescript_typechecker_status";
pub(crate) const TYPESCRIPT_DEFINITION_STATUS_PROPERTY: &str = "typescript_definition_graph_status";
const TYPESCRIPT_DEFINITION_ISSUE_PROPERTY: &str = "typescript_definition_issue";
const TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY: &str = "typescript_dependency_issue";
const TYPESCRIPT_MAX_TYPE_ARGUMENTS: usize = 64;
const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH: usize = 64;
const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_MEMBERS: usize = 256;
pub(crate) const TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS: usize = 2_048;
const TYPESCRIPT_MAX_DISPLAY_NAME_CHARS: usize = 512;
const TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS: usize = 4_096;

pub(crate) fn is_web_definition_relation_kind(kind: &str) -> bool {
    matches!(kind, "declares" | "extends" | "implements" | "instantiates")
}

pub(crate) fn is_web_semantic_dependency_site_kind(kind: &str) -> bool {
    matches!(kind, "web_import" | "web_reexport" | "type_use" | "call")
}

pub(crate) fn is_web_semantic_dependency_edge_kind(kind: &str) -> bool {
    matches!(
        kind,
        "imports" | "reexports" | "type_uses" | "calls" | "may_call"
    )
}

pub(crate) fn is_web_framework_semantic_node(node: &depgraph_protocol::GraphNode) -> bool {
    matches!(
        node.kind.as_str(),
        "component" | "route" | "server_function" | "middleware"
    ) && node.properties.contains_key("canonical_identity")
}

pub(crate) fn is_web_framework_semantic_site_kind(kind: &str) -> bool {
    matches!(
        kind,
        "renders"
            | "hydrates"
            | "client_boundary"
            | "server_boundary"
            | "route_entry"
            | "parent_route"
            | "loads"
            | "before_load"
            | "navigates_to"
            | "masks_to"
            | "rpc_call"
            | "client_stub_for"
            | "handled_by"
            | "uses_middleware"
    )
}

pub(crate) fn is_web_framework_semantic_delta_event(event: &ProtocolEvent) -> bool {
    match event {
        ProtocolEvent::NodeUpsert(upsert) => is_web_framework_semantic_node(&upsert.node),
        ProtocolEvent::EdgeUpsert(upsert) => {
            is_web_framework_semantic_site_kind(&upsert.edge.kind)
                && (upsert.edge.phase == Phase::Semantic
                    || upsert
                        .edge
                        .evidence
                        .first()
                        .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
        }
        ProtocolEvent::DependencySite(site) => {
            is_web_framework_semantic_site_kind(&site.site.kind)
                && site
                    .site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
        }
        _ => false,
    }
}

fn web_semantic_edge_kind_for_site(
    kind: &str,
    resolution_status: ResolutionStatus,
) -> Option<&'static str> {
    match kind {
        "web_import" => Some("imports"),
        "web_reexport" => Some("reexports"),
        "type_use" => Some("type_uses"),
        "call" if resolution_status == ResolutionStatus::Candidates => Some("may_call"),
        "call" => Some("calls"),
        _ => None,
    }
}

fn is_web_callable_symbol_kind(symbol_kind: &str) -> bool {
    matches!(
        symbol_kind,
        "function" | "method" | "constructor" | "anonymous_function" | "local_function"
    )
}

fn is_web_call_source_symbol_kind(symbol_kind: &str) -> bool {
    is_web_callable_symbol_kind(symbol_kind) || symbol_kind == "generated_module_initializer"
}

pub(crate) fn is_web_semantic_delta_event(event: &ProtocolEvent) -> bool {
    match event {
        ProtocolEvent::NodeUpsert(upsert) => {
            matches!(upsert.node.kind.as_str(), "symbol" | "type")
        }
        ProtocolEvent::EdgeUpsert(upsert) => {
            !is_web_framework_semantic_site_kind(&upsert.edge.kind)
                && (upsert.edge.phase == Phase::Semantic
                    || is_web_definition_relation_kind(upsert.edge.kind.as_str()))
        }
        ProtocolEvent::DependencySite(site) => {
            !is_web_framework_semantic_site_kind(&site.site.kind)
                && (matches!(
                    site.site.kind.as_str(),
                    "call"
                        | "type_use"
                        | "rust_use"
                        | "rust_reexport"
                        | "web_import"
                        | "web_reexport"
                ) || site
                    .site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebFrameworkSemanticState {
    Legacy,
    NotEmitted,
    Emitted,
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebFrameworkCompletenessState {
    Legacy,
    NotDetected,
    Complete,
    Incomplete,
}

pub(crate) fn web_framework_completeness_state(
    properties: &depgraph_protocol::Properties,
    features: &[String],
) -> std::result::Result<WebFrameworkCompletenessState, String> {
    let tracked = [
        WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY,
        WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY,
    ];
    let present = tracked
        .iter()
        .filter(|property| properties.contains_key(**property))
        .count();
    if present == 0 {
        return if features.is_empty() {
            Ok(WebFrameworkCompletenessState::Legacy)
        } else {
            Err("Web framework profile omitted its completeness ledger".into())
        };
    }
    if present != tracked.len() {
        return Err("Web worker reported a partial framework completeness declaration".into());
    }
    if properties
        .get(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1)
    {
        return Err("Web worker reported an unapproved framework completeness capability".into());
    }
    let issue_count = properties
        .get(WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            "Web worker reported an invalid framework completeness issue count".to_owned()
        })?;
    let ledger_text = properties
        .get(WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| "Web worker omitted its framework completeness ledger".to_owned())?;
    if ledger_text.len() > 64 * 1024 {
        return Err("Web worker framework completeness ledger exceeded its bound".into());
    }
    let ledger = serde_json::from_str::<Vec<Value>>(ledger_text)
        .map_err(|_| "Web worker reported malformed framework completeness JSON".to_owned())?;
    let state = match properties
        .get(WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY)
        .and_then(Value::as_str)
    {
        Some("not-detected") => WebFrameworkCompletenessState::NotDetected,
        Some("complete") => WebFrameworkCompletenessState::Complete,
        Some("incomplete") => WebFrameworkCompletenessState::Incomplete,
        _ => return Err("Web worker reported an invalid framework completeness status".into()),
    };
    if features.is_empty() {
        return if state == WebFrameworkCompletenessState::NotDetected
            && issue_count == 0
            && ledger.is_empty()
        {
            Ok(state)
        } else {
            Err(
                "Web worker without framework features reported a non-empty completeness ledger"
                    .into(),
            )
        };
    }
    if state == WebFrameworkCompletenessState::NotDetected {
        return Err("Web worker detected framework features but reported not-detected".into());
    }
    let expected_frameworks = features.iter().cloned().collect::<BTreeSet<_>>();
    if expected_frameworks.len() != features.len() || ledger.len() != expected_frameworks.len() {
        return Err("Web framework features and completeness ledger cardinality disagree".into());
    }
    let specific_capability = |framework: &str| match framework {
        "next" => Some("next-route-component-boundary-v1"),
        "astro" => Some("astro-component-render-hydration-v1"),
        "tanstack-router" => Some("tanstack-router-typed-route-v1"),
        "tanstack-start" => Some("tanstack-start-rpc-middleware-v1"),
        _ => None,
    };
    let mut observed_frameworks = BTreeSet::new();
    let mut observed_issue_count = 0usize;
    let mut all_complete = true;
    let mut previous = None::<String>;
    for entry in ledger {
        let object = entry
            .as_object()
            .ok_or_else(|| "Web framework completeness ledger entry is not an object".to_owned())?;
        let framework = object
            .get("framework")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "Web framework completeness ledger entry omitted framework".to_owned()
            })?;
        if previous.as_deref().is_some_and(|value| value >= framework) {
            return Err("Web framework completeness ledger is not strictly sorted".into());
        }
        previous = Some(framework.to_owned());
        let specific = specific_capability(framework).ok_or_else(|| {
            format!("Web framework completeness ledger named unsupported framework {framework}")
        })?;
        let strings = |field: &str| -> std::result::Result<Vec<String>, String> {
            object
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("Web framework completeness entry omitted {field}"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty() && value.len() <= 512)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            format!("Web framework completeness entry has invalid {field}")
                        })
                })
                .collect()
        };
        let required = strings("required_capabilities")?;
        let emitted = strings("emitted_capabilities")?;
        let reasons = strings("reasons")?;
        let expected_required = BTreeSet::from([
            "typescript-definition-import-type-call-graph-v2".to_owned(),
            WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1.to_owned(),
            specific.to_owned(),
        ]);
        let required_set = required.iter().cloned().collect::<BTreeSet<_>>();
        let emitted_set = emitted.iter().cloned().collect::<BTreeSet<_>>();
        let reason_set = reasons.iter().cloned().collect::<BTreeSet<_>>();
        let strictly_sorted = |values: &[String]| values.windows(2).all(|pair| pair[0] < pair[1]);
        if required_set != expected_required
            || required_set.len() != required.len()
            || emitted_set.len() != emitted.len()
            || reason_set.len() != reasons.len()
            || !strictly_sorted(&required)
            || !strictly_sorted(&emitted)
            || !strictly_sorted(&reasons)
            || !emitted_set.is_subset(&required_set)
        {
            return Err(format!(
                "Web framework completeness entry for {framework} has invalid capabilities or reasons"
            ));
        }
        let entry_complete = match object.get("status").and_then(Value::as_str) {
            Some("complete") => true,
            Some("incomplete") => false,
            _ => {
                return Err(format!(
                    "Web framework completeness entry for {framework} has invalid status"
                ));
            }
        };
        if entry_complete != (reasons.is_empty() && emitted_set == required_set) {
            return Err(format!(
                "Web framework completeness entry for {framework} contradicts its capability/reason ledger"
            ));
        }
        all_complete &= entry_complete;
        observed_issue_count += reasons.len();
        observed_frameworks.insert(framework.to_owned());
    }
    if observed_frameworks != expected_frameworks || observed_issue_count != issue_count {
        return Err(
            "Web framework completeness ledger does not match features or issue count".into(),
        );
    }
    if (state == WebFrameworkCompletenessState::Complete) != all_complete {
        return Err("Web framework completeness aggregate status contradicts its ledger".into());
    }
    if state == WebFrameworkCompletenessState::Incomplete && issue_count == 0 {
        return Err("Web incomplete framework profile reported zero issues".into());
    }
    Ok(state)
}

pub(crate) fn web_framework_semantic_state(
    properties: &depgraph_protocol::Properties,
) -> std::result::Result<WebFrameworkSemanticState, String> {
    let tracked = [
        WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
    ];
    let present = tracked
        .iter()
        .filter(|property| properties.contains_key(**property))
        .count();
    if present == 0 {
        return Ok(WebFrameworkSemanticState::Legacy);
    }
    if present != tracked.len() {
        return Err(
            "Web worker reported a partial framework semantic capability declaration".into(),
        );
    }
    if properties
        .get(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1)
    {
        return Err("Web worker reported an unapproved framework semantic capability".into());
    }
    if properties
        .get(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY)
        .and_then(Value::as_str)
        != Some(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION)
    {
        return Err(
            "Web worker reported an unapproved framework semantic extractor version".into(),
        );
    }
    let counts = [
        WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
        WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
    ]
    .map(|property| {
        properties
            .get(property)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| format!("Web worker omitted or has invalid {property}"))
    });
    let [nodes, sites, edges] = counts;
    let (nodes, sites, edges) = (nodes?, sites?, edges?);
    let state = match properties
        .get(WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY)
        .and_then(Value::as_str)
    {
        Some("not-emitted") => WebFrameworkSemanticState::NotEmitted,
        Some("emitted") => WebFrameworkSemanticState::Emitted,
        Some("discarded") => WebFrameworkSemanticState::Discarded,
        _ => return Err("Web worker reported an invalid framework semantic status".into()),
    };
    if state != WebFrameworkSemanticState::Emitted && (nodes != 0 || sites != 0 || edges != 0) {
        return Err(format!(
            "Web worker reported framework semantic status {state:?} with non-zero counts"
        ));
    }
    Ok(state)
}

fn is_web_semantic_sentinel_node(node: &depgraph_protocol::GraphNode) -> bool {
    match node.kind.as_str() {
        "external_system" => {
            node.properties.get("external").and_then(Value::as_bool) == Some(true)
                && node.properties.get("language").and_then(Value::as_str) == Some("typescript")
                && node
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .is_some()
                && node
                    .properties
                    .get("compiler_version")
                    .and_then(Value::as_str)
                    == Some(TYPESCRIPT_COMPILER_VERSION)
        }
        "unknown_target" => {
            node.properties.get("language").and_then(Value::as_str) == Some("web")
                && node
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .is_some()
        }
        _ => false,
    }
}

pub(crate) fn discard_web_definition_delta(
    events: &mut Vec<ProtocolEvent>,
    extra_semantic_node_ids: &BTreeSet<String>,
    semantic_node_candidate_ids: &BTreeSet<String>,
    extra_discarded_site_ids: &BTreeSet<String>,
    extra_semantic_endpoint_ids: &BTreeSet<String>,
) {
    let mut semantic_node_ids = extra_semantic_node_ids.clone();
    semantic_node_ids.extend(events.iter().filter_map(|event| match event {
        ProtocolEvent::NodeUpsert(upsert)
            if matches!(upsert.node.kind.as_str(), "symbol" | "type") =>
        {
            Some(upsert.node.id.clone())
        }
        _ => None,
    }));
    let accepted_node_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::NodeUpsert(upsert) => Some(upsert.node.id.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let orphan_semantic_node_ids = semantic_node_candidate_ids
        .iter()
        .filter(|node_id| !accepted_node_ids.contains(node_id.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let incident_semantic_node_ids = semantic_node_ids
        .union(&orphan_semantic_node_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut discarded_site_ids = extra_discarded_site_ids.clone();
    discarded_site_ids.extend(events.iter().filter_map(|event| {
        match event {
            ProtocolEvent::DependencySite(site)
                if incident_semantic_node_ids.contains(&site.site.source)
                    || site
                        .site
                        .target_ids
                        .iter()
                        .any(|target| incident_semantic_node_ids.contains(target))
                    || is_web_semantic_delta_event(event) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        }
    }));
    discarded_site_ids.extend(events.iter().filter_map(|event| match event {
        ProtocolEvent::EdgeUpsert(upsert)
            if incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                || incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                || is_web_semantic_delta_event(event) =>
        {
            upsert.edge.site_id.clone()
        }
        _ => None,
    }));
    let mut semantic_endpoint_ids = extra_semantic_endpoint_ids.clone();
    for event in events.iter() {
        match event {
            ProtocolEvent::DependencySite(site) if is_web_semantic_delta_event(event) => {
                semantic_endpoint_ids.insert(site.site.source.clone());
                semantic_endpoint_ids.extend(site.site.target_ids.iter().cloned());
            }
            ProtocolEvent::EdgeUpsert(upsert) if is_web_semantic_delta_event(event) => {
                semantic_endpoint_ids.insert(upsert.edge.source.clone());
                semantic_endpoint_ids.insert(upsert.edge.target.clone());
            }
            _ => {}
        }
    }
    let retained_site_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::DependencySite(site)
                if !discarded_site_ids.contains(site.site.id.as_str()) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut retained_endpoint_ids = BTreeSet::new();
    for event in events.iter() {
        match event {
            ProtocolEvent::EdgeUpsert(upsert)
                if !incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                    && !incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                    && upsert
                        .edge
                        .site_id
                        .as_deref()
                        .is_none_or(|site_id| retained_site_ids.contains(site_id))
                    && !is_web_semantic_delta_event(event) =>
            {
                retained_endpoint_ids.insert(upsert.edge.source.clone());
                retained_endpoint_ids.insert(upsert.edge.target.clone());
            }
            ProtocolEvent::DependencySite(site)
                if !discarded_site_ids.contains(site.site.id.as_str()) =>
            {
                retained_endpoint_ids.insert(site.site.source.clone());
                retained_endpoint_ids.extend(site.site.target_ids.iter().cloned());
            }
            _ => {}
        }
    }
    events.retain(|event| match event {
        ProtocolEvent::NodeUpsert(upsert) => {
            let semantic_sentinel = matches!(
                upsert.node.kind.as_str(),
                "external_system" | "unknown_target"
            ) && (semantic_endpoint_ids.contains(upsert.node.id.as_str())
                || is_web_semantic_sentinel_node(&upsert.node));
            !semantic_node_ids.contains(upsert.node.id.as_str())
                && (!semantic_sentinel || retained_endpoint_ids.contains(upsert.node.id.as_str()))
        }
        ProtocolEvent::EdgeUpsert(upsert) => {
            !incident_semantic_node_ids.contains(upsert.edge.source.as_str())
                && !incident_semantic_node_ids.contains(upsert.edge.target.as_str())
                && upsert
                    .edge
                    .site_id
                    .as_deref()
                    .is_none_or(|site_id| retained_site_ids.contains(site_id))
                && !is_web_semantic_delta_event(event)
        }
        ProtocolEvent::DependencySite(site) => !discarded_site_ids.contains(&site.site.id),
        ProtocolEvent::Diagnostic(event) => ![
            TYPESCRIPT_DEFINITION_ISSUE_PROPERTY,
            TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY,
        ]
        .iter()
        .any(|property| {
            event
                .diagnostic
                .properties
                .get(*property)
                .and_then(Value::as_bool)
                == Some(true)
        }),
        ProtocolEvent::FileCompleted(_)
        | ProtocolEvent::ProfileCompleted(_)
        | ProtocolEvent::ScanCompleted(_) => false,
        _ => true,
    });
    for event in events {
        let ProtocolEvent::ProfileDeclared(declared) = event else {
            continue;
        };
        let Ok(capability) = web_semantic_capability(&declared.profile.properties) else {
            continue;
        };
        let project_failed = declared
            .profile
            .properties
            .get(TYPESCRIPT_PROJECT_STATUS_PROPERTY)
            .and_then(Value::as_str)
            == Some("failed");
        let discarded_status = match capability {
            WebSemanticCapability::DefinitionGraphV1 => "definition-graph-discarded",
            WebSemanticCapability::DefinitionImportTypeGraphV1 => {
                "definition-import-type-graph-discarded"
            }
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
            | WebSemanticCapability::DefinitionImportTypeCallGraphV2 => {
                "definition-import-type-call-graph-discarded"
            }
        };
        let properties = &mut declared.profile.properties;
        properties.insert(
            TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY.to_owned(),
            Value::String(if project_failed {
                "failed".to_owned()
            } else {
                discarded_status.to_owned()
            }),
        );
        properties.insert(
            TYPESCRIPT_DEFINITION_STATUS_PROPERTY.to_owned(),
            Value::String("failed".to_owned()),
        );
        for property in [
            "typescript_semantic_node_count",
            "typescript_semantic_relation_count",
            "typescript_semantic_diagnostics",
            "typescript_emitted_semantic_diagnostics",
            "typescript_semantic_issue_count",
        ] {
            properties.insert(property.to_owned(), Value::String("0".to_owned()));
        }
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            properties.insert(
                TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY.to_owned(),
                Value::String("0".to_owned()),
            );
        } else {
            properties.remove(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY);
        }
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            properties.insert(
                TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY.to_owned(),
                Value::String("0".to_owned()),
            );
        } else {
            properties.remove(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY);
        }
    }
}

pub(crate) fn discard_web_framework_delta(events: &mut Vec<ProtocolEvent>) {
    let framework_node_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::NodeUpsert(upsert) if is_web_framework_semantic_node(&upsert.node) => {
                Some(upsert.node.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let framework_site_ids = events
        .iter()
        .filter_map(|event| match event {
            ProtocolEvent::DependencySite(site)
                if is_web_framework_semantic_delta_event(event)
                    || framework_node_ids.contains(&site.site.source)
                    || site
                        .site
                        .target_ids
                        .iter()
                        .any(|target| framework_node_ids.contains(target)) =>
            {
                Some(site.site.id.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    events.retain(|event| match event {
        ProtocolEvent::NodeUpsert(upsert) => !framework_node_ids.contains(&upsert.node.id),
        ProtocolEvent::DependencySite(site) => !framework_site_ids.contains(&site.site.id),
        ProtocolEvent::EdgeUpsert(upsert) => {
            !is_web_framework_semantic_delta_event(event)
                && !framework_node_ids.contains(&upsert.edge.source)
                && !framework_node_ids.contains(&upsert.edge.target)
                && upsert
                    .edge
                    .site_id
                    .as_ref()
                    .is_none_or(|site_id| !framework_site_ids.contains(site_id))
        }
        ProtocolEvent::FileCompleted(_)
        | ProtocolEvent::ProfileCompleted(_)
        | ProtocolEvent::ScanCompleted(_) => false,
        _ => true,
    });
    for event in events {
        let ProtocolEvent::ProfileDeclared(declared) = event else {
            continue;
        };
        if web_framework_semantic_state(&declared.profile.properties)
            != Ok(WebFrameworkSemanticState::Emitted)
        {
            continue;
        }
        let properties = &mut declared.profile.properties;
        properties.insert(
            WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY.to_owned(),
            Value::String("discarded".to_owned()),
        );
        for property in [
            WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
            WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
            WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
        ] {
            properties.insert(property.to_owned(), Value::String("0".to_owned()));
        }
        let Some(ledger_text) = properties
            .get(WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY)
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Ok(mut ledger) = serde_json::from_str::<Vec<Value>>(ledger_text) else {
            continue;
        };
        let mut issue_count = 0usize;
        for entry in &mut ledger {
            let Some(object) = entry.as_object_mut() else {
                continue;
            };
            object.insert("status".to_owned(), Value::String("incomplete".to_owned()));
            let retained_capabilities = object
                .get("emitted_capabilities")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|capability| {
                    *capability == "typescript-definition-import-type-call-graph-v2"
                })
                .map(|capability| Value::String(capability.to_owned()))
                .collect::<Vec<_>>();
            object.insert(
                "emitted_capabilities".to_owned(),
                Value::Array(retained_capabilities),
            );
            let mut reasons = object
                .get("reasons")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            reasons.insert("core_framework_delta_discarded".to_owned());
            issue_count += reasons.len();
            object.insert(
                "reasons".to_owned(),
                Value::Array(reasons.into_iter().map(Value::String).collect()),
            );
        }
        properties.insert(
            WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY.to_owned(),
            Value::String("incomplete".to_owned()),
        );
        properties.insert(
            WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY.to_owned(),
            Value::String(issue_count.to_string()),
        );
        if let Ok(serialized) = serde_json::to_string(&ledger) {
            properties.insert(
                WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY.to_owned(),
                Value::String(serialized),
            );
        }
    }
}

pub(crate) fn record_web_rejected_site_closure(
    event: &ProtocolEvent,
    discarded_site_ids: &mut BTreeSet<String>,
) {
    match event {
        ProtocolEvent::EdgeUpsert(upsert) => {
            if let Some(site_id) = &upsert.edge.site_id {
                discarded_site_ids.insert(site_id.clone());
            }
        }
        ProtocolEvent::DependencySite(site) => {
            discarded_site_ids.insert(site.site.id.clone());
        }
        _ => {}
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebSemanticCapability {
    DefinitionGraphV1,
    DefinitionImportTypeGraphV1,
    DefinitionImportTypeCallGraphV1,
    DefinitionImportTypeCallGraphV2,
}

pub(crate) fn web_semantic_capability(
    properties: &depgraph_protocol::Properties,
) -> std::result::Result<WebSemanticCapability, String> {
    let analysis_mode = properties
        .get(TYPESCRIPT_ANALYSIS_MODE_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web worker omitted {TYPESCRIPT_ANALYSIS_MODE_PROPERTY}"))?;
    let emission = properties
        .get(TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web worker omitted {TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY}"))?;
    match (analysis_mode, emission) {
        (
            TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeCallGraphV1),
        (
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
        ) => Ok(WebSemanticCapability::DefinitionImportTypeCallGraphV2),
        _ => Err(format!(
            "Web worker reported unsupported or mismatched semantic capability {TYPESCRIPT_ANALYSIS_MODE_PROPERTY}={analysis_mode:?}, {TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY}={emission:?}"
        )),
    }
}

pub(crate) fn web_definition_profile_ready(
    properties: &depgraph_protocol::Properties,
    capability: WebSemanticCapability,
) -> std::result::Result<bool, String> {
    let value = |property: &str| {
        properties
            .get(property)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web worker omitted {property}"))
    };
    let state = (
        value(TYPESCRIPT_PROJECT_STATUS_PROPERTY)?,
        value(TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY)?,
        value(TYPESCRIPT_DEFINITION_STATUS_PROPERTY)?,
    );
    let (emitted, discarded) = match capability {
        WebSemanticCapability::DefinitionGraphV1 => {
            ("definition-graph-emitted", "definition-graph-discarded")
        }
        WebSemanticCapability::DefinitionImportTypeGraphV1 => (
            "definition-import-type-graph-emitted",
            "definition-import-type-graph-discarded",
        ),
        WebSemanticCapability::DefinitionImportTypeCallGraphV1
        | WebSemanticCapability::DefinitionImportTypeCallGraphV2 => (
            "definition-import-type-call-graph-emitted",
            "definition-import-type-call-graph-discarded",
        ),
    };
    match state {
        ("ready", checker, "ready") if checker == emitted => Ok(true),
        ("ready", checker, "failed") if checker == discarded => Ok(false),
        ("failed", "failed", "failed") => Ok(false),
        (project, checker, definition) => Err(format!(
            "Web worker reported inconsistent TypeScript semantic state project={project:?}, typechecker={checker:?}, definition={definition:?} for {capability:?}"
        )),
    }
}

fn path_belongs_to_workspace(path: &str, workspace_path: &str) -> bool {
    workspace_path == "."
        || path == workspace_path
        || path
            .strip_prefix(workspace_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn node_package_id(node: &depgraph_protocol::GraphNode) -> Option<&str> {
    node.properties.get("package_id").and_then(Value::as_str)
}

fn web_evidence_matches_source_span(evidence: &depgraph_protocol::Evidence, span: &Value) -> bool {
    [
        ("start_line", evidence.start_line),
        ("start_column", evidence.start_column),
        ("end_line", evidence.end_line),
        ("end_column", evidence.end_column),
    ]
    .into_iter()
    .all(|(field, coordinate)| span.get(field).and_then(Value::as_u64) == coordinate.map(u64::from))
}

fn web_evidence_has_same_anchor(
    left: &depgraph_protocol::Evidence,
    right: &depgraph_protocol::Evidence,
) -> bool {
    left.path == right.path
        && left.start_line == right.start_line
        && left.start_column == right.start_column
        && left.end_line == right.end_line
        && left.end_column == right.end_column
}

fn web_has_matching_source_support(
    evidence: &[depgraph_protocol::Evidence],
    primary: &depgraph_protocol::Evidence,
    profile_id: &str,
    occurrence_kind: &str,
) -> bool {
    evidence.iter().skip(1).any(|supporting| {
        supporting.kind == EvidenceKind::Source
            && supporting.extractor == "typescript-native-syntax"
            && supporting.extractor_version == TYPESCRIPT_COMPILER_VERSION
            && web_evidence_has_same_anchor(primary, supporting)
            && supporting
                .properties
                .get("profile_id")
                .and_then(Value::as_str)
                == Some(profile_id)
            && supporting
                .properties
                .get("occurrence_kind")
                .and_then(Value::as_str)
                == Some(occurrence_kind)
    })
}

fn web_occurrence_kind_matches_site(site_kind: &str, occurrence_kind: &str) -> bool {
    match site_kind {
        "web_import" => matches!(
            occurrence_kind,
            "named_import"
                | "default_import"
                | "namespace_import"
                | "side_effect_import"
                | "empty_import"
                | "import_equals"
                | "require_call"
                | "dynamic_import"
                | "import_type"
        ),
        "web_reexport" => matches!(
            occurrence_kind,
            "named_reexport" | "namespace_reexport" | "empty_reexport" | "export_star"
        ),
        "type_use" => matches!(
            occurrence_kind,
            "type_reference" | "heritage_type" | "jsdoc_type"
        ),
        "call" => matches!(
            occurrence_kind,
            "call_expression" | "new_expression" | "tagged_template"
        ),
        _ => false,
    }
}

fn web_optional_evidence_string<'a>(
    properties: &'a depgraph_protocol::Properties,
    field: &str,
    max_utf16_units: usize,
    allow_empty: bool,
) -> std::result::Result<Option<&'a str>, ()> {
    let Some(value) = properties.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_str() else {
        return Err(());
    };
    if (!allow_empty && value.is_empty()) || value.encode_utf16().count() > max_utf16_units {
        return Err(());
    }
    Ok(Some(value))
}

fn javascript_encode_uri_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}")
                .expect("writing percent encoding into a String cannot fail");
        }
    }
    encoded
}

fn web_occurrence_requires_repository_module(site_kind: &str, occurrence_kind: &str) -> bool {
    match site_kind {
        "web_import" => matches!(
            occurrence_kind,
            "namespace_import"
                | "side_effect_import"
                | "empty_import"
                | "import_equals"
                | "require_call"
                | "dynamic_import"
                | "import_type"
        ),
        "web_reexport" => matches!(
            occurrence_kind,
            "namespace_reexport" | "empty_reexport" | "export_star"
        ),
        _ => false,
    }
}

fn web_source_span_is_canonical(span: Option<&Value>) -> bool {
    let Some(object) = span.and_then(Value::as_object) else {
        return false;
    };
    if object.len() != 4
        || !["start_line", "start_column", "end_line", "end_column"]
            .iter()
            .all(|field| object.contains_key(*field))
    {
        return false;
    }
    let coordinate = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_u64)
            .filter(|coordinate| *coordinate > 0 && *coordinate <= u64::from(u32::MAX))
    };
    let (Some(start_line), Some(start_column), Some(end_line), Some(end_column)) = (
        coordinate("start_line"),
        coordinate("start_column"),
        coordinate("end_line"),
        coordinate("end_column"),
    ) else {
        return false;
    };
    (start_line, start_column) <= (end_line, end_column)
}

fn resolve_web_semantic_reference<'a>(
    reference: &str,
    protocol: &'a ValidatedProtocol,
    nodes_by_resolver: &std::collections::BTreeMap<&str, &'a depgraph_protocol::GraphNode>,
) -> Option<&'a depgraph_protocol::GraphNode> {
    if let Some(node_id) = reference.strip_prefix("node:") {
        protocol.nodes.get(node_id)
    } else {
        nodes_by_resolver.get(reference).copied()
    }
}

fn web_json_object_has_exact_fields(
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn canonical_javascript_number(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        return Some("0".to_owned());
    }

    let negative = value.is_sign_negative();
    let representation = format!("{:?}", value.abs());
    let (mantissa, exponent) = representation.split_once(['e', 'E']).map_or(
        (representation.as_str(), 0),
        |(mantissa, exponent)| {
            (
                mantissa,
                exponent
                    .parse::<i32>()
                    .expect("finite f64 debug exponents are valid integers"),
            )
        },
    );
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let (mut digits, decimal_position) = if integer == "0" {
        let first_significant = fraction
            .find(|character: char| character != '0')
            .unwrap_or(fraction.len());
        (
            fraction[first_significant..].to_owned(),
            -(first_significant as i32),
        )
    } else {
        (
            format!("{integer}{fraction}"),
            integer.len() as i32 + exponent,
        )
    };
    while digits.len() > 1 && digits.ends_with('0') && !fraction.is_empty() {
        digits.pop();
    }
    if digits.is_empty() {
        return Some("0".to_owned());
    }

    let body = if decimal_position > 0 && decimal_position <= 21 {
        let decimal_position = decimal_position as usize;
        if digits.len() <= decimal_position {
            format!("{digits}{}", "0".repeat(decimal_position - digits.len()))
        } else {
            format!(
                "{}.{}",
                &digits[..decimal_position],
                &digits[decimal_position..]
            )
        }
    } else if decimal_position <= 0 && decimal_position > -6 {
        format!("0.{}{digits}", "0".repeat((-decimal_position) as usize))
    } else {
        let exponent = decimal_position - 1;
        let mantissa = if digits.len() == 1 {
            digits
        } else {
            format!("{}.{}", &digits[..1], &digits[1..])
        };
        format!(
            "{mantissa}e{}{exponent}",
            if exponent >= 0 { "+" } else { "" }
        )
    };
    Some(if negative { format!("-{body}") } else { body })
}

fn web_literal_value_is_canonical(value_kind: &str, value: &str) -> bool {
    match value_kind {
        "string" => true,
        "boolean" => matches!(value, "true" | "false"),
        "bigint" => {
            value == "0"
                || value
                    .strip_prefix('-')
                    .unwrap_or(value)
                    .as_bytes()
                    .split_first()
                    .is_some_and(|(first, rest)| {
                        first.is_ascii_digit()
                            && *first != b'0'
                            && rest.iter().all(u8::is_ascii_digit)
                    })
        }
        "number" if value == "-0" => true,
        "number" => value
            .parse::<f64>()
            .ok()
            .and_then(canonical_javascript_number)
            .is_some_and(|canonical| canonical == value),
        _ => false,
    }
}

fn compare_javascript_strings(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn web_resolver_identity_is_portable(resolver: &str) -> bool {
    let bytes = resolver.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    !resolver.is_empty()
        && resolver.encode_utf16().count() <= TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS
        && !resolver.contains('\0')
        && !resolver.starts_with('/')
        && !resolver.starts_with("\\\\")
        && !drive_absolute
        && !resolver.to_ascii_lowercase().starts_with("file://")
}

fn validate_web_type_argument_references(
    descriptor: &Value,
    protocol: &ValidatedProtocol,
    nodes_by_resolver: &std::collections::BTreeMap<&str, &depgraph_protocol::GraphNode>,
    profile_id: &str,
    instance_id: &str,
    depth: usize,
) -> std::result::Result<Value, String> {
    if depth > TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH {
        return Err(format!(
            "Web generic instance {instance_id} type argument nesting exceeds {TYPESCRIPT_MAX_TYPE_DESCRIPTOR_DEPTH}"
        ));
    }
    let object = descriptor.as_object().ok_or_else(|| {
        format!("Web generic instance {instance_id} has a non-object type argument")
    })?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Web generic instance {instance_id} type argument omitted kind"))?;
    let require_reference = |field: &str| -> std::result::Result<_, String> {
        let reference = object.get(field).and_then(Value::as_str).ok_or_else(|| {
            format!("Web generic instance {instance_id} {kind} type argument omitted {field}")
        })?;
        let target = resolve_web_semantic_reference(reference, protocol, nodes_by_resolver)
            .ok_or_else(|| {
                format!(
                    "Web generic instance {instance_id} type argument references missing semantic definition {reference:?}"
                )
            })?;
        if !matches!(target.kind.as_str(), "symbol" | "type")
            || target.properties.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        {
            return Err(format!(
                "Web generic instance {instance_id} type argument reference {reference:?} belongs to another profile or is not semantic"
            ));
        }
        Ok(target)
    };

    let canonical = match kind {
        "intrinsic" => {
            if !web_json_object_has_exact_fields(object, &["kind", "name"]) {
                return Err(format!(
                    "Web generic instance {instance_id} intrinsic type argument has a non-canonical shape"
                ));
            }
            let name = object.get("name").and_then(Value::as_str).ok_or_else(|| {
                format!("Web generic instance {instance_id} intrinsic type argument omitted name")
            })?;
            if !matches!(
                name,
                "any"
                    | "unknown"
                    | "string"
                    | "number"
                    | "boolean"
                    | "bigint"
                    | "symbol"
                    | "void"
                    | "undefined"
                    | "null"
                    | "never"
            ) {
                return Err(format!(
                    "Web generic instance {instance_id} has unknown intrinsic type argument {name:?}"
                ));
            }
            serde_json::json!({"kind": "intrinsic", "name": name})
        }
        "literal" => {
            if !web_json_object_has_exact_fields(object, &["kind", "value_kind", "value"]) {
                return Err(format!(
                    "Web generic instance {instance_id} literal type argument has a non-canonical shape"
                ));
            }
            let value_kind = object
                .get("value_kind")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} literal type argument omitted value_kind"
                    )
                })?;
            let value = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                format!("Web generic instance {instance_id} literal type argument omitted value")
            })?;
            if !web_literal_value_is_canonical(value_kind, value) {
                return Err(format!(
                    "Web generic instance {instance_id} has a non-canonical {value_kind:?} literal {value:?}"
                ));
            }
            serde_json::json!({"kind": "literal", "value_kind": value_kind, "value": value})
        }
        "definition" => {
            if !web_json_object_has_exact_fields(object, &["kind", "resolver_identity"]) {
                return Err(format!(
                    "Web generic instance {instance_id} definition type argument has a non-canonical shape"
                ));
            }
            let target = require_reference("resolver_identity")?;
            if target.kind != "type"
                || target.properties.get("type_kind").and_then(Value::as_str)
                    == Some("generic_instance")
            {
                return Err(format!(
                    "Web generic instance {instance_id} definition argument must reference a concrete type"
                ));
            }
            serde_json::json!({
                "kind": "definition",
                "resolver_identity": object["resolver_identity"].clone(),
            })
        }
        "type_parameter" => {
            if !web_json_object_has_exact_fields(object, &["kind", "owner", "index", "name"]) {
                return Err(format!(
                    "Web generic instance {instance_id} type parameter has a non-canonical shape"
                ));
            }
            require_reference("owner")?;
            let index = object
                .get("index")
                .and_then(Value::as_u64)
                .filter(|index| *index <= 9_007_199_254_740_991)
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} type parameter has an invalid index"
                    )
                })?;
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| {
                    !name.is_empty()
                        && name.encode_utf16().count() <= TYPESCRIPT_MAX_DISPLAY_NAME_CHARS
                })
                .ok_or_else(|| {
                    format!("Web generic instance {instance_id} type parameter has an invalid name")
                })?;
            serde_json::json!({
                "kind": "type_parameter",
                "owner": object["owner"].clone(),
                "index": index,
                "name": name,
            })
        }
        "application" => {
            if !web_json_object_has_exact_fields(object, &["kind", "target", "type_arguments"]) {
                return Err(format!(
                    "Web generic instance {instance_id} application argument has a non-canonical shape"
                ));
            }
            let target = object.get("target").ok_or_else(|| {
                format!("Web generic instance {instance_id} application argument omitted target")
            })?;
            if !matches!(
                target.get("kind").and_then(Value::as_str),
                Some("definition" | "type_parameter")
            ) {
                return Err(format!(
                    "Web generic instance {instance_id} application target is not a definition or type parameter"
                ));
            }
            let target = validate_web_type_argument_references(
                target,
                protocol,
                nodes_by_resolver,
                profile_id,
                instance_id,
                depth + 1,
            )?;
            let arguments = object
                .get("type_arguments")
                .and_then(Value::as_array)
                .filter(|arguments| {
                    !arguments.is_empty() && arguments.len() <= TYPESCRIPT_MAX_TYPE_ARGUMENTS
                })
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {instance_id} application has invalid type arguments"
                    )
                })?;
            let mut canonical_arguments = Vec::with_capacity(arguments.len());
            for argument in arguments {
                canonical_arguments.push(validate_web_type_argument_references(
                    argument,
                    protocol,
                    nodes_by_resolver,
                    profile_id,
                    instance_id,
                    depth + 1,
                )?);
            }
            serde_json::json!({
                "kind": "application",
                "target": target,
                "type_arguments": canonical_arguments,
            })
        }
        "union" | "intersection" => {
            if !web_json_object_has_exact_fields(object, &["kind", "members"]) {
                return Err(format!(
                    "Web generic instance {instance_id} {kind} has a non-canonical shape"
                ));
            }
            let members = object
                .get("members")
                .and_then(Value::as_array)
                .filter(|members| {
                    !members.is_empty() && members.len() <= TYPESCRIPT_MAX_TYPE_DESCRIPTOR_MEMBERS
                })
                .ok_or_else(|| {
                    format!("Web generic instance {instance_id} {kind} has invalid members")
                })?;
            let mut canonical_members = Vec::with_capacity(members.len());
            let mut previous = None::<String>;
            for member in members {
                let canonical_member = validate_web_type_argument_references(
                    member,
                    protocol,
                    nodes_by_resolver,
                    profile_id,
                    instance_id,
                    depth + 1,
                )?;
                let serialized = serde_json::to_string(&canonical_member)
                    .expect("canonical TypeScript type descriptors always serialize");
                if previous.as_deref().is_some_and(|previous| {
                    compare_javascript_strings(previous, &serialized) != std::cmp::Ordering::Less
                }) {
                    return Err(format!(
                        "Web generic instance {instance_id} {kind} members are not in strict canonical order"
                    ));
                }
                previous = Some(serialized);
                canonical_members.push(canonical_member);
            }
            serde_json::json!({"kind": kind, "members": canonical_members})
        }
        other => {
            return Err(format!(
                "Web generic instance {instance_id} has unsupported type argument kind {other:?}"
            ));
        }
    };
    if descriptor != &canonical {
        return Err(format!(
            "Web generic instance {instance_id} has a non-canonical {kind} type argument"
        ));
    }
    let serialized = serde_json::to_string(&canonical)
        .expect("canonical TypeScript type descriptors always serialize");
    if serialized.encode_utf16().count() > TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS {
        return Err(format!(
            "Web generic instance {instance_id} {kind} type argument exceeds {TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS} characters"
        ));
    }
    Ok(canonical)
}

pub(crate) fn validate_web_definition_graph(
    protocol: &ValidatedProtocol,
    web_profiles: &BTreeSet<String>,
    definition_profiles: &BTreeSet<String>,
    import_type_profiles: &BTreeSet<String>,
    call_profiles: &BTreeSet<String>,
    candidate_call_profiles: &BTreeSet<String>,
) -> std::result::Result<(), String> {
    let repository_identities = protocol
        .nodes
        .values()
        .filter(|node| node.kind == "workspace")
        .filter_map(|node| {
            node.properties
                .get("repository_identity")
                .and_then(Value::as_str)
        })
        .collect::<BTreeSet<_>>();
    let repository_identity = (repository_identities.len() == 1).then(|| {
        *repository_identities
            .first()
            .expect("one identity was checked")
    });

    let mut repository_packages = std::collections::BTreeMap::<String, (String, String)>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| node.kind == "package_instance")
    {
        if node.properties.get("workspace").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(locator) = node.properties.get("locator").and_then(Value::as_str) else {
            continue;
        };
        let workspace_path = node
            .properties
            .get("workspace_path")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "repository package {} omitted properties.workspace_path",
                    node.id
                )
            })?;
        if repository_packages
            .insert(
                locator.to_owned(),
                (node.id.clone(), workspace_path.to_owned()),
            )
            .is_some()
        {
            return Err(format!(
                "multiple repository package nodes claim locator {locator:?}"
            ));
        }
    }
    let mut files_by_path =
        std::collections::BTreeMap::<String, &depgraph_protocol::GraphNode>::new();
    for node in protocol.nodes.values().filter(|node| node.kind == "file") {
        let Some(path) = node.properties.get("path").and_then(Value::as_str) else {
            continue;
        };
        if files_by_path.insert(path.to_owned(), node).is_some() {
            return Err(format!(
                "multiple file nodes claim repository path {path:?}"
            ));
        }
    }
    let mut semantic_nodes_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "Web semantic node {} must declare properties.profile_id",
                    node.id
                )
            })?;
        if !definition_profiles.contains(profile_id) {
            return Err(format!(
                "Web semantic node {} references profile {profile_id:?} without the definition-graph-v1 capability",
                node.id
            ));
        }
        let language = node.properties.get("language").and_then(Value::as_str);
        if !matches!(language, Some("typescript" | "javascript")) {
            return Err(format!(
                "Web semantic node {} must declare language=typescript or javascript",
                node.id
            ));
        }
        if node.display_name.as_deref().is_none_or(|display_name| {
            display_name.is_empty()
                || display_name.encode_utf16().count() > TYPESCRIPT_MAX_DISPLAY_NAME_CHARS
        }) {
            return Err(format!(
                "Web semantic node {} has an invalid display name",
                node.id
            ));
        }
        let semantic_kind = node
            .properties
            .get(if node.kind == "symbol" {
                "symbol_kind"
            } else {
                "type_kind"
            })
            .and_then(Value::as_str)
            .expect("the semantic contract requires semantic kinds");
        let semantic_kind_is_supported = if node.kind == "symbol" {
            matches!(
                semantic_kind,
                "anonymous_function"
                    | "constructor"
                    | "function"
                    | "function_variable"
                    | "local_function"
                    | "local_function_variable"
                    | "method"
            ) || (semantic_kind == "variable" && import_type_profiles.contains(profile_id))
                || (semantic_kind == "generated_module_initializer"
                    && call_profiles.contains(profile_id))
        } else {
            matches!(
                semantic_kind,
                "class" | "enum" | "generic_instance" | "interface" | "type_alias"
            )
        };
        if !semantic_kind_is_supported {
            return Err(format!(
                "Web semantic node {} has unsupported {} {semantic_kind:?}",
                node.id, node.kind
            ));
        }
        if !web_source_span_is_canonical(node.properties.get("source_span")) {
            return Err(format!(
                "Web semantic node {} has an invalid source_span",
                node.id
            ));
        }
        let package_locator = node
            .properties
            .get("package_locator")
            .and_then(Value::as_str)
            .expect("the semantic contract requires package_locator");
        let (package_id, workspace_path) = repository_packages.get(package_locator).ok_or_else(|| {
            format!(
                "Web semantic node {} package locator {package_locator:?} is not a repository workspace package",
                node.id
            )
        })?;
        if node.properties.get("package_id").and_then(Value::as_str) != Some(package_id) {
            return Err(format!(
                "Web semantic node {} package_id does not match workspace package {}",
                node.id, package_id
            ));
        }
        let source_path = node
            .properties
            .get("source_path")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web semantic node {} omitted source_path", node.id))?;
        if !path_belongs_to_workspace(source_path, workspace_path) {
            return Err(format!(
                "Web semantic node {} source_path {source_path:?} escapes workspace path {workspace_path:?}",
                node.id
            ));
        }
        let source_file = files_by_path.get(source_path).ok_or_else(|| {
            format!(
                "Web semantic node {} source_path {source_path:?} has no repository file node",
                node.id
            )
        })?;
        if source_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            != Some(package_id)
        {
            return Err(format!(
                "Web semantic node {} and source file {} disagree on package ownership",
                node.id, source_file.id
            ));
        }
        if source_file
            .properties
            .get("language")
            .and_then(Value::as_str)
            != language
        {
            return Err(format!(
                "Web semantic node {} and source file {} disagree on language",
                node.id, source_file.id
            ));
        }
        *semantic_nodes_by_profile.entry(profile_id).or_default() += 1;
    }

    let semantic_node_ids = protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    for edge in protocol.edges.values() {
        let incident_to_definition = semantic_node_ids.contains(edge.source.as_str())
            || semantic_node_ids.contains(edge.target.as_str());
        let allowed_definition_relation = edge.phase == Phase::Semantic
            && is_web_definition_relation_kind(&edge.kind)
            && edge.site_id.is_none()
            && definition_profiles.contains(&edge.profile_id);
        let allowed_dependency_edge = edge.phase == Phase::Semantic
            && is_web_semantic_dependency_edge_kind(&edge.kind)
            && edge.site_id.is_some()
            && if edge.kind == "calls" {
                call_profiles.contains(&edge.profile_id)
            } else if edge.kind == "may_call" {
                candidate_call_profiles.contains(&edge.profile_id)
            } else {
                import_type_profiles.contains(&edge.profile_id)
            };
        let allowed_framework_edge = edge.phase == Phase::Semantic
            && is_web_framework_semantic_site_kind(&edge.kind)
            && edge.site_id.is_some();
        if incident_to_definition
            && !allowed_definition_relation
            && !allowed_dependency_edge
            && !allowed_framework_edge
        {
            return Err(format!(
                "Web edge {} incident to a semantic definition is outside its declared semantic capability",
                edge.id
            ));
        }
    }
    for site in protocol.sites.values() {
        if (semantic_node_ids.contains(site.source.as_str())
            || site
                .target_ids
                .iter()
                .any(|target| semantic_node_ids.contains(target.as_str())))
            && !(is_web_framework_semantic_site_kind(&site.kind)
                && site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
            && !(is_web_semantic_dependency_site_kind(&site.kind)
                && if site.kind == "call" {
                    if site.resolution_status == ResolutionStatus::Candidates {
                        candidate_call_profiles.contains(&site.profile_id)
                    } else {
                        call_profiles.contains(&site.profile_id)
                    }
                } else {
                    import_type_profiles.contains(&site.profile_id)
                })
        {
            return Err(format!(
                "Web dependency site {} is incident to a semantic definition node outside the import/type-use capability",
                site.id
            ));
        }
    }

    let mut nodes_by_resolver =
        std::collections::BTreeMap::<&str, &depgraph_protocol::GraphNode>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let identity = node
            .properties
            .get("canonical_identity")
            .and_then(Value::as_object)
            .expect("the semantic contract requires canonical_identity objects");
        if let Some(resolver) = identity.get("resolver_identity").and_then(Value::as_str)
            && let Some(existing) = nodes_by_resolver.insert(resolver, node)
        {
            return Err(format!(
                "Web semantic nodes {} and {} claim the same resolver identity {resolver:?}",
                existing.id, node.id
            ));
        }
    }

    let mut expected_symbol_origins = std::collections::BTreeMap::<&str, &str>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let identity = node
            .properties
            .get("canonical_identity")
            .and_then(Value::as_object)
            .expect("the semantic contract requires canonical_identity objects");
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .expect("Web semantic nodes were checked above");
        let language = node
            .properties
            .get("language")
            .and_then(Value::as_str)
            .expect("Web semantic nodes were checked above");

        if node.kind == "symbol" {
            if identity.contains_key("generic_origin")
                || identity.contains_key("type_arguments")
                || node.properties.contains_key("generic_origin")
                || node.properties.contains_key("type_arguments")
            {
                return Err(format!(
                    "Web semantic symbol {} contains generic type metadata",
                    node.id
                ));
            }
            let identity_kind = identity
                .get("identity_kind")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Web semantic symbol {} omitted canonical_identity.identity_kind",
                        node.id
                    )
                })?;
            let canonical_resolver = identity.get("resolver_identity").and_then(Value::as_str);
            let top_level_resolver = node
                .properties
                .get("resolver_identity")
                .and_then(Value::as_str);
            let origin_field = match identity_kind {
                "named" => {
                    let canonical_resolver = canonical_resolver
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                        format!(
                            "Web named symbol {} omitted canonical_identity.resolver_identity",
                            node.id
                        )
                    })?;
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "resolver_identity",
                        ],
                    ) || !web_resolver_identity_is_portable(canonical_resolver)
                        || top_level_resolver != Some(canonical_resolver)
                    {
                        return Err(format!(
                            "Web named symbol {} top-level resolver or canonical identity shape is inconsistent",
                            node.id
                        ));
                    }
                    None
                }
                "local" => {
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "enclosing_symbol",
                            "relative_path",
                            "span",
                        ],
                    ) || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web local symbol {} has a resolver or the wrong canonical origin field",
                            node.id
                        ));
                    }
                    Some("enclosing_symbol")
                }
                "anonymous" => {
                    if !web_json_object_has_exact_fields(
                        identity,
                        &[
                            "language",
                            "package_locator",
                            "symbol_kind",
                            "identity_kind",
                            "generated_from",
                            "relative_path",
                            "span",
                        ],
                    ) || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web anonymous symbol {} has a resolver or the wrong canonical origin field",
                            node.id
                        ));
                    }
                    Some("generated_from")
                }
                "generated" => {
                    if node.properties.get("symbol_kind").and_then(Value::as_str)
                        != Some("generated_module_initializer")
                        || !call_profiles.contains(profile_id)
                        || !web_json_object_has_exact_fields(
                            identity,
                            &[
                                "language",
                                "package_locator",
                                "symbol_kind",
                                "identity_kind",
                                "generated_from",
                                "relative_path",
                                "span",
                            ],
                        )
                        || node.properties.contains_key("resolver_identity")
                    {
                        return Err(format!(
                            "Web generated symbol {} has an unsupported kind, capability, resolver, or canonical identity shape",
                            node.id
                        ));
                    }
                    Some("generated_from")
                }
                other => {
                    return Err(format!(
                        "Web semantic symbol {} has unsupported identity_kind {other:?}",
                        node.id
                    ));
                }
            };
            if let Some(origin_field) = origin_field {
                let origin_id = identity
                    .get(origin_field)
                    .and_then(Value::as_str)
                    .filter(|origin_id| !origin_id.is_empty())
                    .ok_or_else(|| {
                        format!(
                            "Web {identity_kind} symbol {} omitted canonical_identity.{origin_field}",
                            node.id
                        )
                    })?;
                if identity.get("relative_path").and_then(Value::as_str)
                    != node.properties.get("source_path").and_then(Value::as_str)
                    || identity.get("span") != node.properties.get("source_span")
                {
                    return Err(format!(
                        "Web {identity_kind} symbol {} canonical source anchor disagrees with its top-level source",
                        node.id
                    ));
                }
                let origin = protocol.nodes.get(origin_id).ok_or_else(|| {
                    format!(
                        "Web semantic symbol {} references missing canonical origin {origin_id}",
                        node.id
                    )
                })?;
                let origin_kind_is_valid = match identity_kind {
                    "local" => origin.kind == "symbol",
                    "generated" => origin.kind == "file",
                    _ => matches!(origin.kind.as_str(), "file" | "symbol" | "type"),
                };
                if !origin_kind_is_valid
                    || node_package_id(origin) != node_package_id(node)
                    || origin.properties.get("language").and_then(Value::as_str) != Some(language)
                {
                    return Err(format!(
                        "Web semantic symbol {} canonical origin {} has incompatible kind, package, or language",
                        node.id, origin.id
                    ));
                }
                if matches!(origin.kind.as_str(), "symbol" | "type") {
                    if origin.properties.get("profile_id").and_then(Value::as_str)
                        != Some(profile_id)
                    {
                        return Err(format!(
                            "Web semantic symbol {} canonical origin {} belongs to another profile",
                            node.id, origin.id
                        ));
                    }
                } else if origin.properties.get("path").and_then(Value::as_str)
                    != node.properties.get("source_path").and_then(Value::as_str)
                {
                    return Err(format!(
                        "Web {identity_kind} symbol {} file origin {} does not anchor its source path",
                        node.id, origin.id
                    ));
                }
                expected_symbol_origins.insert(node.id.as_str(), origin_id);
            }
        } else {
            let type_kind = node
                .properties
                .get("type_kind")
                .and_then(Value::as_str)
                .expect("the semantic contract requires type_kind");
            let canonical_resolver = identity
                .get("resolver_identity")
                .and_then(Value::as_str)
                .filter(|resolver| !resolver.is_empty())
                .expect("the semantic contract requires type resolver identities");
            let is_generic_instance = type_kind == "generic_instance";
            let has_canonical_generic_metadata =
                identity.contains_key("generic_origin") || identity.contains_key("type_arguments");
            let has_top_level_generic_metadata = node.properties.contains_key("generic_origin")
                || node.properties.contains_key("type_arguments");
            if !is_generic_instance
                && (has_canonical_generic_metadata || has_top_level_generic_metadata)
            {
                return Err(format!(
                    "Web non-generic type {} contains generic origin or type argument metadata",
                    node.id
                ));
            }
            let expected_identity_fields: &[&str] = if is_generic_instance {
                &[
                    "language",
                    "package_locator",
                    "type_kind",
                    "resolver_identity",
                    "generic_origin",
                    "type_arguments",
                ]
            } else {
                &[
                    "language",
                    "package_locator",
                    "type_kind",
                    "resolver_identity",
                ]
            };
            if !web_json_object_has_exact_fields(identity, expected_identity_fields)
                || canonical_resolver.encode_utf16().count()
                    > TYPESCRIPT_MAX_RESOLVER_IDENTITY_CHARS
                || (!is_generic_instance && !web_resolver_identity_is_portable(canonical_resolver))
                || node
                    .properties
                    .get("resolver_identity")
                    .and_then(Value::as_str)
                    != Some(canonical_resolver)
            {
                return Err(format!(
                    "Web type {} top-level resolver identity disagrees with its canonical identity",
                    node.id
                ));
            }
            if !is_generic_instance {
                continue;
            }
            let generic_origin = identity
                .get("generic_origin")
                .and_then(Value::as_str)
                .filter(|origin| !origin.is_empty())
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {} omitted canonical_identity.generic_origin",
                        node.id
                    )
                })?;
            let type_arguments = identity
                .get("type_arguments")
                .filter(|arguments| {
                    arguments.as_array().is_some_and(|arguments| {
                        !arguments.is_empty() && arguments.len() <= TYPESCRIPT_MAX_TYPE_ARGUMENTS
                    })
                })
                .ok_or_else(|| {
                    format!(
                        "Web generic instance {} omitted canonical_identity.type_arguments",
                        node.id
                    )
                })?;
            let mut canonical_type_arguments = Vec::with_capacity(
                type_arguments
                    .as_array()
                    .expect("generic type arguments were checked above")
                    .len(),
            );
            for argument in type_arguments
                .as_array()
                .expect("generic type arguments were checked above")
            {
                canonical_type_arguments.push(validate_web_type_argument_references(
                    argument,
                    protocol,
                    &nodes_by_resolver,
                    profile_id,
                    &node.id,
                    0,
                )?);
            }
            let canonical_type_arguments = Value::Array(canonical_type_arguments);
            if type_arguments != &canonical_type_arguments {
                return Err(format!(
                    "Web generic instance {} type arguments are not in canonical materialized form",
                    node.id
                ));
            }
            if node
                .properties
                .get("generic_origin")
                .and_then(Value::as_str)
                != Some(generic_origin)
                || node.properties.get("type_arguments") != Some(&canonical_type_arguments)
            {
                return Err(format!(
                    "Web generic instance {} top-level origin/type arguments disagree with its canonical identity",
                    node.id
                ));
            }
            let resolver_input = Value::Array(vec![
                Value::String(generic_origin.to_owned()),
                canonical_type_arguments,
            ]);
            let expected_resolver = format!(
                "generic:{}",
                serde_json::to_string(&resolver_input)
                    .expect("canonical generic resolver input always serializes")
            );
            if identity.get("resolver_identity").and_then(Value::as_str)
                != Some(expected_resolver.as_str())
                || node
                    .properties
                    .get("resolver_identity")
                    .and_then(Value::as_str)
                    != Some(expected_resolver.as_str())
            {
                return Err(format!(
                    "Web generic instance {} resolver identity does not match its origin and type arguments",
                    node.id
                ));
            }
            let origin = nodes_by_resolver.get(generic_origin).copied().ok_or_else(|| {
                format!(
                    "Web generic instance {} references missing generic origin {generic_origin:?}",
                    node.id
                )
            })?;
            if origin.kind != "type"
                || origin.properties.get("type_kind").and_then(Value::as_str)
                    == Some("generic_instance")
                || origin.properties.get("profile_id").and_then(Value::as_str) != Some(profile_id)
                || node_package_id(origin) != node_package_id(node)
                || origin
                    .properties
                    .get("package_locator")
                    .and_then(Value::as_str)
                    != node
                        .properties
                        .get("package_locator")
                        .and_then(Value::as_str)
                || origin.properties.get("language").and_then(Value::as_str) != Some(language)
                || origin.properties.get("source_path") != node.properties.get("source_path")
                || origin.properties.get("source_span") != node.properties.get("source_span")
            {
                return Err(format!(
                    "Web generic instance {} origin {} is not a same-profile/package/language/source concrete type",
                    node.id, origin.id
                ));
            }
        }
    }

    let mut semantic_relations_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    let mut declared_targets = BTreeSet::<&str>::new();
    let mut declaration_sources_by_target =
        std::collections::BTreeMap::<&str, BTreeSet<&str>>::new();
    let mut canonically_anchored_declaration_targets = BTreeSet::<&str>::new();
    let mut instantiated_targets = BTreeSet::<&str>::new();
    for edge in protocol
        .edges
        .values()
        .filter(|edge| edge.phase == Phase::Semantic && is_web_definition_relation_kind(&edge.kind))
    {
        if !definition_profiles.contains(&edge.profile_id) {
            return Err(format!(
                "Web semantic edge {} references profile {:?} without the definition-graph-v1 capability",
                edge.id, edge.profile_id
            ));
        }
        if !is_web_definition_relation_kind(&edge.kind) {
            return Err(format!(
                "Web definition-graph-v1 profile emitted forbidden semantic edge kind {:?}",
                edge.kind
            ));
        }
        let primary = edge
            .evidence
            .first()
            .expect("the semantic contract requires primary evidence");
        if primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
            || primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
        {
            return Err(format!(
                "Web semantic edge {} must use {}@{} primary evidence",
                edge.id, TYPESCRIPT_SEMANTIC_EXTRACTOR, TYPESCRIPT_COMPILER_VERSION
            ));
        }
        if primary.properties.get("profile_id").and_then(Value::as_str)
            != Some(edge.profile_id.as_str())
        {
            return Err(format!(
                "Web semantic edge {} primary evidence must declare profile_id={:?}",
                edge.id, edge.profile_id
            ));
        }
        if edge.environment.as_deref() != Some("any") {
            return Err(format!(
                "Web semantic definition relation {} must use environment=any",
                edge.id
            ));
        }
        let source = protocol
            .nodes
            .get(&edge.source)
            .expect("the base protocol requires relation sources");
        let target = protocol
            .nodes
            .get(&edge.target)
            .expect("the base protocol requires relation targets");
        for endpoint in [source, target]
            .into_iter()
            .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
        {
            if endpoint
                .properties
                .get("profile_id")
                .and_then(Value::as_str)
                != Some(edge.profile_id.as_str())
            {
                return Err(format!(
                    "Web semantic relation {} endpoint {} belongs to another profile",
                    edge.id, endpoint.id
                ));
            }
        }
        let endpoints_are_valid = match edge.kind.as_str() {
            "declares" => {
                matches!(source.kind.as_str(), "file" | "symbol" | "type")
                    && matches!(target.kind.as_str(), "symbol" | "type")
            }
            "extends" | "implements" => source.kind == "type" && target.kind == "type",
            "instantiates" => {
                matches!(source.kind.as_str(), "symbol" | "type")
                    && target.kind == "type"
                    && target.properties.get("type_kind").and_then(Value::as_str)
                        == Some("generic_instance")
            }
            _ => false,
        };
        if !endpoints_are_valid {
            return Err(format!(
                "Web semantic definition relation {} of kind {} has incompatible or non-repository endpoints {} ({}) -> {} ({})",
                edge.id, edge.kind, source.id, source.kind, target.id, target.kind
            ));
        }
        let evidence_file = files_by_path
            .get(primary.path.as_deref().unwrap_or_default())
            .ok_or_else(|| {
                format!(
                    "Web semantic relation {} evidence path {:?} has no repository file node",
                    edge.id, primary.path
                )
            })?;
        let evidence_package = evidence_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web evidence file {} omitted package_id", evidence_file.id))?;
        match edge.kind.as_str() {
            "declares" => {
                if node_package_id(target) != Some(evidence_package) {
                    return Err(format!(
                        "Web declares relation {} target and evidence file disagree on package ownership",
                        edge.id
                    ));
                }
                if target.properties.get("source_path").and_then(Value::as_str)
                    != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web declares relation {} target does not anchor its evidence path",
                        edge.id
                    ));
                }
                if source.kind == "file" {
                    if source.id != evidence_file.id {
                        return Err(format!(
                            "Web declares relation {} source file does not anchor its evidence",
                            edge.id
                        ));
                    }
                } else if node_package_id(source) != Some(evidence_package)
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web declares relation {} semantic owner does not anchor its evidence",
                        edge.id
                    ));
                }
                declared_targets.insert(target.id.as_str());
                declaration_sources_by_target
                    .entry(target.id.as_str())
                    .or_default()
                    .insert(source.id.as_str());
                if target
                    .properties
                    .get("source_span")
                    .is_some_and(|span| web_evidence_matches_source_span(primary, span))
                {
                    canonically_anchored_declaration_targets.insert(target.id.as_str());
                }
            }
            "extends" | "implements" | "instantiates" => {
                if node_package_id(source) != Some(evidence_package)
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != primary.path.as_deref()
                {
                    return Err(format!(
                        "Web {} relation {} source does not anchor its evidence",
                        edge.kind, edge.id
                    ));
                }
                if edge.kind == "instantiates" {
                    instantiated_targets.insert(target.id.as_str());
                }
            }
            _ => unreachable!("definition relation kinds were checked above"),
        }
        *semantic_relations_by_profile
            .entry(edge.profile_id.as_str())
            .or_default() += 1;
    }

    for node in protocol
        .nodes
        .values()
        .filter(|node| matches!(node.kind.as_str(), "symbol" | "type"))
    {
        let instance = node.kind == "type"
            && node.properties.get("type_kind").and_then(Value::as_str) == Some("generic_instance");
        let owned = if instance {
            instantiated_targets.contains(node.id.as_str())
        } else {
            declared_targets.contains(node.id.as_str())
        };
        if !owned {
            return Err(format!(
                "Web semantic node {} has no canonical {} owner relation",
                node.id,
                if instance { "instantiates" } else { "declares" }
            ));
        }
        if !instance && !canonically_anchored_declaration_targets.contains(node.id.as_str()) {
            return Err(format!(
                "Web semantic node {} has no declares evidence matching its canonical source span",
                node.id
            ));
        }
        if let Some(expected_origin) = expected_symbol_origins.get(node.id.as_str()) {
            let declaration_sources = declaration_sources_by_target
                .get(node.id.as_str())
                .expect("owned local/anonymous symbols have declares relations");
            if declaration_sources.len() != 1 || !declaration_sources.contains(*expected_origin) {
                return Err(format!(
                    "Web semantic symbol {} declares owner does not match canonical origin {}",
                    node.id, expected_origin
                ));
            }
        }
    }

    let repository_package_ids = repository_packages
        .values()
        .map(|(package_id, _)| package_id.as_str())
        .collect::<BTreeSet<_>>();
    let semantic_dependency_edges = protocol
        .edges
        .values()
        .filter(|edge| {
            edge.phase == Phase::Semantic && is_web_semantic_dependency_edge_kind(&edge.kind)
        })
        .collect::<Vec<_>>();
    let mut semantic_sites_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    let mut semantic_call_sites_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for site in protocol.sites.values().filter(|site| {
        is_web_semantic_dependency_site_kind(&site.kind)
            && site
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
    }) {
        let authorized = if site.kind == "call" {
            if site.resolution_status == ResolutionStatus::Candidates {
                candidate_call_profiles.contains(&site.profile_id)
            } else {
                call_profiles.contains(&site.profile_id)
            }
        } else {
            import_type_profiles.contains(&site.profile_id)
        };
        if !authorized {
            return Err(format!(
                "Web semantic dependency site {} references profile {:?} without its required cumulative semantic capability",
                site.id, site.profile_id
            ));
        }
        let expected_edge_kind = web_semantic_edge_kind_for_site(&site.kind, site.resolution_status).ok_or_else(|| {
            format!(
                "Web cumulative semantic profile emitted forbidden semantic dependency site kind {:?}",
                site.kind
            )
        })?;
        if site.kind == "call"
            && ((site.resolution_status == ResolutionStatus::Candidates
                && (site.precision != Precision::Overapprox || site.target_ids.is_empty()))
                || (site.resolution_status != ResolutionStatus::Candidates
                    && (site.precision == Precision::Overapprox || site.target_ids.len() != 1)))
        {
            return Err(format!(
                "Web semantic call site {} has an invalid candidate target or precision shape",
                site.id
            ));
        }
        if site.kind == "call"
            && site.resolution_status == ResolutionStatus::Candidates
            && site.reason.is_some()
        {
            return Err(format!(
                "Web candidate call site {} must not include a reason",
                site.id
            ));
        }
        let primary = site
            .evidence
            .first()
            .expect("semantic dependency sites include primary evidence");
        if primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
            || primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
        {
            return Err(format!(
                "Web semantic dependency site {} must use {}@{} primary evidence",
                site.id, TYPESCRIPT_SEMANTIC_EXTRACTOR, TYPESCRIPT_COMPILER_VERSION
            ));
        }
        if primary.properties.get("profile_id").and_then(Value::as_str)
            != Some(site.profile_id.as_str())
        {
            return Err(format!(
                "Web semantic dependency site {} primary evidence must declare profile_id={:?}",
                site.id, site.profile_id
            ));
        }
        let occurrence_kind = primary
            .properties
            .get("occurrence_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let module_specifier = web_optional_evidence_string(
            &primary.properties,
            "module_specifier",
            TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS,
            true,
        )
        .map_err(|()| {
            format!(
                "Web semantic dependency site {} has invalid module_specifier metadata",
                site.id
            )
        })?;
        if site.kind == "call" {
            let call_kind = primary
                .properties
                .get("call_kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let dispatch = primary
                .properties
                .get("dispatch")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let algorithm = primary.properties.get("algorithm").and_then(Value::as_str);
            let call_kind_is_valid = matches!(
                call_kind,
                "function" | "method" | "constructor" | "tagged_template"
            ) && (occurrence_kind != "new_expression"
                || call_kind == "constructor")
                && (occurrence_kind != "tagged_template" || call_kind == "tagged_template");
            let dispatch_is_valid = match site.resolution_status {
                ResolutionStatus::Resolved => {
                    site.precision == Precision::Exact
                        && matches!(
                            dispatch,
                            "direct" | "static" | "private" | "fresh_instance" | "super"
                        )
                }
                ResolutionStatus::External => {
                    matches!(site.precision, Precision::Exact | Precision::Heuristic)
                        && dispatch == "external"
                }
                ResolutionStatus::Unresolved => {
                    site.precision == Precision::Heuristic && matches!(dispatch, "dynamic" | "open")
                }
                ResolutionStatus::Candidates => {
                    site.precision == Precision::Overapprox
                        && match dispatch {
                            "dynamic" => {
                                algorithm == Some(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM)
                            }
                            "fresh_instance" => {
                                algorithm
                                    == Some(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM)
                                    && matches!(call_kind, "method" | "tagged_template")
                                    && occurrence_kind != "new_expression"
                            }
                            _ => false,
                        }
                }
            };
            if !call_kind_is_valid
                || !dispatch_is_valid
                || (site.resolution_status != ResolutionStatus::Candidates
                    && primary.properties.contains_key("algorithm"))
                || primary.properties.contains_key("type_only")
                || primary.properties.contains_key("imported_name")
                || primary.properties.contains_key("resolution_mode")
            {
                return Err(format!(
                    "Web semantic call site {} has invalid call_kind {call_kind:?}, dispatch {dispatch:?}, algorithm {algorithm:?}, or import-only metadata",
                    site.id
                ));
            }
        } else {
            let type_only = primary
                .properties
                .get("type_only")
                .and_then(Value::as_bool)
                .ok_or_else(|| {
                    format!(
                        "Web semantic dependency site {} primary evidence must declare boolean type_only",
                        site.id
                    )
                })?;
            if (site.kind == "type_use" || occurrence_kind == "import_type") && !type_only {
                return Err(format!(
                    "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} must use type_only=true",
                    site.id
                ));
            }
            if matches!(
                occurrence_kind,
                "side_effect_import" | "require_call" | "dynamic_import"
            ) && type_only
            {
                return Err(format!(
                    "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} must use type_only=false",
                    site.id
                ));
            }
            let imported_name = web_optional_evidence_string(
                &primary.properties,
                "imported_name",
                TYPESCRIPT_MAX_DISPLAY_NAME_CHARS,
                true,
            )
            .map_err(|()| {
                format!(
                    "Web semantic dependency site {} has invalid imported_name metadata",
                    site.id
                )
            })?;
            let resolution_mode = match primary.properties.get("resolution_mode") {
                None => None,
                Some(value) => match value.as_str() {
                    Some(mode @ ("import" | "require")) => Some(mode),
                    _ => {
                        return Err(format!(
                            "Web semantic dependency site {} has invalid resolution_mode metadata",
                            site.id
                        ));
                    }
                },
            };
            if resolution_mode.is_some() && (!type_only || module_specifier.is_none()) {
                return Err(format!(
                    "Web semantic dependency site {} resolution_mode contradicts its occurrence",
                    site.id
                ));
            }
            if resolution_mode.is_some() && occurrence_kind == "import_equals" {
                return Err(format!(
                    "Web semantic dependency site {} import_equals occurrence cannot expose resolution_mode",
                    site.id
                ));
            }
            let named_binding = matches!(
                occurrence_kind,
                "default_import" | "named_import" | "named_reexport"
            );
            let namespace_binding =
                matches!(occurrence_kind, "namespace_import" | "namespace_reexport");
            let module_only = matches!(
                occurrence_kind,
                "side_effect_import"
                    | "empty_import"
                    | "require_call"
                    | "dynamic_import"
                    | "import_type"
                    | "empty_reexport"
                    | "export_star"
            );
            let metadata_shape_is_valid = (site.kind == "type_use" || module_specifier.is_some())
                && (site.kind != "type_use" || imported_name.is_some())
                && (!named_binding || imported_name.is_some())
                && (!namespace_binding || imported_name == Some("*"))
                && (!module_only || imported_name.is_none())
                && (occurrence_kind != "default_import" || imported_name == Some("default"))
                && (occurrence_kind != "import_equals" || imported_name == Some("="))
                && if site.kind == "type_use" {
                    imported_name == Some(site.specifier.as_str())
                } else {
                    module_specifier == Some(site.specifier.as_str())
                };
            if !metadata_shape_is_valid {
                return Err(format!(
                    "Web semantic dependency site {} binding metadata does not match occurrence_kind {:?} or specifier {:?}",
                    site.id, occurrence_kind, site.specifier
                ));
            }
        }
        let expected_analysis_mode = if call_profiles.contains(&site.profile_id) {
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH
        } else {
            TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH
        };
        if primary.properties.get("backend").and_then(Value::as_str)
            != Some(TYPESCRIPT_SEMANTIC_BACKEND)
            || primary
                .properties
                .get("compiler_source")
                .and_then(Value::as_str)
                != Some("bundled")
            || primary
                .properties
                .get("compiler_version")
                .and_then(Value::as_str)
                != Some(TYPESCRIPT_COMPILER_VERSION)
            || primary
                .properties
                .get("analysis_mode")
                .and_then(Value::as_str)
                != Some(expected_analysis_mode)
            || primary
                .properties
                .get("project_code_executed")
                .and_then(Value::as_bool)
                != Some(false)
            || !web_occurrence_kind_matches_site(&site.kind, occurrence_kind)
        {
            return Err(format!(
                "Web semantic dependency site {} has invalid compiler provenance or occurrence_kind {:?}",
                site.id, occurrence_kind
            ));
        }
        if !web_has_matching_source_support(
            &site.evidence,
            primary,
            &site.profile_id,
            occurrence_kind,
        ) {
            return Err(format!(
                "Web semantic dependency site {} must include matching source supporting evidence",
                site.id
            ));
        }
        let evidence_path = primary
            .path
            .as_deref()
            .expect("semantic contract requires a primary evidence path");
        let evidence_file = files_by_path.get(evidence_path).ok_or_else(|| {
            format!(
                "Web semantic dependency site {} evidence path {evidence_path:?} has no repository file node",
                site.id
            )
        })?;
        let source = protocol
            .nodes
            .get(&site.source)
            .expect("base protocol requires dependency site sources");
        let source_language = source.properties.get("language").and_then(Value::as_str);
        if !matches!(source_language, Some("typescript" | "javascript")) {
            return Err(format!(
                "Web semantic dependency site {} source {} must declare language=typescript or javascript",
                site.id, source.id
            ));
        }
        let source_package = source
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "Web semantic dependency site {} source {} omitted package_id",
                    site.id, source.id
                )
            })?;
        if !repository_package_ids.contains(source_package) {
            return Err(format!(
                "Web semantic dependency site {} source {} is not owned by a repository workspace package",
                site.id, source.id
            ));
        }
        if evidence_file
            .properties
            .get("package_id")
            .and_then(Value::as_str)
            != Some(source_package)
            || evidence_file
                .properties
                .get("language")
                .and_then(Value::as_str)
                != source_language
        {
            return Err(format!(
                "Web semantic dependency site {} source and evidence file disagree on package ownership or language",
                site.id
            ));
        }
        match site.kind.as_str() {
            "web_import" | "web_reexport" => {
                if source.kind != "file"
                    || source.properties.get("path").and_then(Value::as_str) != Some(evidence_path)
                    || source.id != evidence_file.id
                {
                    return Err(format!(
                        "Web semantic {} site {} source must be its evidence file",
                        site.kind, site.id
                    ));
                }
            }
            "type_use" => match source.kind.as_str() {
                "file" => {
                    if source.properties.get("path").and_then(Value::as_str) != Some(evidence_path)
                        || source.id != evidence_file.id
                    {
                        return Err(format!(
                            "Web semantic type-use site {} file fallback does not anchor its evidence",
                            site.id
                        ));
                    }
                }
                "symbol" | "type" => {
                    if source.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                        || source.properties.get("source_path").and_then(Value::as_str)
                            != Some(evidence_path)
                    {
                        return Err(format!(
                            "Web semantic type-use site {} owner {} belongs to another profile or source file",
                            site.id, source.id
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "Web semantic type-use site {} source {} must be a file, symbol, or type",
                        site.id, source.id
                    ));
                }
            },
            "call" => {
                if source.kind != "symbol"
                    || source
                        .properties
                        .get("symbol_kind")
                        .and_then(Value::as_str)
                        .is_none_or(|symbol_kind| !is_web_call_source_symbol_kind(symbol_kind))
                    || source.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                    || source.properties.get("source_path").and_then(Value::as_str)
                        != Some(evidence_path)
                {
                    return Err(format!(
                        "Web semantic call site {} source {} must be a same-profile callable symbol anchored to its evidence file",
                        site.id, source.id
                    ));
                }
            }
            _ => unreachable!("Web semantic site kinds were checked above"),
        }

        if matches!(
            site.resolution_status,
            ResolutionStatus::Resolved | ResolutionStatus::Candidates
        ) {
            let has_file_target = site.target_ids.iter().any(|target_id| {
                protocol
                    .nodes
                    .get(target_id)
                    .is_some_and(|target| target.kind == "file")
            });
            let has_definition_target = site.target_ids.iter().any(|target_id| {
                protocol
                    .nodes
                    .get(target_id)
                    .is_some_and(|target| matches!(target.kind.as_str(), "symbol" | "type"))
            });
            if has_file_target && has_definition_target {
                return Err(format!(
                    "Web semantic dependency site {} mixes repository module and canonical definition targets",
                    site.id
                ));
            }
        }

        for target_id in &site.target_ids {
            let target = protocol
                .nodes
                .get(target_id)
                .expect("base protocol requires dependency site targets");
            match site.resolution_status {
                ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                    let valid_kind =
                        if web_occurrence_requires_repository_module(&site.kind, occurrence_kind) {
                            target.kind == "file"
                        } else if site.kind == "call" {
                            target.kind == "symbol"
                                && target
                                    .properties
                                    .get("symbol_kind")
                                    .and_then(Value::as_str)
                                    .is_some_and(is_web_callable_symbol_kind)
                        } else if site.kind == "type_use" {
                            target.kind == "type"
                        } else {
                            matches!(target.kind.as_str(), "file" | "symbol" | "type")
                        };
                    if !valid_kind {
                        if site.kind == "call" {
                            return Err(format!(
                                "Web semantic call site {} resolved target {} must be a canonical callable symbol",
                                site.id, target.id
                            ));
                        }
                        return Err(format!(
                            "Web semantic dependency site {} concrete target {} has incompatible kind {}",
                            site.id, target.id, target.kind
                        ));
                    }
                    if target.kind == "file" {
                        if !web_occurrence_requires_repository_module(&site.kind, occurrence_kind) {
                            return Err(format!(
                                "Web semantic dependency site {} occurrence_kind {occurrence_kind:?} cannot weaken a named binding target to a repository file",
                                site.id
                            ));
                        }
                        let target_path = target
                            .properties
                            .get("path")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                format!(
                                    "Web semantic dependency site {} target file {} omitted path",
                                    site.id, target.id
                                )
                            })?;
                        if files_by_path
                            .get(target_path)
                            .copied()
                            .map(|file| file.id.as_str())
                            != Some(target.id.as_str())
                            || target
                                .properties
                                .get("package_id")
                                .and_then(Value::as_str)
                                .is_none_or(|package_id| {
                                    !repository_package_ids.contains(package_id)
                                })
                            || !matches!(
                                target.properties.get("language").and_then(Value::as_str),
                                Some("typescript" | "javascript")
                            )
                        {
                            return Err(format!(
                                "Web semantic dependency site {} target file {} is not a repository TypeScript/JavaScript file",
                                site.id, target.id
                            ));
                        }
                    } else if target.properties.get("profile_id").and_then(Value::as_str)
                        != Some(site.profile_id.as_str())
                    {
                        return Err(format!(
                            "Web semantic dependency site {} target {} belongs to another profile",
                            site.id, target.id
                        ));
                    }
                }
                ResolutionStatus::External => {
                    let canonical_identity = target
                        .properties
                        .get("canonical_identity")
                        .and_then(Value::as_object);
                    let canonical_identity_is_valid = canonical_identity.is_some_and(|identity| {
                        web_json_object_has_exact_fields(
                            identity,
                            &["language", "compiler_version", "locator"],
                        ) && identity.get("language").and_then(Value::as_str) == Some("typescript")
                            && identity.get("compiler_version").and_then(Value::as_str)
                                == Some(TYPESCRIPT_COMPILER_VERSION)
                            && identity.get("locator").and_then(Value::as_str).is_some_and(
                                |locator| {
                                    !locator.is_empty()
                                        && locator.encode_utf16().count()
                                            <= TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS
                                },
                            )
                    });
                    let expected_external_id = canonical_identity.map(|identity| {
                        depgraph_protocol::stable_id_from_value(
                            "external",
                            &Value::Object(identity.clone()),
                        )
                    });
                    let external_locator = canonical_identity
                        .and_then(|identity| identity.get("locator"))
                        .and_then(Value::as_str);
                    let expected_locator = external_locator.map(|locator| {
                        format!(
                            "external://typescript/{}",
                            javascript_encode_uri_component(locator)
                        )
                    });
                    if target.kind != "external_system"
                        || target.properties.get("workspace").and_then(Value::as_bool) == Some(true)
                        || target.properties.get("external").and_then(Value::as_bool) != Some(true)
                        || target.properties.get("language").and_then(Value::as_str)
                            != Some("typescript")
                        || target.properties.get("profile_id").and_then(Value::as_str)
                            != Some(site.profile_id.as_str())
                        || target
                            .properties
                            .get("compiler_version")
                            .and_then(Value::as_str)
                            != Some(TYPESCRIPT_COMPILER_VERSION)
                        || !canonical_identity_is_valid
                        || expected_external_id.as_deref() != Some(target.id.as_str())
                        || expected_locator.as_deref() != Some(target.locator.as_str())
                        || external_locator != target.display_name.as_deref()
                    {
                        return Err(format!(
                            "Web semantic external site {} must target its canonical profile-scoped TypeScript external_system sentinel",
                            site.id
                        ));
                    }
                }
                ResolutionStatus::Unresolved => {
                    let repository_identity = repository_identity.ok_or_else(|| {
                        format!(
                            "Web semantic unresolved site {} requires exactly one repository identity",
                            site.id
                        )
                    })?;
                    let expected_unknown_id = depgraph_protocol::stable_id_from_value(
                        "unknown",
                        &serde_json::json!({
                            "repository": repository_identity,
                            "profile": site.profile_id,
                            "language": "web",
                            "identity": "unresolved_dependency_target",
                        }),
                    );
                    if target.kind != "unknown_target"
                        || target.id != expected_unknown_id
                        || target.locator != "unknown://web/unresolved-dependency"
                        || target.display_name.as_deref() != Some("Unresolved web dependency")
                        || target.properties.len() != 2
                        || target.properties.get("language").and_then(Value::as_str) != Some("web")
                        || target.properties.get("profile_id").and_then(Value::as_str)
                            != Some(site.profile_id.as_str())
                    {
                        return Err(format!(
                            "Web semantic unresolved site {} must target its profile-scoped Web unknown_target sentinel",
                            site.id
                        ));
                    }
                }
            }
        }
        let expected_target_basis = match site.resolution_status {
            ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                if site.target_ids.iter().any(|target_id| {
                    protocol
                        .nodes
                        .get(target_id)
                        .is_some_and(|target| target.kind == "file")
                }) {
                    "repository_module"
                } else {
                    "canonical_definition"
                }
            }
            ResolutionStatus::External => "external_boundary",
            ResolutionStatus::Unresolved => "unresolved",
        };
        if primary
            .properties
            .get("target_basis")
            .and_then(Value::as_str)
            != Some(expected_target_basis)
        {
            return Err(format!(
                "Web semantic dependency site {} target_basis does not match its status and targets; expected {expected_target_basis:?}",
                site.id
            ));
        }

        let linked_edges = semantic_dependency_edges
            .iter()
            .copied()
            .filter(|edge| edge.site_id.as_deref() == Some(site.id.as_str()))
            .collect::<Vec<_>>();
        if linked_edges.len() != site.target_ids.len() {
            return Err(format!(
                "Web semantic dependency site {} has {} targets but {} semantic dependency edges",
                site.id,
                site.target_ids.len(),
                linked_edges.len()
            ));
        }
        if site.kind == "call" {
            if linked_edges
                .iter()
                .any(|edge| edge.condition.canonicalized() != site.condition.canonicalized())
            {
                return Err(format!(
                    "Web semantic call edge condition does not match dependency site {}",
                    site.id
                ));
            }
        } else {
            let edge_condition_union = Condition::Any {
                conditions: linked_edges
                    .iter()
                    .map(|edge| edge.condition.clone())
                    .collect(),
            }
            .canonicalized();
            if edge_condition_union != site.condition.canonicalized() {
                return Err(format!(
                    "Web semantic dependency site {} condition is not the union of its target edge conditions",
                    site.id
                ));
            }
        }
        for edge in linked_edges {
            if edge.kind != expected_edge_kind
                || edge.source != site.source
                || edge.profile_id != site.profile_id
                || edge.resolution_status != site.resolution_status
                || edge.precision != site.precision
            {
                return Err(format!(
                    "Web semantic edge {} does not match dependency site {} kind/source/profile/status/precision",
                    edge.id, site.id
                ));
            }
            if edge.environment.as_deref() != Some("any") {
                return Err(format!(
                    "Web semantic dependency edge {} must use environment=any",
                    edge.id
                ));
            }
            let edge_primary = edge
                .evidence
                .first()
                .expect("semantic contract requires primary edge evidence");
            if edge.evidence != site.evidence
                || edge_primary.extractor != TYPESCRIPT_SEMANTIC_EXTRACTOR
                || edge_primary.extractor_version != TYPESCRIPT_COMPILER_VERSION
                || edge_primary
                    .properties
                    .get("profile_id")
                    .and_then(Value::as_str)
                    != Some(site.profile_id.as_str())
            {
                return Err(format!(
                    "Web semantic dependency edge {} has invalid TypeChecker provenance",
                    edge.id
                ));
            }
            *semantic_relations_by_profile
                .entry(edge.profile_id.as_str())
                .or_default() += 1;
        }
        *semantic_sites_by_profile
            .entry(site.profile_id.as_str())
            .or_default() += 1;
        if site.kind == "call" {
            *semantic_call_sites_by_profile
                .entry(site.profile_id.as_str())
                .or_default() += 1;
        }
    }
    for edge in semantic_dependency_edges {
        if edge.site_id.as_deref().is_none_or(|site_id| {
            protocol.sites.get(site_id).is_none_or(|site| {
                site.evidence
                    .first()
                    .is_none_or(|evidence| evidence.kind != EvidenceKind::Semantic)
            })
        }) {
            return Err(format!(
                "Web semantic dependency edge {} is not linked to a semantic dependency site",
                edge.id
            ));
        }
    }

    let mut semantic_issues_by_profile = std::collections::BTreeMap::<&str, usize>::new();
    for diagnostic in protocol.diagnostics.values().filter(|diagnostic| {
        [
            TYPESCRIPT_DEFINITION_ISSUE_PROPERTY,
            TYPESCRIPT_DEPENDENCY_ISSUE_PROPERTY,
        ]
        .iter()
        .any(|property| {
            diagnostic
                .properties
                .get(*property)
                .and_then(Value::as_bool)
                == Some(true)
        })
    }) {
        let profile_id = diagnostic.profile_id.as_deref().ok_or_else(|| {
            format!(
                "TypeScript semantic issue diagnostic {} omitted profile_id",
                diagnostic.id
            )
        })?;
        if !web_profiles.contains(profile_id) {
            return Err(format!(
                "TypeScript semantic issue diagnostic {} references unknown profile {profile_id:?}",
                diagnostic.id
            ));
        }
        *semantic_issues_by_profile.entry(profile_id).or_default() += 1;
    }

    for profile_id in web_profiles {
        let profile = protocol
            .profiles
            .get(profile_id)
            .expect("Web capability was recorded from a declared profile");
        for (property, actual) in [
            (
                "typescript_semantic_node_count",
                semantic_nodes_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                "typescript_semantic_relation_count",
                semantic_relations_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                "typescript_semantic_issue_count",
                semantic_issues_by_profile
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
        ] {
            let declared = profile
                .properties
                .get(property)
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or_else(|| {
                    format!("Web profile {profile_id:?} omitted or has invalid {property}")
                })?;
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {property}={declared}, observed {actual}"
                ));
            }
        }
        let semantic_site_count = profile
            .properties
            .get(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok());
        let capability = web_semantic_capability(&profile.properties)
            .expect("Web profiles were validated before graph validation");
        let declares_import_type_capability = matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        );
        if declares_import_type_capability {
            let declared = semantic_site_count.ok_or_else(|| {
                format!(
                    "Web profile {profile_id:?} omitted or has invalid {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}"
                )
            })?;
            let actual = semantic_sites_by_profile
                .get(profile_id.as_str())
                .copied()
                .unwrap_or_default();
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}={declared}, observed {actual}"
                ));
            }
        } else if semantic_site_count.is_some() {
            return Err(format!(
                "Web definition-graph-v1 profile {profile_id:?} must not declare {TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY}"
            ));
        }
        let semantic_call_site_count = profile
            .properties
            .get(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<usize>().ok());
        if matches!(
            capability,
            WebSemanticCapability::DefinitionImportTypeCallGraphV1
                | WebSemanticCapability::DefinitionImportTypeCallGraphV2
        ) {
            let declared = semantic_call_site_count.ok_or_else(|| {
                format!(
                    "Web profile {profile_id:?} omitted or has invalid {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}"
                )
            })?;
            let actual = semantic_call_sites_by_profile
                .get(profile_id.as_str())
                .copied()
                .unwrap_or_default();
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}={declared}, observed {actual}"
                ));
            }
        } else if semantic_call_site_count.is_some() {
            return Err(format!(
                "Web profile {profile_id:?} without the call-graph capability must not declare {TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_web_framework_semantic_graph(
    protocol: &ValidatedProtocol,
    states: &std::collections::BTreeMap<String, WebFrameworkSemanticState>,
) -> std::result::Result<(), String> {
    let mut node_counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut site_counts = std::collections::BTreeMap::<&str, usize>::new();
    let mut edge_counts = std::collections::BTreeMap::<&str, usize>::new();
    for node in protocol
        .nodes
        .values()
        .filter(|node| is_web_framework_semantic_node(node))
    {
        let profile_id = node
            .properties
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Web framework semantic node {} omitted profile_id", node.id))?;
        if states.get(profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic node {} is not authorized by an emitted v1 capability",
                node.id
            ));
        }
        *node_counts.entry(profile_id).or_default() += 1;
    }
    for site in protocol.sites.values().filter(|site| {
        is_web_framework_semantic_site_kind(&site.kind)
            && site
                .evidence
                .first()
                .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic)
    }) {
        if states.get(&site.profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic site {} is not authorized by an emitted v1 capability",
                site.id
            ));
        }
        let primary = site
            .evidence
            .first()
            .expect("framework semantic contract requires primary evidence");
        if primary.extractor_version != WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION
            || primary.properties.get("profile_id").and_then(Value::as_str)
                != Some(site.profile_id.as_str())
            || primary
                .properties
                .get("contract_version")
                .and_then(Value::as_str)
                != Some(WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1)
        {
            return Err(format!(
                "Web framework semantic site {} has invalid capability provenance",
                site.id
            ));
        }
        *site_counts.entry(site.profile_id.as_str()).or_default() += 1;
    }
    for edge in protocol.edges.values().filter(|edge| {
        edge.phase == Phase::Semantic && is_web_framework_semantic_site_kind(&edge.kind)
    }) {
        if states.get(&edge.profile_id) != Some(&WebFrameworkSemanticState::Emitted) {
            return Err(format!(
                "Web framework semantic edge {} is not authorized by an emitted v1 capability",
                edge.id
            ));
        }
        *edge_counts.entry(edge.profile_id.as_str()).or_default() += 1;
    }
    for (profile_id, state) in states {
        if *state == WebFrameworkSemanticState::Legacy {
            continue;
        }
        let profile = protocol
            .profiles
            .get(profile_id)
            .expect("framework semantic state comes from a declared profile");
        for (property, actual) in [
            (
                WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY,
                node_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY,
                site_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
            (
                WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY,
                edge_counts
                    .get(profile_id.as_str())
                    .copied()
                    .unwrap_or_default(),
            ),
        ] {
            let declared = profile
                .properties
                .get(property)
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<usize>().ok())
                .expect("framework semantic profile state validates counts");
            if declared != actual {
                return Err(format!(
                    "Web profile {profile_id:?} reports {property}={declared}, observed {actual}"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn semantic_contract_failure_is_framework(protocol: &ValidatedProtocol) -> bool {
    let mut without_framework = protocol.clone();
    let framework_node_ids = without_framework
        .nodes
        .values()
        .filter(|node| is_web_framework_semantic_node(node))
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let framework_site_ids = without_framework
        .sites
        .values()
        .filter(|site| {
            (is_web_framework_semantic_site_kind(&site.kind)
                && site
                    .evidence
                    .first()
                    .is_some_and(|evidence| evidence.kind == EvidenceKind::Semantic))
                || framework_node_ids.contains(&site.source)
                || site
                    .target_ids
                    .iter()
                    .any(|target| framework_node_ids.contains(target))
        })
        .map(|site| site.id.clone())
        .collect::<BTreeSet<_>>();
    without_framework
        .nodes
        .retain(|node_id, _| !framework_node_ids.contains(node_id));
    without_framework
        .sites
        .retain(|site_id, _| !framework_site_ids.contains(site_id));
    without_framework.edges.retain(|_, edge| {
        !(framework_node_ids.contains(&edge.source)
            || framework_node_ids.contains(&edge.target)
            || edge
                .site_id
                .as_ref()
                .is_some_and(|site_id| framework_site_ids.contains(site_id))
            || edge.phase == Phase::Semantic && is_web_framework_semantic_site_kind(&edge.kind))
    });
    validate_semantic_contract(&without_framework).is_ok()
}
