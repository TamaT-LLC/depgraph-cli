//! Normalize validated source-batch streams before joining their graph records.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use depgraph_protocol::stable_id_from_value;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const V2: &str = "depgraph-analysis-unit-v2";

// This is a core-owned attestation. It is persisted on a canonical profile so
// a later chunk can distinguish a real observed zero/empty value from the
// bounded values emitted by a failed project-model attempt. Worker streams
// must never provide this property themselves.
const TYPESCRIPT_PROJECT_METADATA_AVAILABLE: &str = "typescript_project_model_metadata_available";
const TYPESCRIPT_PROJECT_METADATA_KEYS: [&str; 8] = [
    "features",
    "package_manager",
    "lockfile",
    "typescript_project_root_files",
    "typescript_program_files",
    "typescript_static_config_files",
    "typescript_path_mappings",
    "typescript_standard_library_files",
];

/// Wire profiles identify individual executions. Graph profiles identify one
/// logical unit and stage, independently of batching and execution order.
/// Worker-provided aliases are checked against the adapter's identity contract.
pub(crate) fn normalize_source_batch_profiles(events: &mut [Value]) -> Result<()> {
    let mut aliases = BTreeMap::new();
    let mut web_profiles = BTreeSet::new();
    for event in events.iter() {
        if event["event"] != "profile_declared"
            || event["profile"]["properties"]["analysis_unit_contract"] != V2
        {
            continue;
        }
        let profile = &event["profile"];
        let properties = &profile["properties"];
        let string = |key: &str| {
            properties[key]
                .as_str()
                .with_context(|| format!("source-batch profile is missing {key}"))
        };
        let base = string("analysis_base_profile_id")?;
        let unit = string("analysis_unit_id")?;
        let stage = string("analysis_stage")?;
        let logical = string("analysis_logical_profile_id")?;
        let expected = match profile["language"].as_str() {
            Some("go") => stable_id_from_value(
                "profile",
                &json!({
                    "kind":"profile", "workspace":"go-analysis-unit-v2-logical", "parts":[base,unit,stage],
                }),
            ),
            Some("web") => stable_id_from_value(
                "profile",
                &json!({
                    "base_profile":base, "contract_version":V2, "stage":stage, "unit_id":unit,
                }),
            ),
            _ => anyhow::bail!("source-batch profile has an unsupported adapter"),
        };
        ensure!(
            logical == expected,
            "source-batch logical profile does not match its unit and stage"
        );
        if profile["language"] == "web" {
            web_profiles.insert(logical.to_owned());
        }
        let wire = profile["id"]
            .as_str()
            .context("source-batch profile is missing its wire ID")?;
        ensure!(
            aliases
                .insert(wire.to_owned(), logical.to_owned())
                .is_none(),
            "duplicate source-batch profile alias"
        );
    }
    if aliases.is_empty() {
        return Ok(());
    }
    for event in events {
        rewrite_profile_references(event, &aliases);
        if event["event"] == "node_upsert"
            && is_shared_web_node(&event["node"])
            && let Some(profile) = event["node"]["properties"]["profile_id"].as_str()
            && web_profiles.contains(profile)
        {
            let profile = profile.to_owned();
            ensure!(
                event["node"]["properties"].get("profile_ids").is_none(),
                "worker shared node contains undeclared profile memberships"
            );
            event["node"]["properties"]["profile_ids"] = json!([profile]);
        }
        if event["event"] == "profile_declared"
            && event["profile"]["properties"]["analysis_unit_contract"] == V2
        {
            ensure!(
                event["profile"]["properties"]
                    .get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE)
                    .is_none(),
                "worker supplied core-owned project metadata attestation"
            );
            let wire = event["profile"]["id"]
                .as_str()
                .context("profile ID is missing")?;
            let features_present = event["profile"].get("features").is_some();
            let go_profile = event["profile"]["language"] == "go";
            event["profile"]["id"] = json!(aliases[wire]);
            let properties = event["profile"]["properties"]
                .as_object_mut()
                .context("profile properties must be an object")?;
            for key in [
                "analysis_chunk_id",
                "analysis_chunk_index",
                "analysis_chunk_count",
                "analysis_context_fingerprint",
                "analysis_logical_profile_id",
                "analysis_source_path_count",
            ] {
                properties.remove(key);
            }
            // These are per-execution observations. They remain on the raw
            // worker/checkpoint stream; canonical profiles carry configuration
            // and semantic status, while graph/coverage provide logical counts.
            properties.retain(|key, _| !execution_counter(key));
            if go_profile {
                properties.retain(|key, _| !go_execution_observation(key));
            }
            if let Some(ledger) = properties.get_mut("web_framework_completeness_ledger") {
                *ledger = json!(serde_json::to_string(
                    &parse_framework_ledger(ledger)?
                        .into_values()
                        .collect::<Vec<_>>()
                )?);
            }
            if properties
                .get("typescript_project_model_status")
                .and_then(Value::as_str)
                == Some("ready")
            {
                let available = TYPESCRIPT_PROJECT_METADATA_KEYS
                    .into_iter()
                    .filter(|key| {
                        if *key == "features" {
                            features_present
                        } else {
                            properties.get(*key).is_some()
                        }
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                properties.insert(
                    TYPESCRIPT_PROJECT_METADATA_AVAILABLE.into(),
                    json!(serde_json::to_string(&available)?),
                );
            }
        }
    }
    Ok(())
}

fn is_shared_web_node(node: &Value) -> bool {
    match node["kind"].as_str() {
        Some("symbol" | "type") => node["properties"]["canonical_identity"].is_object(),
        Some("external_system") => {
            let properties = &node["properties"];
            properties["external"] == true
                && properties["language"] == "typescript"
                && properties["compiler_version"].is_string()
                && properties["canonical_identity"].is_object()
        }
        Some("file") => {
            node["properties"]["path"]
                .as_str()
                .is_some_and(|path| !path.is_empty() && node["locator"] == format!("file://{path}"))
                && node["properties"]["package_id"].is_string()
        }
        _ => false,
    }
}

/// Shared files, TypeScript definitions, and TypeScript external sentinels
/// retain one canonical identity across projects and stages. Union verified
/// profile memberships only when every other byte of the payload, including
/// hashes and identity, agrees.
pub(crate) fn merge_shared_web_node(previous: &Value, incoming: &mut Value) -> Result<()> {
    let memberships = |node: &Value| -> Result<BTreeSet<String>> {
        ensure!(
            is_shared_web_node(node),
            "only shared files, canonical semantic nodes, and TypeScript sentinels can merge profile memberships"
        );
        let ids = node["properties"]["profile_ids"]
            .as_array()
            .context("semantic node has no verified profile memberships")?
            .iter()
            .map(|id| {
                id.as_str()
                    .filter(|id| !id.is_empty())
                    .map(ToOwned::to_owned)
                    .context("semantic node has an invalid profile membership")
            })
            .collect::<Result<Vec<_>>>()?;
        let sorted = ids.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            !sorted.is_empty()
                && ids.iter().eq(sorted.iter())
                && node["properties"]["profile_id"].as_str() == sorted.first().map(String::as_str),
            "semantic node profile memberships are not canonical"
        );
        Ok(sorted)
    };
    let mut profiles = memberships(previous)?;
    profiles.extend(memberships(incoming)?);
    let mut left = previous.clone();
    let mut right = incoming.clone();
    for node in [&mut left, &mut right] {
        let properties = node["properties"]
            .as_object_mut()
            .context("node properties missing")?;
        properties.remove("profile_id");
        properties.remove("profile_ids");
    }
    ensure!(left == right, "conflicting canonical shared node payload");
    incoming["properties"]["profile_id"] = json!(profiles.first());
    incoming["properties"]["profile_ids"] = json!(profiles);
    Ok(())
}

/// Per-execution observations of the Go package loader.  A logical Go unit
/// may be typed and analysed as several package-bounded execution units whose
/// loader metrics, reference fingerprints, and split identity differ by
/// construction, and the split plan they were derived from changes with the
/// budget while the canonical graph must not.  They remain on the raw
/// worker/checkpoint stream and in the scan's execution ledger; the canonical
/// profile carries the loader policy and the joined status only.
fn go_execution_observation(key: &str) -> bool {
    matches!(
        key,
        "analysis_split_contract"
            | "analysis_split_plan_id"
            | "analysis_execution_unit_id"
            | "analysis_split_kind"
            | "analysis_loader_input_split"
            | "analysis_context_path_count"
            | "go_loader_target_packages"
            | "go_loader_target_files"
            | "go_loader_target_bytes"
            | "go_loader_body_files"
            | "go_loader_declaration_only_files"
            | "go_loader_loaded_packages"
            | "go_loader_syntax_packages"
            | "go_loader_parsed_files"
            | "go_loader_syntax_equals_targets"
            | "go_loader_reference_packages_export"
            | "go_loader_reference_packages_source"
            | "go_loader_reference_packages_in_repo"
            | "go_loader_reference_packages_external"
            | "go_loader_reference_packages_standard"
            | "go_loader_child_processes"
            | "go_loader_child_max_rss_bytes"
            | "go_loader_peak_rss_bytes"
            | "go_loader_listing_ms"
            | "go_loader_export_compile_ms"
            | "go_loader_type_check_ms"
            | "go_loader_build_cache"
            | "go_loader_build_cache_reused"
            | "go_loader_build_cache_rejected"
            | "go_loader_witness"
            | "go_loader_scope_invalid"
            | "go_reference_fingerprint"
            | "go_reference_fingerprint_packages"
            | "go_reference_fingerprint_files"
            | "go_reference_fingerprint_reasons"
            | "go_packages_packages"
            | "go_packages_typed_packages"
            | "go_packages_typed_files"
            | "go_packages_active_files"
            | "go_packages_compiled_files"
            | "go_packages_embed_files"
            | "go_packages_modules"
            | "go_packages_test_variants"
    )
}

/// Go observations joined across the execution units of one logical stage:
/// the loader scope is `widened` when any unit had to widen it, and the typed
/// stage is complete only when every unit completed it.
const GO_OBSERVATIONS: [&str; 2] = ["analysis_loader_scope", "go_typed_stage_complete"];

fn string_property<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn join_go_observations(left: &Value, right: &Value) -> Vec<(&'static str, Value)> {
    let mut joined = Vec::new();
    match (
        string_property(left, GO_OBSERVATIONS[0]),
        string_property(right, GO_OBSERVATIONS[0]),
    ) {
        (None, None) => {}
        (Some(left), Some(right)) => {
            let value = if left == "widened" || right == "widened" {
                "widened"
            } else {
                left
            };
            joined.push((GO_OBSERVATIONS[0], json!(value)));
        }
        (Some(value), None) | (None, Some(value)) => {
            joined.push((GO_OBSERVATIONS[0], json!(value)));
        }
    }
    match (
        string_property(left, GO_OBSERVATIONS[1]),
        string_property(right, GO_OBSERVATIONS[1]),
    ) {
        (None, None) => {}
        (Some(left), Some(right)) => {
            let value = if left == "true" && right == "true" {
                "true"
            } else {
                "false"
            };
            joined.push((GO_OBSERVATIONS[1], json!(value)));
        }
        (Some(value), None) | (None, Some(value)) => {
            joined.push((GO_OBSERVATIONS[1], json!(value)));
        }
    }
    joined
}

fn execution_counter(key: &str) -> bool {
    ((key.starts_with("typescript_") || key.starts_with("web_framework_"))
        && key.ends_with("_count"))
        || matches!(
            key,
            "typescript_typechecker_queries"
                | "typescript_semantic_diagnostics"
                | "typescript_emitted_semantic_diagnostics"
        )
}

fn profile_field<'a>(profile: &'a Value, key: &str) -> Option<&'a Value> {
    if key == "features" {
        profile.get(key)
    } else {
        profile.get("properties")?.get(key)
    }
}

fn remove_profile_field(profile: &mut Value, key: &str) {
    if key == "features" {
        if let Some(object) = profile.as_object_mut() {
            object.remove(key);
        }
    } else if let Some(object) = profile.get_mut("properties").and_then(Value::as_object_mut) {
        object.remove(key);
    }
}

fn set_profile_field(profile: &mut Value, key: &str, value: Value) -> Result<()> {
    if key == "features" {
        profile
            .as_object_mut()
            .context("profile must be an object")?
            .insert(key.to_owned(), value);
    } else {
        profile
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .context("profile properties are missing")?
            .insert(key.to_owned(), value);
    }
    Ok(())
}

/// Return the project metadata keys whose values are known observations for
/// this profile. A ready profile is backward-compatible with streams that do
/// not yet carry the core marker; a failed profile has no known values unless
/// a prior core merge persisted the marker.
fn project_metadata_available(profile: &Value) -> Result<BTreeSet<String>> {
    if let Some(value) = profile["properties"].get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE) {
        let encoded = value
            .as_str()
            .context("project metadata attestation must be canonical JSON")?;
        let fields = serde_json::from_str::<Vec<String>>(encoded)
            .context("project metadata attestation is invalid JSON")?;
        let available = fields.iter().cloned().collect::<BTreeSet<_>>();
        ensure!(
            fields.iter().eq(available.iter())
                && fields
                    .iter()
                    .all(|key| TYPESCRIPT_PROJECT_METADATA_KEYS.contains(&key.as_str())),
            "project metadata attestation is not canonical"
        );
        for key in &available {
            ensure!(
                profile_field(profile, key).is_some(),
                "project metadata attestation names a missing field"
            );
        }
        return Ok(available);
    }

    let failed = profile["properties"]["typescript_project_model_status"] == "failed";
    Ok(if failed {
        BTreeSet::new()
    } else {
        TYPESCRIPT_PROJECT_METADATA_KEYS
            .into_iter()
            .filter(|key| profile_field(profile, key).is_some())
            .map(ToOwned::to_owned)
            .collect()
    })
}

/// A failed TypeScript project model cannot populate these fields, so the
/// failure event publishes bounded sentinels. Treat only those sentinels as
/// unknown; a non-sentinel value remains part of the strict configuration
/// comparison and cannot be silently overwritten.
fn failed_project_metadata_fallback(
    profile: &Value,
    key: &str,
    available: &BTreeSet<String>,
) -> bool {
    profile["properties"]["typescript_project_model_status"] == "failed"
        && !available.contains(key)
        && match key {
            "features" => profile_field(profile, key)
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty),
            "package_manager" => profile_field(profile, key)
                .and_then(Value::as_str)
                .is_none_or(|value| value == "unknown"),
            "lockfile" => profile_field(profile, key)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty),
            _ => false,
        }
}

fn adopt_known_profile_metadata(previous: &Value, incoming: &mut Value, key: &str) -> Result<()> {
    if failed_project_metadata_fallback(incoming, key, &project_metadata_available(incoming)?)
        && let Some(value) = profile_field(previous, key).cloned()
    {
        set_profile_field(incoming, key, value)?;
    }
    Ok(())
}

fn rewrite_profile_references(value: &mut Value, aliases: &BTreeMap<String, String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                rewrite_profile_references(value, aliases);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(key.as_str(), "profile_id" | "parent_profile_id") {
                    if let Some(logical) = value.as_str().and_then(|wire| aliases.get(wire)) {
                        *value = json!(logical);
                    }
                } else if matches!(key.as_str(), "profile_ids" | "participating_profile_ids") {
                    if let Some(ids) = value.as_array_mut() {
                        for id in ids {
                            if let Some(logical) = id.as_str().and_then(|wire| aliases.get(wire)) {
                                *id = json!(logical);
                            }
                        }
                    }
                } else {
                    rewrite_profile_references(value, aliases);
                }
            }
        }
        _ => {}
    }
}

/// Merge attestations carried by different slices of one logical profile. All
/// known configuration and identity fields must remain identical. Bounded
/// failure fallbacks are treated as unknown, while incomplete attestations in
/// either slice remain incomplete after joining.
pub(crate) fn merge_logical_profile(previous: &Value, incoming: &mut Value) -> Result<()> {
    ensure!(
        previous["properties"]["analysis_unit_contract"] == V2
            && incoming["properties"]["analysis_unit_contract"] == V2,
        "only source-batch profiles can be joined"
    );
    let previous_metadata = project_metadata_available(previous)?;
    let incoming_metadata = project_metadata_available(incoming)?;
    let tracks_project_metadata = previous["properties"]
        .get("typescript_project_model_status")
        .is_some()
        || incoming["properties"]
            .get("typescript_project_model_status")
            .is_some()
        || !previous_metadata.is_empty()
        || !incoming_metadata.is_empty()
        || previous["properties"]
            .get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE)
            .is_some()
        || incoming["properties"]
            .get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE)
            .is_some();
    let mut available_metadata = previous_metadata.clone();
    available_metadata.extend(incoming_metadata.iter().cloned());
    const OBSERVATIONS: [&str; 3] = [
        "web_framework_semantic_status",
        "web_framework_completeness_status",
        "web_framework_completeness_ledger",
    ];
    const TYPESCRIPT_OBSERVATIONS: [&str; 2] = [
        "typescript_definition_graph_status",
        "typescript_typechecker_status",
    ];
    const TYPESCRIPT_PROJECT_OBSERVATIONS: [&str; 7] = [
        "typescript_project_model_status",
        "typescript_project_model_failure_reason",
        "typescript_project_root_files",
        "typescript_program_files",
        "typescript_static_config_files",
        "typescript_path_mappings",
        "typescript_standard_library_files",
    ];
    let mut left_axes = previous.clone();
    let mut right_axes = incoming.clone();
    for profile in [&mut left_axes, &mut right_axes] {
        let properties = profile["properties"]
            .as_object_mut()
            .context("profile properties are missing")?;
        for key in OBSERVATIONS {
            properties.remove(key);
        }
        for key in TYPESCRIPT_OBSERVATIONS {
            properties.remove(key);
        }
        for key in TYPESCRIPT_PROJECT_OBSERVATIONS {
            properties.remove(key);
        }
        for key in GO_OBSERVATIONS {
            properties.remove(key);
        }
        properties.remove(TYPESCRIPT_PROJECT_METADATA_AVAILABLE);
    }
    for key in ["features", "package_manager", "lockfile"] {
        if failed_project_metadata_fallback(previous, key, &previous_metadata)
            || failed_project_metadata_fallback(incoming, key, &incoming_metadata)
        {
            remove_profile_field(&mut left_axes, key);
            remove_profile_field(&mut right_axes, key);
        }
    }
    ensure!(
        left_axes == right_axes,
        "logical profile configuration changed between chunks"
    );
    if previous == incoming {
        return Ok(());
    }
    for key in ["features", "package_manager", "lockfile"] {
        adopt_known_profile_metadata(previous, incoming, key)?;
    }
    if previous["language"] == "go" {
        // Go profiles carry no framework or TypeScript observations; once the
        // axes agree, only the Go observations remain to be joined.
        let joined = join_go_observations(&previous["properties"], &incoming["properties"]);
        let properties = incoming["properties"]
            .as_object_mut()
            .context("profile properties are missing")?;
        for (key, value) in joined {
            properties.insert(key.into(), value);
        }
        return Ok(());
    }
    let left = &previous["properties"];
    let right = &incoming["properties"];
    let mut entries = parse_framework_ledger(&left[OBSERVATIONS[2]])?;
    for (framework, entry) in parse_framework_ledger(&right[OBSERVATIONS[2]])? {
        if let Some(existing) = entries.get_mut(&framework) {
            ensure!(
                existing.required_capabilities == entry.required_capabilities,
                "framework requirements changed between chunks"
            );
            existing.emitted_capabilities = existing
                .emitted_capabilities
                .intersection(&entry.emitted_capabilities)
                .cloned()
                .collect();
            existing.reasons.extend(entry.reasons);
            if entry.status != "complete"
                || !existing.reasons.is_empty()
                || existing.required_capabilities != existing.emitted_capabilities
            {
                existing.status = "incomplete".into();
            }
        } else {
            entries.insert(framework, entry);
        }
    }
    let status = |value: &Value| -> Result<u8> {
        match value.as_str() {
            Some("not-emitted") => Ok(0),
            Some("discarded") => Ok(1),
            Some("emitted") => Ok(2),
            _ => anyhow::bail!("invalid framework emission status"),
        }
    };
    // Presence of emitted records is a fact. Completeness is independently
    // derived from every relevant attestation, including discarded slices.
    let emitted = ["not-emitted", "discarded", "emitted"]
        [usize::from(status(&left[OBSERVATIONS[0]])?.max(status(&right[OBSERVATIONS[0]])?))];
    let complete = if entries.is_empty() {
        "not-detected"
    } else if entries.values().all(|entry| entry.status == "complete") {
        "complete"
    } else {
        "incomplete"
    };
    let ledger = serde_json::to_string(&entries.into_values().collect::<Vec<_>>())?;
    let (definition_status, typechecker_status) = {
        let join_typescript_status =
            |key: &str, rank: fn(&str) -> Option<u8>| -> Result<Option<String>> {
                let left = left[key].as_str();
                let right = right[key].as_str();
                match (left, right) {
                    (None, None) => Ok(None),
                    (Some(left), Some(right)) => {
                        let left_rank = rank(left).with_context(|| format!("invalid {key}"))?;
                        let right_rank = rank(right).with_context(|| format!("invalid {key}"))?;
                        Ok(Some(if left_rank >= right_rank {
                            left.to_owned()
                        } else {
                            right.to_owned()
                        }))
                    }
                    _ => anyhow::bail!("{key} is missing from one logical profile chunk"),
                }
            };
        let definition_status =
            join_typescript_status(TYPESCRIPT_OBSERVATIONS[0], |status| match status {
                "ready" => Some(0),
                "failed" => Some(1),
                _ => None,
            })?;
        let typechecker_status =
            join_typescript_status(TYPESCRIPT_OBSERVATIONS[1], |status| match status {
                "definition-import-type-call-graph-emitted" => Some(0),
                "definition-import-type-call-graph-discarded" => Some(1),
                "failed" => Some(2),
                _ => None,
            })?;
        (definition_status, typechecker_status)
    };
    let project_observations = {
        const COUNT_KEYS: [&str; 5] = [
            "typescript_project_root_files",
            "typescript_program_files",
            "typescript_static_config_files",
            "typescript_path_mappings",
            "typescript_standard_library_files",
        ];
        let project_status = |value: Option<&Value>| -> Result<Option<&str>> {
            match value.and_then(Value::as_str) {
                None => Ok(None),
                Some("ready") => Ok(Some("ready")),
                Some("failed") => Ok(Some("failed")),
                Some(other) => anyhow::bail!("invalid typescript_project_model_status {other:?}"),
            }
        };
        let left_status = project_status(left.get("typescript_project_model_status"))?;
        let right_status = project_status(right.get("typescript_project_model_status"))?;
        let joined_status = match (left_status, right_status) {
            (None, None) => None,
            (Some(status), None) | (None, Some(status)) => Some(status),
            (Some("ready"), Some("ready")) => Some("ready"),
            (Some("failed"), Some("failed"))
            | (Some("ready"), Some("failed"))
            | (Some("failed"), Some("ready")) => Some("failed"),
            _ => unreachable!("project status parser only accepts ready or failed"),
        };
        let failure_reason = match joined_status {
            None => None,
            Some("ready") => {
                ensure!(
                    left.get("typescript_project_model_failure_reason")
                        .and_then(Value::as_str)
                        .is_none_or(|reason| reason == "none")
                        && right
                            .get("typescript_project_model_failure_reason")
                            .and_then(Value::as_str)
                            .is_none_or(|reason| reason == "none"),
                    "ready TypeScript project model has a failure reason"
                );
                Some("none".to_owned())
            }
            Some("failed") => {
                let mut reasons = [
                    left.get("typescript_project_model_failure_reason")
                        .and_then(Value::as_str),
                    right
                        .get("typescript_project_model_failure_reason")
                        .and_then(Value::as_str),
                ]
                .into_iter()
                .flatten()
                .filter(|reason| *reason != "none")
                .collect::<Vec<_>>();
                reasons.sort_unstable();
                Some(
                    reasons
                        .first()
                        .copied()
                        .unwrap_or("compiler_protocol_failure")
                        .to_owned(),
                )
            }
            _ => unreachable!("project status parser only accepts ready or failed"),
        };
        let join_count = |key: &str| -> Result<Option<String>> {
            let left_value = left.get(key).and_then(Value::as_str);
            let right_value = right.get(key).and_then(Value::as_str);
            let parse = |value: &str| {
                value
                    .parse::<u64>()
                    .with_context(|| format!("{key} is not a decimal count"))
            };
            let left_known = previous_metadata.contains(key);
            let right_known = incoming_metadata.contains(key);
            match (left_value, right_value) {
                (None, None) => Ok(None),
                (Some(value), None) | (None, Some(value)) => {
                    let count = parse(value)?;
                    ensure!(
                        left_known || right_known || count == 0,
                        "unattested failed TypeScript project observation {key} must be zero"
                    );
                    Ok(Some(value.to_owned()))
                }
                (Some(left_value), Some(right_value)) => {
                    let left_count = parse(left_value)?;
                    let right_count = parse(right_value)?;
                    let joined = match (left_known, right_known) {
                        (true, true) => {
                            ensure!(
                                left_count == right_count,
                                "TypeScript project observation {key} changed between chunks"
                            );
                            left_count
                        }
                        (true, false) => {
                            ensure!(
                                right_count == 0,
                                "unattested failed TypeScript project observation {key} must be zero"
                            );
                            left_count
                        }
                        (false, true) => {
                            ensure!(
                                left_count == 0,
                                "unattested failed TypeScript project observation {key} must be zero"
                            );
                            right_count
                        }
                        (false, false) => {
                            ensure!(
                                left_count == 0 && right_count == 0,
                                "unattested failed TypeScript project observation {key} must be zero"
                            );
                            0
                        }
                    };
                    Ok(Some(joined.to_string()))
                }
            }
        };
        let counts = COUNT_KEYS
            .into_iter()
            .map(|key| Ok((key, join_count(key)?)))
            .collect::<Result<Vec<_>>>()?;
        (joined_status, failure_reason, counts)
    };
    let properties = incoming["properties"]
        .as_object_mut()
        .context("profile properties are missing")?;
    properties.insert(OBSERVATIONS[0].into(), json!(emitted));
    properties.insert(OBSERVATIONS[1].into(), json!(complete));
    properties.insert(OBSERVATIONS[2].into(), json!(ledger));
    // A failed/discarded chunk downgrades the aggregate attestation only. Its
    // status describes that chunk's delta; graph events from successful chunks
    // are retained independently and are not erased by this profile join.
    if let Some(status) = definition_status {
        properties.insert(TYPESCRIPT_OBSERVATIONS[0].into(), json!(status));
    }
    if let Some(status) = typechecker_status {
        properties.insert(TYPESCRIPT_OBSERVATIONS[1].into(), json!(status));
    }
    if let Some(status) = project_observations.0 {
        properties.insert("typescript_project_model_status".into(), json!(status));
    }
    if let Some(reason) = project_observations.1 {
        properties.insert(
            "typescript_project_model_failure_reason".into(),
            json!(reason),
        );
    }
    for (key, value) in project_observations.2 {
        if let Some(value) = value {
            properties.insert(key.into(), json!(value));
        }
    }
    if tracks_project_metadata {
        let available = available_metadata.into_iter().collect::<Vec<_>>();
        properties.insert(
            TYPESCRIPT_PROJECT_METADATA_AVAILABLE.into(),
            json!(serde_json::to_string(&available)?),
        );
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FrameworkLedgerEntry {
    framework: String,
    required_capabilities: BTreeSet<String>,
    emitted_capabilities: BTreeSet<String>,
    status: String,
    reasons: BTreeSet<String>,
}

fn parse_framework_ledger(value: &Value) -> Result<BTreeMap<String, FrameworkLedgerEntry>> {
    let text = value.as_str().context("framework ledger is missing")?;
    let entries: Vec<FrameworkLedgerEntry> = serde_json::from_str(text)?;
    let mut result = BTreeMap::new();
    for entry in entries {
        ensure!(
            matches!(entry.status.as_str(), "complete" | "incomplete"),
            "invalid framework ledger status"
        );
        ensure!(
            entry.status != "complete"
                || (entry.reasons.is_empty()
                    && entry.required_capabilities == entry.emitted_capabilities),
            "invalid complete framework attestation"
        );
        ensure!(
            result.insert(entry.framework.clone(), entry).is_none(),
            "duplicate framework ledger entry"
        );
    }
    Ok(result)
}

/// One canonical profile completion describes the union of every chunk.
/// Intersect completeness: a successful sibling cannot mask an incomplete one.
pub(crate) fn coalesce_stage_completions(events: &mut Vec<Value>) -> Result<()> {
    let mut grouped = BTreeMap::<(String, String), Value>::new();
    for event in events.drain(..) {
        let kind = event["event"]
            .as_str()
            .context("completion kind is missing")?
            .to_owned();
        let profile = event["profile_id"].as_str().unwrap_or_default().to_owned();
        let key = (kind, profile);
        if let Some(existing) = grouped.get_mut(&key) {
            merge_coverage(&mut existing["coverage"], &event["coverage"])?;
        } else {
            grouped.insert(key, event);
        }
    }
    *events = grouped.into_values().collect();
    Ok(())
}

fn merge_coverage(target: &mut Value, incoming: &Value) -> Result<()> {
    let target = target
        .as_object_mut()
        .context("completion coverage is not an object")?;
    let incoming = incoming
        .as_object()
        .context("completion coverage is not an object")?;
    for (key, value) in incoming {
        match value {
            Value::Number(number) => {
                let right = number
                    .as_u64()
                    .context("coverage counter is not unsigned")?;
                let left = target.get(key).and_then(Value::as_u64).unwrap_or(0);
                let sum = if key == "profiles" {
                    left.max(right)
                } else {
                    left.checked_add(right)
                        .context("coverage counter overflow")?
                };
                target.insert(key.clone(), json!(sum));
            }
            Value::Bool(value) => {
                let observed = target.get(key).and_then(Value::as_bool).unwrap_or(false) || *value;
                target.insert(key.clone(), json!(observed));
            }
            Value::Array(values) => {
                let left = target
                    .get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>();
                let right = values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>();
                let merged = if key == "completeness" {
                    left.intersection(&right).cloned().collect::<Vec<_>>()
                } else {
                    left.union(&right).cloned().collect::<Vec<_>>()
                };
                target.insert(key.clone(), json!(merged));
            }
            _ => anyhow::bail!("unexpected completion coverage field {key}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_definitions_union_verified_profiles_without_changing_identity() -> Result<()> {
        let node = |profile: &str| {
            json!({
                "id":"symbol:shared", "kind":"symbol", "locator":"typescript-symbol:shared",
                "properties": {
                    "canonical_identity":{"language":"typescript", "resolver_identity":"shared:answer"},
                    "source_path":"shared/index.ts", "symbol_kind":"function",
                    "profile_id":profile, "profile_ids":[profile],
                },
            })
        };
        let a = node("profile:a");
        let b = node("profile:b");
        let mut forward = b.clone();
        merge_shared_web_node(&a, &mut forward)?;
        let mut reverse = a.clone();
        merge_shared_web_node(&b, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(forward["id"], "symbol:shared");
        assert_eq!(forward["properties"]["profile_id"], "profile:a");
        assert_eq!(
            forward["properties"]["profile_ids"],
            json!(["profile:a", "profile:b"])
        );
        let mut repeated = b;
        merge_shared_web_node(&forward, &mut repeated)?;
        assert_eq!(forward, repeated);

        let mut conflict = node("profile:c");
        conflict["properties"]["source_path"] = json!("other.ts");
        assert!(merge_shared_web_node(&a, &mut conflict).is_err());
        let mut forged = node("profile:c");
        forged["properties"]["canonical_identity"]["resolver_identity"] = json!("other:answer");
        assert!(merge_shared_web_node(&a, &mut forged).is_err());
        let mut unordered = node("profile:c");
        unordered["properties"]["profile_ids"] = json!(["profile:c", "profile:a"]);
        assert!(merge_shared_web_node(&a, &mut unordered).is_err());
        let mut file = a.clone();
        file["kind"] = json!("file");
        assert!(merge_shared_web_node(&file, &mut file.clone()).is_err());
        Ok(())
    }

    #[test]
    fn shared_typescript_external_sentinels_union_profiles_without_overwriting_payload()
    -> Result<()> {
        let external = |profile: &str| {
            json!({
                "id":"external:shared-typescript",
                "kind":"external_system",
                "locator":"external://typescript/typescript%3Astdlib%3ADate",
                "display_name":"typescript:stdlib:Date",
                "properties": {
                    "language":"typescript", "external":true,
                    "compiler_version":"7.0.2",
                    "canonical_identity": {
                        "language":"typescript", "compiler_version":"7.0.2",
                        "locator":"typescript:stdlib:Date"
                    },
                    "profile_id":profile, "profile_ids":[profile],
                },
            })
        };
        let a = external("profile:a");
        let b = external("profile:b");
        let mut forward = b.clone();
        merge_shared_web_node(&a, &mut forward)?;
        let mut reverse = a.clone();
        merge_shared_web_node(&b, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(forward["properties"]["profile_id"], "profile:a");
        assert_eq!(
            forward["properties"]["profile_ids"],
            json!(["profile:a", "profile:b"])
        );

        let mut changed = external("profile:b");
        changed["properties"]["compiler_version"] = json!("7.0.3");
        assert!(merge_shared_web_node(&a, &mut changed).is_err());
        Ok(())
    }

    #[test]
    fn shared_files_union_profiles_and_reject_path_or_hash_conflicts() -> Result<()> {
        let file = |profile: &str| {
            json!({
                "id":"file:shared", "kind":"file", "locator":"file://shared/index.ts",
                "properties":{"path":"shared/index.ts", "package_id":"package:shared",
                    "content_hash":"sha256:source", "analysis_hash":"sha256:analysis",
                    "profile_id":profile, "profile_ids":[profile]},
            })
        };
        let syntax = file("profile:syntax");
        let semantic = file("profile:semantic");
        let mut forward = semantic.clone();
        merge_shared_web_node(&syntax, &mut forward)?;
        let mut reverse = syntax.clone();
        merge_shared_web_node(&semantic, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(
            forward["properties"]["profile_ids"],
            json!(["profile:semantic", "profile:syntax"])
        );
        for (key, value) in [
            ("content_hash", "sha256:changed"),
            ("analysis_hash", "sha256:changed"),
            ("path", "other/index.ts"),
            ("package_id", "package:other"),
        ] {
            let mut conflict = semantic.clone();
            conflict["properties"][key] = json!(value);
            assert!(
                merge_shared_web_node(&syntax, &mut conflict).is_err(),
                "accepted conflicting {key}"
            );
        }
        Ok(())
    }

    #[test]
    fn logical_framework_profiles_merge_without_hiding_incomplete_slices() -> Result<()> {
        let profile = |status: &str, complete: &str, ledger: Value| {
            json!({
                "id":"logical", "language":"web", "properties":{
                    "analysis_unit_contract":V2, "analysis_unit_id":"unit", "analysis_stage":"semantic",
                    "web_framework_semantic_status":status, "web_framework_completeness_status":complete,
                    "web_framework_completeness_ledger":serde_json::to_string(&ledger).unwrap(),
                },
            })
        };
        let empty = profile("not-emitted", "not-detected", json!([]));
        let complete = profile(
            "emitted",
            "complete",
            json!([{
                "framework":"react", "required_capabilities":["react"], "emitted_capabilities":["react"],
                "status":"complete", "reasons":[],
            }]),
        );
        let incomplete = profile(
            "emitted",
            "incomplete",
            json!([{
                "framework":"react", "required_capabilities":["react"], "emitted_capabilities":[],
                "status":"incomplete", "reasons":["missing-reference"],
            }]),
        );
        let mut joined = complete.clone();
        merge_logical_profile(&empty, &mut joined)?;
        assert_eq!(
            joined["properties"]["web_framework_completeness_status"],
            "complete"
        );
        let mut forward = incomplete.clone();
        merge_logical_profile(&complete, &mut forward)?;
        let mut reverse = complete.clone();
        merge_logical_profile(&incomplete, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(
            forward["properties"]["web_framework_completeness_status"],
            "incomplete"
        );
        let mut forged = complete;
        forged["properties"]["analysis_unit_id"] = json!("another-unit");
        assert!(merge_logical_profile(&empty, &mut forged).is_err());
        Ok(())
    }

    #[test]
    fn logical_typescript_statuses_join_conservatively_without_dropping_partial_graph() -> Result<()>
    {
        let profile = |definition_status: &str, typechecker_status: &str| {
            json!({
                "id":"logical", "language":"web", "properties":{
                    "analysis_unit_contract":V2, "analysis_unit_id":"unit", "analysis_stage":"semantic",
                    "typescript_analysis_mode":"semantic-import-type-call-graph",
                    "typescript_project_model_status":"ready",
                    "typescript_semantic_graph_emission":"definition-import-type-call-graph-v2",
                    "typescript_definition_graph_status":definition_status,
                    "typescript_typechecker_status":typechecker_status,
                    "web_framework_semantic_status":"not-emitted",
                    "web_framework_completeness_status":"not-detected",
                    "web_framework_completeness_ledger": "[]",
                },
            })
        };
        let successful = profile("ready", "definition-import-type-call-graph-emitted");
        let partial = profile("failed", "definition-import-type-call-graph-discarded");

        let mut forward = partial.clone();
        merge_logical_profile(&successful, &mut forward)?;
        assert_eq!(
            forward["properties"]["typescript_definition_graph_status"],
            "failed"
        );
        assert_eq!(
            forward["properties"]["typescript_typechecker_status"],
            "definition-import-type-call-graph-discarded"
        );
        let mut reverse = successful.clone();
        merge_logical_profile(&partial, &mut reverse)?;
        assert_eq!(forward, reverse);

        let mut configuration_conflict = partial;
        configuration_conflict["properties"]["typescript_analysis_mode"] =
            json!("different-analysis-mode");
        assert!(merge_logical_profile(&successful, &mut configuration_conflict).is_err());
        Ok(())
    }

    #[test]
    fn logical_project_observations_join_failed_chunks_without_erasing_context() -> Result<()> {
        let profile = |model_status: &str,
                       failure_reason: &str,
                       root_files: &str,
                       program_files: &str,
                       config_files: &str,
                       path_mappings: &str,
                       standard_library_files: &str,
                       definition_status: &str,
                       typechecker_status: &str| {
            json!({
                "id":"logical", "language":"web", "properties":{
                    "analysis_unit_contract":V2, "analysis_unit_id":"unit", "analysis_stage":"semantic",
                    "typescript_analysis_mode":"semantic-import-type-call-graph",
                    "typescript_project_model_status":model_status,
                    "typescript_project_model_failure_reason":failure_reason,
                    "typescript_project_root_files":root_files,
                    "typescript_program_files":program_files,
                    "typescript_static_config_files":config_files,
                    "typescript_path_mappings":path_mappings,
                    "typescript_standard_library_files":standard_library_files,
                    "typescript_definition_graph_status":definition_status,
                    "typescript_typechecker_status":typechecker_status,
                    "web_framework_semantic_status":"not-emitted",
                    "web_framework_completeness_status":"not-detected",
                    "web_framework_completeness_ledger":"[]",
                },
            })
        };
        let successful = profile(
            "ready",
            "none",
            "12",
            "18",
            "11",
            "1",
            "6",
            "ready",
            "definition-import-type-call-graph-emitted",
        );
        let interrupted = profile(
            "failed",
            "compiler_protocol_failure",
            "0",
            "0",
            "0",
            "0",
            "0",
            "failed",
            "definition-import-type-call-graph-discarded",
        );

        let mut forward = interrupted.clone();
        merge_logical_profile(&successful, &mut forward)?;
        let mut reverse = successful.clone();
        merge_logical_profile(&interrupted, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(
            forward["properties"]["typescript_project_model_status"],
            "failed"
        );
        assert_eq!(
            forward["properties"]["typescript_project_model_failure_reason"],
            "compiler_protocol_failure"
        );
        for (key, value) in [
            ("typescript_project_root_files", "12"),
            ("typescript_program_files", "18"),
            ("typescript_static_config_files", "11"),
            ("typescript_path_mappings", "1"),
            ("typescript_standard_library_files", "6"),
        ] {
            assert_eq!(
                forward["properties"][key], value,
                "joined {key} lost the ready observation"
            );
        }

        let mut changed = successful.clone();
        changed["properties"]["typescript_program_files"] = json!("19");
        assert!(merge_logical_profile(&successful, &mut changed).is_err());
        Ok(())
    }

    #[test]
    fn logical_failed_project_fallback_metadata_keeps_known_configuration() -> Result<()> {
        let profile = |features: &[&str], package_manager: &str, lockfile: &str, status: &str| {
            json!({
                "id":"logical", "language":"web", "toolchain":"typescript 7.0.2",
                "features":features,
                "properties":{
                    "analysis_unit_contract":V2, "analysis_unit_id":"unit", "analysis_stage":"semantic",
                    "package_manager":package_manager, "lockfile":lockfile,
                    "typescript_analysis_mode":"semantic-import-type-call-graph",
                    "typescript_project_model_status":status,
                    "typescript_project_model_failure_reason":if status == "failed" { "compiler_protocol_failure" } else { "none" },
                    "typescript_project_root_files":if status == "failed" { "0" } else { "12" },
                    "typescript_program_files":if status == "failed" { "0" } else { "18" },
                    "typescript_static_config_files":if status == "failed" { "0" } else { "1" },
                    "typescript_path_mappings":"0",
                    "typescript_standard_library_files":if status == "failed" { "0" } else { "4" },
                    "typescript_definition_graph_status":if status == "failed" { "failed" } else { "ready" },
                    "typescript_typechecker_status":if status == "failed" {
                        "failed"
                    } else {
                        "definition-import-type-call-graph-emitted"
                    },
                    "web_framework_semantic_status":"not-emitted",
                    "web_framework_completeness_status":"not-detected",
                    "web_framework_completeness_ledger":"[]",
                },
            })
        };
        let successful = profile(&["next"], "npm", "package-lock.json", "ready");
        let failed = profile(&[], "unknown", "", "failed");

        let mut forward = failed.clone();
        merge_logical_profile(&successful, &mut forward)?;
        let mut reverse = successful.clone();
        merge_logical_profile(&failed, &mut reverse)?;
        assert_eq!(forward, reverse);
        assert_eq!(forward["features"], json!(["next"]));
        assert_eq!(forward["properties"]["package_manager"], "npm");
        assert_eq!(forward["properties"]["lockfile"], "package-lock.json");

        let mut non_fallback = failed.clone();
        non_fallback["properties"]["package_manager"] = json!("pnpm");
        assert!(merge_logical_profile(&successful, &mut non_fallback).is_err());

        let mut configuration_conflict = profile(&["next"], "pnpm", "package-lock.json", "ready");
        assert!(merge_logical_profile(&successful, &mut configuration_conflict).is_err());
        Ok(())
    }

    #[test]
    fn logical_project_observations_preserve_known_values_across_all_chunk_orders() -> Result<()> {
        let profile = |model_status: &str,
                       failure_reason: &str,
                       count: &str,
                       features: Value,
                       package_manager: &str,
                       lockfile: &str| {
            json!({
                "id":"logical", "language":"web", "features":features, "properties":{
                    "analysis_unit_contract":V2, "analysis_unit_id":"unit", "analysis_stage":"semantic",
                    "package_manager":package_manager, "lockfile":lockfile,
                    "typescript_analysis_mode":"semantic-import-type-call-graph",
                    "typescript_project_model_status":model_status,
                    "typescript_project_model_failure_reason":failure_reason,
                    "typescript_project_root_files":count,
                    "typescript_program_files":count,
                    "typescript_static_config_files":count,
                    "typescript_path_mappings":count,
                    "typescript_standard_library_files":count,
                    "typescript_definition_graph_status":if model_status == "failed" { "failed" } else { "ready" },
                    "typescript_typechecker_status":if model_status == "failed" {
                        "failed"
                    } else {
                        "definition-import-type-call-graph-emitted"
                    },
                    "web_framework_semantic_status":"not-emitted",
                    "web_framework_completeness_status":"not-detected",
                    "web_framework_completeness_ledger":"[]",
                },
            })
        };
        let successful = profile(
            "ready",
            "none",
            "18",
            json!(["next"]),
            "npm",
            "package-lock.json",
        );
        let failed = profile(
            "failed",
            "compiler_protocol_failure",
            "0",
            json!([]),
            "unknown",
            "",
        );
        let profiles = [successful.clone(), failed.clone(), failed.clone()];
        let permutations = [
            [0_usize, 1, 2],
            [0_usize, 2, 1],
            [1_usize, 0, 2],
            [1_usize, 2, 0],
            [2_usize, 0, 1],
            [2_usize, 1, 0],
        ];
        let mut results = Vec::new();
        for order in permutations {
            let mut aggregate = profiles[order[0]].clone();
            for index in &order[1..] {
                let mut next = profiles[*index].clone();
                merge_logical_profile(&aggregate, &mut next)?;
                aggregate = next;
            }
            results.push(aggregate);
        }
        for result in &results[1..] {
            assert_eq!(result, &results[0]);
        }
        assert_eq!(results[0]["properties"]["typescript_program_files"], "18");
        assert_eq!(
            results[0]["properties"]["typescript_project_model_status"],
            "failed"
        );
        assert!(
            results[0]["properties"]
                .get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE)
                .is_some_and(|value| value
                    .as_str()
                    .is_some_and(|value| value.contains("program_files")))
        );

        // A successful observation of zero/empty metadata remains known after
        // a failed chunk, so a later different ready observation is rejected.
        let observed_empty = profile("ready", "none", "0", json!([]), "unknown", "");
        let mut empty_aggregate = failed.clone();
        merge_logical_profile(&observed_empty, &mut empty_aggregate)?;
        let mut failed_after_empty = failed;
        merge_logical_profile(&empty_aggregate, &mut failed_after_empty)?;
        assert_eq!(failed_after_empty["features"], json!([]));
        assert_eq!(
            failed_after_empty["properties"]["package_manager"],
            "unknown"
        );
        assert_eq!(failed_after_empty["properties"]["lockfile"], "");
        let mut changed = profile(
            "ready",
            "none",
            "1",
            json!(["next"]),
            "npm",
            "package-lock.json",
        );
        assert!(merge_logical_profile(&failed_after_empty, &mut changed).is_err());
        Ok(())
    }

    /// Package-bounded Go execution units of one logical stage differ in
    /// their loader metrics and split identity by construction.  Those are
    /// stripped as per-execution observations, the loader scope and typed
    /// completion are joined conservatively, and a real configuration change
    /// between units is still rejected.
    #[test]
    fn go_package_execution_units_join_into_one_logical_profile() -> Result<()> {
        let logical = stable_id_from_value(
            "profile",
            &json!({"kind":"profile", "workspace":"go-analysis-unit-v2-logical", "parts":["go:base","unit","typed"]}),
        );
        let declared = |chunk: &str, scope: &str, complete: &str, targets: &str| {
            json!({"event":"profile_declared","profile":{"id":format!("wire-{chunk}"),"language":"go","properties":{
                "analysis_unit_contract":V2,"analysis_base_profile_id":"go:base","analysis_unit_id":"unit","analysis_stage":"typed",
                "analysis_logical_profile_id":logical,"analysis_chunk_count":"2","analysis_chunk_index":"0","analysis_chunk_id":chunk,
                "analysis_source_path_count":"1","analysis_context_path_count":"2",
                "analysis_split_contract":"depgraph-analysis-split-plan-v1","analysis_split_plan_id":format!("analysis-split-plan:{chunk}"),
                "analysis_execution_unit_id":format!("analysis-execution-unit:{chunk}"),"analysis_split_kind":"output_batch",
                "analysis_loader_kind":"package","analysis_loader_input_split":"true","analysis_loader_scope":scope,
                "analysis_loader_mode":"package","go_loader_program_scope":"package-with-declaration-deps",
                "go_loader_target_packages":targets,"go_loader_peak_rss_bytes":"1024","go_loader_type_check_ms":"3",
                "go_reference_fingerprint":format!("sha256:{chunk}"),"go_typed_stage_complete":complete,
            }}})
        };
        let mut first = vec![declared("a", "applied", "true", "1")];
        let mut second = vec![declared("b", "widened", "true", "2")];
        normalize_source_batch_profiles(&mut first)?;
        normalize_source_batch_profiles(&mut second)?;
        let first = first.remove(0)["profile"].clone();
        let mut second = second.remove(0)["profile"].clone();
        for key in [
            "analysis_split_contract",
            "analysis_split_plan_id",
            "analysis_execution_unit_id",
            "analysis_split_kind",
            "go_loader_target_packages",
            "go_loader_peak_rss_bytes",
            "go_reference_fingerprint",
        ] {
            assert!(
                first["properties"].get(key).is_none(),
                "{key} survived normalization"
            );
        }
        assert_eq!(first["properties"]["analysis_loader_mode"], "package");
        assert_eq!(
            first["properties"]["go_loader_program_scope"],
            "package-with-declaration-deps"
        );
        merge_logical_profile(&first, &mut second)?;
        assert_eq!(second["properties"]["analysis_loader_scope"], "widened");
        assert_eq!(second["properties"]["go_typed_stage_complete"], "true");
        let mut reverse = first.clone();
        let mut widened = vec![declared("b", "widened", "false", "2")];
        normalize_source_batch_profiles(&mut widened)?;
        merge_logical_profile(&widened.remove(0)["profile"], &mut reverse)?;
        assert_eq!(reverse["properties"]["analysis_loader_scope"], "widened");
        assert_eq!(reverse["properties"]["go_typed_stage_complete"], "false");

        let mut changed = vec![declared("c", "applied", "true", "1")];
        changed[0]["profile"]["properties"]["analysis_loader_mode"] = json!("module");
        normalize_source_batch_profiles(&mut changed)?;
        assert!(merge_logical_profile(&first, &mut changed.remove(0)["profile"]).is_err());
        Ok(())
    }

    #[test]
    fn worker_cannot_supply_core_project_metadata_attestation() -> Result<()> {
        let logical = stable_id_from_value(
            "profile",
            &json!({
                "base_profile":"web:base",
                "contract_version":V2,
                "stage":"semantic",
                "unit_id":"unit"
            }),
        );
        let profile = |attestation: Option<Value>| {
            let mut properties = json!({
                "analysis_unit_contract":V2,
                "analysis_base_profile_id":"web:base",
                "analysis_unit_id":"unit",
                "analysis_stage":"semantic",
                "analysis_logical_profile_id":logical,
                "typescript_project_model_status":"ready",
                "package_manager":"npm",
                "lockfile":"package-lock.json",
                "typescript_project_root_files":"0",
                "typescript_program_files":"0",
                "typescript_static_config_files":"0",
                "typescript_path_mappings":"0",
                "typescript_standard_library_files":"0"
            });
            if let Some(attestation) = attestation {
                properties[TYPESCRIPT_PROJECT_METADATA_AVAILABLE] = attestation;
            }
            json!({
                "event":"profile_declared",
                "profile":{
                    "id":"wire-profile",
                    "language":"web",
                    "features":[],
                    "properties":properties
                }
            })
        };
        let mut forged = vec![profile(Some(json!("[]")))];
        assert!(normalize_source_batch_profiles(&mut forged).is_err());

        let mut valid = vec![profile(None)];
        normalize_source_batch_profiles(&mut valid)?;
        assert!(
            valid[0]["profile"]["properties"]
                .get(TYPESCRIPT_PROJECT_METADATA_AVAILABLE)
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn wire_references_normalize_without_changing_graph_identities_or_conditions() -> Result<()> {
        let logical = stable_id_from_value(
            "profile",
            &json!({"base_profile":"web:base", "contract_version":V2, "stage":"syntax", "unit_id":"unit-a"}),
        );
        let mut events = vec![
            json!({"event":"profile_declared","profile":{"id":"wire-a","language":"web","properties":{
                "analysis_unit_contract":V2,"analysis_base_profile_id":"web:base", "analysis_unit_id":"unit-a", "analysis_stage":"syntax",
                "analysis_logical_profile_id":logical,"analysis_chunk_count":"2","analysis_chunk_index":"0","analysis_chunk_id":"chunk-a",
                "analysis_source_path_count":"1","analysis_context_path_count":"2",
            }}}),
            json!({"event":"node_upsert","node":{
                "id":"external:shared-typescript", "kind":"external_system",
                "locator":"external://typescript/typescript%3Astdlib%3ADate",
                "display_name":"typescript:stdlib:Date",
                "properties":{
                    "language":"typescript", "external":true, "compiler_version":"7.0.2",
                    "canonical_identity":{"language":"typescript", "compiler_version":"7.0.2", "locator":"typescript:stdlib:Date"},
                    "profile_id":"wire-a"
                }
            }}),
            json!({"event":"edge_upsert","edge":{"id":"stable-edge","profile_id":"wire-a", "condition":{"op":"all","conditions":[]},"evidence":[{"properties":{"profile_id":"wire-a","source_text":"wire-a"}}]}}),
            json!({"event":"profile_completed","profile_id":"wire-a"}),
        ];
        normalize_source_batch_profiles(&mut events)?;
        assert_eq!(events[0]["profile"]["id"], logical);
        assert_eq!(events[1]["node"]["properties"]["profile_id"], logical);
        assert_eq!(
            events[1]["node"]["properties"]["profile_ids"],
            json!([logical])
        );
        assert_eq!(events[2]["edge"]["profile_id"], logical);
        assert_eq!(
            events[2]["edge"]["evidence"][0]["properties"]["profile_id"],
            logical
        );
        assert_eq!(
            events[2]["edge"]["evidence"][0]["properties"]["source_text"],
            "wire-a"
        );
        assert_eq!(events[2]["edge"]["id"], "stable-edge");
        assert_eq!(
            events[2]["edge"]["condition"],
            json!({"op":"all","conditions":[]})
        );
        assert!(
            events[0]["profile"]["properties"]
                .get("analysis_source_path_count")
                .is_none()
        );
        assert!(
            events[0]["profile"]["properties"]
                .get("analysis_chunk_id")
                .is_none()
        );
        let mut invalid = events.clone();
        invalid[0]["profile"]["properties"]["analysis_logical_profile_id"] = json!("other-unit");
        assert!(normalize_source_batch_profiles(&mut invalid).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_chunk_prevents_complete_stage_and_counts_are_accumulated_once() -> Result<()> {
        let mut events = vec![
            json!({"event":"profile_completed","profile_id":"logical","coverage":{"profiles":1,"dependency_sites":2,"project_code_executed":false,"completeness":["syntax-complete","semantic-complete"],"reasons":[]}}),
            json!({"event":"profile_completed","profile_id":"logical","coverage":{"profiles":1,"dependency_sites":3,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":["semantic-incomplete"]}}),
        ];
        coalesce_stage_completions(&mut events)?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["coverage"]["profiles"], 1);
        assert_eq!(events[0]["coverage"]["dependency_sites"], 5);
        assert_eq!(
            events[0]["coverage"]["completeness"],
            json!(["syntax-complete"])
        );
        assert_eq!(
            events[0]["coverage"]["reasons"],
            json!(["semantic-incomplete"])
        );
        Ok(())
    }
}
