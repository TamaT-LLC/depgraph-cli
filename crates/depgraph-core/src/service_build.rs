use std::io::Cursor;

use anyhow::{Context as _, Result as AnyResult, bail};
use depgraph_store::{CacheLayer, Store};

use crate::{
    BuildAudit, BuildExecutionOutcome, BuildOutcomeKind, CancellationToken,
    CompilerPackRequirement, CompilerPreciseCachedEvidence, acquire_store_writer_lock,
    build_cache_key, compiler_precise_cache_hit_audit, compiler_precise_cache_key,
    compiler_precise_graph_ndjson, create_build_execution_request,
    create_compiler_precise_invocation_request, create_compiler_precise_unit_graph_request,
    execute_build_request_with_cancellation, prepare_build_cache_input,
    prepare_compiler_precise_cache_input, rust_build_protocol_ndjson, snapshot_profile_plan_id,
    stage_build_evidence, validate_build_cache_input, validate_build_cache_source,
    validate_compiler_precise_cache_input, validate_compiler_precise_cached_evidence,
    verify_compiler_pack, web_build_protocol_ndjson,
};

use crate::service::{
    DepgraphMutatingUseCaseKind, DepgraphService, DepgraphServiceError, DepgraphServiceResult,
};

/// Acknowledged request for the shared project-execution service boundary.
///
/// The acknowledgement is intentionally a request field instead of ambient
/// process state. It records only the caller's explicit acknowledgement and
/// never substitutes for startup capabilities or the Agent host's human
/// confirmation UI.
#[derive(Clone, Debug)]
pub struct ResolveBuildRequest {
    acknowledgement: bool,
    rust_compiler_precise: bool,
    compiler_pack_requirement: Option<CompilerPackRequirement>,
}

impl ResolveBuildRequest {
    #[must_use]
    pub const fn new(
        acknowledgement: bool,
        rust_compiler_precise: bool,
        compiler_pack_requirement: Option<CompilerPackRequirement>,
    ) -> Self {
        Self {
            acknowledgement,
            rust_compiler_precise,
            compiler_pack_requirement,
        }
    }

    #[must_use]
    pub const fn acknowledgement(&self) -> bool {
        self.acknowledgement
    }

    #[must_use]
    pub const fn rust_compiler_precise(&self) -> bool {
        self.rust_compiler_precise
    }

    #[must_use]
    pub const fn compiler_pack_requirement(&self) -> Option<&CompilerPackRequirement> {
        self.compiler_pack_requirement.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct ResolveBuildServiceOutcome {
    execution: BuildExecutionOutcome,
    completed_snapshot_id: Option<String>,
    evidence_status: &'static str,
    cache_lookup_status: String,
    cache_lookup_reason: String,
    build_cache_status: &'static str,
    cache_reused: bool,
}

impl ResolveBuildServiceOutcome {
    #[must_use]
    pub const fn execution(&self) -> &BuildExecutionOutcome {
        &self.execution
    }

    #[must_use]
    pub fn audit(&self) -> &BuildAudit {
        &self.execution.audit
    }

    #[must_use]
    pub fn completed_snapshot_id(&self) -> Option<&str> {
        self.completed_snapshot_id.as_deref()
    }

    #[must_use]
    pub const fn evidence_status(&self) -> &'static str {
        self.evidence_status
    }

    #[must_use]
    pub fn cache_lookup_status(&self) -> &str {
        &self.cache_lookup_status
    }

    #[must_use]
    pub fn cache_lookup_reason(&self) -> &str {
        &self.cache_lookup_reason
    }

    #[must_use]
    pub const fn build_cache_status(&self) -> &'static str {
        self.build_cache_status
    }

    #[must_use]
    pub const fn cache_reused(&self) -> bool {
        self.cache_reused
    }
}

impl DepgraphService {
    /// Execute and persist `resolve --build` through the shared project-exec
    /// boundary used by the CLI and durable operation runner.
    pub async fn resolve_build_cancellable(
        &self,
        request: &ResolveBuildRequest,
        cancellation: &CancellationToken,
    ) -> DepgraphServiceResult<ResolveBuildServiceOutcome> {
        // Authorization and acknowledgement precede pack access, store access,
        // executable resolution, probes, and project child creation.
        for required in DepgraphMutatingUseCaseKind::ProjectExecution.required_capabilities() {
            if !self.config().capabilities().contains(*required) {
                return Err(DepgraphServiceError::CapabilityDenied {
                    required: *required,
                });
            }
        }
        if !request.acknowledgement {
            return Err(DepgraphServiceError::InvalidInput);
        }
        if !self.config().repository_root_seal().matches_live_root() {
            return Err(DepgraphServiceError::Integrity);
        }
        match (
            request.rust_compiler_precise,
            request.compiler_pack_requirement.as_ref(),
        ) {
            (true, Some(requirement)) => {
                verify_compiler_pack(requirement)
                    .map_err(DepgraphServiceError::project_execution)?;
            }
            (true, None) | (false, Some(_)) => return Err(DepgraphServiceError::InvalidInput),
            (false, None) => {}
        }
        if cancellation.is_cancelled() {
            return Err(DepgraphServiceError::Cancelled);
        }

        resolve_build_inner(self, request, cancellation)
            .await
            .map_err(DepgraphServiceError::project_execution)
    }
}

async fn resolve_build_inner(
    service: &DepgraphService,
    service_request: &ResolveBuildRequest,
    cancellation: &CancellationToken,
) -> AnyResult<ResolveBuildServiceOutcome> {
    let root = service.config().canonical_root();
    let store_path = service.config().store_path();
    let rust_compiler_precise = service_request.rust_compiler_precise;
    let compiler_precise_requirement = service_request.compiler_pack_requirement.clone();
    let compiler_precise_request = compiler_precise_requirement
        .as_ref()
        .map(|requirement| create_compiler_precise_unit_graph_request(root, requirement.clone()))
        .transpose()?;
    let _store_writer_lock = acquire_store_writer_lock(store_path)?;
    let request = if let Some(request) = compiler_precise_request {
        request
    } else {
        create_build_execution_request(root)?
    };
    let mut store = Store::open(store_path)?;
    let base_scan_id = store.latest_successful_id()?;
    let mut cache_input = None;
    let mut cache_key = None;
    let mut compiler_cache_input = None;
    let mut compiler_cache_key = None;
    let mut cache_lookup_status = "unavailable".to_owned();
    let mut cache_lookup_reason = "no-completed-base-scan".to_owned();

    if rust_compiler_precise {
        if let Some(base_scan_id) = base_scan_id.as_deref()
            && let Some(base_snapshot_id) = store.snapshot_id_for_source("scan", base_scan_id)?
        {
            let base = store.load_snapshot(&base_snapshot_id)?;
            if let Some(profile_plan_id) = snapshot_profile_plan_id(&base)? {
                match prepare_compiler_precise_cache_input(
                    &request,
                    &base_snapshot_id,
                    &profile_plan_id,
                ) {
                    Ok(input) => {
                        let key = compiler_precise_cache_key(&input);
                        let lookup = store.lookup_compiler_precise_cache(&key)?;
                        cache_lookup_status = lookup.result.outcome.clone();
                        cache_lookup_reason = lookup.result.reason.clone();
                        if lookup.result.outcome == "hit" {
                            let evidence = lookup
                                .payload
                                .as_ref()
                                .and_then(|payload| payload.get("evidence"))
                                .cloned()
                                .and_then(|value| {
                                    serde_json::from_value::<CompilerPreciseCachedEvidence>(value)
                                        .ok()
                                });
                            let cached_audit = lookup.audit.as_ref().and_then(|audit| {
                                serde_json::from_value::<BuildAudit>(audit.clone()).ok()
                            });
                            let confirmed = prepare_compiler_precise_cache_input(
                                &request,
                                &base_snapshot_id,
                                &profile_plan_id,
                            )
                            .map(|confirmed| compiler_precise_cache_key(&confirmed));
                            if confirmed.as_ref().ok() == Some(&key)
                                && evidence.as_ref().is_some_and(|evidence| {
                                    validate_compiler_precise_cached_evidence(
                                        evidence, &input, &key,
                                    )
                                    .is_ok()
                                })
                                && cached_audit.as_ref().is_some_and(|audit| {
                                    matches!(audit.outcome, BuildOutcomeKind::Completed)
                                        && audit.source_root_digest == input.source_root_digest
                                        && audit.validated_output_digest.as_deref()
                                            == evidence.as_ref().map(|evidence| {
                                                evidence.validated_output_digest.as_str()
                                            })
                                })
                            {
                                let audit = compiler_precise_cache_hit_audit(
                                    cached_audit
                                        .as_ref()
                                        .context("validated compiler cache audit is missing")?,
                                );
                                let audit_value = serde_json::to_value(&audit)?;
                                let published = store
                                    .promote_validated_compiler_precise_cache_hit_with_precommit(
                                        &lookup,
                                        base_scan_id,
                                        &audit_value,
                                        || {
                                            validate_compiler_precise_cache_input(
                                                &input,
                                                &request,
                                                &profile_plan_id,
                                            )
                                        },
                                    )
                                    .is_ok();
                                if published {
                                    let evidence = evidence
                                        .context("validated compiler cache evidence is missing")?;
                                    return Ok(ResolveBuildServiceOutcome {
                                        execution: BuildExecutionOutcome {
                                            audit,
                                            project_code_executed: false,
                                            compiler_pack_attestation: Some(
                                                evidence.compiler_pack_attestation,
                                            ),
                                            rust_cargo_unit_graph: Some(evidence.unit_graph),
                                            rust_compiler_invocation_ledger: Some(
                                                evidence.invocation_ledger,
                                            ),
                                            rust_compiler_mir_ledger: Some(evidence.mir_ledger),
                                            rust_observation: None,
                                            web_observation: None,
                                        },
                                        completed_snapshot_id: store.current_snapshot_id()?,
                                        evidence_status: "reused compiler-precise graph",
                                        cache_lookup_status: "hit".to_owned(),
                                        cache_lookup_reason: "validated".to_owned(),
                                        build_cache_status: "hit",
                                        cache_reused: true,
                                    });
                                }
                            }
                            cache_lookup_status = "reject".to_owned();
                            cache_lookup_reason = "corrupt".to_owned();
                        }
                        compiler_cache_input = Some(input);
                        compiler_cache_key = Some(key);
                    }
                    Err(_) => {
                        cache_lookup_status = "reject".to_owned();
                        cache_lookup_reason = "unsafe-input".to_owned();
                    }
                }
            } else {
                cache_lookup_status = "reject".to_owned();
                cache_lookup_reason = "unsafe-input".to_owned();
            }
        }
    } else if let Some(base_scan_id) = base_scan_id.as_deref()
        && let Some(base_snapshot_id) = store.build_cache_base_snapshot_id(base_scan_id)?
        && let Some(input) = prepare_build_cache_input(&request, &base_snapshot_id).await?
    {
        let key = build_cache_key(&input);
        let lookup = store.lookup_build_cache(&key)?;
        cache_lookup_status = lookup.result.outcome.clone();
        cache_lookup_reason = lookup.result.reason.clone();
        if lookup.result.outcome == "hit" {
            let confirmed = prepare_build_cache_input(&request, &base_snapshot_id)
                .await?
                .map(|input| build_cache_key(&input));
            let cached_audit = lookup
                .audit
                .as_ref()
                .and_then(|audit| serde_json::from_value::<BuildAudit>(audit.clone()).ok());
            if confirmed.as_ref() == Some(&key)
                && cached_audit.as_ref().is_some_and(|audit| {
                    matches!(audit.outcome, BuildOutcomeKind::Completed)
                        && validate_build_cache_input(&input, audit)
                })
                && store
                    .publish_validated_build_cache_hit_with_precommit(&lookup, || {
                        validate_build_cache_source(&input, root)
                    })
                    .is_ok()
            {
                return Ok(ResolveBuildServiceOutcome {
                    execution: BuildExecutionOutcome {
                        audit: cached_audit.context("validated build cache audit is missing")?,
                        project_code_executed: false,
                        compiler_pack_attestation: None,
                        rust_cargo_unit_graph: None,
                        rust_compiler_invocation_ledger: None,
                        rust_compiler_mir_ledger: None,
                        rust_observation: None,
                        web_observation: None,
                    },
                    completed_snapshot_id: store.current_snapshot_id()?,
                    evidence_status: "reused",
                    cache_lookup_status: "hit".to_owned(),
                    cache_lookup_reason: "validated".to_owned(),
                    build_cache_status: "hit",
                    cache_reused: true,
                });
            }
            cache_lookup_status = "reject".to_owned();
            cache_lookup_reason = "input-changed-before-publication".to_owned();
        }
        cache_input = Some(input);
        cache_key = Some(key);
    }

    if cancellation.is_cancelled() {
        bail!("build request was cancelled before execution");
    }
    let mut outcome =
        execute_build_request_with_cancellation(&request, cancellation.cancelled()).await?;
    if rust_compiler_precise && matches!(outcome.audit.outcome, BuildOutcomeKind::Completed) {
        let unit_graph = outcome
            .rust_cargo_unit_graph
            .clone()
            .context("compiler-precise unit graph stage produced no validated graph")?;
        let invocation_request = create_compiler_precise_invocation_request(
            root,
            compiler_precise_requirement
                .clone()
                .context("compiler-precise pack requirement is unavailable")?,
            unit_graph,
            outcome.audit.source_root_digest.clone(),
        )?;
        outcome =
            execute_build_request_with_cancellation(&invocation_request, cancellation.cancelled())
                .await?;
    }

    let audit_value = serde_json::to_value(&outcome.audit)?;
    store.save_build_audit(&audit_value)?;
    let mut evidence_status = "audit-only (no completed base scan)";
    let mut build_cache_status = "not stored";
    if let Some(base_scan_id) = base_scan_id {
        evidence_status = "not promoted";
        let build_attempt_required = requires_build_attempt(
            &outcome.audit.outcome,
            outcome.rust_compiler_mir_ledger.is_some(),
            outcome.rust_compiler_invocation_ledger.is_some(),
            outcome.rust_cargo_unit_graph.is_some(),
        );
        if build_attempt_required {
            if let Some(input) = compiler_cache_input.as_ref() {
                store.start_build_attempt_at_base_snapshot(
                    &base_scan_id,
                    &input.base_snapshot_id,
                    &audit_value,
                )?;
            } else {
                store.start_build_attempt(&base_scan_id, &audit_value)?;
            }
            if cache_input.is_some() && matches!(cache_lookup_status.as_str(), "miss" | "reject") {
                store.record_cache_event(
                    None,
                    Some(&outcome.audit.run_id),
                    CacheLayer::Build,
                    cache_key.as_ref().map(|key| key.key.as_str()),
                    &cache_lookup_status,
                    &cache_lookup_reason,
                )?;
            }
            if rust_compiler_precise && matches!(cache_lookup_status.as_str(), "miss" | "reject") {
                store.record_cache_event(
                    None,
                    Some(&outcome.audit.run_id),
                    CacheLayer::CompilerPrecise,
                    compiler_cache_key.as_ref().map(|key| key.key.as_str()),
                    &cache_lookup_status,
                    &cache_lookup_reason,
                )?;
            }
            if let Some(input) = cache_input.as_mut() {
                let attempt_base_snapshot_id = store
                    .build_attempt(&outcome.audit.run_id)?
                    .and_then(|attempt| attempt.base_snapshot_id)
                    .context("build attempt has no completed base snapshot")?;
                if input.base_snapshot_id != attempt_base_snapshot_id {
                    input.base_snapshot_id = attempt_base_snapshot_id;
                    cache_key = Some(build_cache_key(input));
                }
            }
        }

        match outcome.audit.outcome {
            BuildOutcomeKind::Completed => {
                if let Some(mir) = outcome.rust_compiler_mir_ledger.as_ref() {
                    let snapshot = if let Some(input) = compiler_cache_input.as_ref() {
                        store.load_snapshot(&input.base_snapshot_id)?
                    } else {
                        store.load_snapshot(&base_scan_id)?
                    };
                    let ndjson = compiler_precise_graph_ndjson(
                        &snapshot,
                        &outcome.audit,
                        outcome.compiler_pack_attestation.as_ref().context(
                            "completed compiler-precise attempt has no pack attestation",
                        )?,
                        outcome
                            .rust_cargo_unit_graph
                            .as_ref()
                            .context("completed compiler-precise attempt has no unit graph")?,
                        outcome.rust_compiler_invocation_ledger.as_ref().context(
                            "completed compiler-precise attempt has no invocation ledger",
                        )?,
                        mir,
                    );
                    let ndjson = match ndjson {
                        Ok(value) => value,
                        Err(error) => {
                            store.finish_build_attempt(
                                &outcome.audit.run_id,
                                "security_failed",
                                Some("compiler-precise-graph-correlation-failed"),
                                false,
                            )?;
                            return Err(error.context(
                                "security policy violation: compiler-precise graph could not be correlated",
                            ));
                        }
                    };
                    if let Err(error) =
                        stage_build_evidence(&mut store, &outcome.audit.run_id, Cursor::new(ndjson))
                    {
                        store.finish_build_attempt(
                            &outcome.audit.run_id,
                            "security_failed",
                            Some("compiler-precise-evidence-rejected"),
                            false,
                        )?;
                        return Err(error.context(
                            "security policy violation: compiler-precise evidence was rejected",
                        ));
                    }
                    store.finish_build_attempt(&outcome.audit.run_id, "completed", None, true)?;
                    evidence_status = "promoted compiler-precise graph";

                    if let (Some(input), Some(key)) =
                        (compiler_cache_input.as_ref(), compiler_cache_key.as_ref())
                    {
                        let pack = outcome
                            .compiler_pack_attestation
                            .as_ref()
                            .context("completed compiler-precise cache result has no pack")?;
                        let unit_graph = outcome
                            .rust_cargo_unit_graph
                            .as_ref()
                            .context("completed compiler cache result has no unit graph")?;
                        let invocations = outcome
                            .rust_compiler_invocation_ledger
                            .as_ref()
                            .context("completed compiler cache result has no invocation ledger")?;
                        let validated_output_digest = outcome
                            .audit
                            .validated_output_digest
                            .as_deref()
                            .context("completed compiler cache result has no output digest")?;
                        let cache_evidence = CompilerPreciseCachedEvidence {
                            schema_version: crate::COMPILER_PRECISE_CACHE_ENTRY_SCHEMA_VERSION
                                .to_owned(),
                            cache_contract_version: crate::COMPILER_PRECISE_CACHE_CONTRACT_VERSION
                                .to_owned(),
                            effective_input_identity: key.key.clone(),
                            base_snapshot_id: input.base_snapshot_id.clone(),
                            compiler_pack_attestation: pack.clone(),
                            unit_graph: unit_graph.clone(),
                            invocation_ledger: invocations.clone(),
                            mir_ledger: mir.clone(),
                            validated_output_digest: validated_output_digest.to_owned(),
                        };
                        let admitted = outcome.audit.source_root_digest == input.source_root_digest
                            && pack == &input.compiler_pack_attestation
                            && validate_compiler_precise_cached_evidence(
                                &cache_evidence,
                                input,
                                key,
                            )
                            .is_ok()
                            && validate_compiler_precise_cache_input(
                                input,
                                &request,
                                &input.profile_selection_plan_id,
                            )
                            .is_ok();
                        if admitted {
                            if store
                                .store_compiler_precise_cache(
                                    key,
                                    &outcome.audit.run_id,
                                    &serde_json::to_value(&cache_evidence)?,
                                )
                                .is_ok_and(|cache| cache.outcome == "stored")
                            {
                                build_cache_status = "stored";
                            }
                        } else {
                            store.record_cache_event(
                                None,
                                Some(&outcome.audit.run_id),
                                CacheLayer::CompilerPrecise,
                                Some(&key.key),
                                "reject",
                                "input-changed",
                            )?;
                        }
                    }
                } else if outcome.rust_compiler_invocation_ledger.is_some() {
                    evidence_status = "validated compiler invocation ledger (not promoted)";
                } else if outcome.rust_cargo_unit_graph.is_some() {
                    evidence_status = "validated unit graph (not promoted)";
                } else {
                    let snapshot = store.load_snapshot(&base_scan_id)?;
                    let ndjson = if let Some(observation) = outcome.rust_observation.as_ref() {
                        rust_build_protocol_ndjson(&snapshot, &outcome.audit, observation)
                            .context("Rust build observation could not be correlated")
                    } else if let Some(observation) = outcome.web_observation.as_ref() {
                        web_build_protocol_ndjson(&snapshot, &outcome.audit, observation)
                            .await
                            .context("Web build observation could not be correlated")
                    } else {
                        Err(anyhow::anyhow!(
                            "completed build produced no validated observation"
                        ))
                    };
                    let ndjson = match ndjson {
                        Ok(value) => value,
                        Err(error) => {
                            store.finish_build_attempt(
                                &outcome.audit.run_id,
                                "security_failed",
                                Some("build-observation-correlation-failed"),
                                false,
                            )?;
                            return Err(error.context(
                                "security policy violation: build observation could not be correlated",
                            ));
                        }
                    };
                    if let Err(error) =
                        stage_build_evidence(&mut store, &outcome.audit.run_id, Cursor::new(ndjson))
                    {
                        store.finish_build_attempt(
                            &outcome.audit.run_id,
                            "security_failed",
                            Some("build-evidence-rejected"),
                            false,
                        )?;
                        return Err(
                            error.context("security policy violation: build evidence was rejected")
                        );
                    }
                    store.finish_build_attempt(&outcome.audit.run_id, "completed", None, true)?;
                    evidence_status = "promoted";
                    if let (Some(cache_input), Some(cache_key)) =
                        (cache_input.as_ref(), cache_key.as_ref())
                    {
                        if !validate_build_cache_input(cache_input, &outcome.audit) {
                            store.record_cache_event(
                                None,
                                Some(&outcome.audit.run_id),
                                CacheLayer::Build,
                                Some(&cache_key.key),
                                "reject",
                                "input-changed-during-build",
                            )?;
                            build_cache_status = "rejected";
                        } else {
                            let snapshot_id = store
                                .snapshot_id_for_source("build", &outcome.audit.run_id)?
                                .context("promoted build did not expose its completed snapshot")?;
                            let cache = store.store_snapshot_cache(
                                cache_key,
                                &snapshot_id,
                                None,
                                Some(&outcome.audit.run_id),
                            )?;
                            build_cache_status = if cache.outcome == "stored" {
                                "stored"
                            } else {
                                "rejected"
                            };
                        }
                    }
                }
            }
            BuildOutcomeKind::Failed => store.finish_build_attempt(
                &outcome.audit.run_id,
                "failed",
                outcome.audit.diagnostic_code.as_deref(),
                false,
            )?,
            BuildOutcomeKind::TimedOut => store.finish_build_attempt(
                &outcome.audit.run_id,
                "timed_out",
                outcome.audit.diagnostic_code.as_deref(),
                false,
            )?,
            BuildOutcomeKind::Cancelled => store.finish_build_attempt(
                &outcome.audit.run_id,
                "cancelled",
                outcome.audit.diagnostic_code.as_deref(),
                false,
            )?,
            BuildOutcomeKind::SecurityFailed => store.finish_build_attempt(
                &outcome.audit.run_id,
                "security_failed",
                outcome.audit.diagnostic_code.as_deref(),
                false,
            )?,
        }
    }

    if evidence_status == "audit-only (no completed base scan)" {
        if outcome.rust_compiler_mir_ledger.is_some() {
            evidence_status = "validated typed MIR DTO (audit-only; no completed base scan)";
        } else if outcome.rust_compiler_invocation_ledger.is_some() {
            evidence_status =
                "validated compiler invocation ledger (audit-only; no completed base scan)";
        } else if outcome.rust_cargo_unit_graph.is_some() {
            evidence_status = "validated unit graph (audit-only; no completed base scan)";
        }
    }

    Ok(ResolveBuildServiceOutcome {
        execution: outcome,
        completed_snapshot_id: store.current_snapshot_id()?,
        evidence_status,
        cache_lookup_status,
        cache_lookup_reason,
        build_cache_status,
        cache_reused: false,
    })
}

fn requires_build_attempt(
    outcome: &BuildOutcomeKind,
    has_compiler_mir_ledger: bool,
    has_compiler_invocation_ledger: bool,
    has_cargo_unit_graph: bool,
) -> bool {
    !matches!(outcome, BuildOutcomeKind::Completed)
        || has_compiler_mir_ledger
        || (!has_compiler_invocation_ledger && !has_cargo_unit_graph)
}
