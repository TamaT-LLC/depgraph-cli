use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use depgraph_protocol::{Condition, Profile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::sbom::{
    dependency_inventory, legal_document_section, manifest_framework_build_artifact_checksums,
    normalized_spdx_license, third_party_licenses, verify_bounded_query_sbom,
    verify_cross_language_sbom, verify_framework_build_sbom, verify_runtime_collector_sbom,
    verify_rust_sysroot_sbom, web_legal_documents,
};
use super::{
    Artifact, BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION, BOUNDED_QUERY_SBOM_PACKAGE_NAME,
    BoundedQueryPackageSmokeReport, CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION,
    CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID, CROSS_LANGUAGE_RELEASE_FIXTURE_TARGET,
    CROSS_LANGUAGE_SBOM_PACKAGE_NAME, CrossLanguagePackageSmokeReport, CrossLanguageReleaseFixture,
    CrossLanguageReleaseFixtureFile, MCP_APACHE_NOTICE, MCP_MACROS_VERSION,
    MCP_OPERATION_CONTRACT_VERSION, MCP_PROTOCOL_REVISION, MCP_SDK_NAME, MCP_SDK_VERSION,
    MCP_SERVER_NAME, MCP_TOOL_CONTRACT_VERSION, MCP_TOOL_SCHEMA_PATH, McpServerArtifact,
    PROJECT_LICENSE_EXPRESSION, PROJECT_LICENSES, RUNTIME_COLLECTOR_ARTIFACT,
    RUNTIME_COLLECTOR_CONTRACT_VERSION, RUST_ANALYZER_CRATE_VERSION,
    RUST_ANALYZER_DIRECT_DEPENDENCIES, RUST_ANALYZER_REVISION, RUST_SYSROOT_COMPONENT_NAME,
    RUST_SYSROOT_COMPONENT_ROOT, RUST_SYSROOT_COMPONENT_SHA256, RUST_SYSROOT_COMPONENT_VERSION,
    RUST_SYSROOT_LICENSE_EXPRESSION, ReleaseManifest, SALSA_DIRECT_DEPENDENCIES, SALSA_VERSION,
    SBOM_SCOPE, STABLE_UPGRADE_SOURCE_FIXTURE_PATH, STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
    TYPESCRIPT_VERSION, V0_2_RC1_STORE_SCHEMA_VERSION, VERSION, WEB_DEFINITION_SELECTOR,
    WEB_RUNTIME_ARTIFACTS, WebSemanticAttestation, WorkerArtifact, WorkerBackend, copy_directory,
    executable_name, extract_archive, go_semantic_e2e, is_executable, mcp_package_smoke,
    parse_worker_handshake, prefixed_lowercase_sha256, process_argument_path,
    release_compatibility, rust_backend_from_handshake, rust_semantic_e2e, sha256_file,
    sha256_tree, validate_bounded_query_package_smoke, verified_release_path,
    verify_mcp_tool_schema_bytes, verify_release_artifact, verify_runtime_collector_module,
    verify_rust_backend, verify_rust_sysroot_tree, verify_typescript_compiler,
    verify_web_semantic_attestation, web_semantic_from_handshake, workspace_root,
};

fn materialize_cross_language_fixture(
    fixture: &CrossLanguageReleaseFixture,
    root: &Path,
    reverse: bool,
) -> Result<()> {
    if fixture.schema_version != "cross-language-release-fixture-v1"
        || fixture.files.is_empty()
        || fixture.files.len() > 64
        || fixture
            .files
            .windows(2)
            .any(|pair| pair[0].path.as_bytes() >= pair[1].path.as_bytes())
    {
        bail!("packaged cross-language fixture is non-canonical or unbounded");
    }
    let files: Box<dyn Iterator<Item = &CrossLanguageReleaseFixtureFile>> = if reverse {
        Box::new(fixture.files.iter().rev())
    } else {
        Box::new(fixture.files.iter())
    };
    for file in files {
        let relative = Path::new(&file.path);
        if file.path.is_empty()
            || file.path.len() > 4_096
            || file.content.len() > 1_048_576
            || file.path.contains('\\')
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("packaged cross-language fixture contains an unsafe file");
        }
        let destination = root.join(relative);
        fs::create_dir_all(
            destination
                .parent()
                .context("cross-language fixture file has no parent")?,
        )?;
        fs::write(destination, file.content.as_bytes())?;
    }
    Ok(())
}

fn cross_language_fixture_export(root: &Path) -> Result<(Value, Value)> {
    let profiles = vec![Profile {
        id: CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID.to_owned(),
        language: "polyglot".to_owned(),
        toolchain: None,
        command: None,
        target: Some(CROSS_LANGUAGE_RELEASE_FIXTURE_TARGET.to_owned()),
        features: Vec::new(),
        environment: BTreeMap::new(),
        source_revision: None,
        properties: BTreeMap::new(),
    }];
    let openapi = depgraph_core::scan_openapi_repository(root, &profiles)?
        .context("packaged cross-language fixture has no OpenAPI graph")?;
    let protobuf = depgraph_core::scan_protobuf_repository(root, &profiles)?
        .context("packaged cross-language fixture has no Protobuf graph")?;
    let graphql = depgraph_core::scan_graphql_repository(root, &profiles)?
        .context("packaged cross-language fixture has no GraphQL graph")?;
    let ffi = depgraph_core::scan_ffi_repository(root, &profiles)?
        .context("packaged cross-language fixture has no FFI graph")?;

    let operation = openapi
        .nodes
        .iter()
        .find(|node| {
            node.kind == "operation"
                && node.properties["canonical_identity"]["coordinate"] == "get /pets/{id}"
        })
        .context("packaged OpenAPI graph has no canonical get /pets/{id} operation")?;
    let repository_symbol = openapi
        .nodes
        .iter()
        .find(|node| {
            node.kind == "symbol"
                && node.properties["repository_path"].as_str() == Some("src/client.rs")
                && node.display_name.as_deref() == Some("client::get_pet")
        })
        .context("packaged OpenAPI graph has no repository endpoint symbol")?;
    let mapping = openapi
        .edges
        .iter()
        .find(|edge| {
            edge.kind == "calls_operation"
                && edge.source == repository_symbol.id
                && edge.target == operation.id
                && edge.resolution_status == depgraph_protocol::ResolutionStatus::Resolved
                && edge.precision == depgraph_protocol::Precision::Exact
        })
        .context("packaged OpenAPI graph cannot query contract to repository endpoint")?;
    if !protobuf.nodes.iter().any(|node| {
        node.kind == "operation"
            && node.properties["canonical_identity"]["coordinate"] == "shop.v1.Pets/GetPet"
    }) || !graphql.nodes.iter().any(|node| {
        node.kind == "operation"
            && node.properties["canonical_identity"]["coordinate"] == "query GetPet"
    }) || ffi.sites.is_empty()
    {
        bail!("packaged cross-language fixture did not exercise every source adapter");
    }

    let runtime_trace = cross_language_runtime_trace(repository_symbol.id.clone());
    let http_runtime = depgraph_core::correlate_http_operations(
        &runtime_trace,
        &[openapi.clone(), protobuf.clone(), graphql.clone()],
    )
    .context("packaged cross-language fixture failed HTTP runtime correlation")?;
    let http_outcome = http_runtime
        .outcomes
        .first()
        .filter(|outcome| {
            http_runtime.outcomes.len() == 1
                && outcome.status == depgraph_protocol::ResolutionStatus::Resolved
                && outcome.operation_ids == [operation.id.clone()]
        })
        .context("packaged cross-language fixture did not resolve its HTTP operation")?;
    let http_runtime_edge = http_runtime
        .deltas
        .iter()
        .flat_map(|delta| &delta.edges)
        .find(|edge| {
            edge.phase == depgraph_protocol::Phase::Runtime
                && edge.precision == depgraph_protocol::Precision::Observed
                && edge.resolution_status == depgraph_protocol::ResolutionStatus::Resolved
                && edge.target == operation.id
        })
        .context("packaged cross-language fixture produced no observed HTTP runtime edge")?;

    let ffi_entries = cross_language_ffi_entries(&ffi)?;
    let ffi_outcome = cross_language_ffi_outcome(root, &ffi_entries)?;
    let ffi_observation = depgraph_core::collect_supervised_ffi_link_observation(
        &ffi_outcome,
        "x86_64",
        "dynamic",
        ffi_entries,
    )
    .context("packaged cross-language fixture failed supervised FFI collection")?;
    let ffi = depgraph_core::correlate_ffi_link_observation(&ffi, &ffi_outcome, &ffi_observation)
        .context("packaged cross-language fixture failed supervised FFI correlation")?;
    let ffi_observed_edge_ids = ffi
        .edges
        .iter()
        .filter(|edge| {
            edge.phase == depgraph_protocol::Phase::Build
                && edge.precision == depgraph_protocol::Precision::Observed
                && edge.resolution_status == depgraph_protocol::ResolutionStatus::Resolved
        })
        .map(|edge| edge.id.clone())
        .collect::<Vec<_>>();
    if ffi_observed_edge_ids.is_empty() {
        bail!("packaged cross-language fixture produced no observed FFI link edge");
    }

    let export = json!({
        "ffi": ffi,
        "graphql": graphql,
        "http_runtime": http_runtime,
        "openapi": openapi,
        "protobuf": protobuf,
    });
    let query = json!({
        "edge_id": mapping.id,
        "ffi_observed_edge_ids": ffi_observed_edge_ids,
        "http_runtime_edge_id": http_runtime_edge.id,
        "http_runtime_outcome_id": http_outcome.id,
        "operation_id": operation.id,
        "repository_path": "src/client.rs",
        "repository_symbol_id": repository_symbol.id,
    });
    Ok((export, query))
}

fn cross_language_runtime_trace(source_id: String) -> depgraph_core::ValidatedRuntimeTrace {
    let repository = depgraph_core::RuntimeTraceRepository {
        identity: "cross-language-release-fixture".to_owned(),
        revision: Some("fixture-v1".to_owned()),
    };
    let session = depgraph_core::RuntimeTraceSession {
        id: "cross-language-release-http".to_owned(),
        started_at: "2026-07-26T00:00:00Z".to_owned(),
        ended_at: Some("2026-07-26T00:00:01Z".to_owned()),
        collector_contract_version: Some(
            depgraph_core::RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
        ),
        profile: depgraph_core::RuntimeTraceProfile {
            language: "polyglot".to_owned(),
            target: Some(CROSS_LANGUAGE_RELEASE_FIXTURE_TARGET.to_owned()),
            features: Vec::new(),
            parent_profile_id: Some(CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID.to_owned()),
        },
        environment: depgraph_core::RuntimeTraceEnvironment {
            name: "release-fixture".to_owned(),
            runtime: Some("fixture".to_owned()),
            region: None,
            environment_keys: Vec::new(),
        },
        redaction: depgraph_core::RuntimeTraceRedaction::default(),
    };
    let source = depgraph_core::RuntimeTraceLocator::Node {
        node_id: source_id.clone(),
    };
    let target = depgraph_core::RuntimeTraceLocator::External {
        namespace: "https".to_owned(),
        name: "api.example.test".to_owned(),
    };
    let http = depgraph_core::RuntimeHttpObservation {
        method: "GET".to_owned(),
        route_template: "/pets/{id}".to_owned(),
        format: Some(depgraph_core::RuntimeHttpOperationFormat::Openapi),
        operation: Some("get /pets/{id}".to_owned()),
        contract_locator: Some("openapi.json".to_owned()),
        format_version: Some("3.1.1".to_owned()),
    };
    let event_id = depgraph_protocol::stable_id_from_value(
        "runtime-event",
        &json!({
            "schema_version": depgraph_core::RUNTIME_TRACE_SCHEMA_VERSION,
            "repository_identity": repository.identity,
            "repository_revision": repository.revision,
            "session_id": session.id,
            "sequence": 1,
            "timestamp": "2026-07-26T00:00:00Z",
            "profile": session.profile,
            "environment": session.environment,
            "dependency_kind": "requests",
            "source": source,
            "target": target,
            "http": http,
            "count": 1,
            "duration_ns": 1,
        }),
    );
    depgraph_core::ValidatedRuntimeTrace {
        schema_version: depgraph_core::RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
        repository,
        session,
        profile_match: depgraph_core::RuntimeTraceProfileMatch {
            status: depgraph_core::RuntimeTraceMatchStatus::Resolved,
            parent_profile_id: Some(CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID.to_owned()),
            reason: None,
        },
        events: vec![depgraph_core::ValidatedRuntimeTraceEvent {
            id: event_id,
            sequence: 1,
            timestamp: "2026-07-26T00:00:00Z".to_owned(),
            dependency_kind: "requests".to_owned(),
            source: depgraph_core::MatchedRuntimeTraceLocator {
                status: depgraph_core::RuntimeTraceMatchStatus::Resolved,
                node_id: Some(source_id),
                reason: None,
                input: source,
            },
            target: depgraph_core::MatchedRuntimeTraceLocator {
                status: depgraph_core::RuntimeTraceMatchStatus::External,
                node_id: None,
                reason: Some("collector_external".to_owned()),
                input: target,
            },
            http: Some(http),
            count: 1,
            duration_ns: Some(1),
            redaction: depgraph_core::RuntimeTraceRedaction::default(),
        }],
        summary: depgraph_core::RuntimeTraceSummary {
            events: 1,
            resolved_targets: 0,
            external_targets: 1,
            unresolved_targets: 0,
            redacted_values: 0,
        },
    }
}

fn cross_language_ffi_entries(
    ffi: &depgraph_protocol::CrossLanguageAdapterDelta,
) -> Result<Vec<depgraph_core::FfiObservedLink>> {
    ffi.sites
        .iter()
        .filter(|site| {
            site.precision != depgraph_protocol::Precision::Observed
                && site.evidence.iter().any(|evidence| {
                    evidence.properties["target_profile_id"].as_str()
                        == Some(CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID)
                })
        })
        .map(|site| {
            let properties = &site
                .evidence
                .first()
                .context("packaged FFI declaration has no source evidence")?
                .properties;
            let field = |name: &str| {
                properties[name]
                    .as_str()
                    .with_context(|| format!("packaged FFI declaration has no {name}"))
            };
            let library = field("library_request")?;
            let symbol = field("symbol_request")?;
            Ok(depgraph_core::FfiObservedLink {
                declaration_site_id: site.id.clone(),
                abi: field("ffi_abi")?.to_owned(),
                direction: field("ffi_direction")?.to_owned(),
                library: library.to_owned(),
                symbol: symbol.to_owned(),
                library_artifact_digest: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(format!("{library}:{symbol}").as_bytes()))
                ),
            })
        })
        .collect()
}

fn cross_language_ffi_outcome(
    root: &Path,
    entries: &[depgraph_core::FfiObservedLink],
) -> Result<depgraph_core::BuildExecutionOutcome> {
    let validated_output_digest = hex::encode(Sha256::digest(
        depgraph_protocol::canonical_json(&serde_json::to_value(entries)?).as_bytes(),
    ));
    Ok(depgraph_core::BuildExecutionOutcome {
        audit: depgraph_core::BuildAudit {
            schema_version: "build-audit-v1".to_owned(),
            run_id: "cross-language-release-ffi-link".to_owned(),
            adapter: depgraph_core::FFI_LINK_OBSERVER.to_owned(),
            adapter_version: depgraph_core::FFI_LINK_OBSERVER_VERSION.to_owned(),
            profile_id: CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID.to_owned(),
            command_program: "release-fixture-linker".to_owned(),
            command_arguments: Vec::new(),
            command_plan_digest: validated_output_digest.clone(),
            logical_cwd: ".".to_owned(),
            source_root_digest: sha256_tree(root)?,
            toolchain_executable_digest: hex::encode(Sha256::digest(
                depgraph_core::FFI_LINK_OBSERVER_VERSION.as_bytes(),
            )),
            toolchain_version: Some("fixture-v1".to_owned()),
            target: Some(CROSS_LANGUAGE_RELEASE_FIXTURE_TARGET.to_owned()),
            environment_keys: Vec::new(),
            environment_key_set_digest: hex::encode(Sha256::digest([])),
            redacted_secret_key_count: 0,
            timeout_seconds: 60,
            stdout_limit_bytes: 1_024,
            stderr_limit_bytes: 1_024,
            network_policy: "deny".to_owned(),
            network_isolation: depgraph_core::NetworkIsolation::Enforced,
            isolation: depgraph_core::BuildIsolation::EnforcedLinuxNamespace,
            source_mutation: depgraph_core::BuildSourceMutationAudit {
                status: depgraph_core::BuildSourceMutationStatus::Unchanged,
                non_mutation_guaranteed: true,
                diagnostic: None,
            },
            isolation_diagnostic: None,
            started_at: "2026-07-26T00:00:00Z".to_owned(),
            finished_at: "2026-07-26T00:00:01Z".to_owned(),
            duration_millis: 1,
            outcome: depgraph_core::BuildOutcomeKind::Completed,
            exit_code: Some(0),
            stdout_truncated: false,
            stderr_truncated: false,
            validated_output_digest: Some(validated_output_digest),
            diagnostic_code: None,
            compiler_failure: None,
        },
        project_code_executed: true,
        compiler_pack_attestation: None,
        rust_cargo_unit_graph: None,
        rust_compiler_invocation_ledger: None,
        rust_compiler_mir_ledger: None,
        rust_observation: None,
        web_observation: None,
    })
}

pub(crate) fn verify_packaged_cross_language(
    extracted: &Path,
    target: &str,
    archive_sha256: &str,
) -> Result<CrossLanguagePackageSmokeReport> {
    let fixture_path = extracted.join(depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH);
    let fixture: CrossLanguageReleaseFixture = serde_json::from_slice(&fs::read(&fixture_path)?)
        .context("packaged cross-language fixture has an invalid schema")?;
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    materialize_cross_language_fixture(&fixture, first.path(), false)?;
    materialize_cross_language_fixture(&fixture, second.path(), true)?;
    let first_output = cross_language_fixture_export(first.path())?;
    let second_output = cross_language_fixture_export(second.path())?;
    if first_output != second_output {
        bail!("packaged cross-language graph/query changed with checkout or file order");
    }
    let canonical_export = depgraph_protocol::canonical_json(&first_output.0);
    let canonical_query = depgraph_protocol::canonical_json(&first_output.1);
    Ok(CrossLanguagePackageSmokeReport {
        schema_version: CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION.to_owned(),
        target: target.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        contract: depgraph_core::cross_language_release_compatibility_contract(),
        graph_digest: depgraph_protocol::stable_id_from_value(
            "cross-language-release-graph",
            &first_output.0,
        ),
        canonical_export_sha256: hex::encode(Sha256::digest(canonical_export.as_bytes())),
        query_output_sha256: hex::encode(Sha256::digest(canonical_query.as_bytes())),
    })
}

pub(crate) fn verify_archive(
    archive: &Path,
    checksum: &Path,
    name: &str,
) -> Result<(
    BoundedQueryPackageSmokeReport,
    CrossLanguagePackageSmokeReport,
    mcp_package_smoke::McpPackageSmokeReport,
)> {
    let archive_sha256 = sha256_file(archive)?;
    let verify_root = std::env::temp_dir().join(format!(
        "depgraph-release-gate-{}-{}",
        std::process::id(),
        name
    ));
    if verify_root.exists() {
        fs::remove_dir_all(&verify_root)?;
    }
    fs::create_dir_all(&verify_root)?;
    extract_archive(archive, &verify_root)?;

    let extracted = verify_root.join(name);
    let executable = extracted.join("bin").join(executable_name("depgraph"));
    let release_manifest = verify_release_metadata(&extracted)?;
    #[cfg(unix)]
    {
        let symlinked_root = verify_root.join("symlinked-release-root");
        std::os::unix::fs::symlink(&extracted, &symlinked_root)?;
        let error = verify_release_metadata(&symlinked_root)
            .expect_err("release metadata accepted a symlinked release root");
        if !error
            .to_string()
            .contains("release root must not be a symlink")
        {
            bail!("release-root symlink gate returned the wrong error: {error:#}");
        }
        fs::remove_file(symlinked_root)?;
    }
    #[cfg(unix)]
    verify_release_static_prelaunch_fails_closed(&extracted)?;
    let mcp_smoke = mcp_package_smoke::verify(
        &workspace_root(),
        &extracted,
        archive,
        checksum,
        &release_manifest.target,
        &archive_sha256,
        VERSION,
    )?;
    let store = verify_root.join("gate.db");
    // Doctor is intentionally read-only and must not create or migrate a store.
    // Seed the package-smoke fixture explicitly before exercising that boundary.
    drop(depgraph_store::Store::open(&store)?);
    let doctor = Command::new(&executable)
        .arg("--store")
        .arg(&store)
        .arg("doctor")
        .arg("--json")
        .output()
        .with_context(|| {
            format!(
                "failed to run packaged doctor from {}",
                executable.display()
            )
        })?;
    if !doctor.status.success() {
        bail!(
            "packaged doctor failed: {}",
            String::from_utf8_lossy(&doctor.stderr)
        );
    }
    let doctor: Value = serde_json::from_slice(&doctor.stdout)?;
    let workers_healthy = doctor["workers"].as_array().is_some_and(|workers| {
        workers.len() == 3
            && workers.iter().all(|worker| {
                worker["available"] == Value::Bool(true) && worker["integrity"] == "verified"
            })
    });
    let release = &doctor["release"];
    if doctor["protocol_version"] != "1.0"
        || release["core_integrity"] != "verified"
        || release["schema_integrity"] != "verified"
        || release["compatibility_integrity"] != "verified"
        || !workers_healthy
    {
        bail!("packaged doctor did not verify the public release and worker health: {doctor}");
    }

    let fixture = Path::new("workers/web/test/fixtures/polyglot").canonicalize()?;
    let first_web_store = verify_root.join("web.db");
    verify_packaged_scan(&executable, &first_web_store, &fixture, "web")?;
    verify_packaged_build_evidence(
        &executable,
        &extracted,
        &verify_root,
        &fixture,
        &first_web_store,
    )?;
    verify_packaged_project_licenses_fail_closed(&executable, &extracted, &verify_root, &fixture)?;
    for marker in [
        fixture.join("apps/next-app/NEXT_CONFIG_EXECUTED"),
        fixture.join("apps/astro-app/ASTRO_CONFIG_EXECUTED"),
    ] {
        if marker.exists() {
            bail!(
                "safe release gate executed project code: {}",
                marker.display()
            );
        }
    }
    let second_fixture = verify_root.join("web-fixture-checkout-two");
    copy_directory(&fixture, &second_fixture)?;
    let second_web_store = verify_root.join("web-two.db");
    verify_packaged_scan(&executable, &second_web_store, &second_fixture, "web")?;
    verify_packaged_web_determinism(&executable, &first_web_store, &second_web_store)?;
    let query_smoke = verify_packaged_bounded_query(
        &executable,
        &extracted,
        &fixture,
        &first_web_store,
        &second_fixture,
        &second_web_store,
        &release_manifest.target,
        &archive_sha256,
    )?;
    let cross_language_smoke =
        verify_packaged_cross_language(&extracted, &release_manifest.target, &archive_sha256)?;
    verify_packaged_web_runtime_fails_closed(&executable, &extracted, &verify_root, &fixture)?;
    let semantic_complete_fixture =
        Path::new("workers/web/test/fixtures/semantic-complete").canonicalize()?;
    verify_packaged_web_semantic_complete(
        &executable,
        &verify_root.join("web-semantic-complete.db"),
        &semantic_complete_fixture,
    )?;
    verify_packaged_milestone4(&executable, &verify_root, &semantic_complete_fixture)?;
    let framework_complete_fixture =
        Path::new("workers/web/test/fixtures/framework-complete").canonicalize()?;
    verify_packaged_web_framework_completeness(
        &executable,
        &verify_root,
        &framework_complete_fixture,
    )?;

    let rust_fixture = Path::new("workers/rust/tests/fixtures/security").canonicalize()?;
    verify_packaged_scan(
        &executable,
        &verify_root.join("rust.db"),
        &rust_fixture,
        "rust",
    )?;
    for marker in [
        rust_fixture.join("BUILD_SCRIPT_EXECUTED"),
        rust_fixture.join("PROC_MACRO_EXECUTED"),
        rust_fixture.join("CONFIG_EXECUTED"),
    ] {
        if marker.exists() {
            bail!(
                "safe release gate executed project code: {}",
                marker.display()
            );
        }
    }
    rust_semantic_e2e::verify(&workspace_root(), &executable, None)?;
    verify_packaged_rust_release_fails_closed(
        &executable,
        &extracted,
        &verify_root,
        &rust_fixture,
    )?;

    go_semantic_e2e::verify(&workspace_root(), &executable, None)?;
    let go_fixture = Path::new("workers/go/internal/worker/testdata/workspace").canonicalize()?;
    verify_packaged_layout_fails_closed(&executable, &extracted, &verify_root, &go_fixture)?;
    fs::remove_dir_all(verify_root)?;
    Ok((query_smoke, cross_language_smoke, mcp_smoke))
}

fn verify_packaged_build_evidence(
    executable: &Path,
    release_root: &Path,
    verify_root: &Path,
    fixture: &Path,
    base_store: &Path,
) -> Result<()> {
    let framework_contract = depgraph_core::framework_build_capability_contract();
    let adapters = [
        (
            "next",
            "next-app",
            "web:build:next",
            "next-adapter-observer",
            "NEXT_BUILD_FIXTURE_SECRET",
        ),
        (
            "astro",
            "astro-app",
            "web:build:astro",
            "astro-vite-build-observer",
            "ASTRO_BUILD_FIXTURE_SECRET",
        ),
        (
            "tanstack-start",
            "start",
            "web:build:tanstack-start",
            "tanstack-start-vite-build-observer",
            "START_BUILD_FIXTURE_SECRET",
        ),
        (
            "tanstack-router",
            "router",
            "web:build:tanstack-router",
            "tanstack-router-vite-build-observer",
            "ROUTER_BUILD_FIXTURE_SECRET",
        ),
        (
            "rust",
            "rust-app",
            "rust:build",
            "rust-cargo-build-observer",
            "RUST_BUILD_FIXTURE_SECRET",
        ),
    ];
    for (adapter, app, profile_id, observer, secret) in adapters {
        let framework_capability = framework_contract
            .iter()
            .find(|capability| capability.framework == adapter);
        let store = verify_root.join(format!("build-{adapter}.db"));
        fs::copy(base_store, &store)?;
        let project = fixture.join("apps").join(app);
        let deterministic_project =
            framework_capability.map(|_| verify_root.join(format!("build-{adapter}-checkout-two")));
        if let Some(second_project) = &deterministic_project {
            copy_directory(&project, second_project)?;
        }
        let baseline_name = format!("build-{adapter}-baseline");
        if framework_capability.is_some() {
            create_packaged_snapshot(executable, &store, &baseline_name)?;
        }
        let denied = Command::new(executable)
            .arg("--store")
            .arg(&store)
            .arg("resolve")
            .arg("--build")
            .arg(&project)
            .output()
            .with_context(|| format!("failed to run packaged {adapter} consent gate"))?;
        if denied.status.code() != Some(4)
            || !denied.stdout.is_empty()
            || !String::from_utf8_lossy(&denied.stderr)
                .contains("project code execution permission denied")
        {
            bail!("packaged {adapter} build ran without explicit consent");
        }

        let allowed = run_packaged_build(executable, &store, &project, adapter)?;

        let doctor = Command::new(executable)
            .arg("--store")
            .arg(&store)
            .arg("doctor")
            .arg("--details")
            .arg("--json")
            .output()?;
        if !doctor.status.success() {
            bail!("packaged {adapter} doctor failed after build observation");
        }
        let doctor_json: Value = serde_json::from_slice(&doctor.stdout)?;
        let latest = &doctor_json["latest_attempt"];
        let matrix = &latest["profile_matrix"];
        let phases = &matrix["phase_coverage"];
        let semantic_profile_retained = matrix["entries"].as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["phases"]
                    .as_array()
                    .is_some_and(|phases| phases.iter().any(|phase| phase == "semantic"))
            })
        });
        if latest["project_code_executed"] != Value::Bool(true)
            || !phases["static"].is_object()
            || !semantic_profile_retained
            || !phases["build"].is_object()
            || !latest["profiles"].as_array().is_some_and(|profiles| {
                profiles.iter().any(|profile| {
                    profile["id"] == profile_id
                        && profile["coverage"]["project_code_executed"] == Value::Bool(true)
                        && profile["coverage"]["completeness"].as_array().is_some_and(
                            |completeness| completeness.iter().any(|item| item == "build-observed"),
                        )
                })
            })
        {
            bail!("packaged {adapter} doctor lost the static/semantic/build profile union");
        }
        // The agent-safe doctor projection intentionally omits per-file runtime integrity.
        // Package metadata verification above checks the complete runtime closure instead.
        if doctor_json["release"].get("runtime_integrity").is_some() {
            bail!("packaged {adapter} doctor leaked detailed runtime integrity");
        }

        let export_json = packaged_raw_export_json(
            executable,
            &store,
            &[],
            &format!("export packaged {adapter} graph after build observation"),
        )?;
        let exported_bytes = serde_json::to_vec(&export_json)?;
        let graph = &export_json["graph"];
        let edge = graph["edges"]
            .as_array()
            .and_then(|edges| {
                edges.iter().find(|edge| {
                    edge["phase"] == "build"
                        && edge["precision"] == "observed"
                        && edge["profile_id"] == profile_id
                })
            })
            .with_context(|| format!("packaged {adapter} export has no observed build edge"))?;
        if !graph["evidence"].as_array().is_some_and(|evidence| {
            evidence.iter().any(|item| {
                item["kind"] == "build"
                    && item["extractor"] == observer
                    && item["properties"]["build_run_id"].is_string()
                    && item["properties"]["validated_output_digest"].is_string()
            })
        }) {
            bail!("packaged {adapter} export omitted audited build evidence");
        }

        let why = Command::new(executable)
            .arg("--store")
            .arg(&store)
            .arg("why")
            .arg(format!(
                "id:{}",
                edge["source"].as_str().context("build edge source")?
            ))
            .arg(format!(
                "id:{}",
                edge["target"].as_str().context("build edge target")?
            ))
            .arg("--json")
            .output()?;
        if !why.status.success()
            || serde_json::from_slice::<Value>(&why.stdout)?["data"]["steps"]
                .as_array()
                .is_none_or(|steps| steps.is_empty())
        {
            bail!("packaged {adapter} why query could not traverse observed build evidence");
        }

        let mut deterministic_outputs = None;
        let mut deterministic_store = None;
        if let (Some(capability), Some(second_project)) =
            (framework_capability, deterministic_project.as_ref())
        {
            let target_name = format!("build-{adapter}-target");
            create_packaged_snapshot(executable, &store, &target_name)?;
            verify_packaged_framework_build_e2e(
                executable,
                &project,
                &store,
                &baseline_name,
                &target_name,
                profile_id,
                capability,
                graph,
                edge,
            )?;

            let second_store = verify_root.join(format!("build-{adapter}-checkout-two.db"));
            fs::copy(base_store, &second_store)?;
            let second = run_packaged_build(executable, &second_store, second_project, adapter)?;
            let second_export = packaged_web_export_json(executable, &second_store)?;
            let mut first_graph = graph.clone();
            let mut second_graph = second_export["graph"].clone();
            remove_transient_build_run_ids(&mut first_graph);
            remove_transient_build_run_ids(&mut second_graph);
            if second_graph != first_graph {
                bail!(
                    "packaged {adapter} build graph changed across checkout-equivalent fixture roots"
                );
            }
            deterministic_outputs = Some(second);
            deterministic_store = Some(second_store);
        }

        let secret_bytes = secret.as_bytes();
        if bytes_contain(&allowed.stdout, secret_bytes)
            || bytes_contain(&allowed.stderr, secret_bytes)
            || bytes_contain(&doctor.stdout, secret_bytes)
            || bytes_contain(&exported_bytes, secret_bytes)
            || bytes_contain(&fs::read(&store)?, secret_bytes)
            || deterministic_outputs.as_ref().is_some_and(|output| {
                bytes_contain(&output.stdout, secret_bytes)
                    || bytes_contain(&output.stderr, secret_bytes)
            })
            || deterministic_store.as_ref().is_some_and(|store| {
                fs::read(store).is_ok_and(|bytes| bytes_contain(&bytes, secret_bytes))
            })
        {
            bail!("packaged {adapter} build leaked its fixture secret");
        }

        let completed_graph = graph.clone();
        let failed_project = verify_root.join(format!("failed-build-{adapter}"));
        copy_directory(&project, &failed_project)?;
        let failure_entrypoint = if adapter == "rust" {
            failed_project.join("build.rs")
        } else {
            failed_project.join("depgraph-build.mjs")
        };
        fs::write(
            &failure_entrypoint,
            if adapter == "rust" {
                "fn main() { panic!(\"normalized fixture crash\"); }\n"
            } else {
                "process.exit(19);\n"
            },
        )?;
        let failed = Command::new(executable)
            .arg("--store")
            .arg(&store)
            .arg("resolve")
            .arg("--build")
            .arg(&failed_project)
            .arg("--allow-project-code")
            .output()?;
        if failed.status.code() != Some(3) {
            bail!("packaged {adapter} crash gate did not report a failed build");
        }
        let retained = packaged_raw_export_json(
            executable,
            &store,
            &[],
            &format!("export packaged {adapter} graph after failed build"),
        )?;
        if retained["graph"] != completed_graph {
            bail!("packaged {adapter} failed build replaced the last completed graph");
        }
    }

    let timeout_store = verify_root.join("build-timeout.db");
    fs::copy(base_store, &timeout_store)?;
    let timeout_project = verify_root.join("timed-out-build-next");
    copy_directory(&fixture.join("apps/next-app"), &timeout_project)?;
    let package_path = timeout_project.join("package.json");
    let mut package: Value = serde_json::from_slice(&fs::read(&package_path)?)?;
    package["depgraph"]["build"]["timeout_seconds"] = json!(1);
    fs::write(&package_path, serde_json::to_vec_pretty(&package)?)?;
    fs::write(
        timeout_project.join("depgraph-build.mjs"),
        "setInterval(() => undefined, 1000);\n",
    )?;
    let timed_out = Command::new(executable)
        .arg("--store")
        .arg(&timeout_store)
        .arg("resolve")
        .arg("--build")
        .arg(&timeout_project)
        .arg("--allow-project-code")
        .output()?;
    if timed_out.status.code() != Some(3)
        || !String::from_utf8_lossy(&timed_out.stdout).contains("status: TimedOut")
    {
        bail!("packaged build timeout gate did not stop the supervised process tree");
    }

    for secret in [
        "NEXT_BUILD_FIXTURE_SECRET",
        "ASTRO_BUILD_FIXTURE_SECRET",
        "ROUTER_BUILD_FIXTURE_SECRET",
        "START_BUILD_FIXTURE_SECRET",
        "RUST_BUILD_FIXTURE_SECRET",
    ] {
        for entry in WalkDir::new(release_root).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_file()
                && bytes_contain(&fs::read(entry.path())?, secret.as_bytes())
            {
                bail!(
                    "release artifact {} contains a build fixture secret",
                    entry.path().display()
                );
            }
        }
    }
    verify_packaged_build_runtime_fails_closed(executable, release_root, verify_root, fixture)?;
    Ok(())
}

pub(crate) fn remove_transient_build_run_ids(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                remove_transient_build_run_ids(value);
            }
        }
        Value::Object(values) => {
            values.remove("build_run_id");
            for value in values.values_mut() {
                remove_transient_build_run_ids(value);
            }
        }
        _ => {}
    }
}

fn run_packaged_build(
    executable: &Path,
    store: &Path,
    project: &Path,
    adapter: &str,
) -> Result<std::process::Output> {
    let output = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("resolve")
        .arg("--build")
        .arg(project)
        .arg("--allow-project-code")
        .output()
        .with_context(|| format!("failed to run packaged {adapter} build"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        || !stdout.contains("status: Completed")
        || !stdout.contains("project code executed: true")
        || !stdout.contains("build evidence: promoted")
        || !stdout.contains("network isolation:")
    {
        bail!("packaged {adapter} build evidence gate failed:\n{stdout}\n{stderr}");
    }
    Ok(output)
}

fn create_packaged_snapshot(executable: &Path, store: &Path, name: &str) -> Result<()> {
    let output = Command::new(executable)
        .arg("--store")
        .arg(store)
        .args(["snapshot", "create", name, "--json"])
        .output()
        .with_context(|| format!("failed to create packaged snapshot {name}"))?;
    let snapshot = successful_json(output, &format!("create packaged snapshot {name}"))?;
    if !snapshot["data"]["snapshot"]["names"]
        .as_array()
        .is_some_and(|names| names.iter().any(|snapshot_name| snapshot_name == name))
    {
        bail!("packaged snapshot {name} was not retained by name: {snapshot}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_packaged_framework_build_e2e(
    executable: &Path,
    project: &Path,
    store: &Path,
    baseline_name: &str,
    target_name: &str,
    profile_id: &str,
    capability: &depgraph_core::FrameworkBuildCapabilityHealth,
    graph: &Value,
    edge: &Value,
) -> Result<()> {
    let profile = graph["profiles"]
        .as_array()
        .and_then(|profiles| profiles.iter().find(|profile| profile["id"] == profile_id))
        .with_context(|| {
            format!(
                "packaged {} build graph omitted its profile",
                capability.framework
            )
        })?;
    let properties = &profile["properties"];
    if properties["framework"] != capability.framework
        || properties["observer"] != capability.observer
        || properties["observer_version"] != capability.observer_version
        || properties["framework_build_capability"] != capability.capability
        || properties["framework_build_graph_contract_version"]
            != depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION
        || profile["features"].as_array().is_none_or(|features| {
            !features
                .iter()
                .any(|feature| feature == depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
                || !features
                    .iter()
                    .any(|feature| feature == capability.capability.as_str())
        })
    {
        bail!(
            "packaged {} build profile does not match its release capability: {profile}",
            capability.framework
        );
    }
    let edge_id = edge["id"]
        .as_str()
        .context("packaged framework build edge omitted its ID")?;
    if !graph["evidence"].as_array().is_some_and(|evidence| {
        evidence.iter().any(|item| {
            item["owner_type"] == "edge"
                && item["owner_id"] == edge_id
                && item["kind"] == "build"
                && item["extractor"] == capability.observer
                && item["extractor_version"] == capability.observer_version
                && item["properties"]["framework"] == capability.framework
                && item["properties"]["capability"] == capability.capability
                && item["properties"]["contract_version"]
                    == depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION
        })
    }) {
        bail!(
            "packaged {} build edge omitted exact capability evidence",
            capability.framework
        );
    }
    let dynamic_capability_observed = match capability.framework.as_str() {
        "next" => graph["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node["kind"] == "route"
                    && node["properties"]["observed_only"] == true
                    && node["properties"]["route_pattern"]
                        .as_str()
                        .is_some_and(|pattern| pattern.contains('['))
            })
        }),
        "astro" => graph["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node["kind"] == "route"
                    && node["properties"]["dynamic"] == true
                    && node["properties"]["observed_only"] == true
            })
        }),
        "tanstack-router" => graph["edges"].as_array().is_some_and(|edges| {
            edges.iter().any(|edge| {
                edge["profile_id"] == profile_id
                    && edge["phase"] == "build"
                    && edge["kind"] == "dynamic_imports"
            })
        }),
        "tanstack-start" => graph["nodes"].as_array().is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node["kind"] == "server_function"
                    && node["properties"]["production_rpc_id_status"] == "build-observed"
            })
        }),
        _ => false,
    };
    if !dynamic_capability_observed {
        bail!(
            "packaged {} fixture did not exercise its mandatory dynamic build capability",
            capability.framework
        );
    }

    let source_selector = format!(
        "id:{}",
        edge["source"]
            .as_str()
            .context("packaged framework build edge omitted its source")?
    );
    let target_selector = format!(
        "id:{}",
        edge["target"]
            .as_str()
            .context("packaged framework build edge omitted its target")?
    );
    let query_contains_edge = |query: &Value| {
        query["data"]["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["edge"]["id"] == edge_id
                    && step["evidence"].as_array().is_some_and(|evidence| {
                        evidence.iter().any(|item| {
                            item["kind"] == "build"
                                && item["extractor"] == capability.observer
                                && item["extractor_version"] == capability.observer_version
                        })
                    })
            })
        })
    };
    let deps = packaged_web_query(
        executable,
        store,
        &[
            "deps",
            &source_selector,
            "--phase",
            "build",
            "--profile",
            profile_id,
            "--all",
            "--json",
        ],
        &format!("query packaged {} build dependencies", capability.framework),
    )?;
    let dependents = packaged_web_query(
        executable,
        store,
        &[
            "dependents",
            &target_selector,
            "--phase",
            "build",
            "--profile",
            profile_id,
            "--all",
            "--json",
        ],
        &format!("query packaged {} build dependents", capability.framework),
    )?;
    let why = packaged_web_query(
        executable,
        store,
        &[
            "why",
            &source_selector,
            &target_selector,
            "--phase",
            "build",
            "--profile",
            profile_id,
            "--json",
        ],
        &format!("explain packaged {} build dependency", capability.framework),
    )?;
    if !query_contains_edge(&deps)
        || !query_contains_edge(&dependents)
        || why["data"]["path_found"] != true
        || !query_contains_edge(&why)
    {
        bail!(
            "packaged {} build query lost its exact observed edge",
            capability.framework
        );
    }

    let diff = packaged_web_query(
        executable,
        store,
        &[
            "diff",
            baseline_name,
            target_name,
            "--phase",
            "build",
            "--profile",
            profile_id,
            "--json",
        ],
        &format!("diff packaged {} build snapshots", capability.framework),
    )?;
    if diff["schema_version"] != depgraph_store::SNAPSHOT_DIFF_SCHEMA_VERSION
        || diff["data"]["summary"]["total_changes"]
            .as_u64()
            .unwrap_or_default()
            == 0
    {
        bail!(
            "packaged {} build diff did not expose build changes: {diff}",
            capability.framework
        );
    }

    let impact = packaged_web_query(
        executable,
        store,
        &[
            "impact",
            &target_selector,
            "--phase",
            "build",
            "--profile",
            profile_id,
            "--json",
        ],
        &format!("query packaged {} build impact", capability.framework),
    )?;
    if impact["data"]["root"]["id"] != edge["target"]
        || impact["data"]["complete"] != true
        || !impact["data"]["impacts"].as_array().is_some_and(|impacts| {
            impacts.iter().any(|impact| {
                impact["dependency_path"]
                    .as_array()
                    .is_some_and(|path| path.iter().any(|step| step["edge"]["id"] == edge_id))
            })
        })
    {
        bail!(
            "packaged {} build impact lost its observed reverse path: {impact}",
            capability.framework
        );
    }

    let policy = Command::new(executable)
        .current_dir(project)
        .arg("--store")
        .arg(store)
        .args(["policy", baseline_name, target_name, "--json"])
        .output()?;
    let policy = successful_json(
        policy,
        &format!("evaluate packaged {} build policy", capability.framework),
    )?;
    if policy["data"]["result"]["exit_code"] != 0
        || policy["data"]["result"]["violations"]
            .as_array()
            .is_none_or(|violations| !violations.is_empty())
    {
        bail!(
            "packaged {} build policy was not a clean result: {policy}",
            capability.framework
        );
    }

    let filtered = packaged_raw_export_json(
        executable,
        store,
        &["--phase", "build", "--profile", profile_id],
        &format!("export packaged {} build JSON", capability.framework),
    )?;
    if !filtered["graph"]["edges"].as_array().is_some_and(|edges| {
        edges.iter().any(|edge| edge["id"] == edge_id)
            && edges.iter().all(|edge| edge["phase"] == "build")
    }) {
        bail!(
            "packaged {} filtered JSON export omitted its build edge",
            capability.framework
        );
    }
    let graphml =
        packaged_web_export_filtered_text(executable, store, "graphml", profile_id, "build")?;
    let repeated_graphml =
        packaged_web_export_filtered_text(executable, store, "graphml", profile_id, "build")?;
    if graphml != repeated_graphml
        || !graphml.starts_with("<?xml")
        || !graphml.contains("<graphml")
        || !graphml.contains(&capability.capability)
        || !graphml.contains(depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION)
    {
        bail!(
            "packaged {} GraphML build export was invalid or nondeterministic",
            capability.framework
        );
    }
    Ok(())
}

fn verify_packaged_build_runtime_fails_closed(
    executable: &Path,
    release_root: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let project = fixture.join("apps/next-app");
    let run_gate = |scenario: &str| -> Result<std::process::Output> {
        Ok(Command::new(executable)
            .arg("--store")
            .arg(verify_root.join(format!("{scenario}.db")))
            .arg("resolve")
            .arg("--build")
            .arg(&project)
            .arg("--allow-project-code")
            .output()?)
    };
    let verify_security_failure = |output: &std::process::Output, scenario: &str| -> Result<()> {
        if output.status.code() != Some(4)
            || !String::from_utf8_lossy(&output.stderr).contains("security policy violation")
        {
            bail!("packaged {scenario} did not fail closed before execution");
        }
        Ok(())
    };
    for name in WEB_RUNTIME_ARTIFACTS {
        let path = release_root.join("libexec").join(name);
        let original = fs::read(&path)?;
        fs::write(&path, b"tampered-build-runtime")?;
        let output = run_gate(&format!("tampered-{name}"));
        let restored = fs::write(&path, original);
        restored?;
        let output = output?;
        verify_security_failure(&output, &format!("Web runtime {name} tamper"))?;
    }

    let collector = release_root
        .join("libexec")
        .join(RUNTIME_COLLECTOR_ARTIFACT);
    let original_collector = fs::read(&collector)?;
    fs::remove_file(&collector)?;
    let missing = run_gate("missing-runtime-collector");
    let restored = fs::write(&collector, original_collector);
    restored?;
    let missing = missing?;
    verify_security_failure(&missing, "missing runtime collector")?;

    let manifest_path = release_root.join("release-manifest.json");
    let original_manifest = fs::read(&manifest_path)?;
    let mut manifest: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    manifest.compatibility.runtime_collector_contract_version = "runtime-collector-v2".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    let mismatch = run_gate("runtime-collector-version-mismatch");
    let restored = fs::write(&manifest_path, original_manifest);
    restored?;
    let mismatch = mismatch?;
    verify_security_failure(&mismatch, "runtime collector version mismatch")?;
    Ok(())
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn verify_packaged_project_licenses_fail_closed(
    executable: &Path,
    extracted: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    for (name, original) in PROJECT_LICENSES {
        let path = extracted.join(name);
        fs::remove_file(&path)?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join(format!("project-license-missing-{name}.db")),
            fixture,
            &format!("missing project license {name}"),
        )?;
        fs::write(&path, original)?;

        let mut tampered = original.to_vec();
        tampered.extend_from_slice(b"\ntampered\n");
        fs::write(&path, tampered)?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join(format!("project-license-tampered-{name}.db")),
            fixture,
            &format!("tampered project license {name}"),
        )?;
        fs::write(&path, original)?;
    }
    let query_path = extracted.join(depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH);
    let query = fs::read(&query_path)?;
    fs::remove_file(&query_path)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("bounded-query-fixture-missing.db"),
        fixture,
        "missing bounded query fixture",
    )?;
    fs::write(&query_path, &query)?;
    fs::write(&query_path, b"tampered bounded query fixture")?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("bounded-query-fixture-tampered.db"),
        fixture,
        "tampered bounded query fixture",
    )?;
    fs::write(&query_path, query)?;
    Ok(())
}

#[cfg(unix)]
fn verify_release_static_prelaunch_fails_closed(extracted: &Path) -> Result<()> {
    let manifest_path = extracted.join("release-manifest.json");
    let original_manifest = fs::read(&manifest_path)?;
    let original: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    let worker_path = extracted
        .join("libexec")
        .join(executable_name("depgraph-rust-worker"));
    let original_worker = fs::read(&worker_path)?;
    let marker = extracted.join("libexec/rust-static-prelaunch-spawned");
    let worker_script = format!(
        "#!/bin/sh\nmarker=\"$(dirname \"$0\")/rust-static-prelaunch-spawned\"\n: > \"$marker\"\nprintf '%s\\n' 'depgraph-rust-worker {VERSION} (protocol 1.0; rust-analyzer {RUST_ANALYZER_CRATE_VERSION}; rust-analyzer-revision {RUST_ANALYZER_REVISION}; salsa {SALSA_VERSION})'\n"
    );
    fs::write(&worker_path, worker_script)?;
    restore_executable_permissions(&worker_path)?;

    let mut baseline = original.clone();
    baseline
        .workers
        .iter_mut()
        .find(|worker| worker.adapter == "rust")
        .context("release manifest has no Rust worker")?
        .sha256 = sha256_file(&worker_path)?;

    let verification = (|| -> Result<()> {
        fs::write(&manifest_path, serde_json::to_vec_pretty(&baseline)?)?;
        for (scenario, path) in [
            (
                "MCP server",
                extracted.join("bin").join(executable_name(MCP_SERVER_NAME)),
            ),
            ("MCP tool schema", extracted.join(MCP_TOOL_SCHEMA_PATH)),
        ] {
            let original_artifact = fs::read(&path)?;
            for tampered in [false, true] {
                if marker.exists() {
                    fs::remove_file(&marker)?;
                }
                if tampered {
                    fs::write(&path, b"tampered MCP release artifact")?;
                } else {
                    fs::remove_file(&path)?;
                }
                let result = verify_release_metadata(extracted);
                fs::write(&path, &original_artifact)?;
                if scenario == "MCP server" {
                    restore_executable_permissions(&path)?;
                }
                if marker.exists() {
                    bail!(
                        "{scenario} mutation launched the Rust worker before static release validation"
                    );
                }
                if result.is_ok() {
                    bail!(
                        "static release validation accepted {} {scenario}",
                        if tampered { "tampered" } else { "missing" }
                    );
                }
            }
        }
        let mut cases = Vec::new();

        let mut manifest = baseline.clone();
        manifest.core = manifest.schema.clone();
        cases.push(("core path mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.schema = manifest.core.clone();
        cases.push(("schema path mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_server.path = manifest.core.path.clone();
        manifest.mcp_server.sha256 = manifest.core.sha256.clone();
        cases.push(("MCP server path mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_server.sdk_version = "3.2.0".to_owned();
        cases.push(("MCP SDK version mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_server.protocol_revision = "2025-11-25".to_owned();
        cases.push(("MCP protocol revision mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_server.tool_contract_version = "depgraph-mcp-tools-v2".to_owned();
        cases.push(("MCP tool contract mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_server.operation_contract_version = "depgraph-operation-v2".to_owned();
        cases.push(("MCP operation contract mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.operation_runner.operation_contract_version = "depgraph-operation-v2".to_owned();
        cases.push(("operation runner contract mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_tool_schema.contract_version = "depgraph-mcp-tools-v2".to_owned();
        cases.push(("MCP tool schema contract mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.mcp_tool_schema.path = manifest.schema.path.clone();
        manifest.mcp_tool_schema.sha256 = manifest.schema.sha256.clone();
        cases.push(("MCP tool schema path mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.query_fixture = manifest.schema.clone();
        cases.push(("bounded query fixture path mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.license_expression = "MIT".to_owned();
        cases.push(("project license expression mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.store_schema_version += 1;
        cases.push(("store compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.packaged_smoke_contract = "unverified-packaged-smoke".to_owned();
        cases.push(("packaged smoke compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.bounded_query.result_schema_version =
            "bounded-query-result-v2".to_owned();
        cases.push(("bounded query compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest
            .compatibility
            .profile_selection
            .selection_contract_version = "default-profile-selection-v2".to_owned();
        cases.push(("profile selection compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.framework_build_gate_contract_version =
            "dynamic-framework-evidence-release-gate-v2".to_owned();
        cases.push(("framework build gate compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.framework_build_capabilities[0].observer_version =
            "9.9.9".to_owned();
        cases.push(("framework build capability mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.runtime_collector_contract_version =
            "runtime-collector-v2".to_owned();
        cases.push(("runtime collector compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.compatibility.rust_sysroot.toolchain_commit =
            "0000000000000000000000000000000000000000".to_owned();
        cases.push(("Rust sysroot toolchain compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_artifacts
            .retain(|artifact| artifact.path != format!("libexec/{RUNTIME_COLLECTOR_ARTIFACT}"));
        cases.push(("missing runtime collector artifact", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_artifacts
            .retain(|artifact| artifact.path != depgraph_core::FRAMEWORK_BUILD_CONVERTER_ARTIFACT);
        cases.push(("missing framework build converter artifact", manifest));

        let mut manifest = baseline.clone();
        let observer_path = depgraph_core::framework_build_capability_contract()[0]
            .observer_runtime_artifact
            .clone();
        manifest
            .runtime_artifacts
            .retain(|artifact| artifact.path != observer_path);
        cases.push(("missing framework build observer artifact", manifest));

        let mut manifest = baseline.clone();
        manifest.project_licenses.pop();
        cases.push(("missing project license declaration", manifest));

        let mut manifest = baseline.clone();
        let duplicate = manifest
            .project_licenses
            .first()
            .cloned()
            .context("release manifest has no project license")?;
        manifest.project_licenses.push(duplicate);
        cases.push(("duplicate project license declaration", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_components
            .retain(|component| component.name != "astro-parser-wasm");
        cases.push(("missing Astro runtime component", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_components
            .retain(|component| component.name != RUST_SYSROOT_COMPONENT_NAME);
        cases.push(("missing Rust sysroot source component", manifest));

        let mut manifest = baseline.clone();
        let duplicate = manifest
            .runtime_components
            .first()
            .cloned()
            .context("release manifest has no runtime component")?;
        manifest.runtime_components.push(duplicate);
        cases.push(("duplicate runtime component", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_components
            .iter_mut()
            .find(|component| component.name == "typescript-native-compiler")
            .context("release manifest has no TypeScript runtime component")?
            .name = "renamed-typescript-compiler".to_owned();
        cases.push(("missing named TypeScript compatibility unit", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_components
            .iter_mut()
            .find(|component| component.name == "typescript-native-compiler")
            .context("release manifest has no TypeScript runtime component")?
            .version = "9.9.9".to_owned();
        cases.push(("TypeScript compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest
            .runtime_components
            .iter_mut()
            .find(|component| component.name == RUST_SYSROOT_COMPONENT_NAME)
            .context("release manifest has no Rust sysroot source component")?
            .license = "NOASSERTION".to_owned();
        cases.push(("Rust sysroot source compatibility mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest.runtime_requirements.remove("web");
        cases.push(("missing Web runtime requirement", manifest));

        let mut manifest = baseline.clone();
        manifest
            .workers
            .iter_mut()
            .find(|worker| worker.adapter == "web")
            .context("release manifest has no Web worker")?
            .semantic = None;
        cases.push(("missing Web semantic attestation", manifest));

        for (scenario, mutate) in [
            (
                "Web TypeScript semantic version mismatch",
                "typescript_version",
            ),
            ("Web semantic capability mismatch", "capabilities"),
            ("Web semantic runtime component mismatch", "component"),
            ("Web semantic runtime artifact mismatch", "artifact"),
        ] {
            let mut manifest = baseline.clone();
            let semantic = manifest
                .workers
                .iter_mut()
                .find(|worker| worker.adapter == "web")
                .context("release manifest has no Web worker")?
                .semantic
                .as_mut()
                .context("release manifest Web worker has no semantic attestation")?;
            match mutate {
                "typescript_version" => semantic.typescript_version = "9.9.9".to_owned(),
                "capabilities" => semantic.capabilities.reverse(),
                "component" => semantic.runtime_components = vec!["system-typescript".to_owned()],
                "artifact" => semantic.runtime_artifacts = vec!["system-astro.wasm".to_owned()],
                _ => unreachable!(),
            }
            cases.push((scenario, manifest));
        }

        let mut manifest = baseline.clone();
        manifest
            .workers
            .iter_mut()
            .find(|worker| worker.adapter == "go")
            .context("release manifest has no Go worker")?
            .version = "9.9.9".to_owned();
        cases.push(("Go worker version mismatch", manifest));

        let mut manifest = baseline.clone();
        manifest
            .workers
            .iter_mut()
            .find(|worker| worker.adapter == "web")
            .context("release manifest has no Web worker")?
            .version = "9.9.9".to_owned();
        cases.push(("Web worker version mismatch", manifest));

        let mut manifest = baseline.clone();
        let rust_worker = manifest
            .workers
            .iter()
            .find(|worker| worker.adapter == "rust")
            .cloned()
            .context("release manifest has no Rust worker")?;
        let go_worker = manifest
            .workers
            .iter_mut()
            .find(|worker| worker.adapter == "go")
            .context("release manifest has no Go worker")?;
        go_worker.path = rust_worker.path;
        go_worker.sha256 = rust_worker.sha256;
        cases.push(("Go worker path identity mismatch", manifest));

        for (scenario, manifest) in cases {
            if marker.exists() {
                fs::remove_file(&marker)?;
            }
            fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
            let result = verify_release_metadata(extracted);
            if marker.exists() {
                bail!("{scenario} launched the Rust worker before static release validation");
            }
            if result.is_ok() {
                bail!("static release validation accepted {scenario}");
            }
        }
        Ok(())
    })();

    fs::write(&manifest_path, original_manifest)?;
    fs::write(&worker_path, original_worker)?;
    restore_executable_permissions(&worker_path)?;
    if marker.exists() {
        fs::remove_file(marker)?;
    }
    verification
}

fn verify_packaged_rust_release_fails_closed(
    executable: &Path,
    extracted: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let manifest_path = extracted.join("release-manifest.json");
    let original_manifest = fs::read(&manifest_path)?;
    let worker_path = extracted
        .join("libexec")
        .join(executable_name("depgraph-rust-worker"));
    let original_worker = fs::read(&worker_path)?;

    #[cfg(unix)]
    {
        remove_executable_permissions(&worker_path)?;
        let error = verify_release_metadata(extracted)
            .expect_err("release metadata accepted a non-executable Rust worker");
        if !error.to_string().contains("rust worker is not executable") {
            bail!("non-executable Rust worker static gate returned the wrong error: {error:#}");
        }
        verify_packaged_security_failure(
            executable,
            &verify_root.join("rust-worker-non-executable.db"),
            fixture,
            "non-executable Rust worker",
        )?;
        restore_executable_permissions(&worker_path)?;
    }

    fs::remove_file(&worker_path)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("rust-worker-missing.db"),
        fixture,
        "missing Rust worker",
    )?;
    fs::write(&worker_path, &original_worker)?;
    restore_executable_permissions(&worker_path)?;

    let mut tampered_worker = original_worker.clone();
    tampered_worker.extend_from_slice(b"depgraph-package-tamper");
    fs::write(&worker_path, tampered_worker)?;
    restore_executable_permissions(&worker_path)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("rust-worker-tampered.db"),
        fixture,
        "tampered Rust worker",
    )?;
    fs::write(&worker_path, &original_worker)?;
    restore_executable_permissions(&worker_path)?;

    #[cfg(unix)]
    {
        let real_worker = extracted
            .join("libexec")
            .join(format!("{}.real", executable_name("depgraph-rust-worker")));
        fs::rename(&worker_path, &real_worker)?;
        std::os::unix::fs::symlink(
            real_worker
                .file_name()
                .context("real Rust worker has no file name")?,
            &worker_path,
        )?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("rust-worker-symlink.db"),
            fixture,
            "symlinked Rust worker",
        )?;
        fs::remove_file(&worker_path)?;
        fs::rename(real_worker, &worker_path)?;
    }

    let mut manifest: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    let rust = manifest
        .workers
        .iter_mut()
        .find(|worker| worker.adapter == "rust")
        .context("release manifest has no Rust worker")?;
    rust.backend
        .as_mut()
        .context("release manifest Rust worker has no backend")?
        .revision = "0000000000000000000000000000000000000000".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("rust-backend-mismatch.db"),
        fixture,
        "Rust backend revision mismatch",
    )?;

    let mut manifest: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    manifest
        .workers
        .iter_mut()
        .find(|worker| worker.adapter == "rust")
        .context("release manifest has no Rust worker")?
        .version = "9.9.9".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("rust-adapter-mismatch.db"),
        fixture,
        "Rust adapter version mismatch",
    )?;
    fs::write(&manifest_path, &original_manifest)?;

    #[cfg(unix)]
    {
        let real_manifest = extracted.join("release-manifest.real.json");
        fs::rename(&manifest_path, &real_manifest)?;
        std::os::unix::fs::symlink(
            real_manifest
                .file_name()
                .context("real release manifest has no file name")?,
            &manifest_path,
        )?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("manifest-symlink.db"),
            fixture,
            "symlinked release manifest",
        )?;
        fs::remove_file(&manifest_path)?;
        fs::rename(real_manifest, &manifest_path)?;
    }

    let schema = extracted.join("schemas/depgraph-protocol-v1.schema.json");
    let original_schema = fs::read(&schema)?;
    fs::remove_file(&schema)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("schema-missing.db"),
        fixture,
        "missing protocol schema",
    )?;
    fs::write(&schema, &original_schema)?;
    let mut tampered_schema = original_schema.clone();
    tampered_schema.extend_from_slice(b"\n");
    fs::write(&schema, tampered_schema)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("schema-tampered.db"),
        fixture,
        "tampered protocol schema",
    )?;
    fs::write(&schema, original_schema)?;

    verify_packaged_data_tree_fails_closed(
        executable,
        extracted,
        verify_root,
        fixture,
        &original_manifest,
    )?;
    fs::write(manifest_path, original_manifest)?;
    Ok(())
}

fn verify_packaged_data_tree_fails_closed(
    executable: &Path,
    extracted: &Path,
    verify_root: &Path,
    fixture: &Path,
    original_manifest: &[u8],
) -> Result<()> {
    let manifest_path = extracted.join("release-manifest.json");
    let manifest: ReleaseManifest = serde_json::from_slice(original_manifest)?;
    let component = manifest
        .runtime_components
        .iter()
        .find(|component| component.name == RUST_SYSROOT_COMPONENT_NAME)
        .context("packaged release has no pinned Rust sysroot source component")?;
    let component_root = extracted.join(&component.root);
    let payload = component_root.join("library/core/src/lib.rs");
    let original_payload = fs::read(&payload)?;
    verify_packaged_scan(
        executable,
        &verify_root.join("data-tree-valid.db"),
        fixture,
        "pinned Rust sysroot data-tree",
    )?;

    fs::remove_file(&payload)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-missing.db"),
        fixture,
        "missing Rust data-tree input",
    )?;
    fs::write(&payload, &original_payload)?;

    fs::write(&payload, b"tampered backend data\n")?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-tampered.db"),
        fixture,
        "tampered Rust data-tree",
    )?;
    fs::write(&payload, &original_payload)?;

    let added = component_root.join("added.txt");
    fs::write(&added, b"undeclared addition\n")?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-added.db"),
        fixture,
        "added Rust data-tree input",
    )?;
    fs::remove_file(added)?;

    let added_directory = component_root.join("undeclared-empty-directory");
    fs::create_dir(&added_directory)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-added-directory.db"),
        fixture,
        "added empty Rust data-tree directory",
    )?;
    fs::remove_dir(added_directory)?;

    #[cfg(unix)]
    {
        let symlink = component_root.join("core-link.rs");
        std::os::unix::fs::symlink("library/core/src/lib.rs", &symlink)?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("data-tree-symlink.db"),
            fixture,
            "symlinked Rust data-tree input",
        )?;
        fs::remove_file(symlink)?;
    }

    let mut mismatched: ReleaseManifest = serde_json::from_slice(original_manifest)?;
    mismatched
        .runtime_components
        .iter_mut()
        .find(|component| component.name == RUST_SYSROOT_COMPONENT_NAME)
        .context("packaged release has no pinned Rust sysroot source component")?
        .version = "0.0.0+wrong-rustc".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&mismatched)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-version-mismatch.db"),
        fixture,
        "mismatched Rust sysroot component version",
    )?;

    let mut mismatched: ReleaseManifest = serde_json::from_slice(original_manifest)?;
    mismatched
        .runtime_components
        .iter_mut()
        .find(|component| component.name == RUST_SYSROOT_COMPONENT_NAME)
        .context("packaged release has no pinned Rust sysroot source component")?
        .license = "NOASSERTION".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&mismatched)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-license-mismatch.db"),
        fixture,
        "mismatched Rust sysroot component license",
    )?;

    let mut missing: ReleaseManifest = serde_json::from_slice(original_manifest)?;
    missing
        .runtime_components
        .retain(|component| component.name != RUST_SYSROOT_COMPONENT_NAME);
    fs::write(&manifest_path, serde_json::to_vec_pretty(&missing)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-component-missing.db"),
        fixture,
        "missing Rust sysroot component declaration",
    )?;

    let mut mismatched: ReleaseManifest = serde_json::from_slice(original_manifest)?;
    mismatched.compatibility.rust_sysroot.toolchain_commit =
        "0000000000000000000000000000000000000000".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&mismatched)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("data-tree-toolchain-mismatch.db"),
        fixture,
        "mismatched Rust sysroot toolchain identity",
    )?;
    fs::write(manifest_path, original_manifest)?;
    Ok(())
}

fn restore_executable_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}

#[cfg(unix)]
fn remove_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(permissions.mode() & !0o111);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn verify_packaged_layout_fails_closed(
    executable: &Path,
    extracted: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let removed_manifest = extracted.join("release-manifest.removed");
    fs::rename(extracted.join("release-manifest.json"), &removed_manifest)?;
    let removed_libexec = extracted.join("libexec.removed");
    fs::rename(extracted.join("libexec"), &removed_libexec)?;
    let override_worker = removed_libexec.join(executable_name("depgraph-go-worker"));
    let output = Command::new(executable)
        .env("DEPGRAPH_GO_WORKER", &override_worker)
        .arg("--store")
        .arg(verify_root.join("missing-layout.db"))
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .output()?;
    let report: Value = serde_json::from_slice(&output.stdout)
        .context("missing-layout gate did not return scan JSON")?;
    if output.status.code() != Some(4) || report["status"] != "security_failed" {
        bail!(
            "packaged CLI accepted a development worker after its manifest/layout was removed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    Ok(())
}

fn verify_packaged_web_runtime_fails_closed(
    executable: &Path,
    extracted: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let manifest_path = extracted.join("release-manifest.json");
    let original_manifest = fs::read(&manifest_path)?;
    let typescript_root = extracted.join("libexec/typescript/lib");
    let standard_library = extracted.join("libexec/typescript/lib/lib.d.ts");
    let original = fs::read(&standard_library)?;

    #[cfg(unix)]
    {
        let compiler = extracted
            .join("libexec/typescript/lib")
            .join(executable_name("tsc"));
        remove_executable_permissions(&compiler)?;
        let error = verify_release_metadata(extracted)
            .expect_err("release metadata accepted a non-executable TypeScript compiler");
        if !error.to_string().contains("entrypoint is not executable") {
            bail!("non-executable TypeScript static gate returned the wrong error: {error:#}");
        }
        verify_packaged_security_failure(
            executable,
            &verify_root.join("typescript-non-executable.db"),
            fixture,
            "non-executable TypeScript compiler",
        )?;
        restore_executable_permissions(&compiler)?;
    }

    fs::remove_file(&standard_library)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("typescript-missing.db"),
        fixture,
        "missing TypeScript runtime file",
    )?;
    fs::write(&standard_library, &original)?;

    let mut tampered = original.clone();
    tampered.extend_from_slice(b"\n// tampered\n");
    fs::write(&standard_library, tampered)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("typescript-tampered.db"),
        fixture,
        "tampered TypeScript runtime file",
    )?;
    let metadata_error = verify_release_metadata(extracted)
        .expect_err("release metadata accepted the tampered TypeScript component");
    if !format!("{metadata_error:#}")
        .contains("runtime component typescript-native-compiler failed its whole-tree checksum")
    {
        bail!("TypeScript metadata gate returned the wrong error: {metadata_error:#}");
    }
    fs::write(&standard_library, original)?;

    let added = typescript_root.join("undeclared-runtime.js");
    fs::write(&added, b"undeclared runtime input\n")?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("typescript-added.db"),
        fixture,
        "added TypeScript runtime file",
    )?;
    fs::remove_file(added)?;

    let added_directory = typescript_root.join("undeclared-empty-directory");
    fs::create_dir(&added_directory)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("typescript-added-directory.db"),
        fixture,
        "added TypeScript runtime directory",
    )?;
    fs::remove_dir(added_directory)?;

    #[cfg(unix)]
    {
        let symlink = typescript_root.join("lib-link.d.ts");
        std::os::unix::fs::symlink("lib.d.ts", &symlink)?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("typescript-symlink.db"),
            fixture,
            "symlinked TypeScript runtime file",
        )?;
        fs::remove_file(symlink)?;
    }

    let mut manifest: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    manifest
        .runtime_components
        .iter_mut()
        .find(|component| component.name == "typescript-native-compiler")
        .context("release manifest has no TypeScript component")?
        .version = "9.9.9".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("typescript-version.db"),
        fixture,
        "TypeScript runtime version mismatch",
    )?;
    fs::write(&manifest_path, &original_manifest)?;

    let astro_root = extracted.join("libexec/astro");
    let astro_wasm = astro_root.join("astro.wasm");
    let original_astro = fs::read(&astro_wasm)?;
    fs::remove_file(&astro_wasm)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("astro-missing.db"),
        fixture,
        "missing Astro parser runtime",
    )?;
    fs::write(&astro_wasm, &original_astro)?;

    let mut tampered_astro = original_astro.clone();
    tampered_astro.extend_from_slice(b"tampered");
    fs::write(&astro_wasm, tampered_astro)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("astro-tampered.db"),
        fixture,
        "tampered Astro parser runtime",
    )?;
    let metadata_error = verify_release_metadata(extracted)
        .expect_err("release metadata accepted the tampered Astro component");
    if !format!("{metadata_error:#}")
        .contains("runtime component astro-parser-wasm failed its whole-tree checksum")
    {
        bail!("Astro metadata gate returned the wrong error: {metadata_error:#}");
    }
    fs::write(&astro_wasm, &original_astro)?;

    let astro_added = astro_root.join("undeclared.wasm");
    fs::write(&astro_added, b"undeclared")?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("astro-added.db"),
        fixture,
        "added Astro parser runtime",
    )?;
    fs::remove_file(astro_added)?;

    let astro_added_directory = astro_root.join("undeclared-empty-directory");
    fs::create_dir(&astro_added_directory)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("astro-added-directory.db"),
        fixture,
        "added Astro parser runtime directory",
    )?;
    fs::remove_dir(astro_added_directory)?;

    #[cfg(unix)]
    {
        let symlink = astro_root.join("astro-link.wasm");
        std::os::unix::fs::symlink("astro.wasm", &symlink)?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("astro-symlink.db"),
            fixture,
            "symlinked Astro parser runtime",
        )?;
        fs::remove_file(symlink)?;
    }

    let mut manifest: ReleaseManifest = serde_json::from_slice(&original_manifest)?;
    manifest
        .runtime_components
        .iter_mut()
        .find(|component| component.name == "astro-parser-wasm")
        .context("release manifest has no Astro parser component")?
        .version = "9.9.9".to_owned();
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("astro-version.db"),
        fixture,
        "Astro parser runtime version mismatch",
    )?;
    fs::write(&manifest_path, &original_manifest)?;

    let web_worker = extracted.join("libexec/depgraph-web-worker.mjs");
    let original_worker = fs::read(&web_worker)?;
    fs::remove_file(&web_worker)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("web-worker-missing.db"),
        fixture,
        "missing Web worker artifact",
    )?;
    fs::write(&web_worker, &original_worker)?;
    let mut tampered_worker = original_worker.clone();
    tampered_worker.extend_from_slice(b"\n// tampered\n");
    fs::write(&web_worker, tampered_worker)?;
    verify_packaged_security_failure(
        executable,
        &verify_root.join("web-worker-tampered.db"),
        fixture,
        "tampered Web worker artifact",
    )?;
    fs::write(&web_worker, &original_worker)?;

    #[cfg(unix)]
    {
        let real_worker = extracted.join("libexec/depgraph-web-worker.real.mjs");
        fs::rename(&web_worker, &real_worker)?;
        std::os::unix::fs::symlink(
            real_worker
                .file_name()
                .context("real Web worker has no file name")?,
            &web_worker,
        )?;
        verify_packaged_security_failure(
            executable,
            &verify_root.join("web-worker-symlink.db"),
            fixture,
            "symlinked Web worker artifact",
        )?;
        fs::remove_file(&web_worker)?;
        fs::rename(real_worker, &web_worker)?;
    }

    fs::write(manifest_path, original_manifest)?;
    Ok(())
}

fn verify_packaged_security_failure(
    executable: &Path,
    store: &Path,
    fixture: &Path,
    scenario: &str,
) -> Result<()> {
    let output = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .output()?;
    let report: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{scenario} gate did not return scan JSON"))?;
    if output.status.code() != Some(4) || report["status"] != "security_failed" {
        bail!("packaged CLI did not fail closed for {scenario}: {report}");
    }
    Ok(())
}

fn verify_packaged_scan(
    executable: &Path,
    store: &Path,
    fixture: &Path,
    adapter: &str,
) -> Result<()> {
    let scan = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .output()
        .with_context(|| format!("failed to run packaged {adapter} fixture scan"))?;
    if !scan.status.success() {
        bail!(
            "packaged {adapter} fixture scan failed: {}\n{}",
            String::from_utf8_lossy(&scan.stdout),
            String::from_utf8_lossy(&scan.stderr)
        );
    }
    let scan: Value = serde_json::from_slice(&scan.stdout)?;
    if scan["status"] != "completed"
        || scan["coverage"]["project_code_executed"] != Value::Bool(false)
        || scan["coverage"]["dependency_sites"].as_u64().unwrap_or(0) == 0
    {
        bail!("packaged {adapter} fixture scan failed its safety gate: {scan}");
    }
    if adapter == "web" {
        verify_packaged_web_import_type_call_graph(executable, store)?;
    }
    Ok(())
}

fn verify_packaged_milestone4(
    executable: &Path,
    verify_root: &Path,
    source_fixture: &Path,
) -> Result<()> {
    verify_packaged_legacy_store_migration(executable, verify_root)?;
    verify_packaged_stable_upgrade(executable, verify_root)?;

    let fixture = verify_root.join("milestone4-fixture");
    copy_directory(source_fixture, &fixture)?;
    fs::write(
        fixture.join(".depgraph.toml"),
        "schema_version = 1\n\n[policy]\nschema_version = \"1.0\"\n",
    )?;
    let store = verify_root.join("milestone4.db");

    let initial = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .arg("scan")
        .arg(&fixture)
        .arg("--json")
        .output()
        .context("failed to run packaged Milestone 4 baseline scan")?;
    let initial = successful_json(initial, "packaged Milestone 4 baseline scan")?;
    if initial["status"] != "completed" {
        bail!("packaged Milestone 4 baseline scan was not completed: {initial}");
    }

    let baseline = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .args(["snapshot", "create", "milestone4-baseline", "--json"])
        .output()?;
    let baseline = successful_json(baseline, "packaged snapshot create baseline")?;
    let baseline_id = baseline["data"]["snapshot"]["id"]
        .as_str()
        .context("packaged baseline snapshot has no ID")?
        .to_owned();

    fs::write(
        fixture.join("src/release_candidate_added.ts"),
        "import { choose } from \"./calls\";\nexport const releaseCandidate = () => choose();\n",
    )?;
    let target_scan = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .arg("scan")
        .arg(&fixture)
        .args(["--no-cache", "--json"])
        .output()
        .context("failed to run packaged Milestone 4 target scan")?;
    let target_scan = successful_json(target_scan, "packaged Milestone 4 target scan")?;
    if target_scan["status"] != "completed" {
        bail!("packaged Milestone 4 target scan was not completed: {target_scan}");
    }

    let target = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .args(["snapshot", "create", "milestone4-target", "--json"])
        .output()?;
    let target = successful_json(target, "packaged snapshot create target")?;
    let target_id = target["data"]["snapshot"]["id"]
        .as_str()
        .context("packaged target snapshot has no ID")?
        .to_owned();
    if target_id == baseline_id {
        bail!("packaged target scan did not create a distinct immutable snapshot");
    }

    let listed = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .args(["snapshot", "list", "--json"])
        .output()?;
    let listed = successful_json(listed, "packaged snapshot list")?;
    let names = listed["data"]
        .as_array()
        .context("packaged snapshot list has no data array")?
        .iter()
        .filter_map(|snapshot| snapshot["name"].as_str())
        .collect::<BTreeSet<_>>();
    if names != BTreeSet::from(["milestone4-baseline", "milestone4-target"]) {
        bail!("packaged snapshot list lost an immutable named snapshot: {listed}");
    }

    let diff = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .args(["diff", "milestone4-baseline", "milestone4-target", "--json"])
        .output()?;
    let diff = successful_json(diff, "packaged snapshot diff")?;
    if diff["schema_version"] != depgraph_store::SNAPSHOT_DIFF_SCHEMA_VERSION
        || diff["data"]["from_snapshot_id"] != baseline_id
        || diff["data"]["to_snapshot_id"] != target_id
        || diff["data"]["summary"]["total_changes"]
            .as_u64()
            .unwrap_or_default()
            == 0
    {
        bail!("packaged snapshot diff did not expose the target change: {diff}");
    }

    let impact = Command::new(executable)
        .arg("--store")
        .arg(&store)
        .args(["impact", "path:src/release_candidate_added.ts", "--json"])
        .output()?;
    let impact = successful_json(impact, "packaged impact query")?;
    if impact["command"] != "impact"
        || impact["data"]["root"]["properties"]["path"] != "src/release_candidate_added.ts"
    {
        bail!("packaged impact query did not resolve the changed file: {impact}");
    }

    let policy = Command::new(executable)
        .current_dir(&fixture)
        .arg("--store")
        .arg(&store)
        .args([
            "policy",
            "milestone4-baseline",
            "milestone4-target",
            "--json",
        ])
        .output()?;
    let policy = successful_json(policy, "packaged architecture policy JSON")?;
    if policy["data"]["result"]["exit_code"] != 0
        || policy["data"]["result"]["violations"]
            .as_array()
            .is_none_or(|violations| !violations.is_empty())
    {
        bail!("packaged architecture policy did not pass cleanly: {policy}");
    }
    let annotations = Command::new(executable)
        .current_dir(&fixture)
        .arg("--store")
        .arg(&store)
        .args([
            "policy",
            "milestone4-baseline",
            "milestone4-target",
            "--github-annotations",
        ])
        .output()?;
    if !annotations.status.success()
        || !annotations.stdout.is_empty()
        || !annotations.stderr.is_empty()
    {
        bail!(
            "packaged GitHub policy annotations were not a clean CI result: stdout={:?}, stderr={:?}",
            String::from_utf8_lossy(&annotations.stdout),
            String::from_utf8_lossy(&annotations.stderr)
        );
    }

    verify_packaged_watcher(executable, &store, &fixture)?;
    verify_packaged_runtime_and_graphml(executable, &store, verify_root, &fixture)?;
    Ok(())
}

fn verify_packaged_legacy_store_migration(executable: &Path, verify_root: &Path) -> Result<()> {
    let store_path = verify_root.join("legacy-v0.2.0-rc.1-v5.db");
    let backup_path = verify_root.join("legacy-v0.2.0-rc.1-v5.backup.db");
    let connection = rusqlite::Connection::open(&store_path)?;
    connection.execute_batch(include_str!("../fixtures/v0.2.0-rc.1-store-v5.sql"))?;
    let original_schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if original_schema != V0_2_RC1_STORE_SCHEMA_VERSION {
        bail!("legacy release fixture is schema {original_schema}, expected schema 5");
    }
    drop(connection);
    fs::copy(&store_path, &backup_path)?;
    let backup_bytes = fs::read(&backup_path)?;

    let read_only_before_migration = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "show", "current", "--json"])
        .output()
        .context("failed to open the v0.2.0-rc.1 store with the packaged CLI")?;
    if read_only_before_migration.status.code() != Some(3)
        || !read_only_before_migration.stdout.is_empty()
        || !String::from_utf8_lossy(&read_only_before_migration.stderr)
            .contains("outside supported read-only schema range")
        || fs::read(&store_path)? != backup_bytes
    {
        bail!("packaged read-only command did not require an explicit legacy store mutation");
    }

    let named = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "create", "migrated-v0.2.0-rc.1", "--json"])
        .output()?;
    let named = successful_json(named, "packaged migrated snapshot naming")?;
    let snapshot_id = named["data"]["snapshot"]["id"]
        .as_str()
        .context("packaged migrated snapshot has no ID")?
        .to_owned();

    let show = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "show", "current", "--json"])
        .output()
        .context("failed to read the migrated v0.2.0-rc.1 store")?;
    let show = successful_json(show, "packaged v0.2.0-rc.1 store migration")?;
    if show["data"]["source_kind"] != "scan"
        || show["data"]["scan_id"] != "legacy-v0.2.0-rc.1-scan"
        || show["data"]["status"] != "completed"
        || show["data"]["coverage"]["dependency_sites"] != 1
    {
        bail!("packaged migration lost the legacy completed snapshot: {show}");
    }

    let migrated = depgraph_store::Store::open(&store_path)?;
    if migrated.schema_version()? != depgraph_store::STORE_SCHEMA_VERSION {
        bail!("packaged migration did not reach the current store schema");
    }
    if migrated.current_snapshot_id()?.as_deref() != Some(snapshot_id.as_str()) {
        bail!("packaged migration changed the current completed snapshot identity");
    }
    let snapshot = migrated.load_completed_snapshot(&snapshot_id)?;
    if snapshot.nodes.len() != 2
        || snapshot.sites.len() != 1
        || snapshot.edges.len() != 1
        || snapshot.evidence.len() != 2
        || !migrated.verify_snapshot_integrity(&snapshot_id)?.valid
    {
        bail!("packaged migration changed the legacy completed graph");
    }
    drop(migrated);

    if named["data"]["snapshot"]["id"] != snapshot_id {
        bail!("naming the migrated snapshot changed its immutable ID: {named}");
    }

    let exported = packaged_raw_export_json(
        executable,
        &store_path,
        &[],
        "export packaged migrated graph",
    )?;
    if exported["graph"]["nodes"]
        .as_array()
        .is_none_or(|nodes| nodes.len() != 2)
        || exported["graph"]["edges"]
            .as_array()
            .is_none_or(|edges| edges.len() != 1)
    {
        bail!("packaged migrated graph export lost legacy records: {exported}");
    }

    let why = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args([
            "why",
            "id:file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead",
            "id:module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0",
            "--json",
        ])
        .output()?;
    let why = successful_json(why, "packaged migrated dependency query")?;
    if why["data"]["path_found"] != Value::Bool(true)
        || why["data"]["steps"]
            .as_array()
            .is_none_or(|steps| steps.len() != 1)
    {
        bail!("packaged migration lost the legacy dependency path: {why}");
    }

    if fs::read(&backup_path)? != backup_bytes {
        bail!("packaged migration changed the v0.2.0-rc.1 rollback backup bytes");
    }
    let backup = rusqlite::Connection::open_with_flags(
        &backup_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let backup_schema: i64 = backup.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if backup_schema != V0_2_RC1_STORE_SCHEMA_VERSION {
        bail!("packaged migration modified the rollback backup");
    }
    Ok(())
}

fn verify_packaged_stable_upgrade(executable: &Path, verify_root: &Path) -> Result<()> {
    if sha256_file(&workspace_root().join(STABLE_UPGRADE_SOURCE_FIXTURE_PATH))?
        != STABLE_UPGRADE_SOURCE_FIXTURE_SHA256
    {
        bail!("official v0.4.0-rc.6 store fixture checksum does not match its contract");
    }
    let store_path = verify_root.join("official-v0.4.0-rc.6-v13.db");
    let backup_path = verify_root.join("official-v0.4.0-rc.6-v13.backup.db");
    let connection = rusqlite::Connection::open(&store_path)?;
    connection.execute_batch(include_str!("../fixtures/v0.4.0-rc.6-store-v13.sql"))?;
    let original_schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if original_schema != release_compatibility().stable_upgrade_source_store_schema_version {
        bail!(
            "stable upgrade fixture is schema {original_schema}, expected {}",
            release_compatibility().stable_upgrade_source_store_schema_version
        );
    }
    drop(connection);
    fs::copy(&store_path, &backup_path)?;
    let backup_bytes = fs::read(&backup_path)?;

    let read_only_before_migration = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "show", "current", "--json"])
        .output()
        .context("failed to open the v0.4.0-rc.6 store with the v0.5 packaged CLI")?;
    if read_only_before_migration.status.code() != Some(3)
        || !read_only_before_migration.stdout.is_empty()
        || !String::from_utf8_lossy(&read_only_before_migration.stderr)
            .contains("outside supported read-only schema range")
        || fs::read(&store_path)? != backup_bytes
    {
        bail!("packaged read-only command did not require an explicit stable store mutation");
    }

    let named = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "create", "stable-v0.5.0-upgrade", "--json"])
        .output()?;
    let named = successful_json(named, "packaged stable upgraded snapshot naming")?;
    let snapshot_id = named["data"]["snapshot"]["id"]
        .as_str()
        .context("packaged stable upgraded snapshot has no ID")?
        .to_owned();

    let show = Command::new(executable)
        .arg("--store")
        .arg(&store_path)
        .args(["snapshot", "show", "current", "--json"])
        .output()
        .context("failed to read the migrated v0.4.0-rc.6 store")?;
    let show = successful_json(show, "packaged v0.4.0-rc.6 to v0.5 upgrade")?;
    if show["data"]["source_kind"] != "scan"
        || show["data"]["scan_id"] != "official-v0.4.0-rc.1-scan"
        || show["data"]["status"] != "completed"
        || show["data"]["coverage"]["dependency_sites"] != 1
    {
        bail!("v0.5 upgrade lost the v0.4.0-rc.6 fixture's completed snapshot: {show}");
    }

    let upgraded = depgraph_store::Store::open(&store_path)?;
    if upgraded.schema_version()? != depgraph_store::STORE_SCHEMA_VERSION {
        bail!("stable upgrade did not retain the current store schema");
    }
    if upgraded.current_snapshot_id()?.as_deref() != Some(snapshot_id.as_str()) {
        bail!("stable upgrade changed the current completed snapshot identity");
    }
    let snapshot = upgraded.load_completed_snapshot(&snapshot_id)?;
    if snapshot.scan.id != "official-v0.4.0-rc.1-scan"
        || snapshot.nodes.len() != 2
        || snapshot.sites.len() != 1
        || snapshot.edges.len() != 1
        || snapshot.evidence.len() != 2
        || !upgraded.verify_snapshot_integrity(&snapshot_id)?.valid
    {
        bail!("v0.5 upgrade changed the v0.4.0-rc.6 fixture's immutable graph");
    }
    drop(upgraded);

    if named["data"]["snapshot"]["id"] != snapshot_id {
        bail!("naming the stable upgraded snapshot changed its immutable ID: {named}");
    }

    if fs::read(&backup_path)? != backup_bytes {
        bail!("v0.5 upgrade changed the v0.4.0-rc.6 rollback backup bytes");
    }
    let backup = rusqlite::Connection::open_with_flags(
        &backup_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let backup_schema: i64 = backup.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if backup_schema != release_compatibility().stable_upgrade_source_store_schema_version {
        bail!("v0.5 upgrade modified the v0.4.0-rc.6 rollback backup");
    }
    Ok(())
}

fn verify_packaged_watcher(executable: &Path, store: &Path, fixture: &Path) -> Result<()> {
    use std::{process::Stdio, thread, time::Duration};

    struct ChildGuard(Option<std::process::Child>);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let status_path = PathBuf::from(format!("{}.daemon-status.json", store.display()));
    let mut child = ChildGuard(Some(
        Command::new(executable)
            .arg("--store")
            .arg(store)
            .arg("daemon")
            .arg("start")
            .arg(fixture)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to start the packaged incremental watcher")?,
    ));
    for _ in 0..1_200 {
        if status_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !status_path.exists() {
        bail!("packaged incremental watcher did not publish status");
    }
    fs::write(
        fixture.join("src/watched_release_candidate.ts"),
        "export const watchedReleaseCandidate = true;\n",
    )?;

    let mut completed = None;
    for _ in 0..1_200 {
        let status = Command::new(executable)
            .arg("--store")
            .arg(store)
            .arg("daemon")
            .arg("status")
            .arg(fixture)
            .arg("--json")
            .output()?;
        if status.status.success() {
            let status: Value = serde_json::from_slice(&status.stdout)?;
            let includes_change = status["last_completed_attempt"]["changes"]
                .as_array()
                .is_some_and(|changes| {
                    changes
                        .iter()
                        .any(|change| change["new_path"] == "src/watched_release_candidate.ts")
                });
            if status["phase"] == "idle" && includes_change {
                completed = Some(status);
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let completed =
        completed.context("packaged incremental watcher did not complete the change")?;
    let attempt = &completed["last_completed_attempt"];
    let base_snapshot_id = attempt["base_snapshot_id"]
        .as_str()
        .filter(|value| prefixed_lowercase_sha256(value, "snapshot:sha256:"))
        .context("packaged watcher omitted its valid base snapshot ID")?;
    let completed_snapshot_id = attempt["completed_snapshot_id"]
        .as_str()
        .filter(|value| prefixed_lowercase_sha256(value, "snapshot:sha256:"))
        .context("packaged watcher omitted its valid completed snapshot ID")?
        .to_owned();
    if completed["schema_version"] != depgraph_core::DAEMON_STATUS_SCHEMA_VERSION
        || attempt["status"] != "completed"
        || attempt["attempt_id"].as_str().is_none_or(str::is_empty)
        || attempt["scan_id"].as_str().is_none_or(str::is_empty)
        || completed_snapshot_id == base_snapshot_id
        || attempt.get("invalidation_plan").is_some()
        || attempt["invalidation_summary"]["schema_version"] != "incremental-plan-v2"
        || attempt["invalidation_summary"]["mode"] != "scoped_replacement"
        || attempt["invalidation_summary"]["affected_profile_count"]
            .as_u64()
            .is_none_or(|count| count == 0)
    {
        bail!("packaged incremental watcher returned an invalid completed attempt: {completed}");
    }

    let stopped = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("daemon")
        .arg("stop")
        .arg(fixture)
        .arg("--json")
        .output()?;
    let stopped = successful_json(stopped, "packaged incremental watcher stop")?;
    if stopped["phase"] != "stopped" {
        bail!("packaged incremental watcher did not stop cleanly: {stopped}");
    }
    let status = child
        .0
        .take()
        .context("packaged incremental watcher child was missing")?
        .wait()?;
    if !status.success() {
        bail!("packaged incremental watcher exited with {status}");
    }
    let packaged_store = depgraph_store::Store::open(store)?;
    if packaged_store.current_snapshot_id()?.as_deref() != Some(completed_snapshot_id.as_str())
        || !packaged_store
            .verify_snapshot_integrity(&completed_snapshot_id)?
            .valid
    {
        bail!("packaged incremental watcher did not promote its completed snapshot");
    }
    let snapshot = packaged_store.load_completed_snapshot(&completed_snapshot_id)?;
    if !snapshot.nodes.iter().any(|node| {
        node.properties["path"]
            .as_str()
            .is_some_and(|path| path == "src/watched_release_candidate.ts")
    }) {
        bail!("packaged incremental watcher snapshot omitted the watched file");
    }
    Ok(())
}

fn verify_packaged_runtime_and_graphml(
    executable: &Path,
    store: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let exported =
        packaged_raw_export_json(executable, store, &[], "export packaged runtime base graph")?;
    let graph = &exported["graph"];
    let repository_identity = graph["nodes"]
        .as_array()
        .context("packaged runtime base has no nodes")?
        .iter()
        .find_map(|node| {
            node["properties"]["repository_identity"]
                .as_str()
                .map(ToOwned::to_owned)
        })
        .context("packaged runtime base has no repository identity")?;
    let profile = graph["profiles"]
        .as_array()
        .context("packaged runtime base has no profiles")?
        .iter()
        .find(|profile| matches!(profile["language"].as_str(), Some("web" | "typescript")))
        .context("packaged runtime base has no Web profile")?;
    let profile_id = profile["id"]
        .as_str()
        .context("packaged runtime profile has no ID")?;
    let profile_language = profile["language"]
        .as_str()
        .context("packaged runtime profile has no language")?;
    let nodes = graph["nodes"]
        .as_array()
        .context("packaged runtime base has no nodes")?;
    let source_node = nodes
        .iter()
        .find(|node| {
            node["properties"]["path"]
                .as_str()
                .is_some_and(|path| fixture.join(path).is_file())
        })
        .context("packaged runtime base has no source backed by the real app fixture")?;
    let source = source_node["id"]
        .as_str()
        .context("packaged runtime source node has no ID")?;
    let source_path = source_node["properties"]["path"]
        .as_str()
        .context("packaged runtime source node has no repository path")?;
    let target = nodes
        .iter()
        .filter_map(|node| node["id"].as_str())
        .find(|node| *node != source)
        .context("packaged runtime base has no distinct target node")?;

    let release_root = executable
        .parent()
        .and_then(Path::parent)
        .context("packaged executable has no release root")?;
    let collector_path = release_root
        .join("libexec")
        .join(RUNTIME_COLLECTOR_ARTIFACT);
    if !collector_path.is_file() {
        bail!("packaged runtime collector artifact is missing");
    }
    let trace_path = verify_root.join("milestone4-runtime-trace.json");
    let collector_input_path = verify_root.join("milestone4-runtime-collector-input.json");
    fs::write(
        &collector_input_path,
        serde_json::to_vec_pretty(&json!({
            "repository": {
                "identity": repository_identity
            },
            "session": {
                "id": "milestone4-packaged-session",
                "profile": {
                    "language": profile_language,
                    "parentProfileId": profile_id
                },
                "environment": {
                    "name": "release-candidate",
                    "runtime": "nodejs-24",
                    "region": "package-gate",
                    "environmentKeys": ["NODE_ENV"]
                },
                "redaction": {
                    "environmentKeys": ["API_TOKEN"],
                    "headerNames": ["authorization"],
                    "secretNames": ["release_secret"],
                    "redactedValueCount": 3
                }
            },
            "observations": [
                {
                    "kind": "call",
                    "source": {
                        "kind": "repository_path",
                        "path": source_path,
                        "nodeKind": "file"
                    },
                    "target": {
                        "kind": "node",
                        "nodeId": target
                    },
                    "count": 1,
                    "redaction": {
                        "headerNames": ["authorization"]
                    }
                },
                {
                    "kind": "rpc",
                    "source": {
                        "kind": "node",
                        "nodeId": source
                    },
                    "target": {
                        "kind": "http_url",
                        "url": "https://release-user:release_secret_value@API.EXAMPLE.TEST:443/private/release_secret_value?token=release_secret_value#release_secret_value"
                    },
                    "redaction": {
                        "secretNames": ["release_secret"]
                    }
                }
            ]
        }))?,
    )?;
    let runner_path = verify_root.join("milestone4-runtime-collector-runner.mjs");
    fs::write(
        &runner_path,
        r#"import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [collectorPath, inputPath, tracePath] = process.argv.slice(2);
const sdk = await import(pathToFileURL(collectorPath).href);
if (sdk.RUNTIME_COLLECTOR_CONTRACT_VERSION !== "runtime-collector-v1"
    || sdk.RUNTIME_TRACE_SCHEMA_VERSION !== "1.0") {
  throw new Error("packaged runtime collector compatibility mismatch");
}
const input = JSON.parse(await readFile(inputPath, "utf8"));
let wallMs = Date.parse("2026-07-24T00:00:00Z");
const collector = sdk.createRuntimeCollector({
  repository: input.repository,
  session: input.session,
  sink: sdk.createFileRuntimeCollectorSink(tracePath),
  clock: {
    utcNow() {
      const now = new Date(wallMs);
      wallMs += 1_000;
      return now;
    },
    monotonicNow() {
      return 0;
    },
  },
  retry: { maxAttempts: 0 },
});
for (const observation of input.observations) {
  if (!collector.record(observation)) {
    throw new Error("packaged runtime collector rejected a fixture observation");
  }
}
const result = await collector.shutdown();
if (result.status !== "flushed") {
  throw new Error(`packaged runtime collector flush failed: ${JSON.stringify(result)}`);
}
process.stdout.write(JSON.stringify({
  contract_version: sdk.RUNTIME_COLLECTOR_CONTRACT_VERSION,
  descriptor: collector.descriptor,
  result,
  stats: collector.stats(),
}));
"#,
    )?;
    let generated = Command::new("node")
        .arg(process_argument_path(&runner_path))
        .arg(process_argument_path(&collector_path))
        .arg(process_argument_path(&collector_input_path))
        .arg(process_argument_path(&trace_path))
        .output()
        .context("failed to run the packaged runtime collector")?;
    if bytes_contain(&generated.stdout, b"release_secret_value")
        || bytes_contain(&generated.stderr, b"release_secret_value")
    {
        bail!("packaged runtime collector leaked a secret through diagnostics");
    }
    let generated = successful_json(generated, "packaged runtime collector generation")?;
    if generated["contract_version"] != RUNTIME_COLLECTOR_CONTRACT_VERSION
        || generated["descriptor"]["contract_version"] != RUNTIME_COLLECTOR_CONTRACT_VERSION
        || generated["descriptor"]["output_schema_version"]
            != depgraph_core::RUNTIME_TRACE_SCHEMA_VERSION
        || generated["result"]["status"] != "flushed"
        || generated["stats"]["acceptedEvents"] != 2
        || generated["stats"]["flushedPrefixes"] != 1
    {
        bail!("packaged runtime collector reported an incompatible result: {generated}");
    }
    let generated_trace: Value = serde_json::from_slice(&fs::read(&trace_path)?)
        .context("packaged runtime collector generated invalid JSON")?;
    if generated_trace["session"]["collector_contract_version"]
        != RUNTIME_COLLECTOR_CONTRACT_VERSION
        || generated_trace["events"]
            .as_array()
            .is_none_or(|events| events.len() != 2)
    {
        bail!("packaged runtime collector generated an incompatible trace: {generated_trace}");
    }
    let trace_argument = trace_path
        .strip_prefix(verify_root)
        .context("packaged runtime trace path is outside the verification root")?;

    let validated = Command::new(executable)
        .current_dir(verify_root)
        .arg("--store")
        .arg(store)
        .arg("runtime")
        .arg("validate")
        .arg("--file")
        .arg(trace_argument)
        .arg("--json")
        .output()?;
    let validated = successful_json(validated, "packaged runtime trace validation")?;
    if validated["command"] != "runtime.validate"
        || validated["data"]["profile_match"]["status"] != "resolved"
        || validated["data"]["summary"]["events"] != 2
        || validated["data"]["summary"]["resolved_targets"] != 1
    {
        bail!("packaged runtime trace validation was incomplete: {validated}");
    }

    let imported = Command::new(executable)
        .current_dir(verify_root)
        .arg("--store")
        .arg(store)
        .arg("runtime")
        .arg("import")
        .arg(trace_argument)
        .arg("--json")
        .output()?;
    let imported = successful_json(imported, "packaged runtime trace import")?;
    if imported["command"] != "runtime.import"
        || imported["data"]["status"] != "completed"
        || imported["data"]["deduplicated"] != Value::Bool(false)
    {
        bail!("packaged runtime trace import was incomplete: {imported}");
    }

    let runtime_impact = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("impact")
        .arg(format!("id:{target}"))
        .args([
            "--phase",
            "runtime",
            "--session",
            "milestone4-packaged-session",
            "--json",
        ])
        .output()?;
    let runtime_impact = successful_json(runtime_impact, "packaged runtime impact query")?;
    if runtime_impact["data"]["filters"]["phases"] != json!(["runtime"])
        || runtime_impact["data"]["filters"]["sessions"] != json!(["milestone4-packaged-session"])
    {
        bail!("packaged runtime impact filters were not preserved: {runtime_impact}");
    }

    let render = || {
        packaged_raw_export_text(
            executable,
            store,
            "graphml",
            &[
                "--phase",
                "runtime",
                "--session",
                "milestone4-packaged-session",
            ],
            "export packaged runtime GraphML",
        )
    };
    let first = render()?;
    let second = render()?;
    if first != second
        || !first.contains("<graphml xmlns=")
        || !first.contains("<data key=\"e_phase\">runtime</data>")
    {
        bail!("packaged GraphML runtime export was invalid or nondeterministic");
    }

    let graphml_path = verify_root.join("milestone4.graphml");
    let graphml_argument = graphml_path
        .strip_prefix(verify_root)
        .context("packaged GraphML export path is outside the verification root")?;
    let file = Command::new(executable)
        .current_dir(verify_root)
        .arg("--store")
        .arg(store)
        .args([
            "export",
            "--format",
            "graphml",
            "--phase",
            "runtime",
            "--session",
            "milestone4-packaged-session",
            "--output",
        ])
        .arg(graphml_argument)
        .output()?;
    if !file.status.success()
        || !file.stdout.is_empty()
        || fs::read_to_string(&graphml_path)? != first
        || fs::read_dir(verify_root)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().to_str().map(str::to_owned))
                .is_some_and(|name| name.starts_with(".depgraph-export-"))
        })
    {
        bail!("packaged GraphML atomic file export did not match the canonical raw export");
    }
    if bytes_contain(&fs::read(&trace_path)?, b"release_secret_value")
        || bytes_contain(first.as_bytes(), b"release_secret_value")
        || bytes_contain(&fs::read(store)?, b"release_secret_value")
    {
        bail!("packaged runtime trace leaked a secret value");
    }
    Ok(())
}

fn successful_json(output: std::process::Output, scenario: &str) -> Result<Value> {
    if !output.status.success() {
        bail!(
            "{scenario} failed with {}:\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{scenario} returned invalid JSON"))
}

fn verify_packaged_web_import_type_call_graph(executable: &Path, store: &Path) -> Result<()> {
    let exported = packaged_web_export_json(executable, store)?;
    let graph = exported["graph"]
        .as_object()
        .context("packaged Web semantic export has no graph")?;
    let profile = graph["profiles"]
        .as_array()
        .and_then(|profiles| profiles.iter().find(|profile| profile["language"] == "web"))
        .context("packaged Web semantic export has no Web profile")?;
    let properties = &profile["properties"];
    for (property, expected) in [
        (
            "typescript_analysis_mode",
            "semantic-import-type-call-graph",
        ),
        ("typescript_project_model_status", "ready"),
        (
            "typescript_typechecker_status",
            "definition-import-type-call-graph-emitted",
        ),
        ("typescript_definition_graph_status", "ready"),
        (
            "typescript_semantic_graph_emission",
            "definition-import-type-call-graph-v2",
        ),
        ("typescript_semantic_issue_count", "0"),
        ("typescript_release_gate", "release-gate-verified"),
    ] {
        if properties[property] != expected {
            bail!("packaged Web profile property {property} must be {expected:?}: {properties}");
        }
    }

    let nodes = graph["nodes"]
        .as_array()
        .context("packaged Web semantic export has no nodes")?;
    let semantic_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| matches!(node["kind"].as_str(), Some("symbol" | "type")))
        .collect();
    if semantic_nodes.is_empty()
        || !semantic_nodes.iter().any(|node| {
            node["kind"] == "type" && node["properties"]["type_kind"] == "generic_instance"
        })
    {
        bail!("packaged Web export omitted its semantic or generic-instance nodes");
    }

    let sites = graph["sites"]
        .as_array()
        .context("packaged Web semantic export has no sites")?;
    let edges = graph["edges"]
        .as_array()
        .context("packaged Web semantic export has no edges")?;
    let evidence = graph["evidence"]
        .as_array()
        .context("packaged Web semantic export has no evidence")?;
    let semantic_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "typescript-native-typechecker"
                && item["extractor_version"] == "7.0.2"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let semantic_edges: Vec<_> = edges
        .iter()
        .filter(|edge| {
            edge["phase"] == "semantic"
                && edge["id"]
                    .as_str()
                    .is_some_and(|id| semantic_edge_ids.contains(id))
        })
        .collect();
    let definition_edges: Vec<_> = semantic_edges
        .iter()
        .copied()
        .filter(|edge| edge["site_id"].is_null())
        .collect();
    let dependency_edges: Vec<_> = semantic_edges
        .iter()
        .copied()
        .filter(|edge| !edge["site_id"].is_null())
        .collect();
    let semantic_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "typescript-native-typechecker"
                && item["extractor_version"] == "7.0.2"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let semantic_sites: Vec<_> = sites
        .iter()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| semantic_site_ids.contains(id))
        })
        .collect();
    if semantic_sites.is_empty() || dependency_edges.is_empty() {
        bail!("packaged Web export omitted semantic import/type/call sites or edges");
    }

    let definition_kinds: BTreeSet<_> = definition_edges
        .iter()
        .filter_map(|edge| edge["kind"].as_str())
        .collect();
    let dependency_kinds: BTreeSet<_> = dependency_edges
        .iter()
        .filter_map(|edge| edge["kind"].as_str())
        .collect();
    let site_kinds: BTreeSet<_> = semantic_sites
        .iter()
        .filter_map(|site| site["kind"].as_str())
        .collect();
    let statuses: BTreeSet<_> = semantic_sites
        .iter()
        .filter_map(|site| site["resolution_status"].as_str())
        .collect();
    if definition_kinds != BTreeSet::from(["declares", "extends", "implements", "instantiates"])
        || dependency_kinds
            != BTreeSet::from(["calls", "imports", "may_call", "reexports", "type_uses"])
        || site_kinds != BTreeSet::from(["call", "type_use", "web_import", "web_reexport"])
        || !BTreeSet::from(["candidates", "external", "resolved", "unresolved"])
            .is_subset(&statuses)
        || !statuses.is_subset(&BTreeSet::from([
            "candidates",
            "external",
            "resolved",
            "unresolved",
        ]))
        || definition_edges
            .iter()
            .any(|edge| edge["resolution_status"] != "resolved" || edge["precision"] != "exact")
    {
        bail!("packaged Web export violated the definition-import-type-call-graph-v2 vocabulary");
    }
    for edge in &semantic_edges {
        if !evidence.iter().any(|item| {
            item["owner_type"] == "edge"
                && item["owner_id"] == edge["id"]
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "typescript-native-typechecker"
                && item["extractor_version"] == "7.0.2"
        }) {
            bail!(
                "packaged Web semantic edge {} lost its primary TypeChecker evidence",
                edge["id"]
            );
        }
    }

    let nodes_by_id: BTreeMap<_, _> = nodes
        .iter()
        .filter_map(|node| Some((node["id"].as_str()?, node)))
        .collect();
    let mut saw_type_only_true = false;
    let mut saw_type_only_false = false;
    let mut saw_node_builtin = false;
    let mut saw_empty_import = false;
    let mut saw_empty_reexport = false;
    let mut semantic_call_site_count = 0_usize;
    let mut saw_exact_direct_function = false;
    let mut saw_exact_constructor = false;
    let mut saw_exact_method = false;
    let mut saw_external_call = false;
    let mut saw_closed_local_function_candidate = false;
    let mut saw_multiple_closed_local_function_candidate = false;
    let mut saw_closed_fresh_instance_candidate = false;
    for site in &semantic_sites {
        let site_id = site["id"]
            .as_str()
            .context("packaged Web semantic site omitted its ID")?;
        let kind = site["kind"]
            .as_str()
            .context("packaged Web semantic site omitted its kind")?;
        let status = site["resolution_status"]
            .as_str()
            .context("packaged Web semantic site omitted its status")?;
        let precision = site["precision"]
            .as_str()
            .context("packaged Web semantic site omitted its precision")?;
        let targets = site["target_ids"]
            .as_array()
            .context("packaged Web semantic site omitted target_ids")?;
        let target_ids = targets
            .iter()
            .map(|target| {
                target
                    .as_str()
                    .context("packaged Web semantic site has a non-string target")
            })
            .collect::<Result<Vec<_>>>()?;
        if target_ids.is_empty() || target_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!("packaged Web semantic site {site_id} has non-canonical targets");
        }
        let primary = evidence
            .iter()
            .find(|item| {
                item["owner_type"] == "site"
                    && item["owner_id"] == site_id
                    && item["ordinal"].as_u64() == Some(0)
                    && item["kind"] == "semantic"
                    && item["extractor"] == "typescript-native-typechecker"
                    && item["extractor_version"] == "7.0.2"
            })
            .with_context(|| {
                format!("packaged Web semantic site {site_id} lost its stored primary evidence")
            })?;
        let occurrence_kind = primary["properties"]["occurrence_kind"]
            .as_str()
            .context("packaged Web semantic site primary evidence omitted occurrence_kind")?;
        let evidence_properties = primary["properties"]
            .as_object()
            .context("packaged Web semantic site primary evidence properties are malformed")?;
        let type_only = match evidence_properties.get("type_only") {
            None => None,
            Some(value) => Some(value.as_bool().with_context(|| {
                format!("packaged Web semantic site {site_id} has non-boolean type_only")
            })?),
        };
        let module_specifier = match evidence_properties.get("module_specifier") {
            None => None,
            Some(value) => Some(value.as_str().with_context(|| {
                format!("packaged Web semantic site {site_id} has invalid module_specifier")
            })?),
        };
        let imported_name = match evidence_properties.get("imported_name") {
            None => None,
            Some(value) => Some(value.as_str().with_context(|| {
                format!("packaged Web semantic site {site_id} has invalid imported_name")
            })?),
        };
        let resolution_mode = match evidence_properties.get("resolution_mode") {
            None => None,
            Some(value) => Some(value.as_str().with_context(|| {
                format!("packaged Web semantic site {site_id} has invalid resolution_mode")
            })?),
        };
        let specifier = site["specifier"]
            .as_str()
            .context("packaged Web semantic site omitted its specifier")?;
        if let Some(type_only) = type_only {
            saw_type_only_true |= type_only;
            saw_type_only_false |= !type_only;
        }
        saw_empty_import |= occurrence_kind == "empty_import";
        saw_empty_reexport |= occurrence_kind == "empty_reexport";
        let occurrence_matches_site = match kind {
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
        };
        if !occurrence_matches_site {
            bail!(
                "packaged Web semantic site {site_id} has occurrence_kind {occurrence_kind} incompatible with {kind}"
            );
        }
        if kind == "call" {
            semantic_call_site_count += 1;
            let call_kind = evidence_properties
                .get("call_kind")
                .and_then(Value::as_str)
                .context("packaged Web call site omitted call_kind")?;
            let dispatch = evidence_properties
                .get("dispatch")
                .and_then(Value::as_str)
                .context("packaged Web call site omitted dispatch")?;
            let algorithm = evidence_properties.get("algorithm").and_then(Value::as_str);
            if type_only.is_some()
                || imported_name.is_some()
                || resolution_mode.is_some()
                || specifier.is_empty()
                || !matches!(
                    call_kind,
                    "function" | "method" | "constructor" | "tagged_template"
                )
                || !matches!(
                    dispatch,
                    "direct"
                        | "static"
                        | "private"
                        | "fresh_instance"
                        | "super"
                        | "external"
                        | "dynamic"
                        | "open"
                )
                || (status == "candidates"
                    && (precision != "overapprox"
                        || !site["reason"].is_null()
                        || !matches!(
                            (dispatch, algorithm),
                            ("dynamic", Some("typescript-closed-local-call-flow-v1"))
                                | (
                                    "fresh_instance",
                                    Some("typescript-closed-local-fresh-instance-flow-v1")
                                )
                        )))
                || (status != "candidates" && algorithm.is_some())
            {
                bail!("packaged Web call site {site_id} has invalid call metadata");
            }
            let acceptance_fixture = primary["path"] == "apps/shared/src/calls.ts";
            saw_exact_direct_function |= acceptance_fixture
                && specifier == "directTarget"
                && call_kind == "function"
                && dispatch == "direct"
                && status == "resolved"
                && precision == "exact";
            saw_exact_constructor |= acceptance_fixture
                && specifier == "DirectReceiver"
                && call_kind == "constructor"
                && dispatch == "direct"
                && status == "resolved"
                && precision == "exact";
            saw_exact_method |= acceptance_fixture
                && call_kind == "method"
                && matches!(dispatch, "static" | "private" | "fresh_instance" | "super")
                && status == "resolved"
                && precision == "exact";
            saw_external_call |= acceptance_fixture
                && specifier == "value.trim"
                && dispatch == "external"
                && status == "external";
            saw_closed_local_function_candidate |= acceptance_fixture
                && specifier == "dynamicTarget"
                && dispatch == "dynamic"
                && status == "candidates"
                && precision == "overapprox"
                && algorithm == Some("typescript-closed-local-call-flow-v1");
            saw_multiple_closed_local_function_candidate |= acceptance_fixture
                && specifier == "conditionalTarget"
                && dispatch == "dynamic"
                && status == "candidates"
                && precision == "overapprox"
                && target_ids.len() == 2
                && algorithm == Some("typescript-closed-local-call-flow-v1");
            saw_closed_fresh_instance_candidate |= acceptance_fixture
                && specifier == "candidateReceiver.closedMethod"
                && dispatch == "fresh_instance"
                && status == "candidates"
                && precision == "overapprox"
                && algorithm == Some("typescript-closed-local-fresh-instance-flow-v1");
        } else {
            let type_only = type_only
                .context("packaged Web import/type semantic site omitted boolean type_only")?;
            if (kind == "type_use" || occurrence_kind == "import_type") && !type_only {
                bail!("packaged Web type-only semantic site {site_id} reported type_only=false");
            }
            if matches!(
                occurrence_kind,
                "side_effect_import" | "require_call" | "dynamic_import"
            ) && type_only
            {
                bail!("packaged Web runtime semantic site {site_id} reported type_only=true");
            }
            if !matches!(resolution_mode, None | Some("import" | "require"))
                || (resolution_mode.is_some() && (!type_only || module_specifier.is_none()))
            {
                bail!("packaged Web semantic site {site_id} has contradictory resolution_mode");
            }
            if resolution_mode.is_some() && occurrence_kind == "import_equals" {
                bail!(
                    "packaged Web semantic site {site_id} import_equals occurrence exposed resolution_mode"
                );
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
            if (kind == "type_use" && imported_name != Some(specifier))
                || (kind != "type_use" && module_specifier != Some(specifier))
                || (named_binding && imported_name.is_none())
                || (namespace_binding && imported_name != Some("*"))
                || (module_only && imported_name.is_some())
                || (occurrence_kind == "default_import" && imported_name != Some("default"))
                || (occurrence_kind == "import_equals" && imported_name != Some("="))
            {
                bail!(
                    "packaged Web semantic site {site_id} has occurrence metadata inconsistent with its public specifier"
                );
            }
        }
        if kind == "web_import" && primary["properties"]["module_specifier"] == "node:fs" {
            saw_node_builtin = true;
            let target = target_ids
                .first()
                .and_then(|target| nodes_by_id.get(target))
                .context("packaged Web node:fs site target node is missing")?;
            if kind != "web_import"
                || site["specifier"] != "node:fs"
                || type_only != Some(false)
                || status != "external"
                || precision != "exact"
                || target_ids.len() != 1
                || !site["reason"].is_null()
                || target["kind"] != "external_system"
                || target["locator"] != "external://typescript/node%3Afs"
                || target["display_name"] != "node:fs"
                || target["properties"]["canonical_identity"]
                    != json!({
                        "language": "typescript",
                        "compiler_version": "7.0.2",
                        "locator": "node:fs",
                    })
            {
                bail!("packaged Web node:fs import lost its exact canonical builtin identity");
            }
        }
        let expected_edge_kind = match kind {
            "web_import" => "imports",
            "web_reexport" => "reexports",
            "type_use" => "type_uses",
            "call" if status == "candidates" => "may_call",
            "call" => "calls",
            _ => bail!("packaged Web semantic site {site_id} has unsupported kind {kind}"),
        };
        let linked: Vec<_> = dependency_edges
            .iter()
            .copied()
            .filter(|edge| edge["site_id"] == site_id)
            .collect();
        let linked_targets: BTreeSet<_> = linked
            .iter()
            .filter_map(|edge| edge["target"].as_str())
            .collect();
        let edge_condition_union = Condition::Any {
            conditions: linked
                .iter()
                .map(|edge| {
                    serde_json::from_value(edge["condition"].clone()).with_context(|| {
                        format!(
                            "packaged Web semantic edge omitted a valid condition for {site_id}"
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        }
        .canonicalized();
        let site_condition: Condition = serde_json::from_value(site["condition"].clone())
            .with_context(|| {
                format!("packaged Web semantic site {site_id} omitted a valid condition")
            })?;
        if linked.len() != target_ids.len()
            || linked_targets != target_ids.iter().copied().collect()
            || edge_condition_union != site_condition.canonicalized()
            || linked.iter().any(|edge| {
                edge["kind"] != expected_edge_kind
                    || edge["source"] != site["source"]
                    || edge["profile_id"] != site["profile_id"]
                    || edge["resolution_status"] != site["resolution_status"]
                    || edge["precision"] != site["precision"]
            })
        {
            bail!("packaged Web semantic site {site_id} disagrees with its dependency edges");
        }
        match status {
            "resolved" if target_ids.len() == 1 && precision == "exact" => {}
            "candidates" if precision == "overapprox" => {}
            "external" if target_ids.len() == 1 && matches!(precision, "exact" | "heuristic") => {}
            "unresolved"
                if target_ids.len() == 1
                    && precision == "heuristic"
                    && site["reason"]
                        .as_str()
                        .is_some_and(|reason| !reason.is_empty()) => {}
            _ => bail!(
                "packaged Web semantic site {site_id} has invalid {status}/{precision} cardinality"
            ),
        }
        if status == "external" {
            let target = nodes_by_id
                .get(target_ids[0])
                .context("packaged Web external site target node is missing")?;
            if target["kind"] != "external_system"
                || target["properties"]["language"] != "typescript"
                || target["properties"]["profile_id"] != site["profile_id"]
                || target["properties"]["compiler_version"] != "7.0.2"
                || target["properties"]["external"] != true
                || target["properties"]["workspace"] == true
            {
                bail!("packaged Web external site {site_id} has an invalid external sentinel");
            }
        }
        if status == "unresolved" {
            let target = nodes_by_id
                .get(target_ids[0])
                .context("packaged Web unresolved site target node is missing")?;
            if target["kind"] != "unknown_target"
                || target["properties"]["language"] != "web"
                || target["properties"]["profile_id"] != site["profile_id"]
            {
                bail!("packaged Web unresolved site {site_id} has an invalid unknown sentinel");
            }
        }
        if kind == "type_use"
            && matches!(status, "resolved" | "candidates")
            && target_ids.iter().any(|target| {
                nodes_by_id
                    .get(target)
                    .is_none_or(|node| node["kind"] != "type")
            })
        {
            bail!("packaged Web type-use site {site_id} has a non-type concrete target");
        }
        if kind == "call" {
            let source = site["source"]
                .as_str()
                .and_then(|source| nodes_by_id.get(source))
                .context("packaged Web call site source symbol is missing")?;
            if source["kind"] != "symbol"
                || (matches!(status, "resolved" | "candidates")
                    && target_ids.iter().any(|target| {
                        nodes_by_id
                            .get(target)
                            .is_none_or(|target| target["kind"] != "symbol")
                    }))
                || ((status == "resolved" || status == "candidates") && !site["reason"].is_null())
            {
                bail!("packaged Web call site {site_id} has a non-canonical source or callee");
            }
        }
        if matches!(
            occurrence_kind,
            "namespace_import"
                | "side_effect_import"
                | "empty_import"
                | "import_equals"
                | "require_call"
                | "dynamic_import"
                | "import_type"
                | "namespace_reexport"
                | "empty_reexport"
                | "export_star"
        ) && matches!(status, "resolved" | "candidates")
            && target_ids.iter().any(|target| {
                nodes_by_id
                    .get(target)
                    .is_none_or(|node| node["kind"] != "file")
            })
        {
            bail!("packaged Web module-level site {site_id} has a non-file concrete target");
        }
        if target_ids.iter().any(|target| {
            nodes_by_id
                .get(target)
                .is_some_and(|node| node["kind"] == "file")
        }) && !matches!(
            primary["properties"]["occurrence_kind"].as_str(),
            Some(
                "namespace_import"
                    | "side_effect_import"
                    | "empty_import"
                    | "import_equals"
                    | "require_call"
                    | "dynamic_import"
                    | "import_type"
                    | "namespace_reexport"
                    | "empty_reexport"
                    | "export_star"
            )
        ) {
            bail!("packaged Web named semantic binding {site_id} was weakened to a file target");
        }
    }
    if !saw_type_only_true || !saw_type_only_false {
        bail!("packaged Web semantic sites did not cover both type-only and runtime occurrences");
    }
    if !saw_node_builtin {
        bail!("packaged Web semantic sites omitted the node:fs builtin acceptance fixture");
    }
    if !saw_empty_import || !saw_empty_reexport {
        bail!("packaged Web semantic sites omitted empty import/re-export acceptance fixtures");
    }
    if !saw_exact_direct_function
        || !saw_exact_constructor
        || !saw_exact_method
        || !saw_external_call
        || !saw_closed_local_function_candidate
        || !saw_multiple_closed_local_function_candidate
        || !saw_closed_fresh_instance_candidate
    {
        bail!(
            "packaged Web call fixture did not cover exact direct/function/method/constructor, external, or closed local single/multiple-target candidate call cases"
        );
    }
    for (property, actual) in [
        ("typescript_semantic_node_count", semantic_nodes.len()),
        ("typescript_semantic_relation_count", semantic_edges.len()),
        ("typescript_semantic_site_count", semantic_sites.len()),
        (
            "typescript_semantic_call_site_count",
            semantic_call_site_count,
        ),
    ] {
        let declared = properties[property]
            .as_str()
            .and_then(|value| value.parse::<usize>().ok());
        if declared != Some(actual) {
            bail!("packaged Web profile reports {property}={declared:?}, observed {actual}");
        }
    }

    let all_framework_node_ids: BTreeSet<_> = nodes
        .iter()
        .filter(|node| {
            matches!(
                node["properties"]["canonical_identity"]["framework"].as_str(),
                Some("next" | "astro" | "tanstack-router" | "tanstack-start")
            ) && node["properties"]["framework"]
                == node["properties"]["canonical_identity"]["framework"]
        })
        .filter_map(|node| node["id"].as_str())
        .collect();
    let all_framework_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| {
            node["id"]
                .as_str()
                .is_some_and(|id| all_framework_node_ids.contains(id))
        })
        .collect();
    let all_framework_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let all_framework_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let all_framework_sites: Vec<_> = sites
        .iter()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| all_framework_site_ids.contains(id))
        })
        .collect();
    let all_framework_edges: Vec<_> = edges
        .iter()
        .filter(|edge| {
            edge["id"]
                .as_str()
                .is_some_and(|id| all_framework_edge_ids.contains(id))
        })
        .collect();

    let framework_node_ids: BTreeSet<_> = nodes
        .iter()
        .filter(|node| {
            matches!(node["kind"].as_str(), Some("component" | "route"))
                && node["properties"]["framework"] == "next"
                && node["properties"]["canonical_identity"]["framework"] == "next"
        })
        .filter_map(|node| node["id"].as_str())
        .collect();
    let framework_nodes: Vec<_> = nodes
        .iter()
        .filter(|node| {
            node["id"]
                .as_str()
                .is_some_and(|id| framework_node_ids.contains(id))
        })
        .collect();
    let framework_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "next-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "next"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let framework_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "next-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "next"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let framework_sites: Vec<_> = sites
        .iter()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| framework_site_ids.contains(id))
        })
        .collect();
    let framework_edges: Vec<_> = edges
        .iter()
        .filter(|edge| {
            edge["id"]
                .as_str()
                .is_some_and(|id| framework_edge_ids.contains(id))
        })
        .collect();
    if properties["web_framework_semantic_status"] != "emitted"
        || properties["web_framework_semantic_capability"] != "framework-semantic-graph-v1"
        || properties["web_framework_semantic_extractor_version"] != "0.1.0"
    {
        bail!("packaged Web profile did not emit the Next.js semantic graph: {properties}");
    }
    for (property, actual) in [
        (
            "web_framework_semantic_node_count",
            all_framework_nodes.len(),
        ),
        (
            "web_framework_semantic_site_count",
            all_framework_sites.len(),
        ),
        (
            "web_framework_semantic_edge_count",
            all_framework_edges.len(),
        ),
    ] {
        let declared = properties[property]
            .as_str()
            .and_then(|value| value.parse::<usize>().ok());
        if declared != Some(actual) || actual == 0 {
            bail!("packaged Web profile reports {property}={declared:?}, observed {actual}");
        }
    }
    let framework_kinds: BTreeSet<_> = framework_edges
        .iter()
        .filter_map(|edge| edge["kind"].as_str())
        .collect();
    if framework_kinds
        != BTreeSet::from([
            "client_boundary",
            "parent_route",
            "renders",
            "route_entry",
            "server_boundary",
        ])
    {
        bail!("packaged Next.js graph lost its route/component/boundary vocabulary");
    }

    let product_route = framework_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "route"
                && node["properties"]["canonical_identity"]["route_kind"] == "next-app-page"
                && node["properties"]["canonical_identity"]["route_pattern"] == "/shop/products/$id"
        })
        .context("packaged Next.js graph omitted the App Router product route")?;
    if product_route["properties"]["canonical_identity"]["route_groups"] != json!(["(shop)"]) {
        bail!("packaged Next.js product route lost its route-group identity");
    }
    let intercepted_route = framework_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "route"
                && node["properties"]["canonical_identity"]["route_pattern"] == "/shop/photo/$slug*"
        })
        .context("packaged Next.js graph omitted the intercepting route")?;
    if intercepted_route["properties"]["canonical_identity"]["parallel_slots"] != json!(["@modal"])
        || intercepted_route["properties"]["canonical_identity"]["intercepting_segments"]
            != json!(["(.)photo"])
    {
        bail!("packaged Next.js intercepting route lost its parallel/intercept identity");
    }
    let framework_component = |name: &str| {
        framework_nodes
            .iter()
            .copied()
            .find(|node| node["kind"] == "component" && node["display_name"] == name)
    };
    let product_component = framework_component("Product")
        .context("packaged Next.js graph omitted the product component")?;
    let client_component = framework_component("ClientPanel")
        .context("packaged Next.js graph omitted the client component")?;
    let lazy_component = framework_component("LazyPanel")
        .context("packaged Next.js graph omitted the dynamic component")?;
    let get_component =
        framework_component("GET").context("packaged Next.js graph omitted the route handler")?;
    let product_route_id = product_route["id"]
        .as_str()
        .context("packaged Next.js product route omitted its ID")?
        .to_owned();
    let product_component_id = product_component["id"]
        .as_str()
        .context("packaged Next.js product component omitted its ID")?
        .to_owned();
    let client_component_id = client_component["id"]
        .as_str()
        .context("packaged Next.js client component omitted its ID")?
        .to_owned();
    let lazy_component_id = lazy_component["id"]
        .as_str()
        .context("packaged Next.js dynamic component omitted its ID")?
        .to_owned();
    let get_component_id = get_component["id"]
        .as_str()
        .context("packaged Next.js route handler omitted its ID")?
        .to_owned();
    let framework_edge = |kind: &str, source: &str, target: &str| {
        framework_edges.iter().copied().find(|edge| {
            edge["kind"] == kind && edge["source"] == source && edge["target"] == target
        })
    };
    let route_render = framework_edge("renders", &product_route_id, &product_component_id)
        .context("packaged Next.js graph omitted route-to-component rendering")?;
    let client_boundary = framework_edge(
        "client_boundary",
        &product_component_id,
        &client_component_id,
    )
    .context("packaged Next.js graph omitted its directive-backed client boundary")?;
    let server_boundary =
        framework_edge("server_boundary", &get_component_id, &get_component_id)
            .context("packaged Next.js graph omitted its directive-backed server boundary")?;
    let dynamic_render = framework_edge("renders", &product_component_id, &lazy_component_id)
        .context("packaged Next.js graph omitted its literal next/dynamic dependency")?;
    let dynamic_occurrence = |edge: &Value| {
        evidence.iter().find(|item| {
            item["owner_type"] == "edge"
                && item["owner_id"] == edge["id"]
                && item["ordinal"].as_u64() == Some(0)
        })
    };
    if !route_render["condition"]
        .to_string()
        .contains("next.runtime")
        || !route_render["condition"].to_string().contains("next.cache")
        || !client_boundary["condition"]
            .to_string()
            .contains("use client")
        || !server_boundary["condition"]
            .to_string()
            .contains("use server")
        || dynamic_occurrence(dynamic_render)
            .is_none_or(|item| item["properties"]["occurrence_kind"] != "next_dynamic_render")
    {
        bail!("packaged Next.js graph lost directive, runtime, cache, or dynamic evidence");
    }
    let unresolved_dynamic = framework_edges
        .iter()
        .copied()
        .find(|edge| {
            edge["kind"] == "renders"
                && edge["source"] == product_component_id
                && edge["resolution_status"] == "unresolved"
        })
        .context("packaged Next.js graph silently omitted computed next/dynamic")?;
    let unresolved_target = unresolved_dynamic["target"]
        .as_str()
        .and_then(|target| nodes_by_id.get(target))
        .context("packaged Next.js computed dynamic target is missing")?;
    let unresolved_site = unresolved_dynamic["site_id"]
        .as_str()
        .and_then(|site_id| {
            framework_sites
                .iter()
                .copied()
                .find(|site| site["id"] == site_id)
        })
        .context("packaged Next.js computed dynamic site is missing")?;
    if unresolved_dynamic["precision"] != "heuristic"
        || unresolved_site["reason"]
            .as_str()
            .is_none_or(|reason| reason.is_empty())
        || unresolved_target["kind"] != "unknown_target"
    {
        bail!("packaged Next.js computed dynamic target was not retained as unresolved");
    }

    for (edge, label, require_exact_why_edge) in [
        (route_render, "route render", true),
        (client_boundary, "client boundary", false),
    ] {
        let edge_id = edge["id"]
            .as_str()
            .with_context(|| format!("packaged Next.js {label} edge omitted its ID"))?;
        let source_selector = format!(
            "id:{}",
            edge["source"]
                .as_str()
                .with_context(|| format!("packaged Next.js {label} edge omitted its source"))?
        );
        let target_selector = format!(
            "id:{}",
            edge["target"]
                .as_str()
                .with_context(|| format!("packaged Next.js {label} edge omitted its target"))?
        );
        let query_contains_edge = |query: &Value| {
            query["data"]["steps"].as_array().is_some_and(|steps| {
                steps.iter().any(|step| {
                    step["edge"]["id"] == edge_id
                        && step["edge"]["phase"] == "semantic"
                        && step["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["kind"] == "semantic"
                                    && item["extractor"] == "next-static-adapter"
                            })
                        })
                })
            })
        };
        let deps = packaged_web_query(
            executable,
            store,
            &["deps", &source_selector, "--all", "--json"],
            &format!("query packaged Next.js {label} dependencies"),
        )?;
        let dependents = packaged_web_query(
            executable,
            store,
            &["dependents", &target_selector, "--all", "--json"],
            &format!("query packaged Next.js {label} dependents"),
        )?;
        let why = packaged_web_query(
            executable,
            store,
            &["why", &source_selector, &target_selector, "--json"],
            &format!("explain packaged Next.js {label}"),
        )?;
        if !query_contains_edge(&deps)
            || !query_contains_edge(&dependents)
            || why["data"]["path_found"] != true
            || (require_exact_why_edge && !query_contains_edge(&why))
        {
            bail!("packaged Web queries lost the Next.js {label} edge or its evidence");
        }
    }

    let astro_nodes: Vec<_> = all_framework_nodes
        .iter()
        .copied()
        .filter(|node| node["properties"]["framework"] == "astro")
        .collect();
    let astro_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "astro-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "astro"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let astro_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "astro-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "astro"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let astro_sites: Vec<_> = all_framework_sites
        .iter()
        .copied()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| astro_site_ids.contains(id))
        })
        .collect();
    let astro_edges: Vec<_> = all_framework_edges
        .iter()
        .copied()
        .filter(|edge| {
            edge["id"]
                .as_str()
                .is_some_and(|id| astro_edge_ids.contains(id))
        })
        .collect();
    let astro_kinds: BTreeSet<_> = astro_edges
        .iter()
        .filter_map(|edge| edge["kind"].as_str())
        .collect();
    if astro_kinds
        != BTreeSet::from([
            "client_boundary",
            "handled_by",
            "hydrates",
            "loads",
            "renders",
            "route_entry",
            "server_boundary",
        ])
    {
        bail!("packaged Astro graph lost its route/render/hydration/resource vocabulary");
    }
    let astro_component = |source_path: &str, environment: &str| {
        astro_nodes.iter().copied().find(|node| {
            node["kind"] == "component"
                && node["properties"]["source_path"] == source_path
                && node["properties"]["environment"] == environment
        })
    };
    let astro_page = astro_component("apps/astro-app/src/pages/blog/[slug].astro", "server")
        .context("packaged Astro graph omitted its page component")?;
    let astro_card = astro_component("apps/astro-app/src/components/Card.astro", "server")
        .context("packaged Astro graph omitted its imported local component")?;
    let astro_alternative =
        astro_component("apps/astro-app/src/components/Alternative.astro", "server")
            .context("packaged Astro graph omitted its dynamic alternative component")?;
    let astro_interactive_browser =
        astro_component("apps/astro-app/src/components/Interactive.tsx", "browser")
            .context("packaged Astro graph omitted its browser component identity")?;
    let astro_route = astro_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "route"
                && node["properties"]["canonical_identity"]["route_pattern"] == "/docs/blog/$slug"
        })
        .context("packaged Astro graph omitted its filesystem page route")?;
    let astro_page_id = astro_page["id"]
        .as_str()
        .context("packaged Astro page omitted its ID")?;
    let astro_card_id = astro_card["id"]
        .as_str()
        .context("packaged Astro card omitted its ID")?;
    let astro_alternative_id = astro_alternative["id"]
        .as_str()
        .context("packaged Astro alternative omitted its ID")?;
    let astro_interactive_browser_id = astro_interactive_browser["id"]
        .as_str()
        .context("packaged Astro browser component omitted its ID")?;
    let astro_route_id = astro_route["id"]
        .as_str()
        .context("packaged Astro route omitted its ID")?;
    let astro_card_render = astro_edges
        .iter()
        .copied()
        .find(|edge| {
            edge["kind"] == "renders"
                && edge["source"] == astro_page_id
                && edge["target"] == astro_card_id
                && evidence.iter().any(|item| {
                    item["owner_type"] == "edge"
                        && item["owner_id"] == edge["id"]
                        && item["ordinal"].as_u64() == Some(0)
                        && item["properties"]["occurrence_kind"] == "astro_component_render"
                })
        })
        .context("packaged Astro graph omitted its exact imported component render")?;
    if astro_card_render["resolution_status"] != "resolved"
        || astro_card_render["precision"] != "exact"
    {
        bail!("packaged Astro imported component render is not exact");
    }
    let astro_route_render = astro_edges
        .iter()
        .copied()
        .find(|edge| {
            edge["kind"] == "renders"
                && edge["source"] == astro_route_id
                && edge["target"] == astro_page_id
                && evidence.iter().any(|item| {
                    item["owner_type"] == "edge"
                        && item["owner_id"] == edge["id"]
                        && item["ordinal"].as_u64() == Some(0)
                        && item["properties"]["occurrence_kind"] == "astro_route_render"
                })
        })
        .context("packaged Astro graph omitted its route-to-page render")?;
    let hydration_sites: Vec<_> = astro_sites
        .iter()
        .copied()
        .filter(|site| site["kind"] == "hydrates")
        .collect();
    if hydration_sites.len() != 3
        || hydration_sites.iter().any(|site| {
            site["resolution_status"] != "resolved"
                || site["precision"] != "exact"
                || site["target_ids"] != json!([astro_interactive_browser_id])
                || !site["condition"].to_string().contains("client:")
                || !site["condition"].to_string().contains("browser")
        })
        || astro_edges
            .iter()
            .filter(|edge| edge["kind"] == "client_boundary")
            .count()
            != 3
        || !astro_edges.iter().any(|edge| {
            edge["kind"] == "server_boundary"
                && edge["source"] == astro_page_id
                && edge["condition"].to_string().contains("server:defer")
        })
    {
        bail!("packaged Astro graph lost directive-backed hydration or defer boundaries");
    }
    let dynamic_astro = astro_sites
        .iter()
        .copied()
        .find(|site| site["kind"] == "renders" && site["specifier"] == "Dynamic")
        .context("packaged Astro graph omitted its closed dynamic component flow")?;
    let dynamic_targets: BTreeSet<_> = dynamic_astro["target_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if dynamic_astro["resolution_status"] != "candidates"
        || dynamic_astro["precision"] != "overapprox"
        || dynamic_targets != BTreeSet::from([astro_card_id, astro_alternative_id])
    {
        bail!("packaged Astro dynamic component flow lost its closed candidate set");
    }
    let missing_astro = astro_sites
        .iter()
        .copied()
        .find(|site| site["kind"] == "renders" && site["specifier"] == "Missing")
        .context("packaged Astro graph silently omitted a missing component import")?;
    if missing_astro["resolution_status"] != "unresolved"
        || missing_astro["reason"].as_str().is_none_or(str::is_empty)
        || missing_astro["target_ids"]
            .as_array()
            .and_then(|targets| targets.first())
            .and_then(Value::as_str)
            .and_then(|target| nodes_by_id.get(target))
            .is_none_or(|target| target["kind"] != "unknown_target")
    {
        bail!("packaged Astro missing component did not remain unresolved");
    }
    let broken_directive = astro_sites
        .iter()
        .copied()
        .find(|site| site["reason"] == "multiple_astro_environment_directives")
        .context("packaged Astro graph silently omitted conflicting environment directives")?;
    if broken_directive["resolution_status"] != "unresolved"
        || broken_directive["target_ids"]
            .as_array()
            .and_then(|targets| targets.first())
            .and_then(Value::as_str)
            .and_then(|target| nodes_by_id.get(target))
            .is_none_or(|target| target["kind"] != "unknown_target")
    {
        bail!("packaged Astro conflicting directives did not remain unresolved");
    }
    let asset_load = astro_sites
        .iter()
        .copied()
        .find(|site| site["kind"] == "loads" && site["specifier"] == "../../assets/hero.svg")
        .context("packaged Astro graph omitted its static asset load")?;
    let asset_target = asset_load["target_ids"]
        .as_array()
        .and_then(|targets| targets.first())
        .and_then(Value::as_str)
        .and_then(|target| nodes_by_id.get(target))
        .context("packaged Astro asset load target is missing")?;
    let collection_load = astro_sites
        .iter()
        .copied()
        .find(|site| site["kind"] == "loads" && site["specifier"] == "astro:content/posts")
        .context("packaged Astro graph omitted getCollection")?;
    let entry_load = astro_sites
        .iter()
        .copied()
        .find(|site| site["kind"] == "loads" && site["specifier"] == "astro:content/posts/one")
        .context("packaged Astro graph omitted getEntry")?;
    if asset_target["kind"] != "file"
        || asset_target["properties"]["path"] != "apps/astro-app/src/assets/hero.svg"
        || collection_load["resolution_status"] != "candidates"
        || collection_load["target_ids"].as_array().map(Vec::len) != Some(2)
        || entry_load["resolution_status"] != "resolved"
    {
        bail!("packaged Astro resource graph lost static asset or content targets");
    }
    let astro_handler = astro_edges
        .iter()
        .copied()
        .find(|edge| edge["kind"] == "handled_by")
        .context("packaged Astro graph omitted its endpoint handler")?;
    if astro_handler["target"]
        .as_str()
        .and_then(|target| nodes_by_id.get(target))
        .is_none_or(|target| target["kind"] != "symbol")
        || !astro_handler["condition"].to_string().contains("GET")
    {
        bail!("packaged Astro endpoint handler lost its exact method symbol");
    }

    let astro_edge_id = astro_route_render["id"]
        .as_str()
        .context("packaged Astro render edge omitted its ID")?;
    let astro_source_selector = format!("id:{astro_route_id}");
    let astro_target_selector = format!("id:{astro_page_id}");
    let astro_query_contains_edge = |query: &Value| {
        query["data"]["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["edge"]["id"] == astro_edge_id
                    && step["edge"]["phase"] == "semantic"
                    && step["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["kind"] == "semantic"
                                && item["extractor"] == "astro-static-adapter"
                        })
                    })
            })
        })
    };
    let astro_deps = packaged_web_query(
        executable,
        store,
        &["deps", &astro_source_selector, "--all", "--json"],
        "query packaged Astro render dependencies",
    )?;
    let astro_why = packaged_web_query(
        executable,
        store,
        &[
            "why",
            &astro_source_selector,
            &astro_target_selector,
            "--json",
        ],
        "explain packaged Astro render",
    )?;
    if !astro_query_contains_edge(&astro_deps)
        || astro_why["data"]["path_found"] != true
        || !astro_query_contains_edge(&astro_why)
    {
        bail!("packaged Web queries lost the Astro render edge or its evidence");
    }

    let tanstack_nodes: Vec<_> = all_framework_nodes
        .iter()
        .copied()
        .filter(|node| node["properties"]["framework"] == "tanstack-router")
        .collect();
    let tanstack_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "tanstack-router-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "tanstack-router"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let tanstack_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "tanstack-router-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "tanstack-router"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let tanstack_sites: Vec<_> = all_framework_sites
        .iter()
        .copied()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| tanstack_site_ids.contains(id))
        })
        .collect();
    let tanstack_edges: Vec<_> = all_framework_edges
        .iter()
        .copied()
        .filter(|edge| {
            edge["id"]
                .as_str()
                .is_some_and(|id| tanstack_edge_ids.contains(id))
        })
        .collect();
    let tanstack_kinds: BTreeSet<_> = tanstack_edges
        .iter()
        .filter_map(|edge| edge["kind"].as_str())
        .collect();
    if tanstack_kinds
        != BTreeSet::from([
            "before_load",
            "loads",
            "masks_to",
            "navigates_to",
            "parent_route",
            "renders",
            "route_entry",
        ])
    {
        bail!("packaged TanStack Router graph lost its typed route vocabulary");
    }
    let tanstack_route = |pattern: &str, route_kind: &str| {
        tanstack_nodes.iter().copied().find(|node| {
            node["kind"] == "route"
                && node["properties"]["route_pattern"] == pattern
                && node["properties"]["route_kind"] == route_kind
        })
    };
    let tanstack_code_root = tanstack_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "route"
                && node["properties"]["route_pattern"] == "/router"
                && node["properties"]["route_kind"] == "tanstack-code-root-route"
                && node["properties"]["source_path"] == "apps/router/src/code-routes.tsx"
        })
        .context("packaged TanStack Router graph omitted its code root")?;
    let tanstack_code_child = tanstack_route("/router/code", "tanstack-code-route")
        .context("packaged TanStack Router graph omitted its registered code child")?;
    tanstack_route("/router", "tanstack-file-root-route")
        .context("packaged TanStack Router graph omitted its file root")?;
    tanstack_route("/router/posts", "tanstack-lazy-file-route")
        .context("packaged TanStack Router graph omitted its lazy file route")?;
    tanstack_route("/router/virtual", "tanstack-virtual-route")
        .context("packaged TanStack Router graph omitted its virtual route")?;
    if tanstack_nodes.iter().any(|node| {
        node["kind"] == "route" && node["properties"]["route_pattern"] == "/router/orphan"
    }) {
        bail!("packaged TanStack Router graph promoted an unregistered declaration");
    }
    let tanstack_code_root_id = tanstack_code_root["id"]
        .as_str()
        .context("packaged TanStack Router code root omitted its ID")?;
    let tanstack_code_child_id = tanstack_code_child["id"]
        .as_str()
        .context("packaged TanStack Router code child omitted its ID")?;
    let code_parent_edges: Vec<_> = tanstack_edges
        .iter()
        .copied()
        .filter(|edge| {
            edge["kind"] == "parent_route"
                && edge["source"] == tanstack_code_child_id
                && edge["target"] == tanstack_code_root_id
        })
        .collect();
    let code_parent_occurrences: BTreeSet<_> = code_parent_edges
        .iter()
        .filter_map(|edge| {
            evidence.iter().find(|item| {
                item["owner_type"] == "edge"
                    && item["owner_id"] == edge["id"]
                    && item["ordinal"].as_u64() == Some(0)
            })
        })
        .filter_map(|item| item["properties"]["occurrence_kind"].as_str())
        .collect();
    if code_parent_occurrences
        != BTreeSet::from([
            "tanstack_add_children_registration",
            "tanstack_declared_parent",
        ])
        || !tanstack_sites
            .iter()
            .any(|site| site["kind"] == "parent_route" && site["resolution_status"] == "candidates")
        || !tanstack_sites.iter().any(|site| {
            site["kind"] == "parent_route"
                && site["resolution_status"] == "unresolved"
                && site["reason"] == "tanstack_runtime_child_registration"
        })
        || tanstack_sites.iter().any(|site| {
            matches!(site["kind"].as_str(), Some("navigates_to" | "masks_to"))
                && site["resolution_status"] != "resolved"
        })
    {
        bail!(
            "packaged TanStack Router graph lost registration, candidate, unresolved, or navigation evidence"
        );
    }
    let tanstack_source_selector = format!("id:{tanstack_code_child_id}");
    let tanstack_deps = packaged_web_query(
        executable,
        store,
        &["deps", &tanstack_source_selector, "--all", "--json"],
        "query packaged TanStack Router parent dependencies",
    )?;
    let queried_parent_edges: BTreeSet<_> = tanstack_deps["data"]["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|step| step["edge"]["id"].as_str())
        .filter(|id| code_parent_edges.iter().any(|edge| edge["id"] == *id))
        .collect();
    if queried_parent_edges.len() != 2 {
        bail!("packaged Web queries lost TanStack Router declared/registered parent evidence");
    }

    let start_nodes: Vec<_> = all_framework_nodes
        .iter()
        .copied()
        .filter(|node| node["properties"]["framework"] == "tanstack-start")
        .collect();
    let start_site_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "site"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "tanstack-start-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "tanstack-start"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let start_edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["ordinal"].as_u64() == Some(0)
                && item["kind"] == "semantic"
                && item["extractor"] == "tanstack-start-static-adapter"
                && item["extractor_version"] == "0.1.0"
                && item["properties"]["framework"] == "tanstack-start"
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let start_sites: Vec<_> = all_framework_sites
        .iter()
        .copied()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| start_site_ids.contains(id))
        })
        .collect();
    let start_edges: Vec<_> = all_framework_edges
        .iter()
        .copied()
        .filter(|edge| {
            edge["id"]
                .as_str()
                .is_some_and(|id| start_edge_ids.contains(id))
        })
        .collect();
    let start_node_kinds: BTreeSet<_> = start_nodes
        .iter()
        .filter_map(|node| node["kind"].as_str())
        .collect();
    if start_node_kinds != BTreeSet::from(["component", "middleware", "route", "server_function"]) {
        bail!("packaged TanStack Start graph lost its route/RPC/middleware vocabulary");
    }

    let start_server_function = start_nodes
        .iter()
        .copied()
        .find(|node| node["kind"] == "server_function" && node["display_name"] == "getAccount")
        .context("packaged TanStack Start graph omitted getAccount")?;
    let start_account_route = start_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "route" && node["properties"]["route_pattern"] == "/account/$accountId"
        })
        .context("packaged TanStack Start graph omitted the account route")?;
    let start_public_route = start_nodes
        .iter()
        .copied()
        .find(|node| node["kind"] == "route" && node["properties"]["route_pattern"] == "/public")
        .context("packaged TanStack Start graph omitted the break-out route")?;
    let start_account_component = start_nodes
        .iter()
        .copied()
        .find(|node| node["kind"] == "component" && node["display_name"] == "AccountPage")
        .context("packaged TanStack Start graph omitted AccountPage")?;
    let start_middleware = |name: &str| {
        start_nodes
            .iter()
            .copied()
            .find(|node| node["kind"] == "middleware" && node["display_name"] == name)
    };
    let auth_middleware = start_middleware("authMiddleware")
        .context("packaged TanStack Start graph omitted authMiddleware")?;
    let audit_middleware = start_middleware("auditMiddleware")
        .context("packaged TanStack Start graph omitted auditMiddleware")?;
    let account_middleware = start_middleware("accountRouteMiddleware")
        .context("packaged TanStack Start graph omitted accountRouteMiddleware")?;
    let root_middleware = start_middleware("rootMiddleware")
        .context("packaged TanStack Start graph omitted rootMiddleware")?;
    let root_audit_middleware = start_middleware("rootAuditMiddleware")
        .context("packaged TanStack Start graph omitted rootAuditMiddleware")?;
    let pathless_audit_middleware = start_middleware("pathlessAuditMiddleware")
        .context("packaged TanStack Start graph omitted pathlessAuditMiddleware")?;
    let breakout_middleware = start_nodes
        .iter()
        .copied()
        .find(|node| {
            node["kind"] == "middleware"
                && node["properties"]["middleware_inheritance"] == "break-out"
        })
        .context("packaged TanStack Start graph omitted its middleware break-out boundary")?;
    if start_server_function["properties"]["http_method"] != "GET"
        || !start_server_function["properties"]["production_rpc_id"].is_null()
        || start_server_function["properties"]["production_rpc_id_status"] != "build-unobserved"
        || start_server_function["properties"]["build_boundary_reason"]
            != "tanstack_start_internal_virtual_module_unobserved"
        || start_server_function["properties"]["handler_definition_id"]
            .as_str()
            .is_none_or(str::is_empty)
        || start_server_function["properties"]["validator_definition_id"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        bail!("packaged TanStack Start server function guessed or lost RPC metadata");
    }

    let start_server_function_id = start_server_function["id"]
        .as_str()
        .context("packaged TanStack Start server function omitted its ID")?;
    let start_account_route_id = start_account_route["id"]
        .as_str()
        .context("packaged TanStack Start account route omitted its ID")?;
    let start_public_route_id = start_public_route["id"]
        .as_str()
        .context("packaged TanStack Start public route omitted its ID")?;
    let start_account_component_id = start_account_component["id"]
        .as_str()
        .context("packaged TanStack Start account component omitted its ID")?;
    let handled_by = start_edges
        .iter()
        .copied()
        .find(|edge| edge["kind"] == "handled_by" && edge["source"] == start_server_function_id)
        .context("packaged TanStack Start graph omitted its server handler")?;
    let start_handler_id = handled_by["target"]
        .as_str()
        .context("packaged TanStack Start handler edge omitted its target")?;
    if nodes_by_id
        .get(start_handler_id)
        .is_none_or(|node| node["display_name"] != "accountHandler")
    {
        bail!("packaged TanStack Start server handler lost its TypeScript definition")
    }

    let rpc_sources: BTreeSet<_> = start_edges
        .iter()
        .filter(|edge| edge["kind"] == "rpc_call" && edge["target"] == start_server_function_id)
        .filter_map(|edge| edge["source"].as_str())
        .collect();
    if rpc_sources != BTreeSet::from([start_account_route_id, start_account_component_id]) {
        bail!("packaged TanStack Start graph lost route/component RPC calls");
    }
    let middleware_targets = |source: &str| -> BTreeSet<&str> {
        start_edges
            .iter()
            .filter(|edge| edge["kind"] == "uses_middleware" && edge["source"] == source)
            .filter_map(|edge| edge["target"].as_str())
            .collect()
    };
    let auth_middleware_id = auth_middleware["id"]
        .as_str()
        .context("packaged TanStack Start auth middleware omitted its ID")?;
    let audit_middleware_id = audit_middleware["id"]
        .as_str()
        .context("packaged TanStack Start audit middleware omitted its ID")?;
    let account_middleware_id = account_middleware["id"]
        .as_str()
        .context("packaged TanStack Start account middleware omitted its ID")?;
    let root_middleware_id = root_middleware["id"]
        .as_str()
        .context("packaged TanStack Start root middleware omitted its ID")?;
    let root_audit_middleware_id = root_audit_middleware["id"]
        .as_str()
        .context("packaged TanStack Start root audit middleware omitted its ID")?;
    let pathless_audit_middleware_id = pathless_audit_middleware["id"]
        .as_str()
        .context("packaged TanStack Start pathless audit middleware omitted its ID")?;
    let breakout_middleware_id = breakout_middleware["id"]
        .as_str()
        .context("packaged TanStack Start break-out middleware omitted its ID")?;
    if middleware_targets(start_server_function_id)
        != BTreeSet::from([auth_middleware_id, audit_middleware_id])
        || middleware_targets(start_account_route_id)
            != BTreeSet::from([
                account_middleware_id,
                auth_middleware_id,
                pathless_audit_middleware_id,
                root_middleware_id,
                root_audit_middleware_id,
            ])
        || middleware_targets(start_public_route_id)
            != BTreeSet::from([
                breakout_middleware_id,
                root_middleware_id,
                root_audit_middleware_id,
            ])
    {
        bail!("packaged TanStack Start graph lost direct, inherited, or break-out middleware");
    }
    let start_occurrence = |site: &&Value| {
        site["id"]
            .as_str()
            .and_then(|site_id| {
                evidence.iter().find(|item| {
                    item["owner_type"] == "site"
                        && item["owner_id"] == site_id
                        && item["ordinal"].as_u64() == Some(0)
                })
            })
            .and_then(|item| item["properties"]["occurrence_kind"].as_str())
    };
    if !start_sites.iter().any(|site| {
        site["kind"] == "uses_middleware"
            && site["source"] == start_account_route_id
            && start_occurrence(site) == Some("tanstack_start_inherited_pathless_middleware")
            && site["condition"].to_string().contains("_authenticated")
    }) || !start_sites.iter().any(|site| {
        site["kind"] == "uses_middleware"
            && site["source"] == start_public_route_id
            && start_occurrence(site) == Some("tanstack_start_middleware_breakout")
            && site["condition"].to_string().contains("break-out")
    }) {
        bail!("packaged TanStack Start graph lost pathless or break-out occurrence evidence");
    }
    if !graph["diagnostics"].as_array().is_some_and(|diagnostics| {
        diagnostics.iter().any(|diagnostic| {
            diagnostic["code"] == "web.tanstack_start_build_rpc_id_unobserved"
                && diagnostic["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("were not guessed"))
        })
    }) {
        bail!("packaged TanStack Start graph did not expose its build-only RPC ID boundary");
    }

    let start_component_selector = format!("id:{start_account_component_id}");
    let start_handler_selector = format!("id:{start_handler_id}");
    let start_why = packaged_web_query(
        executable,
        store,
        &[
            "why",
            &start_component_selector,
            &start_handler_selector,
            "--json",
        ],
        "explain packaged TanStack Start client-to-handler RPC path",
    )?;
    let why_steps = start_why["data"]["steps"]
        .as_array()
        .context("packaged TanStack Start why query omitted its steps")?;
    let why_kinds: BTreeSet<_> = why_steps
        .iter()
        .filter_map(|step| step["edge"]["kind"].as_str())
        .collect();
    if start_why["data"]["path_found"] != true
        || !why_kinds.contains("rpc_call")
        || !why_kinds.contains("handled_by")
        || !why_steps.iter().all(|step| {
            step["evidence"].as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item["kind"] == "semantic"
                        && item["extractor"] == "tanstack-start-static-adapter"
                })
            })
        })
    {
        bail!("packaged Web queries lost the TanStack Start client-to-handler explanation");
    }
    let start_auth_selector = format!("id:{auth_middleware_id}");
    let middleware_why = packaged_web_query(
        executable,
        store,
        &[
            "why",
            &start_component_selector,
            &start_auth_selector,
            "--json",
        ],
        "explain packaged TanStack Start client-to-middleware RPC path",
    )?;
    let middleware_why_kinds: BTreeSet<_> = middleware_why["data"]["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|step| step["edge"]["kind"].as_str())
        .collect();
    if middleware_why["data"]["path_found"] != true
        || !middleware_why_kinds.contains("rpc_call")
        || !middleware_why_kinds.contains("uses_middleware")
    {
        bail!("packaged Web queries lost the TanStack Start client-to-middleware explanation");
    }
    let coverage = &graph["coverage"];
    let classified_sites = ["resolved", "candidates", "external", "unresolved"]
        .iter()
        .map(|field| coverage[*field].as_u64().unwrap_or_default())
        .sum::<u64>();
    if coverage["dependency_sites"].as_u64() != Some(sites.len() as u64)
        || coverage["dependency_sites"].as_u64() != Some(classified_sites)
    {
        bail!("packaged Web semantic export lost dependency-site coverage conservation");
    }
    if graph["coverage"]["completeness"]
        .as_array()
        .is_some_and(|levels| levels.iter().any(|level| level == "semantic-complete"))
    {
        bail!("packaged Web import/type/call slice claimed semantic-complete");
    }
    let framework_features = profile["features"]
        .as_array()
        .filter(|features| !features.is_empty())
        .context("packaged Web framework fixture lost its detected features")?;
    let framework_ledger: Vec<Value> = serde_json::from_str(
        profile["properties"]["web_framework_completeness_ledger"]
            .as_str()
            .context("packaged Web framework fixture omitted its completeness ledger")?,
    )?;
    let framework_issue_count = framework_ledger
        .iter()
        .map(|entry| entry["reasons"].as_array().map_or(0, Vec::len))
        .sum::<usize>();
    if profile["properties"]["web_framework_completeness_capability"]
        != "framework-semantic-completeness-v1"
        || profile["properties"]["web_framework_completeness_status"] != "incomplete"
        || profile["properties"]["web_framework_completeness_issue_count"]
            .as_str()
            .and_then(|value| value.parse::<usize>().ok())
            != Some(framework_issue_count)
        || framework_ledger.len() != framework_features.len()
        || framework_ledger.iter().any(|entry| {
            entry["status"] != "incomplete" || entry["reasons"].as_array().is_none_or(Vec::is_empty)
        })
        || !graph["coverage"]["reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons
                    .iter()
                    .any(|reason| reason == "framework_semantic_incomplete")
            })
    {
        bail!("packaged Web framework fixture lost its bounded completeness ledger");
    }
    if !edges.iter().any(|edge| {
        edge["phase"] == "source" && matches!(edge["kind"].as_str(), Some("imports" | "reexports"))
    }) {
        bail!("packaged Web semantic union overwrote the source import/re-export graph");
    }

    let deps = packaged_web_query(
        executable,
        store,
        &["deps", WEB_DEFINITION_SELECTOR, "--all", "--json"],
        "query the packaged Web definition graph",
    )?;
    let steps = deps["data"]["steps"]
        .as_array()
        .context("packaged Web definition query has no steps")?;
    let query_kinds: BTreeSet<_> = steps
        .iter()
        .filter_map(|step| step["edge"]["kind"].as_str())
        .collect();
    if !BTreeSet::from(["extends", "implements", "instantiates"]).is_subset(&query_kinds)
        || steps.iter().any(|step| {
            step["edge"]["phase"] != "semantic" || step["evidence"][0]["kind"] != "semantic"
        })
    {
        bail!("packaged Web definition query lost its exact relations or evidence: {deps}");
    }

    for (edge_kind, label) in [("type_uses", "type-use"), ("calls", "call")] {
        let exact_edge = dependency_edges
            .iter()
            .copied()
            .find(|edge| edge["kind"] == edge_kind && edge["resolution_status"] == "resolved")
            .with_context(|| {
                format!("packaged Web graph has no exact {label} edge for query verification")
            })?;
        let edge_id = exact_edge["id"]
            .as_str()
            .with_context(|| format!("packaged Web exact {label} edge omitted its ID"))?;
        let source_selector = format!(
            "id:{}",
            exact_edge["source"]
                .as_str()
                .with_context(|| format!("packaged Web exact {label} edge omitted its source"))?
        );
        let target_selector = format!(
            "id:{}",
            exact_edge["target"]
                .as_str()
                .with_context(|| format!("packaged Web exact {label} edge omitted its target"))?
        );
        let query_contains_edge = |query: &Value| {
            query["data"]["steps"].as_array().is_some_and(|steps| {
                steps.iter().any(|step| {
                    step["edge"]["id"] == edge_id
                        && step["edge"]["phase"] == "semantic"
                        && step["evidence"].as_array().is_some_and(|items| {
                            items.iter().any(|item| {
                                item["kind"] == "semantic"
                                    && item["extractor"] == "typescript-native-typechecker"
                            })
                        })
                })
            })
        };
        let semantic_deps = packaged_web_query(
            executable,
            store,
            &["deps", &source_selector, "--all", "--json"],
            &format!("query packaged Web exact {label} dependencies"),
        )?;
        let semantic_dependents = packaged_web_query(
            executable,
            store,
            &["dependents", &target_selector, "--all", "--json"],
            &format!("query packaged Web exact {label} dependents"),
        )?;
        let semantic_why = packaged_web_query(
            executable,
            store,
            &["why", &source_selector, &target_selector, "--json"],
            &format!("explain a packaged Web exact {label} dependency"),
        )?;
        if !query_contains_edge(&semantic_deps)
            || !query_contains_edge(&semantic_dependents)
            || semantic_why["data"]["path_found"] != true
            || !query_contains_edge(&semantic_why)
        {
            bail!("packaged Web queries lost the exact {label} edge or its evidence");
        }
    }

    let multiple_candidate_site = semantic_sites
        .iter()
        .find(|site| {
            site["kind"] == "call"
                && site["specifier"] == "conditionalTarget"
                && site["resolution_status"] == "candidates"
                && site["precision"] == "overapprox"
                && site["target_ids"]
                    .as_array()
                    .is_some_and(|targets| targets.len() == 2)
        })
        .context("packaged Web graph has no two-target closed local call candidate")?;
    let multiple_candidate_site_id = multiple_candidate_site["id"]
        .as_str()
        .context("packaged Web two-target candidate omitted its site ID")?;
    let multiple_candidate_edges: Vec<_> = dependency_edges
        .iter()
        .copied()
        .filter(|edge| edge["site_id"] == multiple_candidate_site_id)
        .collect();
    if multiple_candidate_edges.len() != 2
        || multiple_candidate_edges.iter().any(|edge| {
            edge["kind"] != "may_call"
                || edge["resolution_status"] != "candidates"
                || edge["precision"] != "overapprox"
        })
    {
        bail!("packaged Web two-target candidate lost its per-target may_call edges");
    }
    let multiple_candidate_source_selector = format!(
        "id:{}",
        multiple_candidate_site["source"]
            .as_str()
            .context("packaged Web two-target candidate omitted its source")?
    );
    let multiple_candidate_deps = packaged_web_query(
        executable,
        store,
        &[
            "deps",
            &multiple_candidate_source_selector,
            "--all",
            "--json",
        ],
        "query packaged Web two-target candidate dependencies",
    )?;
    let candidate_query_contains_edge = |query: &Value, edge_id: &str| {
        query["data"]["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["edge"]["id"] == edge_id
                    && step["edge"]["kind"] == "may_call"
                    && step["edge"]["phase"] == "semantic"
                    && step["edge"]["resolution_status"] == "candidates"
                    && step["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["kind"] == "semantic"
                                && item["extractor"] == "typescript-native-typechecker"
                                && item["properties"]["algorithm"]
                                    == "typescript-closed-local-call-flow-v1"
                        })
                    })
            })
        })
    };
    for candidate_edge in multiple_candidate_edges {
        let candidate_edge_id = candidate_edge["id"]
            .as_str()
            .context("packaged Web two-target candidate edge omitted its ID")?;
        let candidate_target_selector = format!(
            "id:{}",
            candidate_edge["target"]
                .as_str()
                .context("packaged Web two-target candidate edge omitted its target")?
        );
        let candidate_dependents = packaged_web_query(
            executable,
            store,
            &["dependents", &candidate_target_selector, "--all", "--json"],
            "query packaged Web two-target candidate dependents",
        )?;
        let candidate_why = packaged_web_query(
            executable,
            store,
            &[
                "why",
                &multiple_candidate_source_selector,
                &candidate_target_selector,
                "--json",
            ],
            "explain a packaged Web two-target candidate dependency",
        )?;
        if !candidate_query_contains_edge(&multiple_candidate_deps, candidate_edge_id)
            || !candidate_query_contains_edge(&candidate_dependents, candidate_edge_id)
            || candidate_why["data"]["path_found"] != true
            || !candidate_query_contains_edge(&candidate_why, candidate_edge_id)
        {
            bail!(
                "packaged Web queries lost a two-target may_call candidate edge or its algorithm evidence"
            );
        }
    }

    let unresolved_site = semantic_sites
        .iter()
        .find(|site| site["kind"] == "call" && site["resolution_status"] == "unresolved")
        .context("packaged Web graph has no unresolved call site")?;
    let unresolved_id = unresolved_site["id"]
        .as_str()
        .context("packaged Web unresolved call site omitted its ID")?;
    let unresolved = packaged_web_query(
        executable,
        store,
        &["unresolved", "--all", "--json"],
        "query packaged Web unresolved sites",
    )?;
    if !unresolved["data"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["site"]["id"] == unresolved_id
                && item["site"]["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
                && item["evidence"].as_array().is_some_and(|evidence| {
                    evidence.iter().any(|item| {
                        item["kind"] == "semantic"
                            && item["extractor"] == "typescript-native-typechecker"
                    })
                })
        })
    }) {
        bail!("packaged Web unresolved query lost its call site, reason, or evidence");
    }
    Ok(())
}

fn verify_packaged_web_semantic_complete(
    executable: &Path,
    store: &Path,
    fixture: &Path,
) -> Result<()> {
    let scan = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .output()
        .context("failed to scan the packaged pure TypeScript semantic-complete fixture")?;
    if !scan.status.success() {
        bail!(
            "packaged pure TypeScript semantic-complete scan failed: {}\n{}",
            String::from_utf8_lossy(&scan.stdout),
            String::from_utf8_lossy(&scan.stderr)
        );
    }
    let scan: Value = serde_json::from_slice(&scan.stdout)
        .context("packaged pure TypeScript semantic-complete scan returned invalid JSON")?;
    let coverage = &scan["coverage"];
    if scan["status"] != "completed"
        || coverage["project_code_executed"] != Value::Bool(false)
        || coverage["completeness"].as_array().is_none_or(|levels| {
            !levels.iter().any(|level| level == "syntax-complete")
                || !levels.iter().any(|level| level == "semantic-complete")
        })
        || coverage["reasons"]
            .as_array()
            .is_none_or(|reasons| !reasons.is_empty())
        || coverage["unresolved"].as_u64() != Some(0)
        || coverage["candidates"].as_u64().unwrap_or_default() == 0
        || coverage["external"].as_u64().unwrap_or_default() == 0
    {
        bail!("packaged pure TypeScript fixture did not satisfy semantic completeness: {scan}");
    }

    let exported = packaged_web_export_json(executable, store)?;
    let graph = exported["graph"]
        .as_object()
        .context("packaged pure TypeScript semantic-complete export has no graph")?;
    let profile = graph["profiles"]
        .as_array()
        .and_then(|profiles| profiles.iter().find(|profile| profile["language"] == "web"))
        .context("packaged pure TypeScript semantic-complete export has no Web profile")?;
    let properties = &profile["properties"];
    if !profile["features"].as_array().is_some_and(Vec::is_empty)
        || !matches!(
            properties["typescript_release_gate"].as_str(),
            Some("release-gate-pending" | "release-gate-verified")
        )
        || properties["typescript_typechecker_status"]
            != "definition-import-type-call-graph-emitted"
        || properties["typescript_definition_graph_status"] != "ready"
        || properties["typescript_semantic_graph_emission"]
            != "definition-import-type-call-graph-v2"
        || properties["typescript_semantic_diagnostics"] != "0"
        || properties["typescript_emitted_semantic_diagnostics"] != "0"
        || properties["typescript_semantic_issue_count"] != "0"
        || properties["web_framework_completeness_capability"]
            != "framework-semantic-completeness-v1"
        || properties["web_framework_completeness_status"] != "not-detected"
        || properties["web_framework_completeness_issue_count"] != "0"
        || properties["web_framework_completeness_ledger"] != "[]"
        || properties["project_code_executed"] != "false"
    {
        bail!(
            "packaged pure TypeScript fixture lost its semantic-completeness profile contract: {profile}"
        );
    }

    let semantic_site_ids: BTreeSet<_> = graph["evidence"]
        .as_array()
        .context("packaged pure TypeScript semantic-complete export has no evidence")?
        .iter()
        .filter(|evidence| {
            evidence["owner_type"] == "site"
                && evidence["ordinal"].as_u64() == Some(0)
                && evidence["kind"] == "semantic"
        })
        .filter_map(|evidence| evidence["owner_id"].as_str())
        .collect();
    let semantic_statuses: BTreeSet<_> = graph["sites"]
        .as_array()
        .context("packaged pure TypeScript semantic-complete export has no sites")?
        .iter()
        .filter(|site| {
            site["id"]
                .as_str()
                .is_some_and(|id| semantic_site_ids.contains(id))
        })
        .filter_map(|site| site["resolution_status"].as_str())
        .collect();
    if !semantic_statuses.contains("candidates") || !semantic_statuses.contains("external") {
        bail!(
            "packaged pure TypeScript semantic-complete fixture lost its allowed candidate/external sites"
        );
    }
    Ok(())
}

fn verify_packaged_web_framework_completeness(
    executable: &Path,
    verify_root: &Path,
    fixture: &Path,
) -> Result<()> {
    let framework_apps = [
        ("astro", "astro"),
        ("next", "next"),
        ("tanstack-router", "router"),
        ("tanstack-start", "start"),
    ];
    for (framework, selected_app) in framework_apps {
        let isolated_fixture = verify_root.join(format!("web-framework-{selected_app}"));
        copy_directory(fixture, &isolated_fixture)?;
        for (_, app) in framework_apps {
            if app != selected_app {
                fs::remove_dir_all(isolated_fixture.join("apps").join(app)).with_context(|| {
                    format!("failed to isolate the packaged {framework} fixture")
                })?;
            }
        }
        if matches!(framework, "astro" | "next") {
            fs::remove_dir_all(isolated_fixture.join("packages")).with_context(|| {
                format!("failed to isolate the packaged {framework} fixture dependencies")
            })?;
        }
        let store = verify_root.join(format!("web-framework-{selected_app}.db"));
        verify_packaged_web_framework_profile(executable, &store, &isolated_fixture, &[framework])?;
    }

    let store = verify_root.join("web-framework-complete.db");
    verify_packaged_web_framework_profile(
        executable,
        &store,
        fixture,
        &["astro", "next", "tanstack-router", "tanstack-start"],
    )?;

    let second_fixture = verify_root.join("web-framework-checkout-two");
    copy_directory(fixture, &second_fixture)?;
    let second_store = verify_root.join("web-framework-complete-two.db");
    verify_packaged_web_framework_profile(
        executable,
        &second_store,
        &second_fixture,
        &["astro", "next", "tanstack-router", "tanstack-start"],
    )?;
    verify_packaged_web_graph_exports_deterministic(executable, &store, &second_store)
}

fn verify_packaged_web_framework_profile(
    executable: &Path,
    store: &Path,
    fixture: &Path,
    expected_frameworks: &[&str],
) -> Result<()> {
    let scan = Command::new(executable)
        .arg("--store")
        .arg(store)
        .arg("scan")
        .arg(fixture)
        .arg("--json")
        .output()
        .context("failed to scan the packaged Web framework-complete fixture")?;
    if !scan.status.success() {
        bail!(
            "packaged Web framework-complete scan failed: {}\n{}",
            String::from_utf8_lossy(&scan.stdout),
            String::from_utf8_lossy(&scan.stderr)
        );
    }
    let scan: Value = serde_json::from_slice(&scan.stdout)
        .context("packaged Web framework-complete scan returned invalid JSON")?;
    let coverage = &scan["coverage"];
    let semantic_complete = expected_frameworks
        .iter()
        .all(|framework| matches!(*framework, "astro" | "next"));
    if scan["status"] != "completed"
        || coverage["project_code_executed"] != Value::Bool(false)
        || coverage["completeness"].as_array().is_none_or(|levels| {
            !levels.iter().any(|level| level == "syntax-complete")
                || levels.iter().any(|level| level == "semantic-complete") != semantic_complete
        })
        || coverage["reasons"].as_array().is_none_or(|reasons| {
            reasons
                .iter()
                .any(|reason| reason == "framework_semantic_incomplete")
                || (semantic_complete && !reasons.is_empty())
                || (!semantic_complete
                    && !reasons
                        .iter()
                        .any(|reason| reason == "unresolved_dependency_sites"))
        })
    {
        bail!("packaged Web framework fixture lost its completion gate: {scan}");
    }

    let exported = packaged_web_export_json(executable, store)?;
    let graph = exported["graph"]
        .as_object()
        .context("packaged Web framework-complete export has no graph")?;
    let profile = graph["profiles"]
        .as_array()
        .and_then(|profiles| profiles.iter().find(|profile| profile["language"] == "web"))
        .context("packaged Web framework-complete export has no Web profile")?;
    if profile["features"].as_array().is_none_or(|features| {
        features
            != &expected_frameworks
                .iter()
                .map(|framework| Value::String((*framework).to_owned()))
                .collect::<Vec<_>>()
    }) {
        bail!("packaged Web framework fixture lost detected framework order: {profile}");
    }
    let properties = &profile["properties"];
    let ledger: Vec<Value> = serde_json::from_str(
        properties["web_framework_completeness_ledger"]
            .as_str()
            .context("packaged Web framework fixture omitted its completeness ledger")?,
    )?;
    if properties["web_framework_completeness_capability"] != "framework-semantic-completeness-v1"
        || properties["web_framework_completeness_status"] != "complete"
        || properties["web_framework_completeness_issue_count"] != "0"
        || ledger.len() != expected_frameworks.len()
    {
        bail!("packaged Web framework fixture lost its complete capability ledger: {profile}");
    }
    for (entry, &framework) in ledger.iter().zip(expected_frameworks) {
        let specific = match framework {
            "astro" => "astro-component-render-hydration-v1",
            "next" => "next-route-component-boundary-v1",
            "tanstack-router" => "tanstack-router-typed-route-v1",
            "tanstack-start" => "tanstack-start-rpc-middleware-v1",
            _ => unreachable!(),
        };
        let required = entry["required_capabilities"]
            .as_array()
            .context("packaged Web framework ledger omitted required capabilities")?;
        let required_set = required
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        if entry["framework"] != framework
            || entry["status"] != "complete"
            || entry["reasons"]
                .as_array()
                .is_none_or(|reasons| !reasons.is_empty())
            || entry["emitted_capabilities"] != entry["required_capabilities"]
            || required_set
                != BTreeSet::from([
                    "framework-semantic-graph-v1",
                    specific,
                    "typescript-definition-import-type-call-graph-v2",
                ])
        {
            bail!("packaged Web framework ledger entry is incomplete: {entry}");
        }
    }
    if !semantic_complete
        && !graph["sites"].as_array().is_some_and(|sites| {
            sites.iter().any(|site| {
                site["resolution_status"] == "unresolved"
                    && site["reason"] == "function_value_dispatch"
            })
        })
    {
        bail!("packaged Web framework fixture lost its bounded dynamic-call reason");
    }
    for &framework in expected_frameworks {
        verify_packaged_web_framework_query(executable, store, graph, framework)?;
    }
    Ok(())
}

fn verify_packaged_web_framework_query(
    executable: &Path,
    store: &Path,
    graph: &serde_json::Map<String, Value>,
    framework: &str,
) -> Result<()> {
    let evidence = graph["evidence"]
        .as_array()
        .context("packaged Web framework graph has no evidence")?;
    let edge_ids: BTreeSet<_> = evidence
        .iter()
        .filter(|item| {
            item["owner_type"] == "edge"
                && item["kind"] == "semantic"
                && item["properties"]["framework"] == framework
                && item["properties"]["contract_version"] == "framework-semantic-graph-v1"
        })
        .filter_map(|item| item["owner_id"].as_str())
        .collect();
    let edge = graph["edges"]
        .as_array()
        .context("packaged Web framework graph has no edges")?
        .iter()
        .find(|edge| {
            edge["id"].as_str().is_some_and(|id| edge_ids.contains(id))
                && edge["phase"] == "semantic"
                && edge["resolution_status"] == "resolved"
        })
        .with_context(|| format!("packaged {framework} graph has no exact semantic edge"))?;
    let edge_id = edge["id"]
        .as_str()
        .context("packaged Web framework edge omitted its ID")?;
    let source_selector = format!(
        "id:{}",
        edge["source"]
            .as_str()
            .context("packaged Web framework edge omitted its source")?
    );
    let target_selector = format!(
        "id:{}",
        edge["target"]
            .as_str()
            .context("packaged Web framework edge omitted its target")?
    );
    let contains_edge = |query: &Value| {
        query["data"]["steps"].as_array().is_some_and(|steps| {
            steps.iter().any(|step| {
                step["edge"]["id"] == edge_id
                    && step["evidence"].as_array().is_some_and(|items| {
                        items.iter().any(|item| {
                            item["kind"] == "semantic"
                                && item["properties"]["framework"] == framework
                                && item["properties"]["contract_version"]
                                    == "framework-semantic-graph-v1"
                        })
                    })
            })
        })
    };
    let deps = packaged_web_query(
        executable,
        store,
        &["deps", &source_selector, "--all", "--json"],
        &format!("query packaged {framework} dependencies"),
    )?;
    let dependents = packaged_web_query(
        executable,
        store,
        &["dependents", &target_selector, "--all", "--json"],
        &format!("query packaged {framework} dependents"),
    )?;
    let why = packaged_web_query(
        executable,
        store,
        &["why", &source_selector, &target_selector, "--json"],
        &format!("explain a packaged {framework} dependency"),
    )?;
    if !contains_edge(&deps)
        || !contains_edge(&dependents)
        || why["data"]["path_found"] != true
        || !contains_edge(&why)
    {
        bail!("packaged Web queries lost the {framework} semantic edge or its evidence");
    }
    Ok(())
}

fn packaged_web_export_json(executable: &Path, store: &Path) -> Result<Value> {
    packaged_raw_export_json(
        executable,
        store,
        &[],
        "export the packaged Web semantic graph",
    )
}

fn packaged_raw_export_json(
    executable: &Path,
    store: &Path,
    filters: &[&str],
    action: &str,
) -> Result<Value> {
    let output_root = tempfile::tempdir().context("create packaged raw export directory")?;
    let output_name = "graph.json";
    let output = Command::new(executable)
        .current_dir(output_root.path())
        .arg("--store")
        .arg(store)
        .args(["export", "--format", "json"])
        .args(filters)
        .args(["--output", output_name])
        .output()
        .with_context(|| format!("failed to {action}"))?;
    if !output.status.success() || !output.stdout.is_empty() {
        bail!(
            "failed to {action}: {}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output_path = output_root.path().join(output_name);
    let bytes = fs::read(&output_path)
        .with_context(|| format!("read packaged raw export {}", output_path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{action} returned invalid JSON"))
}

fn packaged_web_query(
    executable: &Path,
    store: &Path,
    arguments: &[&str],
    action: &str,
) -> Result<Value> {
    let output = Command::new(executable)
        .arg("--store")
        .arg(store)
        .args(arguments)
        .output()
        .with_context(|| format!("failed to {action}"))?;
    if !output.status.success() {
        bail!(
            "failed to {action}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("{action} returned invalid JSON"))
}

fn packaged_web_export_text(executable: &Path, store: &Path, format: &str) -> Result<String> {
    packaged_raw_export_text(
        executable,
        store,
        format,
        &[],
        &format!("export packaged Web graph as {format}"),
    )
}

fn packaged_web_export_filtered_text(
    executable: &Path,
    store: &Path,
    format: &str,
    profile: &str,
    phase: &str,
) -> Result<String> {
    packaged_raw_export_text(
        executable,
        store,
        format,
        &["--phase", phase, "--profile", profile],
        &format!("export filtered packaged Web graph as {format}"),
    )
}

fn packaged_raw_export_text(
    executable: &Path,
    store: &Path,
    format: &str,
    filters: &[&str],
    action: &str,
) -> Result<String> {
    let output_root = tempfile::tempdir().context("create packaged raw export directory")?;
    let output_name = format!("graph.{format}");
    let output = Command::new(executable)
        .current_dir(output_root.path())
        .arg("--store")
        .arg(store)
        .args(["export", "--format", format])
        .args(filters)
        .arg("--output")
        .arg(&output_name)
        .output()
        .with_context(|| format!("failed to {action}"))?;
    if !output.status.success() || !output.stdout.is_empty() {
        bail!(
            "failed to {action}: {}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output_path = output_root.path().join(output_name);
    fs::read_to_string(&output_path)
        .with_context(|| format!("read packaged raw export {}", output_path.display()))
}

fn verify_packaged_web_graph_exports_deterministic(
    executable: &Path,
    first_store: &Path,
    second_store: &Path,
) -> Result<()> {
    let first = packaged_web_export_json(executable, first_store)?;
    let second = packaged_web_export_json(executable, second_store)?;
    if first["graph"] != second["graph"] {
        bail!("packaged Web semantic graph changed across checkout-equivalent roots");
    }
    for format in ["dot", "mermaid"] {
        let first = packaged_web_export_text(executable, first_store, format)?;
        let second = packaged_web_export_text(executable, second_store, format)?;
        if first != second {
            bail!("packaged Web {format} export changed across checkout-equivalent roots");
        }
    }
    Ok(())
}

fn verify_packaged_web_determinism(
    executable: &Path,
    first_store: &Path,
    second_store: &Path,
) -> Result<()> {
    let first = packaged_web_export_json(executable, first_store)?;
    let second = packaged_web_export_json(executable, second_store)?;
    if first["graph"] != second["graph"] {
        bail!("packaged Web semantic graph changed across checkout-equivalent roots");
    }
    let semantic_source = first["graph"]["edges"]
        .as_array()
        .and_then(|edges| {
            edges.iter().find(|edge| {
                edge["phase"] == "semantic"
                    && edge["kind"] == "calls"
                    && edge["resolution_status"] == "resolved"
            })
        })
        .and_then(|edge| edge["source"].as_str())
        .context("packaged Web graph has no exact call source")?;
    let source_selector = format!("id:{semantic_source}");
    let first_query = packaged_web_query(
        executable,
        first_store,
        &["deps", &source_selector, "--all", "--json"],
        "query the first packaged Web semantic graph",
    )?;
    let second_query = packaged_web_query(
        executable,
        second_store,
        &["deps", &source_selector, "--all", "--json"],
        "query the second packaged Web semantic graph",
    )?;
    if first_query["data"] != second_query["data"] {
        bail!("packaged Web semantic query changed across checkout-equivalent roots");
    }
    for format in ["dot", "mermaid"] {
        let first = packaged_web_export_text(executable, first_store, format)?;
        let second = packaged_web_export_text(executable, second_store, format)?;
        if first != second {
            bail!("packaged Web {format} export changed across checkout-equivalent roots");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_packaged_bounded_query(
    executable: &Path,
    release_root: &Path,
    first_checkout: &Path,
    first_store: &Path,
    second_checkout: &Path,
    second_store: &Path,
    target: &str,
    archive_sha256: &str,
) -> Result<BoundedQueryPackageSmokeReport> {
    let fixture_path = release_root.join(depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH);
    let query = fs::read_to_string(&fixture_path)
        .context("packaged bounded query smoke fixture is not valid UTF-8")?;
    if query != depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_QUERY {
        bail!("packaged bounded query smoke fixture differs from the compiled contract");
    }
    let run = |checkout: &Path, store: &Path, explain: bool| -> Result<std::process::Output> {
        let mut command = Command::new(executable);
        command
            .current_dir(checkout)
            .arg("--store")
            .arg(store)
            .args(["query", "--query", &query]);
        if explain {
            command.arg("--explain");
        }
        command.arg("--json");
        let output = command
            .output()
            .context("failed to run packaged bounded query")?;
        if !output.status.success() || !output.stderr.is_empty() {
            bail!(
                "packaged bounded query failed: status={:?}\n{}\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output)
    };

    let first_plan = run(first_checkout, first_store, true)?;
    let second_plan = run(second_checkout, second_store, true)?;
    let first_result = run(first_checkout, first_store, false)?;
    let second_result = run(second_checkout, second_store, false)?;
    if first_plan.stdout != second_plan.stdout || first_result.stdout != second_result.stdout {
        bail!("packaged bounded query changed across checkout-equivalent snapshots");
    }
    let plan: Value = serde_json::from_slice(&first_plan.stdout)
        .context("packaged query plan is invalid JSON")?;
    let result: Value = serde_json::from_slice(&first_result.stdout)
        .context("packaged query result is invalid JSON")?;
    let contract = depgraph_core::bounded_query_release_compatibility_contract();
    if plan["schema_version"] != contract.plan_schema_version
        || plan["contract_version"] != contract.language_contract_version
        || plan["limit_version"] != contract.limit_version
        || plan["admitted"] != Value::Bool(true)
        || result["schema_version"] != contract.result_schema_version
        || result["contract_version"] != contract.language_contract_version
        || result["rows"]
            .as_array()
            .is_none_or(|rows| !rows.is_empty())
        || result["plan_digest"] != plan["plan_digest"]
    {
        bail!("packaged bounded query output does not satisfy its release contract");
    }
    let plan_digest = plan["plan_digest"]
        .as_str()
        .context("packaged bounded query plan omitted its digest")?
        .to_owned();
    let result_digest = result["result_digest"]
        .as_str()
        .context("packaged bounded query result omitted its digest")?
        .to_owned();
    if !prefixed_lowercase_sha256(&plan_digest, "bounded-query-plan:sha256:")
        || !prefixed_lowercase_sha256(&result_digest, "bounded-query-result:sha256:")
    {
        bail!("packaged bounded query returned malformed plan/result digests");
    }
    let rendered = String::from_utf8(first_result.stdout.clone())
        .context("packaged bounded query result is not UTF-8")?;
    if rendered.contains("\"properties\"")
        || rendered.contains("\"detail\"")
        || rendered.contains(first_checkout.to_string_lossy().as_ref())
        || rendered.contains(second_checkout.to_string_lossy().as_ref())
    {
        bail!("packaged bounded query exposed a closed or checkout-local field");
    }

    let run_profile_plan = |checkout: &Path| -> Result<std::process::Output> {
        let output = Command::new(executable)
            .args(["profiles", "plan"])
            .arg(checkout)
            .arg("--json")
            .output()
            .context("failed to run packaged profile planner")?;
        if !output.status.success() || !output.stderr.is_empty() {
            bail!(
                "packaged profile planner failed: status={:?}\n{}\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output)
    };
    let first_profile_plan = run_profile_plan(first_checkout)?;
    let second_profile_plan = run_profile_plan(second_checkout)?;
    if first_profile_plan.stdout != second_profile_plan.stdout {
        bail!("packaged profile plan changed across checkout-equivalent repositories");
    }
    let profile_preview: Value = serde_json::from_slice(&first_profile_plan.stdout)
        .context("packaged profile plan is invalid JSON")?;
    let profile_contract = depgraph_core::profile_selection_release_compatibility_contract();
    if profile_preview["plan"]["contract_version"] != profile_contract.selection_contract_version
        || profile_preview["plan"]["input"]["limits"]["limit_version"]
            != profile_contract.limit_version
        || profile_preview["plan"]["input"]["contract_version"]
            != profile_contract.selection_contract_version
    {
        bail!("packaged profile plan output does not satisfy its release contract");
    }
    let profile_plan_digest = profile_preview["plan"]["plan_id"]
        .as_str()
        .filter(|value| prefixed_lowercase_sha256(value, "profile-selection-plan:sha256:"))
        .context("packaged profile plan omitted its canonical digest")?
        .to_owned();

    let report = BoundedQueryPackageSmokeReport {
        schema_version: BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION.to_owned(),
        target: target.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        contract,
        plan_digest,
        result_digest,
        canonical_output_sha256: hex::encode(Sha256::digest(&first_result.stdout)),
        profile_contract,
        profile_plan_digest,
        profile_canonical_output_sha256: hex::encode(Sha256::digest(&first_profile_plan.stdout)),
    };
    validate_bounded_query_package_smoke(&report, target, archive_sha256)?;
    Ok(report)
}

fn verify_release_metadata(extracted: &Path) -> Result<ReleaseManifest> {
    if fs::symlink_metadata(extracted)?.file_type().is_symlink() {
        bail!(
            "release root must not be a symlink: {}",
            extracted.display()
        );
    }
    for required in [
        "release-manifest.json",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "THIRD_PARTY_LICENSES.txt",
        "sbom.spdx.json",
        "schemas/depgraph-protocol-v1.schema.json",
        MCP_TOOL_SCHEMA_PATH,
        depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
        depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
    ] {
        let path = extracted.join(required);
        if !path.is_file()
            || fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("release archive is missing {required}");
        }
    }
    for schema in depgraph_core::cross_language_release_compatibility_contract().schemas {
        if !extracted.join(&schema.path).is_file() {
            bail!("release archive is missing {}", schema.path);
        }
    }
    let manifest: ReleaseManifest =
        serde_json::from_slice(&fs::read(extracted.join("release-manifest.json"))?)
            .context("release manifest is invalid")?;
    if manifest.release_version != VERSION
        || manifest.protocol_version != "1.0"
        || manifest.schema_version != "1.0"
        || manifest.compatibility != release_compatibility()
        || manifest.target.trim().is_empty()
    {
        bail!("release manifest has an incompatible release compatibility unit");
    }
    if manifest.license_expression != PROJECT_LICENSE_EXPRESSION {
        bail!("release manifest project license expression must be {PROJECT_LICENSE_EXPRESSION}");
    }
    if manifest.query_fixture.path != depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH {
        bail!("release manifest bounded query fixture path is incompatible");
    }
    let query_fixture =
        verify_release_artifact(extracted, &manifest.query_fixture, "bounded query fixture")?;
    if fs::read_to_string(query_fixture)? != depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_QUERY
        || format!("sha256:{}", manifest.query_fixture.sha256)
            != manifest.compatibility.bounded_query.fixture_sha256
    {
        bail!("release manifest bounded query fixture identity is incompatible");
    }
    let cross_language_contract = depgraph_core::cross_language_release_compatibility_contract();
    if manifest.cross_language_fixture.path != cross_language_contract.fixture_path
        || format!("sha256:{}", manifest.cross_language_fixture.sha256)
            != cross_language_contract.fixture_sha256
    {
        bail!("release manifest cross-language fixture identity is incompatible");
    }
    let cross_language_fixture = verify_release_artifact(
        extracted,
        &manifest.cross_language_fixture,
        "cross-language fixture",
    )?;
    if fs::read_to_string(cross_language_fixture)?
        != depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE
    {
        bail!("release manifest cross-language fixture differs from the compiled contract");
    }
    let declared_cross_language_schemas = manifest
        .cross_language_schemas
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if declared_cross_language_schemas.len() != cross_language_contract.schemas.len()
        || manifest.cross_language_schemas.len() != cross_language_contract.schemas.len()
    {
        bail!("release manifest cross-language schema closure is incomplete or duplicated");
    }
    for schema in &cross_language_contract.schemas {
        let artifact = declared_cross_language_schemas
            .get(schema.path.as_str())
            .with_context(|| format!("release manifest is missing {}", schema.path))?;
        if format!("sha256:{}", artifact.sha256) != schema.sha256 {
            bail!(
                "release manifest cross-language schema {} has an incompatible digest",
                schema.path
            );
        }
        verify_release_artifact(extracted, artifact, "cross-language schema")?;
    }
    if manifest.project_licenses.len() != PROJECT_LICENSES.len() {
        bail!("release manifest must contain exactly the project license files");
    }
    let project_licenses = manifest
        .project_licenses
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if project_licenses.len() != PROJECT_LICENSES.len() {
        bail!("release manifest contains a duplicate project license path");
    }
    for (path, expected) in PROJECT_LICENSES {
        let artifact = project_licenses
            .get(path)
            .with_context(|| format!("release manifest is missing project license {path}"))?;
        let verified = verify_release_artifact(extracted, artifact, "project license")?;
        if fs::read(&verified)? != *expected {
            bail!("release project license {path} differs from the declared source text");
        }
    }
    let expected_core_path = format!("bin/{}", executable_name("depgraph"));
    if manifest.core.path != expected_core_path {
        bail!("release manifest core path does not match {expected_core_path}");
    }
    let core = verify_release_artifact(extracted, &manifest.core, "core")?;
    let expected_core = verified_release_path(extracted, &expected_core_path, "expected core")?;
    if core != expected_core || !is_executable(&core)? {
        bail!("release manifest core must be the packaged executable");
    }
    let expected_mcp_server_path = format!("bin/{}", executable_name(MCP_SERVER_NAME));
    if manifest.mcp_server.version != VERSION
        || manifest.mcp_server.path != expected_mcp_server_path
        || manifest.mcp_server.sdk_name != MCP_SDK_NAME
        || manifest.mcp_server.sdk_version != MCP_SDK_VERSION
        || manifest.mcp_server.protocol_revision != MCP_PROTOCOL_REVISION
        || manifest.mcp_server.tool_contract_version != MCP_TOOL_CONTRACT_VERSION
        || manifest.mcp_server.operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
    {
        bail!("release manifest MCP server compatibility unit is incompatible");
    }
    let mcp_server = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.mcp_server.path.clone(),
            sha256: manifest.mcp_server.sha256.clone(),
        },
        "MCP server",
    )?;
    if !is_executable(&mcp_server)? {
        bail!("release manifest MCP server must be executable");
    }
    let expected_operation_runner_path =
        format!("libexec/{}", executable_name("depgraph-operation-runner"));
    if manifest.operation_runner.version != VERSION
        || manifest.operation_runner.operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
        || manifest.operation_runner.path != expected_operation_runner_path
    {
        bail!("release manifest operation runner metadata is incompatible");
    }
    let operation_runner = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.operation_runner.path.clone(),
            sha256: manifest.operation_runner.sha256.clone(),
        },
        "operation runner",
    )?;
    if !is_executable(&operation_runner)? {
        bail!("release manifest operation runner must be executable");
    }
    if manifest.schema.path != "schemas/depgraph-protocol-v1.schema.json" {
        bail!("release manifest schema path does not match the packaged protocol schema");
    }
    verify_release_artifact(extracted, &manifest.schema, "schema")?;
    if manifest.mcp_tool_schema.contract_version != MCP_TOOL_CONTRACT_VERSION
        || manifest.mcp_tool_schema.path != MCP_TOOL_SCHEMA_PATH
    {
        bail!("release manifest MCP tool schema compatibility unit is incompatible");
    }
    let mcp_tool_schema = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.mcp_tool_schema.path.clone(),
            sha256: manifest.mcp_tool_schema.sha256.clone(),
        },
        "MCP tool schema",
    )?;
    verify_mcp_tool_schema_bytes(&mcp_tool_schema, "release manifest")?;
    let expected_runtime_paths = WEB_RUNTIME_ARTIFACTS
        .iter()
        .map(|name| format!("libexec/{name}"))
        .collect::<BTreeSet<_>>();
    let declared_runtime_paths = manifest
        .runtime_artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    if declared_runtime_paths != expected_runtime_paths
        || manifest.runtime_artifacts.len() != WEB_RUNTIME_ARTIFACTS.len()
    {
        bail!("release manifest Web runtime artifact closure is incomplete or unknown");
    }
    let mut runtime_paths = BTreeSet::new();
    for artifact in &manifest.runtime_artifacts {
        if !runtime_paths.insert(artifact.path.as_str()) {
            bail!(
                "release manifest contains duplicate runtime artifact {}",
                artifact.path
            );
        }
        verify_release_artifact(extracted, artifact, "runtime artifact")?;
    }
    let runtime_collector_sha256 = manifest
        .runtime_artifacts
        .iter()
        .find(|artifact| artifact.path == format!("libexec/{RUNTIME_COLLECTOR_ARTIFACT}"))
        .context("release manifest has no runtime collector artifact")?
        .sha256
        .clone();
    let mut components = BTreeMap::new();
    for component in &manifest.runtime_components {
        if component.name.trim().is_empty()
            || component.version.trim().is_empty()
            || component.license.trim().is_empty()
        {
            bail!(
                "release manifest runtime component name, version, and license must be non-empty"
            );
        }
        if component.root.trim().is_empty() {
            bail!("release manifest runtime component root must be non-empty");
        }
        if component
            .entrypoint
            .as_deref()
            .is_some_and(|entrypoint| entrypoint.trim().is_empty())
        {
            bail!("release manifest runtime component entrypoint must be non-empty when present");
        }
        if components
            .insert(component.name.as_str(), component)
            .is_some()
        {
            bail!(
                "release manifest contains duplicate runtime component {}",
                component.name
            );
        }
        match (component.kind.as_str(), component.entrypoint.as_deref()) {
            ("executable-tree", Some(_)) | ("data-tree", _) => {}
            ("executable-tree", None) => {
                bail!(
                    "executable runtime component {} has no entrypoint",
                    component.name
                );
            }
            (kind, _) => bail!(
                "runtime component {} has unsupported kind {kind}",
                component.name
            ),
        }
        let root = verified_release_path(extracted, &component.root, "runtime component")?;
        if !root.is_dir() || sha256_tree(&root)? != component.sha256 {
            bail!(
                "runtime component {} failed its whole-tree checksum",
                component.name
            );
        }
        if let Some(entrypoint) = &component.entrypoint {
            let entrypoint = verified_release_path(extracted, entrypoint, "component entrypoint")?;
            if !entrypoint.is_file() || !entrypoint.starts_with(&root) {
                bail!(
                    "runtime component {} entrypoint escapes its root",
                    component.name
                );
            }
            if component.kind == "executable-tree" && !is_executable(&entrypoint)? {
                bail!(
                    "executable runtime component {} entrypoint is not executable",
                    component.name
                );
            }
        }
    }
    let astro = components
        .get("astro-parser-wasm")
        .context("release manifest has no required Web runtime component astro-parser-wasm")?;
    if astro.version != "4.0.0"
        || astro.kind != "data-tree"
        || astro.root != "libexec/astro"
        || astro.entrypoint.as_deref() != Some("libexec/astro/astro.wasm")
        || astro.license != "MIT"
    {
        bail!("Astro parser runtime component does not match 4.0.0 at libexec/astro/astro.wasm");
    }
    let typescript = components.get("typescript-native-compiler").context(
        "release manifest has no required Web runtime component typescript-native-compiler",
    )?;
    let expected_typescript_entrypoint =
        format!("libexec/typescript/lib/{}", executable_name("tsc"));
    if typescript.version != TYPESCRIPT_VERSION
        || typescript.kind != "executable-tree"
        || typescript.root != "libexec/typescript/lib"
        || typescript.entrypoint.as_deref() != Some(expected_typescript_entrypoint.as_str())
        || typescript.license != "Apache-2.0"
    {
        bail!(
            "TypeScript runtime component does not match {TYPESCRIPT_VERSION} at {expected_typescript_entrypoint}"
        );
    }
    let rust_sysroot = components
        .get(RUST_SYSROOT_COMPONENT_NAME)
        .context("release manifest has no required pinned Rust sysroot source component")?;
    if rust_sysroot.version != RUST_SYSROOT_COMPONENT_VERSION
        || rust_sysroot.kind != "data-tree"
        || rust_sysroot.root != RUST_SYSROOT_COMPONENT_ROOT
        || rust_sysroot.entrypoint.is_some()
        || rust_sysroot.license != RUST_SYSROOT_LICENSE_EXPRESSION
        || rust_sysroot.sha256 != RUST_SYSROOT_COMPONENT_SHA256
    {
        bail!("Rust sysroot source component does not match the pinned compatibility unit");
    }
    verify_rust_sysroot_tree(extracted, rust_sysroot, "release")?;
    let rust_sysroot_sha256 = rust_sysroot.sha256.clone();
    if manifest.runtime_requirements.get("web").map(String::as_str) != Some("Node.js >=24.0.0") {
        bail!("release manifest Web runtime requirement must be Node.js >=24.0.0");
    }
    let mut worker_adapters = BTreeSet::new();
    for worker in &manifest.workers {
        if !matches!(worker.adapter.as_str(), "rust" | "go" | "web") {
            bail!(
                "release manifest contains unknown worker adapter {}",
                worker.adapter
            );
        }
        let expected_worker_path = if worker.adapter == "web" {
            "libexec/depgraph-web-worker.mjs".to_owned()
        } else {
            format!(
                "libexec/{}",
                executable_name(&format!("depgraph-{}-worker", worker.adapter))
            )
        };
        if worker.path != expected_worker_path {
            bail!(
                "{} worker path does not match {expected_worker_path}",
                worker.adapter
            );
        }
        if !worker_adapters.insert(worker.adapter.as_str()) {
            bail!(
                "release manifest contains duplicate {} worker",
                worker.adapter
            );
        }
        if worker.version != VERSION {
            bail!(
                "{} worker adapter version {} does not match release version {VERSION}",
                worker.adapter,
                worker.version
            );
        }
        let artifact = verify_release_artifact(
            extracted,
            &Artifact {
                path: worker.path.clone(),
                sha256: worker.sha256.clone(),
            },
            "worker",
        )?;
        if worker.adapter != "web" && !is_executable(&artifact)? {
            bail!("packaged {} worker is not executable", worker.adapter);
        }
        if worker.adapter == "rust" {
            let backend = worker
                .backend
                .as_ref()
                .context("release manifest Rust worker has no backend compatibility unit")?;
            verify_rust_backend(backend)?;
        } else if worker.backend.is_some() {
            bail!(
                "{} worker unexpectedly declares a Rust backend compatibility unit",
                worker.adapter
            );
        }
        if worker.adapter == "web" {
            let semantic = worker
                .semantic
                .as_ref()
                .context("release manifest Web worker has no semantic compatibility unit")?;
            verify_web_semantic_attestation(semantic)?;
        } else if worker.semantic.is_some() {
            bail!(
                "{} worker unexpectedly declares a Web semantic compatibility unit",
                worker.adapter
            );
        }
    }
    if worker_adapters != BTreeSet::from(["go", "rust", "web"]) {
        bail!("release manifest must contain exactly the Rust, Go, and Web workers");
    }
    let sbom: Value = serde_json::from_slice(&fs::read(extracted.join("sbom.spdx.json"))?)?;
    if sbom["spdxVersion"] != "SPDX-2.3" {
        bail!("release SBOM has an invalid SPDX version");
    }
    let packages = sbom["packages"]
        .as_array()
        .context("release SBOM has no package inventory")?;
    if packages.is_empty() {
        bail!("release SBOM package inventory is empty");
    }
    let ids = packages
        .iter()
        .filter_map(|package| package["SPDXID"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if ids.len() != packages.len() {
        bail!("release SBOM contains a missing or duplicate SPDXID");
    }
    let package_names = packages
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "@astrojs/compiler",
        BOUNDED_QUERY_SBOM_PACKAGE_NAME,
        CROSS_LANGUAGE_SBOM_PACKAGE_NAME,
        "depgraph-runtime-collector",
        "flate2",
        "typescript",
        "golang.org/x/tools",
        "ra_ap_hir",
        "ra_ap_ide_db",
        "ra_ap_syntax",
        "ra_ap_vfs",
        "rmcp",
        "rmcp-macros",
        "rusqlite",
        "salsa",
        "salsa-macro-rules",
        "salsa-macros",
        "syn",
        "tar",
        "zip",
    ] {
        if !package_names.contains(required) {
            bail!("release SBOM is missing runtime dependency {required}");
        }
    }
    verify_runtime_collector_sbom(&sbom, &runtime_collector_sha256, "release")?;
    verify_rust_sysroot_sbom(&sbom, &rust_sysroot_sha256, "release")?;
    verify_bounded_query_sbom(&sbom, "release")?;
    verify_cross_language_sbom(&sbom, &cross_language_contract, "release")?;
    verify_framework_build_sbom(
        &sbom,
        &manifest_framework_build_artifact_checksums(&manifest)?,
        "release",
    )?;
    if package_names
        .iter()
        .filter(|name| name.starts_with("@typescript/typescript-"))
        .count()
        != 1
    {
        bail!("release SBOM must contain exactly one target TypeScript compiler package");
    }
    for build_only in [
        "@types/node",
        "assert_cmd",
        "esbuild",
        "jsonschema",
        "predicates",
        "pretty_assertions",
        "spdx",
        "tsx",
    ] {
        if package_names.contains(build_only) {
            bail!("release SBOM incorrectly contains build/test dependency {build_only}");
        }
    }
    for package in packages {
        if package["filesAnalyzed"] != Value::Bool(false)
            || !package["packageVerificationCode"].is_null()
        {
            bail!(
                "release SBOM packages must declare filesAnalyzed=false without a verification code"
            );
        }
        let declared = package["licenseDeclared"]
            .as_str()
            .context("release SBOM package has no declared license")?;
        if declared != "NOASSERTION"
            && normalized_spdx_license(declared).as_deref() != Some(declared)
        {
            bail!("release SBOM contains a non-canonical SPDX license: {declared}");
        }
        for reference in package["externalRefs"].as_array().into_iter().flatten() {
            if reference["referenceType"] == "purl" {
                let locator = reference["referenceLocator"]
                    .as_str()
                    .context("release SBOM contains a non-string purl")?;
                if !locator.starts_with("pkg:") || locator.starts_with("pkg:npm/@") {
                    bail!("release SBOM contains a non-canonical purl: {locator}");
                }
            }
        }
    }
    let relationships = sbom["relationships"]
        .as_array()
        .context("release SBOM has no relationships")?;
    for relationship in relationships {
        for field in ["spdxElementId", "relatedSpdxElement"] {
            let reference = relationship[field]
                .as_str()
                .with_context(|| format!("release SBOM relationship has no {field}"))?;
            if reference != "SPDXRef-DOCUMENT" && !ids.contains(reference) {
                bail!("release SBOM relationship references unknown element {reference}");
            }
        }
    }
    let root = packages
        .iter()
        .find(|package| package["SPDXID"] == "SPDXRef-Package-depgraph")
        .context("release SBOM has no depgraph root package")?;
    if root["comment"] != SBOM_SCOPE {
        bail!("release SBOM does not declare its package-manager component boundary");
    }
    let license_inventory = fs::read_to_string(extracted.join("THIRD_PARTY_LICENSES.txt"))?;
    if !license_inventory.contains(&format!(
        "First-party artifact {RUNTIME_COLLECTOR_ARTIFACT} ({RUNTIME_COLLECTOR_CONTRACT_VERSION}) is licensed under {PROJECT_LICENSE_EXPRESSION}"
    )) {
        bail!("license inventory is missing the runtime collector project license notice");
    }
    if !license_inventory.contains(&format!(
        "First-party bounded query contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION}",
        depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
        depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION,
    )) {
        bail!("license inventory is missing the bounded query project license notice");
    }
    if !license_inventory.contains(&format!(
        "First-party cross-language contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION}",
        depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
        depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION,
    )) {
        bail!("license inventory is missing the cross-language project license notice");
    }
    if !license_inventory
        .lines()
        .any(|line| line == MCP_APACHE_NOTICE)
    {
        bail!("license inventory is missing the rmcp Apache-2.0 notice");
    }
    for (name, version) in [
        (MCP_SDK_NAME, MCP_SDK_VERSION),
        ("rmcp-macros", MCP_MACROS_VERSION),
    ] {
        let matches = packages
            .iter()
            .filter(|package| package["name"] == name)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0]["versionInfo"] != version
            || matches[0]["licenseDeclared"] != "Apache-2.0"
        {
            bail!(
                "release SBOM must contain exactly one cargo:{name} {version} licensed Apache-2.0"
            );
        }
        let expected = format!("cargo:{name} {version} — Apache-2.0");
        if !license_inventory.lines().any(|line| line == expected) {
            bail!("third-party license inventory is missing {expected}");
        }
    }
    for (name, version, license) in [
        ("@astrojs/compiler", "4.0.0", "MIT"),
        ("typescript", TYPESCRIPT_VERSION, "Apache-2.0"),
    ] {
        let matches = packages
            .iter()
            .filter(|package| package["name"] == name)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0]["versionInfo"] != version
            || matches[0]["licenseDeclared"] != license
        {
            bail!(
                "release SBOM must contain exactly one npm:{name} {version} with license {license}"
            );
        }
        let expected = format!("npm:{name} {version} — {license}");
        if !license_inventory.lines().any(|line| line == expected) {
            bail!("third-party license inventory is missing {expected}");
        }
    }
    for (name, version, license) in RUST_ANALYZER_DIRECT_DEPENDENCIES
        .iter()
        .map(|name| (*name, RUST_ANALYZER_CRATE_VERSION, "MIT OR Apache-2.0"))
        .chain(
            SALSA_DIRECT_DEPENDENCIES
                .iter()
                .map(|name| (*name, SALSA_VERSION, "Apache-2.0 OR MIT")),
        )
    {
        let matches = packages
            .iter()
            .filter(|package| package["name"] == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!(
                "release SBOM must contain exactly one pinned package {name}, found {}",
                matches.len()
            );
        }
        let package = matches[0];
        if package["versionInfo"] != version || package["licenseDeclared"] != license {
            bail!("release SBOM must record cargo:{name} {version} with license {license}");
        }
        let expected = format!("cargo:{name} {version} — {license}");
        if !license_inventory.lines().any(|line| line == expected) {
            bail!("third-party license inventory is missing {expected}");
        }
    }
    let expected_backend_packages = dependency_inventory(&manifest.target)?
        .into_iter()
        .filter(|package| {
            package.ecosystem == "cargo"
                && (package.name.starts_with("ra_ap_") || package.name.starts_with("salsa"))
        })
        .map(|package| (package.name, package.version, package.license))
        .collect::<BTreeSet<_>>();
    let actual_backend_packages = packages
        .iter()
        .filter_map(|package| {
            let name = package["name"].as_str()?;
            (name.starts_with("ra_ap_") || name.starts_with("salsa")).then(|| {
                (
                    name.to_owned(),
                    package["versionInfo"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    package["licenseDeclared"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    if actual_backend_packages != expected_backend_packages {
        bail!(
            "release SBOM Rust backend closure differs from Cargo metadata: expected {expected_backend_packages:?}, found {actual_backend_packages:?}"
        );
    }
    for (name, version, license) in &expected_backend_packages {
        let expected = format!("cargo:{name} {version} — {license}");
        if !license_inventory.lines().any(|line| line == expected) {
            bail!("third-party license inventory is missing {expected}");
        }
    }
    for (label, content) in web_legal_documents()? {
        let section = legal_document_section(&label, &content);
        if !license_inventory.contains(&section) {
            bail!("third-party license inventory is missing {label}");
        }
    }
    if sbom != crate::sbom::sbom(&manifest.target, &rust_sysroot_sha256)? {
        bail!("release SBOM differs from the locked package dependency inventory");
    }
    if license_inventory != third_party_licenses(&manifest.target)? {
        bail!("third-party license inventory differs from the locked package dependency inventory");
    }
    verify_typescript_compiler(extracted)?;
    verify_runtime_collector_module(
        &verified_release_path(
            extracted,
            &format!("libexec/{RUNTIME_COLLECTOR_ARTIFACT}"),
            "runtime collector",
        )?,
        "release",
    )?;
    verify_packaged_mcp_handshake(extracted, &manifest.mcp_server)?;
    let rust_worker = manifest
        .workers
        .iter()
        .find(|worker| worker.adapter == "rust")
        .context("release manifest has no Rust worker")?;
    verify_packaged_rust_handshake(
        extracted,
        rust_worker,
        rust_worker
            .backend
            .as_ref()
            .context("release manifest Rust worker has no backend compatibility unit")?,
    )?;
    let web_worker = manifest
        .workers
        .iter()
        .find(|worker| worker.adapter == "web")
        .context("release manifest has no Web worker")?;
    verify_packaged_web_handshake(
        extracted,
        web_worker,
        web_worker
            .semantic
            .as_ref()
            .context("release manifest Web worker has no semantic compatibility unit")?,
    )?;
    Ok(manifest)
}

fn verify_packaged_mcp_handshake(extracted: &Path, server: &McpServerArtifact) -> Result<()> {
    let server_path = verified_release_path(extracted, &server.path, "MCP server")?;
    let output = Command::new(&server_path).arg("--version").output()?;
    let expected = format!("{MCP_SERVER_NAME} {}", server.version);
    if !output.status.success()
        || !output.stderr.is_empty()
        || String::from_utf8(output.stdout)?.trim() != expected
    {
        bail!("packaged MCP server version handshake failed");
    }
    Ok(())
}

fn verify_packaged_rust_handshake(
    extracted: &Path,
    worker: &WorkerArtifact,
    backend: &WorkerBackend,
) -> Result<()> {
    let worker_path = verified_release_path(extracted, &worker.path, "Rust worker")?;
    let output = Command::new(&worker_path).arg("--version").output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("packaged Rust worker version handshake failed");
    }
    let raw = String::from_utf8(output.stdout)?;
    let handshake = parse_worker_handshake(raw.trim())
        .context("packaged Rust worker returned a malformed version handshake")?;
    let actual_backend = rust_backend_from_handshake(&handshake)?;
    if handshake.name != "depgraph-rust-worker"
        || handshake.version != worker.version
        || handshake.protocol != "1.0"
        || &actual_backend != backend
    {
        bail!(
            "packaged Rust worker handshake does not match its release manifest compatibility unit"
        );
    }
    Ok(())
}

fn verify_packaged_web_handshake(
    extracted: &Path,
    worker: &WorkerArtifact,
    semantic: &WebSemanticAttestation,
) -> Result<()> {
    let worker_path = verified_release_path(extracted, &worker.path, "Web worker")?;
    let output = Command::new("node")
        .arg(process_argument_path(&worker_path))
        .arg("--version")
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!(
            "packaged Web worker version handshake failed (status {}; stdout {:?}; stderr {:?})",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let raw = String::from_utf8(output.stdout)?;
    let handshake = parse_worker_handshake(raw.trim())
        .context("packaged Web worker returned a malformed version handshake")?;
    let actual_semantic = web_semantic_from_handshake(&handshake)?;
    if handshake.name != "depgraph-web-worker"
        || handshake.version != worker.version
        || handshake.protocol != "1.0"
        || &actual_semantic != semantic
    {
        bail!(
            "packaged Web worker handshake does not match its release manifest compatibility unit"
        );
    }
    Ok(())
}
