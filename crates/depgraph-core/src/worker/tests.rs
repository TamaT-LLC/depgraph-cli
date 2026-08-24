use super::*;

#[test]
fn non_cross_language_web_stream_remains_accepted() -> Result<()> {
    let root = tempfile::tempdir()?.path().canonicalize()?;
    let common = serde_json::json!({
        "protocol_version": "1.0",
        "scan_id": "non-cross-web",
        "adapter": "web",
        "adapter_version": "0.1.0",
    });
    let coverage = serde_json::json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 0,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": [],
    });
    let event = |value: serde_json::Value| {
        let mut object = common.as_object().cloned().unwrap_or_default();
        object.extend(value.as_object().cloned().unwrap_or_default());
        serde_json::Value::Object(object)
    };
    let events = [
        event(serde_json::json!({
            "event": "scan_started",
            "seq": 1,
            "root": root,
            "project_code_executed": false,
            "safe_mode": true,
        })),
        event(serde_json::json!({
            "event": "profile_declared",
            "seq": 2,
            "profile": {
                "id": "web:test",
                "language": "web",
                "features": [],
                "environment": {},
                "properties": {
                    "typescript_analysis_mode": "semantic-definition-graph",
                    "typescript_project_model_status": "ready",
                    "typescript_typechecker_status": "definition-graph-emitted",
                    "typescript_definition_graph_status": "ready",
                    "typescript_semantic_graph_emission": "definition-graph-v1",
                    "typescript_semantic_node_count": "0",
                    "typescript_semantic_relation_count": "0",
                    "typescript_semantic_issue_count": "0",
                    "typescript_release_gate": "release-gate-pending",
                },
            },
        })),
        event(serde_json::json!({
            "event": "profile_completed",
            "seq": 3,
            "profile_id": "web:test",
            "coverage": coverage,
        })),
        event(serde_json::json!({
            "event": "scan_completed",
            "seq": 4,
            "coverage": coverage,
        })),
    ];
    let output = events
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join("\n");
    let parsed = parse_events_preserving_prefix(
        output.as_bytes(),
        "non-cross-web",
        "web",
        &root,
        4096,
        Some("0.1.0"),
        Some(false),
    );

    assert!(parsed.error.is_none(), "{:?}", parsed.error);
    Ok(())
}

#[tokio::test]
async fn non_cross_language_web_worker_remains_accepted() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("project");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let worker = temp.path().join("web-worker.mjs");
    std::fs::write(
        &worker,
        r#"const args = process.argv.slice(2);
const root = args[args.indexOf("--root") + 1];
const scan = args[args.indexOf("--scan-id") + 1];
const common = {protocol_version:"1.0",scan_id:scan,adapter:"web",adapter_version:"0.1.0"};
const coverage = {profiles:1,files_discovered:0,files_analyzed:0,files_skipped:0,dependency_sites:0,resolved:0,candidates:0,external:0,unresolved:0,unsupported_syntax:0,project_code_executed:false,completeness:["syntax-complete"],reasons:[]};
const events = [
  {event:"scan_started",...common,seq:1,root,project_code_executed:false,safe_mode:true},
  {event:"profile_declared",...common,seq:2,profile:{id:"web:test",language:"web",features:[],environment:{},properties:{typescript_analysis_mode:"semantic-definition-graph",typescript_project_model_status:"ready",typescript_typechecker_status:"definition-graph-emitted",typescript_definition_graph_status:"ready",typescript_semantic_graph_emission:"definition-graph-v1",typescript_semantic_node_count:"0",typescript_semantic_relation_count:"0",typescript_semantic_issue_count:"0",typescript_release_gate:"release-gate-pending"}}},
  {event:"profile_completed",...common,seq:3,profile_id:"web:test",coverage},
  {event:"scan_completed",...common,seq:4,coverage}
];
for (const event of events) console.log(JSON.stringify(event));
"#,
    )?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Web,
        program: OsString::from("node"),
        leading_args: vec![worker.clone().into_os_string()],
        display: worker.display().to_string(),
        artifact_path: worker,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "non-cross-web",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;

    assert!(execution.error.is_none(), "{:?}", execution.error);
    assert_eq!(execution.events.len(), 4);
    Ok(())
}

#[test]
fn worker_capability_handshake_is_exact_sorted_and_fail_closed() {
    assert_eq!(
        worker_capabilities(
            "depgraph-web-worker 0.5.0 (protocol 1.0; capabilities alpha,worker-delta-v1,zeta)"
        ),
        ["alpha", "worker-delta-v1", "zeta"]
    );
    assert!(worker_capabilities("depgraph-web-worker 0.5.0").is_empty());
    assert!(
        worker_capabilities(
            "depgraph-web-worker 0.5.0 (protocol 1.0; capabilities worker-delta-v1,alpha)"
        )
        .is_empty()
    );
    assert!(
        worker_capabilities(
            "depgraph-web-worker 0.5.0 (protocol 1.0; capabilities worker-delta-v1,worker-delta-v1)"
        )
        .is_empty()
    );
    assert!(
        worker_capabilities(
            "depgraph-web-worker 0.5.0 (protocol 1.0; future-capabilities worker-delta-v1)"
        )
        .is_empty()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn worker_version_probe_honors_cancellation_without_waiting_for_timeout() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let script = temp.path().join("slow-version-worker.sh");
    std::fs::write(&script, "#!/bin/sh\nexec sleep 30\n")?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
    });

    let started = std::time::Instant::now();
    let error = probe_worker_version_with_cancellation(&spec, &root, &cancellation)
        .await
        .expect_err("the slow version probe should be cancelled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancelled probe waited {:?}",
        started.elapsed()
    );
    assert!(format!("{error:#}").contains("runtime probe cancelled"));
    Ok(())
}

struct TestRelease {
    manifest: PathBuf,
    rust_worker: PathBuf,
    go_worker: PathBuf,
}

fn manifest_artifact(path: &str, contents: &[u8]) -> Value {
    serde_json::json!({
        "path": path,
        "sha256": hex::encode(Sha256::digest(contents)),
    })
}

fn write_manifest_artifact(release: &Path, path: &str, contents: &[u8]) -> Result<Value> {
    let artifact = release.join(path);
    if let Some(parent) = artifact.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&artifact, contents)?;
    Ok(manifest_artifact(path, contents))
}

fn make_test_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn write_test_release_manifest(
    release: &Path,
    mut runtime_artifacts: Vec<Value>,
    mut runtime_components: Vec<Value>,
) -> Result<TestRelease> {
    if runtime_artifacts.is_empty() {
        for path in WEB_RUNTIME_ARTIFACT_PATHS {
            runtime_artifacts.push(write_manifest_artifact(
                release,
                path,
                format!("verified {path}").as_bytes(),
            )?);
        }
    }
    if !runtime_components
        .iter()
        .any(|component| component["name"] == "astro-parser-wasm")
    {
        let astro = release.join("libexec/astro");
        std::fs::create_dir_all(&astro)?;
        std::fs::write(astro.join("astro.wasm"), b"verified wasm")?;
        runtime_components.push(serde_json::json!({
            "name": "astro-parser-wasm",
            "version": "4.0.0",
            "kind": "data-tree",
            "root": "libexec/astro",
            "entrypoint": "libexec/astro/astro.wasm",
            "license": "MIT",
            "sha256": runtime_tree_digest(&astro)?,
        }));
    }
    if !runtime_components
        .iter()
        .any(|component| component["name"] == "typescript-native-compiler")
    {
        let typescript = release.join("libexec/typescript/lib");
        std::fs::create_dir_all(&typescript)?;
        let compiler = typescript.join(executable_name("tsc"));
        std::fs::write(&compiler, b"verified compiler")?;
        make_test_executable(&compiler)?;
        std::fs::write(typescript.join("lib.d.ts"), b"verified standard library")?;
        runtime_components.push(serde_json::json!({
            "name": "typescript-native-compiler",
            "version": "7.0.2",
            "kind": "executable-tree",
            "root": "libexec/typescript/lib",
            "entrypoint": format!("libexec/typescript/lib/{}", executable_name("tsc")),
            "license": "Apache-2.0",
            "sha256": runtime_tree_digest(&typescript)?,
        }));
    }
    if !runtime_components
        .iter()
        .any(|component| component["name"] == RUST_SYSROOT_COMPONENT_NAME)
    {
        let sysroot = release.join(RUST_SYSROOT_COMPONENT_ROOT);
        let core = sysroot.join("library/core/src/lib.rs");
        std::fs::create_dir_all(core.parent().context("test core source has no parent")?)?;
        std::fs::write(&core, b"verified bundled core source")?;
        runtime_components.push(serde_json::json!({
            "name": RUST_SYSROOT_COMPONENT_NAME,
            "version": RUST_SYSROOT_COMPONENT_VERSION,
            "kind": "data-tree",
            "root": RUST_SYSROOT_COMPONENT_ROOT,
            "license": RUST_SYSROOT_LICENSE_EXPRESSION,
            "sha256": runtime_tree_digest(&sysroot)?,
        }));
    }
    write_test_release_manifest_exact(release, runtime_artifacts, runtime_components)
}

fn write_test_release_manifest_exact(
    release: &Path,
    runtime_artifacts: Vec<Value>,
    runtime_components: Vec<Value>,
) -> Result<TestRelease> {
    let core_path = format!("bin/{}", executable_name("depgraph"));
    let rust_worker_path = format!("libexec/{}", executable_name("depgraph-rust-worker"));
    let go_worker_path = format!("libexec/{}", executable_name("depgraph-go-worker"));
    let web_worker_path = "libexec/depgraph-web-worker.mjs";
    let core = write_manifest_artifact(release, &core_path, b"verified core")?;
    let schema = write_manifest_artifact(release, PROTOCOL_SCHEMA_PATH, b"verified schema")?;
    let query_fixture = write_manifest_artifact(
        release,
        BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
        BOUNDED_QUERY_RELEASE_SMOKE_QUERY.as_bytes(),
    )?;
    let cross_language_fixture = write_manifest_artifact(
        release,
        crate::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
        crate::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE.as_bytes(),
    )?;
    let cross_language_contract = crate::cross_language_release_compatibility_contract();
    let cross_language_schemas = cross_language_contract
        .schemas
        .iter()
        .map(|schema| {
            let contents = match schema.path.as_str() {
                depgraph_protocol::CROSS_LANGUAGE_SCHEMA_PATH => {
                    depgraph_protocol::CROSS_LANGUAGE_SCHEMA
                }
                crate::FFI_LINK_OBSERVATION_SCHEMA_PATH => crate::FFI_LINK_OBSERVATION_SCHEMA,
                "schemas/depgraph-runtime-trace-v1.schema.json" => crate::RUNTIME_TRACE_SCHEMA,
                path => panic!("unknown test cross-language schema {path}"),
            };
            write_manifest_artifact(release, &schema.path, contents.as_bytes())
        })
        .collect::<Result<Vec<_>>>()?;
    let apache_license =
        write_manifest_artifact(release, "LICENSE-APACHE", b"test Apache-2.0 license")?;
    let mit_license = write_manifest_artifact(release, "LICENSE-MIT", b"test MIT license")?;
    let rust_worker = write_manifest_artifact(release, &rust_worker_path, b"verified rust worker")?;
    let go_worker = write_manifest_artifact(release, &go_worker_path, b"verified go worker")?;
    let web_worker = write_manifest_artifact(release, web_worker_path, b"verified web worker")?;
    make_test_executable(&release.join(&core_path))?;
    make_test_executable(&release.join(&rust_worker_path))?;
    make_test_executable(&release.join(&go_worker_path))?;
    let manifest = release.join("release-manifest.json");
    std::fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "release_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "compatibility": crate::release_compatibility_contract(),
            "target": "test-target",
            "license_expression": PROJECT_LICENSE_EXPRESSION,
            "project_licenses": [apache_license, mit_license],
            "core": core,
            "schema": schema,
            "query_fixture": query_fixture,
            "cross_language_fixture": cross_language_fixture,
            "cross_language_schemas": cross_language_schemas,
            "runtime_artifacts": runtime_artifacts,
            "runtime_components": runtime_components,
            "runtime_requirements": {"web": WEB_RUNTIME_REQUIREMENT},
            "workers": [
                {
                    "adapter": "rust",
                    "version": env!("CARGO_PKG_VERSION"),
                    "backend": {
                        "kind": RUST_BACKEND_KIND,
                        "version": RUST_BACKEND_VERSION,
                        "revision": RUST_BACKEND_REVISION,
                        "salsa_version": RUST_BACKEND_SALSA_VERSION,
                    },
                    "path": rust_worker["path"],
                    "sha256": rust_worker["sha256"],
                },
                {
                    "adapter": "go",
                    "version": env!("CARGO_PKG_VERSION"),
                    "path": go_worker["path"],
                    "sha256": go_worker["sha256"],
                },
                {
                    "adapter": "web",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semantic": {
                        "typescript_version": TYPESCRIPT_COMPILER_VERSION,
                        "capabilities": WEB_SEMANTIC_CAPABILITIES,
                        "runtime_components": WEB_SEMANTIC_RUNTIME_COMPONENTS,
                        "runtime_artifacts": WEB_SEMANTIC_RUNTIME_ARTIFACTS,
                    },
                    "path": web_worker["path"],
                    "sha256": web_worker["sha256"],
                },
            ],
        }))?,
    )?;
    Ok(TestRelease {
        manifest,
        rust_worker: release.join(rust_worker_path),
        go_worker: release.join(go_worker_path),
    })
}

fn update_test_manifest(
    manifest: &Path,
    update: impl FnOnce(&mut Value) -> Result<()>,
) -> Result<()> {
    let mut value: Value = serde_json::from_slice(&std::fs::read(manifest)?)?;
    update(&mut value)?;
    std::fs::write(manifest, serde_json::to_vec_pretty(&value)?)?;
    Ok(())
}

fn rust_gate_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
    profile_protocol(
        root,
        "rust-gate-scan",
        "rust",
        serde_json::json!({"rust_hir_enable_gate": gate}),
    )
}

fn typescript_gate_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
    profile_protocol(
        root,
        "typescript-gate-scan",
        "web",
        serde_json::json!({
            TYPESCRIPT_RELEASE_GATE_PROPERTY: gate,
            TYPESCRIPT_ANALYSIS_MODE_PROPERTY: TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH,
            TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY: TYPESCRIPT_SEMANTIC_EMISSION_DEFINITION_GRAPH_V1,
            TYPESCRIPT_PROJECT_STATUS_PROPERTY: "ready",
            TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY: "definition-graph-emitted",
            TYPESCRIPT_DEFINITION_STATUS_PROPERTY: "ready",
            "typescript_semantic_node_count": "0",
            "typescript_semantic_relation_count": "0",
            "typescript_semantic_issue_count": "0",
        }),
    )
}

fn add_framework_semantic_delta(
    events: &mut Vec<Value>,
    valid_target: bool,
    status: &str,
    capability: &str,
) {
    let profile_id = "web:default";
    let package_locator = "npm:workspace:definition-fixture@1.0.0#.";
    let component_identity = serde_json::json!({
        "framework":"next",
        "package_locator":package_locator,
        "component_kind":"page",
        "environment":"server",
        "resolver_identity":format!("{package_locator}::app/products/page.tsx#default"),
    });
    let route_identity = serde_json::json!({
        "framework":"next",
        "package_locator":package_locator,
        "route_kind":"page",
        "environment":"server",
        "router_instance":"next-app:app",
        "route_pattern":"/products",
    });
    let component_id = depgraph_protocol::stable_id_from_value("component", &component_identity);
    let route_id = depgraph_protocol::stable_id_from_value("route", &route_identity);
    let target_id = if valid_target {
        route_id.as_str()
    } else {
        component_id.as_str()
    };
    let condition = serde_json::json!({
        "op":"all",
        "conditions":[
            {"op":"eq","key":"environment","value":"server"},
            {"op":"eq","key":"mode","value":"production"}
        ],
    });
    let semantic_evidence = serde_json::json!({
        "kind":"semantic",
        "extractor":"next-static-adapter",
        "extractor_version":WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
        "path":"app/products/page.tsx",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":32,
        "properties":{
            "profile_id":profile_id,
            "framework":"next",
            "contract_version":WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
            "occurrence_kind":"page_route_entry",
        },
    });
    let source_evidence = serde_json::json!({
        "kind":"source",
        "extractor":"next-static-adapter",
        "extractor_version":WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION,
        "path":"app/products/page.tsx",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":32,
        "properties":{
            "profile_id":profile_id,
            "framework":"next",
            "occurrence_kind":"page_route_entry",
        },
    });
    let site_id = depgraph_protocol::stable_id_from_value(
        "site",
        &serde_json::json!({
            "condition":condition,
            "kind":"route_entry",
            "path":"app/products/page.tsx",
            "profile_id":profile_id,
            "source":component_id,
            "span":{"start_line":1,"start_column":1,"end_line":1,"end_column":32},
        }),
    );
    let edge_id = depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({"kind":"route_entry","site_id":site_id,"target":target_id}),
    );
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["features"] = serde_json::json!(["next"]);
    let properties = &mut profile["profile"]["properties"];
    properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH);
    properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2);
    properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-import-type-call-graph-emitted");
    properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
    properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("0");
    properties[WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY] = serde_json::json!(capability);
    properties[WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY] = serde_json::json!(status);
    properties[WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY] =
        serde_json::json!(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION);
    properties[WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY] = serde_json::json!("2");
    properties[WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("1");
    properties[WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY] = serde_json::json!("1");
    properties[WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_PROPERTY] =
        serde_json::json!(WEB_FRAMEWORK_COMPLETENESS_CAPABILITY_V1);
    properties[WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY] = serde_json::json!("complete");
    properties[WEB_FRAMEWORK_COMPLETENESS_ISSUE_COUNT_PROPERTY] = serde_json::json!("0");
    properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY] = serde_json::json!(
        "[{\"framework\":\"next\",\"required_capabilities\":[\"framework-semantic-graph-v1\",\"next-route-component-boundary-v1\",\"typescript-definition-import-type-call-graph-v2\"],\"emitted_capabilities\":[\"framework-semantic-graph-v1\",\"next-route-component-boundary-v1\",\"typescript-definition-import-type-call-graph-v2\"],\"status\":\"complete\",\"reasons\":[]}]"
    );
    let insert_at = events
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    let payload = vec![
        serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":component_id,
                "kind":"component",
                "locator":format!("framework-component:{component_id}"),
                "display_name":"ProductsPage",
                "properties":{
                    "framework":"next","package_locator":package_locator,
                    "component_kind":"page","environment":"server",
                    "profile_id":profile_id,"canonical_identity":component_identity,
                },
            },
        }),
        serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":route_id,
                "kind":"route",
                "locator":format!("framework-route:{route_id}"),
                "display_name":"/products",
                "properties":{
                    "framework":"next","package_locator":package_locator,
                    "route_kind":"page","environment":"server",
                    "profile_id":profile_id,"canonical_identity":route_identity,
                },
            },
        }),
        serde_json::json!({
            "event":"dependency_site",
            "site":{
                "id":site_id,"source":component_id,"kind":"route_entry",
                "specifier":"/products","resolution_status":"resolved",
                "target_ids":[target_id],"profile_id":profile_id,
                "condition":condition,"precision":"exact","reason":null,
                "evidence":[semantic_evidence,source_evidence],
            },
        }),
        serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":edge_id,"source":component_id,"target":target_id,
                "kind":"route_entry","site_id":site_id,"phase":"semantic",
                "environment":"server","profile_id":profile_id,"condition":condition,
                "resolution_status":"resolved","precision":"exact","generated":false,
                "evidence":[semantic_evidence,source_evidence],
            },
        }),
    ];
    for event in payload.into_iter().rev() {
        events.insert(insert_at, event);
    }
    for event in events.iter_mut().filter(|event| {
        matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        )
    }) {
        event["coverage"]["dependency_sites"] = serde_json::json!(1);
        event["coverage"]["resolved"] = serde_json::json!(1);
    }
    resequence_test_protocol(events);
    for event in events {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    }
}

fn typescript_definition_protocol(root: &Path, gate: &str, relation_kind: &str) -> Result<Vec<u8>> {
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"definition-fixture","version":"1.0.0"}"#,
    )?;
    std::fs::write(root.join("src/index.ts"), b"export class Definition {}\n")?;
    let output = typescript_gate_protocol(root, gate)?;
    let mut events = String::from_utf8(output)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let profile_id = "web:default";
    let package_locator = "npm:workspace:definition-fixture@1.0.0#.";
    let package_id = depgraph_protocol::stable_id_from_value(
        "package",
        &serde_json::json!({"locator": package_locator}),
    );
    let file_id = depgraph_protocol::stable_id_from_value(
        "file",
        &serde_json::json!({"package": package_locator, "path": "src/index.ts"}),
    );
    let named_identity = |namespace: &str,
                          semantic_kind: &str,
                          resolver_suffix: &str,
                          generic_origin: Option<&str>| {
        let kind_property = if namespace == "symbol" {
            "symbol_kind"
        } else {
            "type_kind"
        };
        let mut identity = serde_json::json!({
            "language": "typescript",
            "package_locator": package_locator,
            "resolver_identity": format!("{package_locator}::module:src/index.ts#{resolver_suffix}"),
        });
        identity[kind_property] = serde_json::json!(semantic_kind);
        if namespace == "symbol" {
            identity["identity_kind"] = serde_json::json!("named");
        }
        if let Some(generic_origin) = generic_origin {
            let type_arguments = serde_json::json!([{"kind":"intrinsic","name":"string"}]);
            identity["resolver_identity"] = serde_json::json!(format!(
                "generic:{}",
                serde_json::to_string(&serde_json::json!([generic_origin, type_arguments.clone()]))
                    .expect("test generic resolver input serializes")
            ));
            identity["generic_origin"] = serde_json::json!(generic_origin);
            identity["type_arguments"] = type_arguments;
        }
        identity
    };
    let semantic_node = |namespace: &str,
                         semantic_kind: &str,
                         resolver_suffix: &str,
                         generic_origin: Option<&str>| {
        let identity = named_identity(namespace, semantic_kind, resolver_suffix, generic_origin);
        let kind_property = if namespace == "symbol" {
            "symbol_kind"
        } else {
            "type_kind"
        };
        let id = depgraph_protocol::stable_id_from_value(namespace, &identity);
        let mut properties = serde_json::json!({
            "language": "typescript",
            "package_locator": package_locator,
            "package_id": package_id,
            "canonical_identity": identity.clone(),
            "profile_id": profile_id,
            "source_path": "src/index.ts",
            "source_span": {
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 9,
            },
        });
        properties[kind_property] = serde_json::json!(semantic_kind);
        properties["resolver_identity"] = identity["resolver_identity"].clone();
        if generic_origin.is_some() {
            properties["generic_origin"] = identity["generic_origin"].clone();
            properties["type_arguments"] = identity["type_arguments"].clone();
        }
        serde_json::json!({
            "id": id,
            "kind": namespace,
            "locator": format!("typescript-{namespace}:{id}"),
            "display_name": semantic_kind,
            "properties": properties,
        })
    };
    let condition = serde_json::json!({"op":"all","conditions":[]});
    let relation = |kind: &str, source: &str, target: &str| {
        let evidence = serde_json::json!({
            "kind": "semantic",
            "extractor": TYPESCRIPT_SEMANTIC_EXTRACTOR,
            "extractor_version": TYPESCRIPT_COMPILER_VERSION,
            "path": "src/index.ts",
            "start_line": 1,
            "start_column": 1,
            "end_line": 1,
            "end_column": 9,
            "detail": "TypeChecker definition relation",
            "properties": {"profile_id": profile_id},
        });
        let edge_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "condition": condition,
                "kind": kind,
                "path": evidence["path"],
                "profile_id": profile_id,
                "source": source,
                "span": {
                    "end_column": evidence["end_column"],
                    "end_line": evidence["end_line"],
                    "start_column": evidence["start_column"],
                    "start_line": evidence["start_line"],
                },
                "target": target,
            }),
        );
        serde_json::json!({
            "event":"edge_upsert",
            "edge": {
                "id":edge_id,
                "source":source,
                "target":target,
                "kind":kind,
                "phase":"semantic",
                "environment":"any",
                "profile_id":profile_id,
                "condition":condition,
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":false,
                "evidence":[evidence],
            },
        })
    };
    let mut semantic_nodes = Vec::new();
    let mut semantic_edges = Vec::new();
    match relation_kind {
        "declares" => {
            let symbol = semantic_node("symbol", "function", "definition", None);
            semantic_edges.push(relation(
                "declares",
                &file_id,
                symbol["id"].as_str().expect("symbol ID"),
            ));
            semantic_nodes.push(symbol);
        }
        "extends" | "implements" => {
            let left = semantic_node("type", "class", "left", None);
            let right = semantic_node("type", "interface", "right", None);
            for node in [&left, &right] {
                semantic_edges.push(relation(
                    "declares",
                    &file_id,
                    node["id"].as_str().expect("type ID"),
                ));
            }
            semantic_edges.push(relation(
                relation_kind,
                left["id"].as_str().expect("left type ID"),
                right["id"].as_str().expect("right type ID"),
            ));
            semantic_nodes.extend([left, right]);
        }
        "instantiates" => {
            let source = semantic_node("type", "class", "source", None);
            let origin = semantic_node("type", "class", "origin", None);
            let origin_resolver = origin["properties"]["canonical_identity"]["resolver_identity"]
                .as_str()
                .expect("origin resolver");
            let instance = semantic_node(
                "type",
                "generic_instance",
                "origin<string>",
                Some(origin_resolver),
            );
            for node in [&source, &origin] {
                semantic_edges.push(relation(
                    "declares",
                    &file_id,
                    node["id"].as_str().expect("type ID"),
                ));
            }
            semantic_edges.push(relation(
                "instantiates",
                source["id"].as_str().expect("source type ID"),
                instance["id"].as_str().expect("instance type ID"),
            ));
            semantic_nodes.extend([source, origin, instance]);
        }
        other => bail!("unsupported test relation {other}"),
    }
    events[1]["profile"]["properties"]["typescript_semantic_node_count"] =
        serde_json::json!(semantic_nodes.len().to_string());
    events[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
        serde_json::json!(semantic_edges.len().to_string());
    let mut payload = vec![
        serde_json::json!({
            "event":"node_upsert",
            "node": {
                "id":package_id,
                "kind":"package_instance",
                "locator":format!("package://{package_locator}"),
                "display_name":"definition-fixture",
                "properties":{
                    "locator":package_locator,
                    "manifest_path":"package.json",
                    "workspace":true,
                    "workspace_path":".",
                },
            },
        }),
        serde_json::json!({
            "event":"node_upsert",
            "node": {
                "id":file_id,
                "kind":"file",
                "locator":"file://src/index.ts",
                "display_name":"src/index.ts",
                "properties":{
                    "path":"src/index.ts",
                    "package_id":package_id,
                    "language":"typescript",
                    "generated":false,
                },
            },
        }),
    ];
    payload.extend(
        semantic_nodes
            .into_iter()
            .map(|node| serde_json::json!({"event":"node_upsert","node":node})),
    );
    payload.extend(semantic_edges);
    for item in payload.into_iter().rev() {
        events.insert(2, item);
    }
    for (index, event) in events.iter_mut().enumerate() {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        event["seq"] = serde_json::json!(index + 1);
    }
    let mut protocol = Vec::new();
    for event in events {
        serde_json::to_writer(&mut protocol, &event)?;
        protocol.push(b'\n');
    }
    Ok(protocol)
}

fn typescript_import_type_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
    let mut events = test_protocol_values(typescript_definition_protocol(root, gate, "extends")?)?;
    std::fs::write(root.join("src/target.ts"), b"export interface Target {}\n")?;
    let profile_id = "web:default";
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["properties"][TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
    profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
    profile["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-import-type-graph-emitted");
    profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
        serde_json::json!("3");

    let package = events
        .iter()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("package node");
    let package_id = package["node"]["id"]
        .as_str()
        .expect("package ID")
        .to_owned();
    let package_locator = package["node"]["properties"]["locator"]
        .as_str()
        .expect("package locator")
        .to_owned();
    let source_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let target_file_id = depgraph_protocol::stable_id_from_value(
        "file",
        &serde_json::json!({"package": package_locator, "path": "src/target.ts"}),
    );
    let mut type_ids = events
        .iter()
        .filter(|event| event["node"]["kind"] == "type")
        .map(|event| event["node"]["id"].as_str().expect("type ID").to_owned())
        .collect::<Vec<_>>();
    type_ids.sort();
    let owner_type_id = type_ids.first().context("owner type")?.clone();
    let target_type_id = type_ids.get(1).context("target type")?.clone();

    let condition = serde_json::json!({"op":"all","conditions":[]});
    let evidence = |occurrence_kind: &str,
                    target_basis: &str,
                    start_column: u64,
                    end_column: u64,
                    module_specifier: Option<&str>,
                    imported_name: Option<&str>| {
        let type_only = matches!(
            occurrence_kind,
            "type_reference" | "heritage_type" | "jsdoc_type" | "import_type"
        );
        let mut primary = serde_json::json!({
                "kind":"semantic",
                "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
                "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                "path":"src/index.ts",
                "start_line":1,
                "start_column":start_column,
                "end_line":1,
                "end_column":end_column,
                "detail":"TypeChecker dependency occurrence",
                "properties":{
                "backend":TYPESCRIPT_SEMANTIC_BACKEND,
                    "compiler_source":"bundled",
                    "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                    "analysis_mode":TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH,
                    "profile_id":profile_id,
                    "project_code_executed":false,
                    "occurrence_kind":occurrence_kind,
                    "target_basis":target_basis,
                    "type_only":type_only,
                },
        });
        if let Some(module_specifier) = module_specifier {
            primary["properties"]["module_specifier"] = serde_json::json!(module_specifier);
        }
        if let Some(imported_name) = imported_name {
            primary["properties"]["imported_name"] = serde_json::json!(imported_name);
        }
        let supporting = serde_json::json!({
            "kind":"source",
            "extractor":"typescript-native-syntax",
            "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                "path":"src/index.ts",
                "start_line":1,
                "start_column":start_column,
                "end_line":1,
                "end_column":end_column,
                "detail":"syntax dependency occurrence",
            "properties":{
                "profile_id":profile_id,
                "occurrence_kind":occurrence_kind,
            },
        });
        serde_json::json!([primary, supporting])
    };
    let dependency = |kind: &str,
                      edge_kind: &str,
                      source: &str,
                      target: &str,
                      specifier: &str,
                      evidence: Value| {
        let primary = &evidence[0];
        let site_id = depgraph_protocol::stable_id_from_value(
            "site",
            &serde_json::json!({
                "condition":condition,
                "kind":kind,
                "path":primary["path"],
                "profile_id":profile_id,
                "source":source,
                "span":{
                    "end_column":primary["end_column"],
                    "end_line":primary["end_line"],
                    "start_column":primary["start_column"],
                    "start_line":primary["start_line"],
                },
            }),
        );
        let edge_id = depgraph_protocol::stable_id_from_value(
            "edge",
            &serde_json::json!({
                "kind":edge_kind,
                "site_id":site_id,
                "target":target,
            }),
        );
        [
            serde_json::json!({
                "event":"dependency_site",
                "site":{
                    "id":site_id,
                    "source":source,
                    "kind":kind,
                    "specifier":specifier,
                    "resolution_status":"resolved",
                    "target_ids":[target],
                    "profile_id":profile_id,
                    "condition":condition,
                    "precision":"exact",
                    "evidence":evidence,
                },
            }),
            serde_json::json!({
                "event":"edge_upsert",
                "edge":{
                    "id":edge_id,
                    "source":source,
                    "target":target,
                    "kind":edge_kind,
                    "site_id":site_id,
                    "phase":"semantic",
                    "environment":"any",
                    "profile_id":profile_id,
                    "condition":condition,
                    "resolution_status":"resolved",
                    "precision":"exact",
                    "generated":false,
                    "evidence":evidence,
                },
            }),
        ]
    };
    let mut payload = vec![serde_json::json!({
        "event":"node_upsert",
        "node":{
            "id":target_file_id,
            "kind":"file",
            "locator":"file://src/target.ts",
            "display_name":"src/target.ts",
            "properties":{
                "path":"src/target.ts",
                "package_id":package_id,
                "language":"typescript",
                "generated":false,
            },
        },
    })];
    payload.extend(dependency(
        "web_import",
        "imports",
        &source_file_id,
        &target_file_id,
        "./target",
        evidence(
            "namespace_import",
            "repository_module",
            1,
            8,
            Some("./target"),
            Some("*"),
        ),
    ));
    payload.extend(dependency(
        "web_reexport",
        "reexports",
        &source_file_id,
        &target_type_id,
        "./target",
        evidence(
            "named_reexport",
            "canonical_definition",
            9,
            18,
            Some("./target"),
            Some("Target"),
        ),
    ));
    payload.extend(dependency(
        "type_use",
        "type_uses",
        &owner_type_id,
        &target_type_id,
        "Target",
        evidence(
            "type_reference",
            "canonical_definition",
            19,
            25,
            None,
            Some("Target"),
        ),
    ));
    let completion_index = events
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    for item in payload.into_iter().rev() {
        events.insert(completion_index, item);
    }
    let relation_count = events
        .iter()
        .filter(|event| event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
        .count();
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["properties"]["typescript_semantic_relation_count"] =
        serde_json::json!(relation_count.to_string());
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = serde_json::json!(3);
            event["coverage"]["resolved"] = serde_json::json!(3);
        }
    }
    for event in &mut events {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    }
    resequence_test_protocol(&mut events);
    serialize_test_protocol(events)
}

fn typescript_call_protocol(root: &Path, gate: &str) -> Result<Vec<u8>> {
    let mut events = test_protocol_values(typescript_definition_protocol(root, gate, "declares")?)?;
    let profile_id = "web:default";
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    let properties = &mut profile["profile"]["properties"];
    properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH);
    properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1);
    properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-import-type-call-graph-emitted");
    properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("1");
    properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("1");

    let package = events
        .iter()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("package node");
    let package_id = package["node"]["id"]
        .as_str()
        .expect("package ID")
        .to_owned();
    let package_locator = package["node"]["properties"]["locator"]
        .as_str()
        .expect("package locator")
        .to_owned();
    let source_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let target_symbol_id = events
        .iter()
        .find(|event| event["node"]["properties"]["symbol_kind"] == "function")
        .expect("target function")["node"]["id"]
        .as_str()
        .expect("target function ID")
        .to_owned();
    let initializer_span = serde_json::json!({
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":9,
    });
    let variable_resolver_identity =
        format!("{package_locator}::module:src/index.ts#callFixtureVariable");
    let variable_identity = serde_json::json!({
        "language":"typescript",
        "package_locator":package_locator,
        "symbol_kind":"variable",
        "identity_kind":"named",
        "resolver_identity":variable_resolver_identity,
    });
    let variable_symbol_id = depgraph_protocol::stable_id_from_value("symbol", &variable_identity);
    let variable_node = serde_json::json!({
        "event":"node_upsert",
        "node":{
            "id":variable_symbol_id,
            "kind":"symbol",
            "locator":format!("typescript-symbol:{variable_symbol_id}"),
            "display_name":"callFixtureVariable",
            "properties":{
                "language":"typescript",
                "package_locator":package_locator,
                "package_id":package_id,
                "symbol_kind":"variable",
                "canonical_identity":variable_identity,
                "resolver_identity":variable_resolver_identity,
                "profile_id":profile_id,
                "source_path":"src/index.ts",
                "source_span":initializer_span,
            },
        },
    });
    let initializer_identity = serde_json::json!({
        "language":"typescript",
        "package_locator":package_locator,
        "symbol_kind":"generated_module_initializer",
        "identity_kind":"generated",
        "generated_from":source_file_id,
        "relative_path":"src/index.ts",
        "span":initializer_span,
    });
    let initializer_id = depgraph_protocol::stable_id_from_value("symbol", &initializer_identity);
    let initializer_node = serde_json::json!({
        "event":"node_upsert",
        "node":{
            "id":initializer_id,
            "kind":"symbol",
            "locator":format!("typescript-symbol:{initializer_id}"),
            "display_name":"<module initializer>",
            "properties":{
                "language":"typescript",
                "package_locator":package_locator,
                "package_id":package_id,
                "symbol_kind":"generated_module_initializer",
                "canonical_identity":initializer_identity,
                "profile_id":profile_id,
                "source_path":"src/index.ts",
                "source_span":initializer_span,
                "generated":true,
            },
        },
    });
    let condition = serde_json::json!({"op":"all","conditions":[]});
    let definition_evidence = serde_json::json!({
        "kind":"semantic",
        "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":9,
        "detail":"TypeChecker generated module initializer",
        "properties":{"profile_id":profile_id},
    });
    let declares_id = depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "condition":condition,
            "kind":"declares",
            "path":"src/index.ts",
            "profile_id":profile_id,
            "source":source_file_id,
            "span":initializer_span,
            "target":initializer_id,
        }),
    );
    let declares = serde_json::json!({
        "event":"edge_upsert",
        "edge":{
            "id":declares_id,
            "source":source_file_id,
            "target":initializer_id,
            "kind":"declares",
            "phase":"semantic",
            "environment":"any",
            "profile_id":profile_id,
            "condition":condition,
            "resolution_status":"resolved",
            "precision":"exact",
            "generated":true,
            "evidence":[definition_evidence],
        },
    });
    let variable_definition_evidence = serde_json::json!({
        "kind":"semantic",
        "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":9,
        "detail":"TypeChecker variable declaration",
        "properties":{"profile_id":profile_id},
    });
    let variable_declares_id = depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "condition":condition,
            "kind":"declares",
            "path":"src/index.ts",
            "profile_id":profile_id,
            "source":source_file_id,
            "span":initializer_span,
            "target":variable_symbol_id,
        }),
    );
    let variable_declares = serde_json::json!({
        "event":"edge_upsert",
        "edge":{
            "id":variable_declares_id,
            "source":source_file_id,
            "target":variable_symbol_id,
            "kind":"declares",
            "phase":"semantic",
            "environment":"any",
            "profile_id":profile_id,
            "condition":condition,
            "resolution_status":"resolved",
            "precision":"exact",
            "generated":false,
            "evidence":[variable_definition_evidence],
        },
    });
    let call_evidence = serde_json::json!([{
        "kind":"semantic",
        "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":9,
        "detail":"TypeChecker resolved-signature direct call occurrence",
        "properties":{
            "backend":TYPESCRIPT_SEMANTIC_BACKEND,
            "compiler_source":"bundled",
            "compiler_version":TYPESCRIPT_COMPILER_VERSION,
            "analysis_mode":TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            "profile_id":profile_id,
            "project_code_executed":false,
            "occurrence_kind":"call_expression",
            "target_basis":"canonical_definition",
            "call_kind":"function",
            "dispatch":"direct",
        },
    }, {
        "kind":"source",
        "extractor":"typescript-native-syntax",
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":9,
        "detail":"syntax call occurrence",
        "properties":{
            "profile_id":profile_id,
            "occurrence_kind":"call_expression",
        },
    }]);
    let call_site_id = depgraph_protocol::stable_id_from_value(
        "site",
        &serde_json::json!({
            "condition":condition,
            "kind":"call",
            "path":"src/index.ts",
            "profile_id":profile_id,
            "source":initializer_id,
            "span":initializer_span,
        }),
    );
    let call_edge_id = depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "kind":"calls",
            "site_id":call_site_id,
            "target":target_symbol_id,
        }),
    );
    let call_site = serde_json::json!({
        "event":"dependency_site",
        "site":{
            "id":call_site_id,
            "source":initializer_id,
            "kind":"call",
            "specifier":"Definition()",
            "resolution_status":"resolved",
            "target_ids":[target_symbol_id],
            "profile_id":profile_id,
            "condition":condition,
            "precision":"exact",
            "evidence":call_evidence,
        },
    });
    let call_edge = serde_json::json!({
        "event":"edge_upsert",
        "edge":{
            "id":call_edge_id,
            "source":initializer_id,
            "target":target_symbol_id,
            "kind":"calls",
            "site_id":call_site_id,
            "phase":"semantic",
            "environment":"any",
            "profile_id":profile_id,
            "condition":condition,
            "resolution_status":"resolved",
            "precision":"exact",
            "generated":false,
            "evidence":call_evidence,
        },
    });
    let completion_index = events
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    for item in [
        initializer_node,
        declares,
        variable_node,
        variable_declares,
        call_site,
        call_edge,
    ]
    .into_iter()
    .rev()
    {
        events.insert(completion_index, item);
    }
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["properties"]["typescript_semantic_node_count"] = serde_json::json!("3");
    profile["profile"]["properties"]["typescript_semantic_relation_count"] = serde_json::json!("4");
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = serde_json::json!(1);
            event["coverage"]["resolved"] = serde_json::json!(1);
        }
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    }
    resequence_test_protocol(&mut events);
    serialize_test_protocol(events)
}

fn promote_typescript_semantic_complete(events: &mut [Value], gate: &str) {
    let standard_library_integrity = match gate {
        TYPESCRIPT_RELEASE_GATE_PENDING => "build-produced-pending-core-attestation",
        TYPESCRIPT_RELEASE_GATE_VERIFIED => "core-attested-whole-tree",
        unexpected => panic!("unsupported TypeScript release gate {unexpected:?}"),
    };
    {
        let profile = events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration");
        profile["profile"]["features"] = serde_json::json!([]);
        let properties = &mut profile["profile"]["properties"];
        for (property, value) in [
            ("bundled_typescript", "true"),
            ("typescript_syntax_compiler", "native-7.0.2"),
            ("typescript_compiler_source", "bundled"),
            ("typescript_compiler_version", TYPESCRIPT_COMPILER_VERSION),
            ("typescript_compiler_selection", "bundled-only"),
            ("typescript_compiler_fallback", "fail-closed"),
            (
                TYPESCRIPT_ANALYSIS_MODE_PROPERTY,
                TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_CALL_GRAPH,
            ),
            ("typescript_project_local_policy", "metadata-only"),
            ("typescript_project_local_loaded", "false"),
            (
                TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY,
                "definition-import-type-call-graph-emitted",
            ),
            (TYPESCRIPT_PROJECT_STATUS_PROPERTY, "ready"),
            ("typescript_project_model_failure_reason", "none"),
            ("typescript_project_config", "worker-neutral-allowlist"),
            ("typescript_module_resolution", "inventory-only"),
            ("typescript_standard_library_source", "bundled"),
            (
                "typescript_standard_library_integrity",
                standard_library_integrity,
            ),
            (TYPESCRIPT_RELEASE_GATE_PROPERTY, gate),
            (
                TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY,
                TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
            ),
            ("typescript_compiler_processes", "1"),
            ("typescript_project_filesystem", "isolated-virtual"),
            (TYPESCRIPT_DEFINITION_STATUS_PROPERTY, "ready"),
            ("typescript_semantic_diagnostics", "0"),
            ("typescript_emitted_semantic_diagnostics", "0"),
            ("typescript_semantic_issue_count", "0"),
            ("project_code_executed", "false"),
        ] {
            properties[property] = serde_json::json!(value);
        }
        if properties
            .get(TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY)
            .is_none()
        {
            properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        }
        if properties
            .get(TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY)
            .is_none()
        {
            properties[TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        }
    }
    for event in events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["completeness"] =
                serde_json::json!(["syntax-complete", "semantic-complete"]);
            event["coverage"]["files_skipped"] = serde_json::json!(0);
            event["coverage"]["unsupported_syntax"] = serde_json::json!(0);
            event["coverage"]["unresolved"] = serde_json::json!(0);
            event["coverage"]["project_code_executed"] = serde_json::json!(false);
            event["coverage"]["reasons"] = serde_json::json!([]);
        }
    }
}

fn recanonicalize_typescript_call(events: &mut [Value]) {
    let site_index = events
        .iter()
        .position(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("call site");
    let source = events[site_index]["site"]["source"]
        .as_str()
        .expect("call source")
        .to_owned();
    let target = events[site_index]["site"]["target_ids"][0]
        .as_str()
        .expect("call target")
        .to_owned();
    let profile_id = events[site_index]["site"]["profile_id"]
        .as_str()
        .expect("call profile")
        .to_owned();
    let condition = events[site_index]["site"]["condition"].clone();
    let primary = &events[site_index]["site"]["evidence"][0];
    let path = primary["path"].as_str().expect("call evidence path");
    let span = serde_json::json!({
        "start_line":primary["start_line"],
        "start_column":primary["start_column"],
        "end_line":primary["end_line"],
        "end_column":primary["end_column"],
    });
    let site_id = depgraph_protocol::stable_id_from_value(
        "site",
        &serde_json::json!({
            "condition":condition,
            "kind":"call",
            "path":path,
            "profile_id":profile_id,
            "source":source,
            "span":span,
        }),
    );
    events[site_index]["site"]["id"] = serde_json::json!(site_id);

    let edge = events
        .iter_mut()
        .find(|event| {
            event["event"] == "edge_upsert"
                && matches!(event["edge"]["kind"].as_str(), Some("calls" | "may_call"))
        })
        .expect("call edge");
    let edge_kind = edge["edge"]["kind"]
        .as_str()
        .expect("call edge kind")
        .to_owned();
    edge["edge"]["source"] = serde_json::json!(source);
    edge["edge"]["target"] = serde_json::json!(target);
    edge["edge"]["site_id"] = serde_json::json!(site_id);
    edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "kind":edge_kind,
            "site_id":site_id,
            "target":target,
        }),
    ));
}

fn configure_typescript_candidate_call(events: &mut Vec<Value>, emission: &str) {
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["properties"][TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(emission);

    let package = events
        .iter()
        .find(|event| {
            event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
        })
        .expect("package node");
    let package_id = package["node"]["id"]
        .as_str()
        .expect("package ID")
        .to_owned();
    let package_locator = package["node"]["properties"]["locator"]
        .as_str()
        .expect("package locator")
        .to_owned();
    let source_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let candidate_span = serde_json::json!({
        "start_line": 1,
        "start_column": 10,
        "end_line": 1,
        "end_column": 25,
    });
    let candidate_resolver = format!("{package_locator}::module:src/index.ts#candidateTarget");
    let candidate_identity = serde_json::json!({
        "language": "typescript",
        "package_locator": package_locator,
        "symbol_kind": "function",
        "identity_kind": "named",
        "resolver_identity": candidate_resolver,
    });
    let candidate_target_id =
        depgraph_protocol::stable_id_from_value("symbol", &candidate_identity);
    let candidate_node = serde_json::json!({
        "protocol_version": "1.0",
        "scan_id": "typescript-gate-scan",
        "adapter": "web",
        "adapter_version": env!("CARGO_PKG_VERSION"),
        "event": "node_upsert",
        "node": {
            "id": candidate_target_id,
            "kind": "symbol",
            "locator": format!("typescript-symbol:{candidate_target_id}"),
            "display_name": "candidateTarget",
            "properties": {
                "language": "typescript",
                "package_locator": package_locator,
                "package_id": package_id,
                "symbol_kind": "function",
                "canonical_identity": candidate_identity,
                "resolver_identity": candidate_resolver,
                "profile_id": "web:default",
                "source_path": "src/index.ts",
                "source_span": candidate_span,
            },
        },
    });
    let candidate_declaration_evidence = serde_json::json!({
        "kind": "semantic",
        "extractor": TYPESCRIPT_SEMANTIC_EXTRACTOR,
        "extractor_version": TYPESCRIPT_COMPILER_VERSION,
        "path": "src/index.ts",
        "start_line": 1,
        "start_column": 10,
        "end_line": 1,
        "end_column": 25,
        "detail": "TypeChecker candidate function declaration",
        "properties": {"profile_id": "web:default"},
    });
    let candidate_declaration_id = depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "condition": {"op":"all","conditions":[]},
            "kind": "declares",
            "path": "src/index.ts",
            "profile_id": "web:default",
            "source": source_file_id,
            "span": candidate_span,
            "target": candidate_target_id,
        }),
    );
    let candidate_declaration = serde_json::json!({
        "protocol_version": "1.0",
        "scan_id": "typescript-gate-scan",
        "adapter": "web",
        "adapter_version": env!("CARGO_PKG_VERSION"),
        "event": "edge_upsert",
        "edge": {
            "id": candidate_declaration_id,
            "source": source_file_id,
            "target": candidate_target_id,
            "kind": "declares",
            "phase": "semantic",
            "environment": "any",
            "profile_id": "web:default",
            "condition": {"op":"all","conditions":[]},
            "resolution_status": "resolved",
            "precision": "exact",
            "generated": false,
            "evidence": [candidate_declaration_evidence],
        },
    });
    let call_site_index = events
        .iter()
        .position(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("call site");
    events.insert(call_site_index, candidate_node);
    events.insert(call_site_index + 1, candidate_declaration);

    let call_site_index = events
        .iter()
        .position(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("call site");
    let existing_target_id = events[call_site_index]["site"]["target_ids"][0]
        .as_str()
        .expect("existing candidate target")
        .to_owned();
    let mut target_ids = vec![existing_target_id, candidate_target_id];
    target_ids.sort();
    events[call_site_index]["site"]["target_ids"] = serde_json::json!(target_ids);
    events[call_site_index]["site"]["resolution_status"] = serde_json::json!("candidates");
    events[call_site_index]["site"]["precision"] = serde_json::json!("overapprox");
    let call_site_id = events[call_site_index]["site"]["id"]
        .as_str()
        .expect("call site ID")
        .to_owned();
    mutate_semantic_primary_properties(events, "call", |properties| {
        properties["dispatch"] = serde_json::json!("dynamic");
        properties["algorithm"] = serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM);
    });
    let call_edge_index = events
        .iter()
        .position(|event| {
            event["event"] == "edge_upsert"
                && event["edge"]["site_id"] == call_site_id
                && event["edge"]["kind"] == "calls"
        })
        .expect("calls edge");
    events[call_edge_index]["edge"]["kind"] = serde_json::json!("may_call");
    events[call_edge_index]["edge"]["resolution_status"] = serde_json::json!("candidates");
    events[call_edge_index]["edge"]["precision"] = serde_json::json!("overapprox");
    recanonicalize_typescript_call(events);

    let call_edge_index = events
        .iter()
        .position(|event| {
            event["event"] == "edge_upsert"
                && event["edge"]["site_id"] == call_site_id
                && event["edge"]["kind"] == "may_call"
        })
        .expect("first may_call edge");
    let mut additional_edge = events[call_edge_index].clone();
    let second_target_id = events[call_site_index]["site"]["target_ids"][1]
        .as_str()
        .expect("second candidate target")
        .to_owned();
    additional_edge["edge"]["target"] = serde_json::json!(second_target_id);
    additional_edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "kind": "may_call",
            "site_id": call_site_id,
            "target": second_target_id,
        }),
    ));
    events.insert(call_edge_index + 1, additional_edge);

    for event in events.iter_mut() {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = serde_json::json!(1);
            event["coverage"]["resolved"] = serde_json::json!(0);
            event["coverage"]["candidates"] = serde_json::json!(1);
            event["coverage"]["external"] = serde_json::json!(0);
            event["coverage"]["unresolved"] = serde_json::json!(0);
        }
    }
    sync_test_semantic_counts(events);
    resequence_test_protocol(events);
}

fn test_protocol_values(output: Vec<u8>) -> Result<Vec<Value>> {
    Ok(String::from_utf8(output)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?)
}

fn serialize_test_protocol(events: Vec<Value>) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for event in events {
        serde_json::to_writer(&mut output, &event)?;
        output.push(b'\n');
    }
    Ok(output)
}

fn mutate_semantic_primary_properties(
    events: &mut [Value],
    site_kind: &str,
    mut mutation: impl FnMut(&mut Value),
) {
    let site_id = events
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == site_kind)
        .unwrap_or_else(|| panic!("missing {site_kind} site"))["site"]["id"]
        .as_str()
        .expect("semantic site ID")
        .to_owned();
    for event in events {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            mutation(&mut event["site"]["evidence"][0]["properties"]);
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            mutation(&mut event["edge"]["evidence"][0]["properties"]);
        }
    }
}

fn rehash_test_definition_edge(edge: &mut Value) {
    let evidence = edge["evidence"][0].clone();
    let identity = serde_json::json!({
        "condition": edge["condition"].clone(),
        "kind": edge["kind"].clone(),
        "path": evidence["path"].clone(),
        "profile_id": edge["profile_id"].clone(),
        "source": edge["source"].clone(),
        "span": {
            "end_column": evidence["end_column"].clone(),
            "end_line": evidence["end_line"].clone(),
            "start_column": evidence["start_column"].clone(),
            "start_line": evidence["start_line"].clone(),
        },
        "target": edge["target"].clone(),
    });
    edge["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value("edge", &identity));
}

fn refresh_test_semantic_node_id(events: &mut [Value], node_index: usize) -> String {
    let (old_id, new_id) = {
        let node = &mut events[node_index]["node"];
        let old_id = node["id"].as_str().expect("semantic node ID").to_owned();
        let kind = node["kind"]
            .as_str()
            .expect("semantic node kind")
            .to_owned();
        let language = node["properties"]["language"]
            .as_str()
            .expect("semantic node language")
            .to_owned();
        let new_id = depgraph_protocol::stable_id_from_value(
            &kind,
            &node["properties"]["canonical_identity"],
        );
        node["id"] = serde_json::json!(new_id);
        node["locator"] = serde_json::json!(format!("{language}-{kind}:{new_id}"));
        (old_id, new_id)
    };
    for event in events {
        if event["event"] != "edge_upsert" {
            continue;
        }
        let edge = &mut event["edge"];
        let mut changed = false;
        for endpoint in ["source", "target"] {
            if edge[endpoint].as_str() == Some(old_id.as_str()) {
                edge[endpoint] = serde_json::json!(new_id);
                changed = true;
            }
        }
        if changed {
            rehash_test_definition_edge(edge);
        }
    }
    new_id
}

fn rewrite_test_generic_instance(
    events: &mut [Value],
    type_arguments: Value,
    resolver_override: Option<String>,
) -> String {
    let node_index = events
        .iter()
        .position(|event| event["node"]["properties"]["type_kind"] == "generic_instance")
        .expect("generic instance node");
    let node = &mut events[node_index]["node"];
    let generic_origin = node["properties"]["canonical_identity"]["generic_origin"]
        .as_str()
        .expect("generic origin resolver")
        .to_owned();
    let resolver = resolver_override.unwrap_or_else(|| {
        format!(
            "generic:{}",
            serde_json::to_string(&serde_json::json!([generic_origin, type_arguments.clone()]))
                .expect("test generic resolver input serializes")
        )
    });
    node["properties"]["canonical_identity"]["type_arguments"] = type_arguments.clone();
    node["properties"]["canonical_identity"]["resolver_identity"] = serde_json::json!(resolver);
    node["properties"]["type_arguments"] = type_arguments;
    node["properties"]["resolver_identity"] = serde_json::json!(resolver);
    refresh_test_semantic_node_id(events, node_index)
}

fn resequence_test_protocol(events: &mut [Value]) {
    for (index, event) in events.iter_mut().enumerate() {
        event["seq"] = serde_json::json!(index + 1);
    }
}

fn sync_test_semantic_counts(events: &mut [Value]) {
    let node_count = events
        .iter()
        .filter(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
        .count();
    let relation_count = events
        .iter()
        .filter(|event| event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
        .count();
    let profile = events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration");
    profile["profile"]["properties"]["typescript_semantic_node_count"] =
        serde_json::json!(node_count.to_string());
    profile["profile"]["properties"]["typescript_semantic_relation_count"] =
        serde_json::json!(relation_count.to_string());
}

fn profile_protocol(
    root: &Path,
    scan_id: &str,
    adapter: &str,
    properties: Value,
) -> Result<Vec<u8>> {
    let coverage = serde_json::json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 0,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": [],
    });
    let profile_id = format!("{adapter}:default");
    let events = [
        serde_json::json!({
            "event": "scan_started",
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": adapter,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 1,
            "root": root.to_string_lossy(),
            "project_code_executed": false,
            "safe_mode": true,
        }),
        serde_json::json!({
            "event": "profile_declared",
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": adapter,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 2,
            "profile": {
                "id": profile_id,
                "language": adapter,
                "properties": properties,
            },
        }),
        serde_json::json!({
            "event": "profile_completed",
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": adapter,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 3,
            "profile_id": profile_id,
            "coverage": coverage,
        }),
        serde_json::json!({
            "event": "scan_completed",
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": adapter,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 4,
            "coverage": coverage,
        }),
    ];
    let mut output = Vec::new();
    for event in events {
        serde_json::to_writer(&mut output, &event)?;
        output.push(b'\n');
    }
    Ok(output)
}

#[test]
fn normalizes_windows_verbatim_paths_for_external_runtimes() {
    let wide = |value: &str| value.encode_utf16().collect::<Vec<_>>();
    let text = |value: Vec<u16>| String::from_utf16(&value).unwrap();

    assert_eq!(
        text(without_windows_verbatim_prefix(&wide(
            r"\\?\C:\release\libexec\worker.mjs"
        ))),
        r"C:\release\libexec\worker.mjs"
    );
    assert_eq!(
        text(without_windows_verbatim_prefix(&wide(
            r"\\?\UNC\server\share\worker.mjs"
        ))),
        r"\\server\share\worker.mjs"
    );
    assert_eq!(
        text(without_windows_verbatim_prefix(&wide(
            r"C:\release\libexec\worker.mjs"
        ))),
        r"C:\release\libexec\worker.mjs"
    );
}

#[test]
fn detects_workspace_markers_without_build_directories() -> Result<()> {
    let temp = tempfile::tempdir()?;
    std::fs::write(temp.path().join("Cargo.toml"), "[workspace]")?;
    std::fs::create_dir(temp.path().join("node_modules"))?;
    std::fs::write(temp.path().join("node_modules/package.json"), "{}")?;
    assert_eq!(
        detect_adapters(temp.path(), false)?,
        vec![AdapterKind::Rust]
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn detects_symlinked_workspace_markers_for_worker_confinement_reporting() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    std::fs::write(
        outside.path().join("go.mod"),
        "module outside.example/test\n",
    )?;
    symlink(outside.path().join("go.mod"), temp.path().join("go.mod"))?;

    assert_eq!(
        detect_adapters(temp.path(), false)?,
        vec![AdapterKind::Go],
        "the adapter must run so its ledger can report the confined skip"
    );
    Ok(())
}

#[test]
fn rejects_unknown_and_out_of_order_events() {
    let root = Path::new("/tmp/project");
    let output = br#"{"event":"scan_started","protocol_version":"1.0","scan_id":"s","adapter":"web","adapter_version":"0.1.0","seq":1}
{"event":"mystery","protocol_version":"1.0","scan_id":"s","adapter":"web","adapter_version":"0.1.0","seq":2}
"#;
    assert!(parse_and_validate_events(output, "s", "web", root, 1024).is_err());
}

#[test]
fn recognizes_security_failures_for_exit_code_mapping() {
    assert!(is_security_error(
        "safe-mode scan reports project_code_executed=true"
    ));
    assert!(is_security_error(
        "protocol path ../secret escapes scan root /project"
    ));
    assert!(!is_security_error("worker timed out"));
    assert!(!is_security_error(
        "failed to start /tmp/security policy/checksum mismatch/worker"
    ));
}

#[test]
fn protocol_values_cannot_spoof_security_classification() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = format!(
        "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"security policy\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
        serde_json::to_string(&root.to_string_lossy())?
    );
    let parsed =
        parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn retains_a_valid_prefix_before_malformed_output() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = format!(
        "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n{{\"event\":\"node_upsert\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":2,\"node\":{{\"id\":\"file:one\",\"kind\":\"file\",\"locator\":\"file://one\",\"properties\":{{}}}}}}\nnot-json\n",
        serde_json::to_string(&root.to_string_lossy())?
    );
    let parsed =
        parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
    assert_eq!(parsed.events.len(), 2);
    assert!(parsed.error.unwrap().contains("malformed NDJSON"));
    assert!(parse_and_validate_events(output.as_bytes(), "s", "go", &root, 4096).is_err());
    Ok(())
}

#[test]
fn normal_scan_rejects_an_unsafe_worker_declaration() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = format!(
        "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":true,\"safe_mode\":false}}\n",
        serde_json::to_string(&root.to_string_lossy())?
    );
    let parsed =
        parse_events_preserving_prefix(output.as_bytes(), "s", "go", &root, 4096, None, None);
    let error = parsed.error.unwrap();
    assert!(error.contains("security policy"));
    assert!(is_security_error(&error));
    assert!(parsed.events.is_empty());
    Ok(())
}

#[test]
fn bundled_workers_are_confined_and_checksum_verified() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    let spec = locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)?;
    assert_eq!(spec.artifact_path, test_release.go_worker.canonicalize()?);

    std::fs::write(&test_release.go_worker, b"tampered")?;
    assert!(
        locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest)
            .unwrap_err()
            .to_string()
            .contains("checksum mismatch")
    );
    Ok(())
}

#[test]
fn bundled_workers_require_the_exact_bounded_query_contract_fixture() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for mutation in ["path", "version", "missing", "tampered"] {
        let release = temp.path().join(mutation);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        match mutation {
            "path" => update_test_manifest(&test_release.manifest, |manifest| {
                manifest["query_fixture"]["path"] = Value::String("queries/other.query".to_owned());
                Ok(())
            })?,
            "version" => update_test_manifest(&test_release.manifest, |manifest| {
                manifest["compatibility"]["bounded_query"]["result_schema_version"] =
                    Value::String("bounded-query-result-v2".to_owned());
                Ok(())
            })?,
            "missing" => {
                std::fs::remove_file(release.join(BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH))?
            }
            "tampered" => std::fs::write(
                release.join(BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH),
                b"tampered query",
            )?,
            _ => unreachable!(),
        }
        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(
            error.to_string().contains("bounded query")
                || error.to_string().contains("compatibility")
                || error.to_string().contains("checksum mismatch")
                || error.to_string().contains("failed to canonicalize"),
            "{mutation}: {error:#}"
        );
    }
    Ok(())
}

#[test]
fn bundled_workers_require_the_cross_language_capability_and_artifact_closure() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for mutation in [
        "capability",
        "fixture-missing",
        "fixture-tampered",
        "schema-missing",
    ] {
        let release = temp.path().join(mutation);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        match mutation {
            "capability" => update_test_manifest(&test_release.manifest, |manifest| {
                manifest["compatibility"]["cross_language"]["capabilities"]
                    .as_array_mut()
                    .context("test manifest has no cross-language capabilities")?
                    .pop();
                Ok(())
            })?,
            "fixture-missing" => std::fs::remove_file(
                release.join(crate::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH),
            )?,
            "fixture-tampered" => std::fs::write(
                release.join(crate::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH),
                b"tampered fixture",
            )?,
            "schema-missing" => {
                std::fs::remove_file(release.join(depgraph_protocol::CROSS_LANGUAGE_SCHEMA_PATH))?
            }
            _ => unreachable!(),
        }
        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(
            error.to_string().contains("cross-language")
                || error.to_string().contains("compatibility")
                || error.to_string().contains("checksum mismatch")
                || error.to_string().contains("failed to canonicalize"),
            "{mutation}: {error:#}"
        );
    }
    Ok(())
}

#[test]
fn bundled_workers_require_exact_project_license_metadata_and_files() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for mutation in ["expression", "declaration", "missing", "tampered"] {
        let release = temp.path().join(mutation);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        match mutation {
            "expression" => update_test_manifest(&test_release.manifest, |manifest| {
                manifest["license_expression"] = Value::String("MIT".to_owned());
                Ok(())
            })?,
            "declaration" => update_test_manifest(&test_release.manifest, |manifest| {
                manifest["project_licenses"]
                    .as_array_mut()
                    .context("test manifest has no project licenses")?
                    .pop();
                Ok(())
            })?,
            "missing" => std::fs::remove_file(release.join("LICENSE-MIT"))?,
            "tampered" => std::fs::write(release.join("LICENSE-APACHE"), b"tampered")?,
            _ => unreachable!(),
        }

        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(
            error.to_string().contains("project license")
                || error.to_string().contains("checksum mismatch"),
            "{mutation}: {error:#}"
        );
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn packaged_layout_without_manifest_is_detected() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let bin = temp.path().join("bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::create_dir_all(temp.path().join("libexec"))?;
    assert!(looks_like_packaged_layout(&bin));
    assert!(!looks_like_packaged_layout(temp.path()));
    Ok(())
}

#[test]
fn parses_runtime_versions_strictly() {
    assert_eq!(parse_version_triplet("24.18.0"), Some((24, 18, 0)));
    assert_eq!(parse_version_triplet("24.18.0-rc.1"), Some((24, 18, 0)));
    assert_eq!(parse_version_triplet("24.18"), None);
    assert_eq!(parse_version_triplet("latest"), None);
}

#[test]
fn safe_path_drops_relative_repository_and_symlinked_repository_entries() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("project");
    let safe = temp.path().join("safe-bin");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&safe)?;
    let entries = vec![PathBuf::from("."), root.clone(), safe.clone()];
    #[cfg(unix)]
    let entries = {
        let mut entries = entries;
        let alias = temp.path().join("project-alias");
        std::os::unix::fs::symlink(&root, &alias)?;
        entries.push(alias);
        entries
    };
    let raw = std::env::join_paths(entries)?;
    let sanitized = sanitize_path_value(&raw, &root)?;
    let paths = std::env::split_paths(&sanitized).collect::<Vec<_>>();
    assert_eq!(paths, vec![safe.canonicalize()?]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn unverified_development_worker_inside_scan_root_is_rejected() -> Result<()> {
    let root = tempfile::tempdir()?;
    let worker = root.path().join("depgraph-go-worker");
    std::fs::write(&worker, "#!/bin/sh\nexit 0\n")?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: worker.clone().into_os_string(),
        leading_args: Vec::new(),
        display: worker.display().to_string(),
        artifact_path: worker,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };

    let error = resolve_worker_program(&spec, root.path()).unwrap_err();
    assert!(error.to_string().contains("security policy"));
    Ok(())
}

#[test]
fn packaged_web_worker_requires_the_astro_runtime_component() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["runtime_components"]
            .as_array_mut()
            .context("test manifest has no runtime components")?
            .retain(|component| component["name"] != "astro-parser-wasm");
        Ok(())
    })?;
    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("astro-parser-wasm"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn packaged_web_worker_requires_the_typescript_runtime_component() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["runtime_components"]
            .as_array_mut()
            .context("test manifest has no runtime components")?
            .retain(|component| component["name"] != "typescript-native-compiler");
        Ok(())
    })?;
    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("typescript-native-compiler"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn packaged_release_requires_the_pinned_rust_sysroot_source_component() -> Result<()> {
    for mutation in ["missing", "version", "root", "entrypoint", "license"] {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join(mutation);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            let components = manifest["runtime_components"]
                .as_array_mut()
                .context("test manifest has no runtime components")?;
            if mutation == "missing" {
                components.retain(|component| component["name"] != RUST_SYSROOT_COMPONENT_NAME);
                return Ok(());
            }
            let replacement_sha256 = (mutation == "root")
                .then(|| {
                    components
                        .iter()
                        .find(|component| component["name"] == "astro-parser-wasm")
                        .map(|component| component["sha256"].clone())
                })
                .flatten();
            let component = components
                .iter_mut()
                .find(|component| component["name"] == RUST_SYSROOT_COMPONENT_NAME)
                .context("test manifest has no Rust sysroot component")?;
            component[mutation] = serde_json::json!(match mutation {
                "version" => "0.0.0+wrong-rustc",
                "root" => "libexec/astro",
                "entrypoint" => "libexec/rust-sysroot/library/core/src/lib.rs",
                "license" => "NOASSERTION",
                _ => unreachable!(),
            });
            if let Some(sha256) = replacement_sha256 {
                component["sha256"] = sha256;
            }
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(
            error.to_string().contains("Rust sysroot"),
            "{mutation}: {error:#}"
        );
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn packaged_release_requires_the_runtime_collector_artifact() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["runtime_artifacts"]
            .as_array_mut()
            .context("test manifest has no runtime artifacts")?
            .retain(|artifact| artifact["path"] != "libexec/depgraph-runtime-collector.mjs");
        Ok(())
    })?;
    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("artifact closure"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn packaged_web_worker_requires_the_exact_semantic_attestation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for mutation in [
        "missing",
        "capability",
        "component",
        "artifact",
        "typescript",
    ] {
        let release = temp.path().join(mutation);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            let web = manifest["workers"]
                .as_array_mut()
                .context("test manifest has no workers array")?
                .iter_mut()
                .find(|worker| worker["adapter"] == "web")
                .context("test manifest has no Web worker")?;
            match mutation {
                "missing" => {
                    web.as_object_mut()
                        .context("Web worker is not an object")?
                        .remove("semantic");
                }
                "capability" => {
                    web["semantic"]["capabilities"][0] = serde_json::json!("unknown-capability-v1")
                }
                "component" => {
                    web["semantic"]["runtime_components"][0] =
                        serde_json::json!("system-typescript")
                }
                "artifact" => {
                    web["semantic"]["runtime_artifacts"] = serde_json::json!(["system-astro.wasm"])
                }
                "typescript" => web["semantic"]["typescript_version"] = serde_json::json!("9.9.9"),
                _ => unreachable!(),
            }
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
        assert!(
            error.to_string().contains("semantic"),
            "{mutation}: {error:#}"
        );
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn rust_preflight_requires_the_web_runtime_requirement() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["runtime_requirements"]
            .as_object_mut()
            .context("test manifest has no runtime requirement object")?
            .remove("web");
        Ok(())
    })?;

    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("Web runtime requirement"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn packaged_web_runtime_requirement_must_match_the_compatibility_unit() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["runtime_requirements"]["web"] = Value::String("Node.js >=23.0.0".to_owned());
        Ok(())
    })?;

    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains(WEB_RUNTIME_REQUIREMENT));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn every_packaged_worker_version_must_match_the_core() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for adapter in ["go", "web"] {
        let release = temp.path().join(adapter);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            let worker = manifest["workers"]
                .as_array_mut()
                .context("test manifest has no workers array")?
                .iter_mut()
                .find(|worker| worker["adapter"] == adapter)
                .with_context(|| format!("test manifest has no {adapter} worker"))?;
            worker["version"] = Value::String("9.9.9".to_owned());
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains("does not match core version"));
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn every_packaged_worker_path_must_match_its_adapter_identity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for (adapter, invalid_path) in [
        (
            "rust",
            format!("libexec/{}", executable_name("depgraph-go-worker")),
        ),
        (
            "go",
            format!("libexec/{}", executable_name("depgraph-rust-worker")),
        ),
        ("web", "libexec/astro/astro.wasm".to_owned()),
    ] {
        let release = temp.path().join(adapter);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            let worker = manifest["workers"]
                .as_array_mut()
                .context("test manifest has no workers array")?
                .iter_mut()
                .find(|worker| worker["adapter"] == adapter)
                .with_context(|| format!("test manifest has no {adapter} worker"))?;
            worker["path"] = Value::String(invalid_path);
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("{adapter} worker path"))
        );
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn packaged_core_and_schema_paths_are_exact() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for (field, invalid_path) in [
        ("core", "bin/not-depgraph"),
        ("schema", "schemas/not-the-protocol-schema.json"),
    ] {
        let release = temp.path().join(field);
        let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
        update_test_manifest(&test_release.manifest, |manifest| {
            manifest[field]["path"] = Value::String(invalid_path.to_owned());
            Ok(())
        })?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains(&format!("{field} path")));
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn bundled_native_workers_must_be_executable_but_web_is_exempt() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;

    // The helper intentionally leaves the Web .mjs artifact non-executable.
    locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)?;

    for (adapter, worker) in [
        ("rust", &test_release.rust_worker),
        ("go", &test_release.go_worker),
    ] {
        let mut permissions = std::fs::metadata(worker)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(worker, permissions)?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains(&format!("{adapter} worker")));
        assert!(error.to_string().contains("not executable"));
        assert!(is_security_error(&error.to_string()));

        make_test_executable(worker)?;
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn non_rust_worker_cannot_spoof_the_verified_rust_release_gate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("go-worker.sh");
    let scan_id = "cross-adapter-gate-scan";
    let write_protocol_script = |properties: Value| -> Result<()> {
        let output = profile_protocol(&root, scan_id, "go", properties)?;
        let mut contents = b"#!/bin/sh\ncat <<'DEPGRAPH_PROTOCOL'\n".to_vec();
        contents.extend_from_slice(&output);
        contents.extend_from_slice(b"DEPGRAPH_PROTOCOL\n");
        std::fs::write(&script, contents)?;
        make_test_executable(&script)
    };

    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script.clone(),
        runtime_requirement: None,
        expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        release_attested: false,
        attested_rust_sysroot: None,
    };

    write_protocol_script(serde_json::json!({
        "rust_hir_enable_gate": RUST_RELEASE_GATE_VERIFIED,
    }))?;
    let spoofed = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        scan_id,
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(spoofed.events.len(), 1);
    assert_eq!(
        spoofed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(spoofed.security_violation);
    assert!(
        spoofed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("verified Rust release attestation"))
    );

    write_protocol_script(serde_json::json!({
        TYPESCRIPT_RELEASE_GATE_PROPERTY: TYPESCRIPT_RELEASE_GATE_VERIFIED,
    }))?;
    let typescript_spoofed = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        scan_id,
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(typescript_spoofed.events.len(), 1);
    assert_eq!(
        typescript_spoofed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(typescript_spoofed.security_violation);
    assert!(
        typescript_spoofed
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("verified TypeScript release attestation") })
    );

    write_protocol_script(serde_json::json!({"go_list_mode": "safe"}))?;
    let normal = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        scan_id,
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(normal.events.len(), 4);
    assert!(normal.error.is_none(), "{:?}", normal.error);
    assert!(!normal.security_violation);
    Ok(())
}

#[test]
fn typescript_runtime_tree_is_confined_and_checksum_verified() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let typescript = release.join("libexec/typescript/lib");
    std::fs::create_dir_all(&typescript)?;
    let worker = release.join("libexec/depgraph-web-worker.mjs");
    let compiler = typescript.join(executable_name("tsc"));
    let standard_library = typescript.join("lib.d.ts");
    std::fs::write(&worker, b"verified worker")?;
    std::fs::write(&compiler, b"verified compiler")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&compiler)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&compiler, permissions)?;
    }
    std::fs::write(&standard_library, b"verified standard library")?;
    let digest = runtime_tree_digest(&typescript)?;
    let component = serde_json::json!({
        "name":"typescript-native-compiler",
        "version":"7.0.2",
        "kind":"executable-tree",
        "root":"libexec/typescript/lib",
        "entrypoint":format!("libexec/typescript/lib/{}", executable_name("tsc")),
        "license":"Apache-2.0",
        "sha256":digest
    });
    let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;
    let web_spec = locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest)?;
    assert!(web_spec.release_attested);

    #[cfg(unix)]
    {
        let typescript_parent = release.join("libexec/typescript");
        let moved = release.join("libexec/typescript-real");
        std::fs::rename(&typescript_parent, &moved)?;
        std::os::unix::fs::symlink("typescript-real", &typescript_parent)?;
        let symlinked =
            locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
        assert!(symlinked.to_string().contains("symlink"));
        assert!(is_security_error(&symlinked.to_string()));
        std::fs::remove_file(&typescript_parent)?;
        std::fs::rename(&moved, &typescript_parent)?;

        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&compiler)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&compiler, permissions)?;
        let non_executable =
            locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
        assert!(non_executable.to_string().contains("entrypoint"));
        assert!(is_security_error(&non_executable.to_string()));
        let mut permissions = std::fs::metadata(&compiler)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&compiler, permissions)?;
    }

    std::fs::write(&standard_library, b"tampered")?;
    let tampered =
        locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
    assert!(tampered.to_string().contains("checksum mismatch"));
    assert!(is_security_error(&tampered.to_string()));

    std::fs::write(&standard_library, b"verified standard library")?;
    std::fs::remove_file(&compiler)?;
    let missing =
        locate_verified_bundled_worker(AdapterKind::Web, &test_release.manifest).unwrap_err();
    assert!(missing.to_string().contains("entrypoint"));
    assert!(is_security_error(&missing.to_string()));
    Ok(())
}

#[test]
fn bundled_release_requires_exactly_one_of_each_worker() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    update_test_manifest(&test_release.manifest, |manifest| {
        let workers = manifest["workers"]
            .as_array_mut()
            .context("test manifest has no workers array")?;
        workers.retain(|worker| worker["adapter"] != "web");
        Ok(())
    })?;

    let error =
        locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("has no web worker"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn bundled_release_requires_the_exact_core_compatibility_contract() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;

    update_test_manifest(&test_release.manifest, |manifest| {
        manifest["compatibility"]["store_schema_version"] =
            Value::Number((depgraph_store::STORE_SCHEMA_VERSION + 1).into());
        Ok(())
    })?;
    let drifted =
        locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
    assert!(drifted.to_string().contains("compatibility"));
    assert!(is_security_error(&drifted.to_string()));

    update_test_manifest(&test_release.manifest, |manifest| {
        manifest
            .as_object_mut()
            .context("test manifest is not an object")?
            .remove("compatibility");
        Ok(())
    })?;
    let missing =
        locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
    assert!(missing.to_string().contains("invalid release manifest"));
    assert!(is_security_error(&missing.to_string()));
    Ok(())
}

#[test]
fn rust_backend_manifest_mismatch_is_rejected_before_worker_launch() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let test_release = write_test_release_manifest(&release, Vec::new(), Vec::new())?;
    let spawn_marker = release.join("libexec/rust-worker-spawned");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(
            &test_release.rust_worker,
            "#!/bin/sh\n: > \"${0%/*}/rust-worker-spawned\"\nexit 0\n",
        )?;
        let mut permissions = std::fs::metadata(&test_release.rust_worker)?.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&test_release.rust_worker, permissions)?;
    }
    let rust_digest = hex::encode(Sha256::digest(std::fs::read(&test_release.rust_worker)?));
    update_test_manifest(&test_release.manifest, |manifest| {
        let rust = manifest["workers"]
            .as_array_mut()
            .context("test manifest has no workers array")?
            .iter_mut()
            .find(|worker| worker["adapter"] == "rust")
            .context("test manifest has no Rust worker")?;
        rust["sha256"] = Value::String(rust_digest);
        rust["backend"]["revision"] = Value::String("untrusted-revision".to_owned());
        Ok(())
    })?;

    let error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("backend attestation"));
    assert!(is_security_error(&error.to_string()));
    assert!(
        !spawn_marker.exists(),
        "manifest validation must not launch the worker"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn bundled_release_rejects_symlinked_manifest_root_and_worker() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;

    let manifest_release = temp.path().join("manifest-release");
    let manifest_test = write_test_release_manifest(&manifest_release, Vec::new(), Vec::new())?;
    let real_manifest = manifest_release.join("real-release-manifest.json");
    std::fs::rename(&manifest_test.manifest, &real_manifest)?;
    symlink("real-release-manifest.json", &manifest_test.manifest)?;
    let manifest_error =
        locate_verified_bundled_worker(AdapterKind::Go, &manifest_test.manifest).unwrap_err();
    assert!(manifest_error.to_string().contains("non-symlink"));
    assert!(is_security_error(&manifest_error.to_string()));

    let real_release = temp.path().join("real-release");
    write_test_release_manifest(&real_release, Vec::new(), Vec::new())?;
    let release_alias = temp.path().join("release-alias");
    symlink(&real_release, &release_alias)?;
    let root_error = locate_verified_bundled_worker(
        AdapterKind::Go,
        &release_alias.join("release-manifest.json"),
    )
    .unwrap_err();
    assert!(root_error.to_string().contains("release root"));
    assert!(is_security_error(&root_error.to_string()));

    let worker_release = temp.path().join("worker-release");
    let worker_test = write_test_release_manifest(&worker_release, Vec::new(), Vec::new())?;
    let real_worker = worker_release.join("libexec/real-go-worker");
    std::fs::rename(&worker_test.go_worker, &real_worker)?;
    symlink(&real_worker, &worker_test.go_worker)?;
    let worker_error =
        locate_verified_bundled_worker(AdapterKind::Go, &worker_test.manifest).unwrap_err();
    assert!(worker_error.to_string().contains("symlink"));
    assert!(is_security_error(&worker_error.to_string()));
    Ok(())
}

#[test]
fn data_tree_runtime_component_allows_no_entrypoint_and_verifies_the_whole_tree() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let sysroot = release.join("libexec/rust-release-data");
    let core_source = sysroot.join("library/core/src/lib.rs");
    std::fs::create_dir_all(core_source.parent().context("core source has no parent")?)?;
    std::fs::write(&core_source, b"verified sysroot source")?;
    let component = serde_json::json!({
        "name": "rust-release-data-test",
        "version": RUST_BACKEND_REVISION,
        "kind": "data-tree",
        "root": "libexec/rust-release-data",
        "license": PROJECT_LICENSE_EXPRESSION,
        "sha256": runtime_tree_digest(&sysroot)?,
    });
    let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;
    let spec = locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest)?;
    assert!(spec.release_attested);
    assert_eq!(spec.artifact_path, test_release.rust_worker.canonicalize()?);

    std::fs::write(&core_source, b"tampered sysroot source")?;
    let tampered =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(tampered.to_string().contains("checksum mismatch"));
    assert!(is_security_error(&tampered.to_string()));
    std::fs::write(&core_source, b"verified sysroot source")?;

    let added_directory = sysroot.join("library/undeclared-empty-directory");
    std::fs::create_dir(&added_directory)?;
    let added_directory_error =
        locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
    assert!(
        added_directory_error
            .to_string()
            .contains("checksum mismatch")
    );
    assert!(is_security_error(&added_directory_error.to_string()));
    std::fs::remove_dir(added_directory)?;

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("library/core/src/lib.rs", sysroot.join("core-link.rs"))?;
        let symlinked =
            locate_verified_bundled_worker(AdapterKind::Rust, &test_release.manifest).unwrap_err();
        assert!(symlinked.to_string().contains("symlink"));
        assert!(is_security_error(&symlinked.to_string()));
    }
    Ok(())
}

#[test]
fn runtime_component_requires_non_empty_identity_and_paths() -> Result<()> {
    for (field, value, expected) in [
        ("name", " \t", "name, version, and license"),
        ("version", "\n", "name, version, and license"),
        ("license", "\r", "name, version, and license"),
        ("root", " ", "root must be non-empty"),
        ("entrypoint", "\t", "entrypoint must be non-empty"),
    ] {
        let temp = tempfile::tempdir()?;
        let release = temp.path().join(field);
        let runtime = release.join("libexec/runtime-data");
        std::fs::create_dir_all(&runtime)?;
        std::fs::write(runtime.join("payload"), b"verified runtime data")?;
        let mut component = serde_json::json!({
            "name": "runtime-data",
            "version": "1.0.0",
            "kind": "data-tree",
            "root": "libexec/runtime-data",
            "license": PROJECT_LICENSE_EXPRESSION,
            "sha256": runtime_tree_digest(&runtime)?,
        });
        component[field] = serde_json::json!(value);
        let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;

        let error =
            locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
        assert!(error.to_string().contains(expected));
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn executable_tree_runtime_component_requires_an_entrypoint() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let release = temp.path().join("release");
    let runtime = release.join("libexec/toolchain");
    std::fs::create_dir_all(&runtime)?;
    std::fs::write(runtime.join("tool"), b"verified tool")?;
    let component = serde_json::json!({
        "name": "test-toolchain",
        "version": "1.0.0",
        "kind": "executable-tree",
        "root": "libexec/toolchain",
        "license": PROJECT_LICENSE_EXPRESSION,
        "sha256": runtime_tree_digest(&runtime)?,
    });
    let test_release = write_test_release_manifest(&release, Vec::new(), vec![component])?;

    let error =
        locate_verified_bundled_worker(AdapterKind::Go, &test_release.manifest).unwrap_err();
    assert!(error.to_string().contains("has no entrypoint"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn development_rust_worker_cannot_spoof_the_verified_release_gate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = rust_gate_protocol(&root, RUST_RELEASE_GATE_VERIFIED)?;
    let parsed = parse_events_preserving_prefix(
        &output,
        "rust-gate-scan",
        "rust",
        &root,
        4096,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );

    assert_eq!(parsed.events.len(), 1);
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("without a verified Rust release attestation"))
    );
    Ok(())
}

#[test]
fn attested_rust_worker_must_report_the_verified_success_gate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = rust_gate_protocol(&root, RUST_RELEASE_GATE_PENDING)?;
    let parsed = parse_events_preserving_prefix(
        &output,
        "rust-gate-scan",
        "rust",
        &root,
        4096,
        Some(env!("CARGO_PKG_VERSION")),
        Some(true),
    );

    assert_eq!(parsed.events.len(), 1);
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("reported release-gate-pending"))
    );
    Ok(())
}

#[test]
fn rust_release_gate_allows_matching_and_fallback_profile_values() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (RUST_RELEASE_GATE_PENDING, false),
        (RUST_RELEASE_GATE_VERIFIED, true),
        ("toolchain-unsupported", false),
        ("toolchain-unsupported", true),
        ("semantic-backend-failure", false),
        ("semantic-backend-failure", true),
    ] {
        let output = rust_gate_protocol(&root, gate)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "rust-gate-scan",
            "rust",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(release_attested),
        );
        assert!(
            parsed.error.is_none(),
            "gate {gate:?}, release_attested={release_attested}: {:?}",
            parsed.error
        );
        assert_eq!(parsed.events.len(), 4);
        assert!(!parsed.security_violation);
    }
    Ok(())
}

#[test]
fn development_web_worker_cannot_spoof_the_verified_typescript_release_gate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_VERIFIED)?;
    let parsed = parse_events_preserving_prefix(
        &output,
        "typescript-gate-scan",
        "web",
        &root,
        4096,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );

    assert_eq!(parsed.events.len(), 1);
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(parsed.error.as_deref().is_some_and(|error| {
        error.contains("without a verified TypeScript release attestation")
    }));
    Ok(())
}

#[test]
fn attested_web_worker_must_report_the_verified_typescript_release_gate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
    let parsed = parse_events_preserving_prefix(
        &output,
        "typescript-gate-scan",
        "web",
        &root,
        4096,
        Some(env!("CARGO_PKG_VERSION")),
        Some(true),
    );

    assert_eq!(parsed.events.len(), 1);
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("verified TypeScript release worker"))
    );
    Ok(())
}

#[test]
fn typescript_release_gate_allows_matching_profile_values() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (TYPESCRIPT_RELEASE_GATE_PENDING, false),
        (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
    ] {
        let output = typescript_gate_protocol(&root, gate)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(release_attested),
        );
        assert!(
            parsed.error.is_none(),
            "gate {gate:?}, release_attested={release_attested}: {:?}",
            parsed.error
        );
        assert_eq!(parsed.events.len(), 4);
        assert!(!parsed.security_violation);
    }
    Ok(())
}

#[test]
fn typescript_release_gate_rejects_missing_and_unknown_values() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (None, false),
        (Some("unknown-gate"), false),
        (Some("unknown-gate"), true),
    ] {
        let output =
            typescript_gate_protocol(&root, gate.unwrap_or(TYPESCRIPT_RELEASE_GATE_PENDING))?;
        let mut events = String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if gate.is_none() {
            events[1]["profile"]["properties"]
                .as_object_mut()
                .context("profile properties must be an object")?
                .remove(TYPESCRIPT_RELEASE_GATE_PROPERTY);
        }
        let mut invalid = Vec::new();
        for event in events {
            serde_json::to_writer(&mut invalid, &event)?;
            invalid.push(b'\n');
        }
        let parsed = parse_events_preserving_prefix(
            &invalid,
            "typescript-gate-scan",
            "web",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(release_attested),
        );
        assert_eq!(parsed.events.len(), 1, "gate={gate:?}: {:?}", parsed.error);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(parsed.error.is_some());
    }
    Ok(())
}

#[test]
fn web_worker_requires_the_exact_definition_graph_capability() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for property in [
        TYPESCRIPT_ANALYSIS_MODE_PROPERTY,
        TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY,
    ] {
        for value in [None, Some("unknown-capability")] {
            let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
            let mut events = String::from_utf8(output)?
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if let Some(value) = value {
                events[1]["profile"]["properties"][property] = serde_json::json!(value);
            } else {
                events[1]["profile"]["properties"]
                    .as_object_mut()
                    .context("profile properties must be an object")?
                    .remove(property);
            }
            let mut spoofed = Vec::new();
            for event in events {
                serde_json::to_writer(&mut spoofed, &event)?;
                spoofed.push(b'\n');
            }
            let parsed = parse_events_preserving_prefix(
                &spoofed,
                "typescript-gate-scan",
                "web",
                &root,
                4096,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert_eq!(
                parsed.events.len(),
                1,
                "{property}={value:?}: {:?}",
                parsed.error
            );
            assert_eq!(
                parsed.failure_kind,
                Some(WorkerFailureKind::MalformedProtocol)
            );
            assert!(parsed.security_violation);
            assert!(
                parsed
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains(property)),
                "{property}={value:?}: {:?}",
                parsed.error
            );
        }
    }
    Ok(())
}

#[test]
fn web_definition_graph_capability_accepts_only_the_definition_slice() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (TYPESCRIPT_RELEASE_GATE_PENDING, false),
        (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
    ] {
        for relation_kind in ["declares", "extends", "implements", "instantiates"] {
            let output = typescript_definition_protocol(&root, gate, relation_kind)?;
            let parsed = parse_events_preserving_prefix(
                &output,
                "typescript-gate-scan",
                "web",
                &root,
                16 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(release_attested),
            );
            assert_eq!(parsed.error, None, "{gate}/{relation_kind}");
            assert_eq!(parsed.failure_kind, None, "{gate}/{relation_kind}");
            assert!(!parsed.security_violation, "{gate}/{relation_kind}");
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["kind"] == relation_kind
                    && event["edge"]["phase"] == "semantic"
                    && event["edge"]["site_id"].is_null()
            }));
        }
    }
    Ok(())
}

#[test]
fn web_framework_semantic_capability_accepts_only_the_versioned_contract() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut valid = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    add_framework_semantic_delta(
        &mut valid,
        true,
        "emitted",
        WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
    );
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(valid)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None);
    assert!(!parsed.security_violation);
    assert!(parsed.events.iter().any(|event| {
        event["event"] == "edge_upsert"
            && event["edge"]["kind"] == "route_entry"
            && event["edge"]["phase"] == "semantic"
    }));

    for capability in ["framework-semantic-graph-v2", ""] {
        let mut invalid = test_protocol_values(typescript_gate_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let profile = invalid
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile");
        let properties = &mut profile["profile"]["properties"];
        properties[WEB_FRAMEWORK_SEMANTIC_CAPABILITY_PROPERTY] = serde_json::json!(capability);
        properties[WEB_FRAMEWORK_SEMANTIC_STATUS_PROPERTY] = serde_json::json!("not-emitted");
        properties[WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION_PROPERTY] =
            serde_json::json!(WEB_FRAMEWORK_SEMANTIC_EXTRACTOR_VERSION);
        properties[WEB_FRAMEWORK_SEMANTIC_NODE_COUNT_PROPERTY] = serde_json::json!("0");
        properties[WEB_FRAMEWORK_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
        properties[WEB_FRAMEWORK_SEMANTIC_EDGE_COUNT_PROPERTY] = serde_json::json!("0");
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(invalid)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        assert!(
            parsed.error.as_deref().is_some_and(|error| {
                error.contains("unapproved framework semantic capability")
            })
        );
    }
    Ok(())
}

#[test]
fn web_framework_failure_preserves_syntax_and_typescript_semantic_graph() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut invalid = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    add_framework_semantic_delta(
        &mut invalid,
        false,
        "emitted",
        WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
    );
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(invalid)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(parsed.error.as_deref().is_some_and(|error| {
        error.contains("invalid Web semantic protocol") && error.contains("incompatible target")
    }));
    assert!(parsed.events.iter().any(|event| {
        event["event"] == "node_upsert"
            && matches!(event["node"]["kind"].as_str(), Some("file" | "symbol"))
    }));
    assert!(
        parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["kind"] == "declares"
        })
    );
    assert!(!parsed.events.iter().any(|event| {
        event["event"] == "node_upsert"
            && matches!(
                event["node"]["kind"].as_str(),
                Some("component" | "route" | "server_function" | "middleware")
            )
    }));
    assert!(!parsed.events.iter().any(|event| {
        event["event"] == "dependency_site" && event["site"]["kind"] == "route_entry"
    }));
    let properties = &parsed
        .events
        .iter()
        .find(|event| event["event"] == "profile_declared")
        .expect("preserved Web profile")["profile"]["properties"];
    assert_eq!(
        properties[WEB_FRAMEWORK_COMPLETENESS_STATUS_PROPERTY],
        "incomplete"
    );
    let ledger: Vec<Value> = serde_json::from_str(
        properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY]
            .as_str()
            .expect("framework completeness ledger"),
    )?;
    assert_eq!(ledger[0]["status"], "incomplete");
    assert_eq!(
        ledger[0]["emitted_capabilities"],
        serde_json::json!(["typescript-definition-import-type-call-graph-v2"])
    );
    assert!(ledger[0]["reasons"].as_array().is_some_and(|reasons| {
        reasons
            .iter()
            .any(|reason| reason == "core_framework_delta_discarded")
    }));
    Ok(())
}

#[test]
fn web_framework_completeness_ledger_rejects_claimed_or_mismatched_capabilities() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mutations = [
        serde_json::json!([{
            "framework":"next",
            "required_capabilities":["framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
            "emitted_capabilities":["framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
            "status":"complete",
            "reasons":[]
        }]),
        serde_json::json!([{
            "framework":"next",
            "required_capabilities":["framework-semantic-graph-v1","next-route-component-boundary-v1","typescript-definition-import-type-call-graph-v2"],
            "emitted_capabilities":["framework-semantic-graph-v1","next-route-component-boundary-v1","typescript-definition-import-type-call-graph-v2"],
            "status":"complete",
            "reasons":["collector_delta_discarded"]
        }]),
        serde_json::json!([{
            "framework":"astro",
            "required_capabilities":["astro-component-render-hydration-v1","framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
            "emitted_capabilities":["astro-component-render-hydration-v1","framework-semantic-graph-v1","typescript-definition-import-type-call-graph-v2"],
            "status":"complete",
            "reasons":[]
        }]),
        serde_json::json!([{
            "framework":"next",
            "required_capabilities":["typescript-definition-import-type-call-graph-v2","next-route-component-boundary-v1","framework-semantic-graph-v1"],
            "emitted_capabilities":["typescript-definition-import-type-call-graph-v2","next-route-component-boundary-v1","framework-semantic-graph-v1"],
            "status":"complete",
            "reasons":[]
        }]),
    ];
    for mutation in mutations {
        let mut events = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "declares",
        )?)?;
        add_framework_semantic_delta(
            &mut events,
            true,
            "emitted",
            WEB_FRAMEWORK_SEMANTIC_CAPABILITY_V1,
        );
        let properties = &mut events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile")["profile"]["properties"];
        properties[WEB_FRAMEWORK_COMPLETENESS_LEDGER_PROPERTY] =
            serde_json::json!(mutation.to_string());
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{mutation}"
        );
        assert!(parsed.security_violation, "{mutation}: {:?}", parsed.error);
        assert!(!parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && matches!(event["node"]["kind"].as_str(), Some("component" | "route"))
        }));
    }
    Ok(())
}

#[test]
fn web_import_type_capability_accepts_definition_import_reexport_and_type_use() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (TYPESCRIPT_RELEASE_GATE_PENDING, false),
        (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
    ] {
        let output = typescript_import_type_protocol(&root, gate)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(release_attested),
        );
        assert_eq!(parsed.error, None, "gate={gate:?}");
        assert_eq!(parsed.failure_kind, None, "gate={gate:?}");
        assert!(!parsed.security_violation, "gate={gate:?}");
        for (site_kind, edge_kind) in [
            ("web_import", "imports"),
            ("web_reexport", "reexports"),
            ("type_use", "type_uses"),
        ] {
            let site = parsed
                .events
                .iter()
                .find(|event| {
                    event["event"] == "dependency_site" && event["site"]["kind"] == site_kind
                })
                .unwrap_or_else(|| panic!("missing {site_kind} site"));
            let site_id = site["site"]["id"].as_str().expect("semantic site ID");
            assert!(parsed.events.iter().any(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["kind"] == edge_kind
                    && event["edge"]["site_id"] == site_id
                    && event["edge"]["phase"] == "semantic"
            }));
            assert_eq!(site["site"]["evidence"][0]["kind"], "semantic");
            assert_eq!(site["site"]["evidence"][1]["kind"], "source");
        }
        let type_only_values = parsed
            .events
            .iter()
            .filter(|event| {
                event["event"] == "dependency_site"
                    && event["site"]["evidence"][0]["kind"] == "semantic"
            })
            .filter_map(|event| event["site"]["evidence"][0]["properties"]["type_only"].as_bool())
            .collect::<BTreeSet<_>>();
        assert_eq!(type_only_values, BTreeSet::from([false, true]));
        assert!(!parsed.events.iter().any(|event| {
            event["coverage"]["completeness"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
        }));
    }

    let mut discarded = test_protocol_values(typescript_gate_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let properties = &mut discarded
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile")["profile"]["properties"];
    properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
    properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
    properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-import-type-graph-discarded");
    properties[TYPESCRIPT_DEFINITION_STATUS_PROPERTY] = serde_json::json!("failed");
    properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
    properties["typescript_semantic_issue_count"] = serde_json::json!("1");
    let completion_index = discarded
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    discarded.insert(
        completion_index,
        serde_json::json!({
            "event":"diagnostic",
            "protocol_version":"1.0",
            "scan_id":"typescript-gate-scan",
            "adapter":"web",
            "adapter_version":env!("CARGO_PKG_VERSION"),
            "seq":0,
            "diagnostic":{
                "id":"diagnostic:web:dependency-issue",
                "severity":"warning",
                "code":"web.typescript_dependency_issue",
                "message":"dependency semantic issue",
                "profile_id":"web:default",
                "evidence":[],
                "properties":{
                    "typescript_definition_issue":true,
                    "typescript_dependency_issue":true,
                },
            },
        }),
    );
    resequence_test_protocol(&mut discarded);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(discarded)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "discarded profile: {:?}", parsed.error);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_call_capability_accepts_generated_initializer_and_exact_direct_call() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (gate, release_attested) in [
        (TYPESCRIPT_RELEASE_GATE_PENDING, false),
        (TYPESCRIPT_RELEASE_GATE_VERIFIED, true),
    ] {
        let parsed = parse_events_preserving_prefix(
            &typescript_call_protocol(&root, gate)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(release_attested),
        );
        assert_eq!(parsed.error, None, "gate={gate:?}");
        assert_eq!(parsed.failure_kind, None, "gate={gate:?}");
        assert!(!parsed.security_violation, "gate={gate:?}");
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "generated_module_initializer"
                && event["node"]["properties"]["canonical_identity"]["identity_kind"] == "generated"
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "dependency_site"
                && event["site"]["kind"] == "call"
                && event["site"]["resolution_status"] == "resolved"
                && event["site"]["precision"] == "exact"
        }));
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert"
                && event["edge"]["kind"] == "calls"
                && event["edge"]["phase"] == "semantic"
        }));
        assert!(!parsed.events.iter().any(|event| {
            event["edge"]["kind"] == "may_call"
                || event["coverage"]["completeness"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
        }));
    }
    Ok(())
}

#[test]
fn web_call_capability_v2_accepts_well_formed_candidate_calls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "{:?}", parsed.error);
    assert_eq!(parsed.failure_kind, None, "{:?}", parsed.failure_kind);
    assert!(!parsed.security_violation);
    let candidate_site = parsed
        .events
        .iter()
        .find(|event| {
            event["event"] == "dependency_site"
                && event["site"]["kind"] == "call"
                && event["site"]["resolution_status"] == "candidates"
        })
        .expect("candidate call site");
    let target_ids = candidate_site["site"]["target_ids"]
        .as_array()
        .expect("candidate call targets");
    assert_eq!(target_ids.len(), 2);
    assert!(
        candidate_site["site"]["evidence"][0]["properties"]["algorithm"]
            .as_str()
            .is_some_and(|algorithm| !algorithm.is_empty())
    );
    let site_id = candidate_site["site"]["id"]
        .as_str()
        .expect("candidate call site ID");
    assert_eq!(
        parsed
            .events
            .iter()
            .filter(|event| {
                event["event"] == "edge_upsert"
                    && event["edge"]["kind"] == "may_call"
                    && event["edge"]["site_id"] == site_id
                    && event["edge"]["resolution_status"] == "candidates"
                    && event["edge"]["precision"] == "overapprox"
            })
            .count(),
        2
    );
    assert!(
        parsed
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event["event"].as_str(),
                    Some("profile_completed" | "scan_completed")
                )
            })
            .all(|event| {
                event["coverage"]["dependency_sites"] == 1
                    && event["coverage"]["resolved"] == 0
                    && event["coverage"]["candidates"] == 1
                    && event["coverage"]["completeness"]
                        .as_array()
                        .is_some_and(|values| {
                            values.iter().any(|value| value == "semantic-complete")
                        })
            })
    );
    Ok(())
}

#[test]
fn web_semantic_complete_rejects_compiler_diagnostics() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for property in [
        "typescript_semantic_diagnostics",
        "typescript_emitted_semantic_diagnostics",
    ] {
        let mut events = test_protocol_values(typescript_call_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
        events
            .iter_mut()
            .find(|event| event["event"] == "profile_declared")
            .expect("Web profile declaration")["profile"]["properties"][property] =
            serde_json::json!("1");
        resequence_test_protocol(&mut events);

        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{property}: {:?}",
            parsed.error
        );
        assert!(parsed.security_violation, "{property}: {:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains(property)),
            "{property}: {:?}",
            parsed.error
        );
        assert!(!parsed.events.iter().any(|event| {
            event["coverage"]["completeness"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
        }));
    }
    Ok(())
}

#[test]
fn web_call_capability_v1_rejects_candidate_calls() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1,
    );
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("forbidden semantic dependency site") })
    );
    Ok(())
}

#[test]
fn web_call_capability_v2_rejects_candidate_call_without_algorithm() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    mutate_semantic_primary_properties(&mut events, "call", |properties| {
        properties
            .as_object_mut()
            .expect("primary properties")
            .remove("algorithm");
    });

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed.error.as_deref().is_some_and(|error| {
            error.contains("may_call edge") && error.contains("algorithm")
        }),
        "{:?}",
        parsed.error
    );
    Ok(())
}

#[test]
fn web_call_capability_v2_rejects_candidate_call_with_reason() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    let call_site = events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("candidate call site");
    call_site["site"]["reason"] = serde_json::json!("spoofed_candidate_reason");

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed.error.as_deref().is_some_and(|error| {
            error.contains("candidate call site") && error.contains("reason")
        }),
        "{:?}",
        parsed.error
    );
    Ok(())
}

#[test]
fn web_call_capability_v2_rejects_spoofed_candidate_algorithm() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    mutate_semantic_primary_properties(&mut events, "call", |properties| {
        properties["algorithm"] =
            serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
    });

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed.error.as_deref().is_some_and(|error| {
            error.contains("dispatch \"dynamic\"") && error.contains("algorithm")
        }),
        "{:?}",
        parsed.error
    );
    Ok(())
}

#[test]
fn web_call_capability_v2_accepts_fresh_instance_method_candidate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    mutate_semantic_primary_properties(&mut events, "call", |properties| {
        properties["dispatch"] = serde_json::json!("fresh_instance");
        properties["algorithm"] =
            serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
        properties["call_kind"] = serde_json::json!("method");
    });

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "{:?}", parsed.error);
    assert_eq!(parsed.failure_kind, None, "{:?}", parsed.failure_kind);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_call_capability_v2_rejects_fresh_instance_constructor_candidate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    configure_typescript_candidate_call(
        &mut events,
        TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V2,
    );
    mutate_semantic_primary_properties(&mut events, "call", |properties| {
        properties["dispatch"] = serde_json::json!("fresh_instance");
        properties["algorithm"] =
            serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_FRESH_INSTANCE_FLOW_ALGORITHM);
        properties["call_kind"] = serde_json::json!("constructor");
        properties["occurrence_kind"] = serde_json::json!("new_expression");
    });

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed.error.as_deref().is_some_and(|error| {
            error.contains("call_kind \"constructor\"")
                && error.contains("dispatch \"fresh_instance\"")
        }),
        "{:?}",
        parsed.error
    );
    Ok(())
}

#[test]
fn web_call_capability_rejects_algorithm_on_non_candidate_call() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    mutate_semantic_primary_properties(&mut events, "call", |properties| {
        properties["algorithm"] = serde_json::json!(TYPESCRIPT_CLOSED_LOCAL_CALL_FLOW_ALGORITHM);
    });

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed.error.as_deref().is_some_and(|error| {
            error.contains("dispatch \"direct\"") && error.contains("algorithm")
        }),
        "{:?}",
        parsed.error
    );
    Ok(())
}

#[test]
fn web_call_capability_rejects_non_callable_symbol_source() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let variable_id = events
        .iter()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "variable"
        })
        .expect("variable symbol")["node"]["id"]
        .as_str()
        .expect("variable symbol ID")
        .to_owned();
    let call_site = events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("call site");
    call_site["site"]["source"] = serde_json::json!(variable_id);
    recanonicalize_typescript_call(&mut events);

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| { error.contains("source") && error.contains("callable symbol") })
    );
    Ok(())
}

#[test]
fn web_call_capability_rejects_non_callable_symbol_target() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let variable_id = events
        .iter()
        .find(|event| {
            event["event"] == "node_upsert"
                && event["node"]["properties"]["symbol_kind"] == "variable"
        })
        .expect("variable symbol")["node"]["id"]
        .as_str()
        .expect("variable symbol ID")
        .to_owned();
    let call_site = events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "call")
        .expect("call site");
    call_site["site"]["target_ids"] = serde_json::json!([variable_id]);
    recanonicalize_typescript_call(&mut events);

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(parsed.error.as_deref().is_some_and(|error| {
        error.contains("resolved target") && error.contains("canonical callable symbol")
    }));
    Ok(())
}

#[test]
fn web_import_equals_accepts_a_repository_module_surrogate() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let site_id = events
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut events {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("import_equals");
            event["site"]["evidence"][0]["properties"]["imported_name"] = serde_json::json!("=");
            event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("import_equals");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("import_equals");
            event["edge"]["evidence"][0]["properties"]["imported_name"] = serde_json::json!("=");
            event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("import_equals");
        }
    }
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "{:?}", parsed.error);
    assert_eq!(parsed.failure_kind, None);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_literal_binding_scheme_specifier_is_not_reserved() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let specifier = "binding:[\"pkg\",\"X\"]";
    mutate_semantic_primary_properties(&mut events, "web_import", |properties| {
        properties["module_specifier"] = serde_json::json!(specifier);
    });
    events
        .iter_mut()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["specifier"] = serde_json::json!(specifier);
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "{:?}", parsed.error);
    assert_eq!(parsed.failure_kind, None);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_empty_clauses_and_empty_module_export_names_are_attested() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;

    for (site_kind, occurrence_kind) in [
        ("web_import", "empty_import"),
        ("web_reexport", "empty_reexport"),
    ] {
        let mut events = test_protocol_values(typescript_import_type_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
        )?)?;
        let site_id = events
            .iter()
            .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == site_kind)
            .expect("Web semantic site")["site"]["id"]
            .as_str()
            .expect("site ID")
            .to_owned();
        for event in &mut events {
            if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!(occurrence_kind);
                event["site"]["evidence"][0]["properties"]
                    .as_object_mut()
                    .expect("primary properties")
                    .remove("imported_name");
                event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!(occurrence_kind);
            } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                    serde_json::json!(occurrence_kind);
                event["edge"]["evidence"][0]["properties"]
                    .as_object_mut()
                    .expect("primary properties")
                    .remove("imported_name");
                event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                    serde_json::json!(occurrence_kind);
            }
        }
        if occurrence_kind == "empty_reexport" {
            let mut malformed = events.clone();
            resequence_test_protocol(&mut malformed);
            let parsed = parse_events_preserving_prefix(
                &serialize_test_protocol(malformed)?,
                "typescript-gate-scan",
                "web",
                &root,
                64 * 1024,
                Some(env!("CARGO_PKG_VERSION")),
                Some(false),
            );
            assert!(
                parsed
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("incompatible kind type")),
                "malformed empty re-export: {:?}",
                parsed.error
            );

            let target_file_id = events
                .iter()
                .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
                .expect("target file node")["node"]["id"]
                .as_str()
                .expect("target file ID")
                .to_owned();
            for event in &mut events {
                if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
                    event["site"]["target_ids"] = serde_json::json!([target_file_id.as_str()]);
                    event["site"]["evidence"][0]["properties"]["target_basis"] =
                        serde_json::json!("repository_module");
                } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
                    event["edge"]["target"] = serde_json::json!(target_file_id.as_str());
                    event["edge"]["evidence"][0]["properties"]["target_basis"] =
                        serde_json::json!("repository_module");
                    let edge_id = depgraph_protocol::stable_id_from_value(
                        "edge",
                        &serde_json::json!({
                            "kind": event["edge"]["kind"].clone(),
                            "site_id": site_id.as_str(),
                            "target": target_file_id.as_str(),
                        }),
                    );
                    event["edge"]["id"] = serde_json::json!(edge_id);
                }
            }
        }
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{site_kind}: {:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
    }

    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    mutate_semantic_primary_properties(&mut events, "web_reexport", |properties| {
        properties["imported_name"] = serde_json::json!("");
    });
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.error, None,
        "empty ModuleExportName: {:?}",
        parsed.error
    );
    assert_eq!(parsed.failure_kind, None);
    assert!(!parsed.security_violation);

    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let site_id = events
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut events {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["specifier"] = serde_json::json!("");
            event["site"]["evidence"][0]["properties"]["module_specifier"] = serde_json::json!("");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["module_specifier"] = serde_json::json!("");
        }
    }
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.error, None,
        "empty module specifier: {:?}",
        parsed.error
    );
    assert_eq!(parsed.failure_kind, None);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_type_only_reexport_accepts_resolution_mode_attestation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    mutate_semantic_primary_properties(&mut events, "web_reexport", |properties| {
        properties["type_only"] = serde_json::json!(true);
        properties["resolution_mode"] = serde_json::json!("require");
    });
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(parsed.error, None, "{:?}", parsed.error);
    assert_eq!(parsed.failure_kind, None);
    assert!(!parsed.security_violation);
    Ok(())
}

#[test]
fn web_import_type_gate_rejects_mismatched_capability_and_strict_site_contract() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let baseline = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let mut cases = Vec::<(&str, Vec<Value>, &str)>::new();

    let mut mismatched_capability = baseline.clone();
    mismatched_capability
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("profile")["profile"]["properties"][TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_DEFINITION_GRAPH);
    cases.push((
        "mismatched capability",
        mismatched_capability,
        "mismatched semantic capability",
    ));

    let mut missing_source_support = baseline.clone();
    let site_id = missing_source_support
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut missing_source_support {
        if (event["event"] == "dependency_site" && event["site"]["id"] == site_id)
            || (event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
        {
            let evidence = if event["event"] == "dependency_site" {
                &mut event["site"]["evidence"]
            } else {
                &mut event["edge"]["evidence"]
            };
            *evidence = serde_json::json!([evidence[0].clone()]);
        }
    }
    cases.push((
        "missing source support",
        missing_source_support,
        "matching source supporting evidence",
    ));

    let mut spoofed_source_support = baseline.clone();
    let site_id = spoofed_source_support
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut spoofed_source_support {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][1]["extractor"] = serde_json::json!("typescript-static");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][1]["extractor"] = serde_json::json!("typescript-static");
        }
    }
    cases.push((
        "spoofed source support",
        spoofed_source_support,
        "matching source supporting evidence",
    ));

    let mut non_boolean_type_only = baseline.clone();
    let site_id = non_boolean_type_only
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut non_boolean_type_only {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][0]["properties"]["type_only"] = serde_json::json!("false");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["type_only"] = serde_json::json!("false");
        }
    }
    cases.push((
        "non-boolean type-only marker",
        non_boolean_type_only,
        "must declare boolean type_only",
    ));

    let mut false_type_use = baseline.clone();
    let site_id = false_type_use
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "type_use")
        .expect("type-use site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut false_type_use {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(false);
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(false);
        }
    }
    cases.push((
        "false type-use marker",
        false_type_use,
        "must use type_only=true",
    ));

    let mut type_only_dynamic_import = baseline.clone();
    let site_id = type_only_dynamic_import
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut type_only_dynamic_import {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("dynamic_import");
            event["site"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(true);
            event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("dynamic_import");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("dynamic_import");
            event["edge"]["evidence"][0]["properties"]["type_only"] = serde_json::json!(true);
            event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("dynamic_import");
        }
    }
    cases.push((
        "type-only dynamic import",
        type_only_dynamic_import,
        "must use type_only=false",
    ));

    let mut invalid_resolution_mode = baseline.clone();
    mutate_semantic_primary_properties(
        &mut invalid_resolution_mode,
        "web_reexport",
        |properties| {
            properties["resolution_mode"] = serde_json::json!("node");
        },
    );
    cases.push((
        "invalid resolution mode",
        invalid_resolution_mode,
        "invalid resolution_mode metadata",
    ));

    let mut resolution_mode_on_value_import = baseline.clone();
    mutate_semantic_primary_properties(
        &mut resolution_mode_on_value_import,
        "web_import",
        |properties| {
            properties["resolution_mode"] = serde_json::json!("require");
        },
    );
    cases.push((
        "resolution mode on value import",
        resolution_mode_on_value_import,
        "resolution_mode contradicts its occurrence",
    ));

    let mut resolution_mode_on_import_equals = baseline.clone();
    let site_id = resolution_mode_on_import_equals
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut resolution_mode_on_import_equals {
        let semantic = if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            Some(&mut event["site"]["evidence"])
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            Some(&mut event["edge"]["evidence"])
        } else {
            None
        };
        if let Some(evidence) = semantic {
            evidence[0]["properties"]["occurrence_kind"] = serde_json::json!("import_equals");
            evidence[0]["properties"]["imported_name"] = serde_json::json!("=");
            evidence[0]["properties"]["type_only"] = serde_json::json!(true);
            evidence[0]["properties"]["resolution_mode"] = serde_json::json!("require");
            evidence[1]["properties"]["occurrence_kind"] = serde_json::json!("import_equals");
        }
    }
    cases.push((
        "resolution mode on import-equals",
        resolution_mode_on_import_equals,
        "import_equals occurrence cannot expose resolution_mode",
    ));

    let mut missing_module_specifier = baseline.clone();
    mutate_semantic_primary_properties(&mut missing_module_specifier, "web_import", |properties| {
        properties
            .as_object_mut()
            .expect("evidence properties")
            .remove("module_specifier");
    });
    cases.push((
        "missing module specifier",
        missing_module_specifier,
        "binding metadata does not match occurrence_kind",
    ));

    let mut missing_imported_name = baseline.clone();
    mutate_semantic_primary_properties(&mut missing_imported_name, "web_reexport", |properties| {
        properties
            .as_object_mut()
            .expect("evidence properties")
            .remove("imported_name");
    });
    cases.push((
        "missing imported name",
        missing_imported_name,
        "binding metadata does not match occurrence_kind",
    ));

    let mut mismatched_protocol_specifier = baseline.clone();
    mutate_semantic_primary_properties(
        &mut mismatched_protocol_specifier,
        "web_reexport",
        |properties| {
            properties["module_specifier"] = serde_json::json!("./other");
        },
    );
    cases.push((
        "mismatched protocol specifier",
        mismatched_protocol_specifier,
        "binding metadata does not match occurrence_kind",
    ));

    let mut named_binding_file_target = baseline.clone();
    let site_id = named_binding_file_target
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut named_binding_file_target {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("named_import");
            event["site"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("named_import");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["evidence"][0]["properties"]["occurrence_kind"] =
                serde_json::json!("named_import");
            event["edge"]["evidence"][1]["properties"]["occurrence_kind"] =
                serde_json::json!("named_import");
        }
    }
    cases.push((
        "named binding file target",
        named_binding_file_target,
        "cannot weaken a named binding target",
    ));

    let mut mixed_repository_and_definition_targets = baseline.clone();
    let definition_target = mixed_repository_and_definition_targets
        .iter()
        .find(|event| event["event"] == "node_upsert" && event["node"]["kind"] == "type")
        .expect("semantic type target")["node"]["id"]
        .as_str()
        .expect("semantic type ID")
        .to_owned();
    let import_site = mixed_repository_and_definition_targets
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site");
    let site_id = import_site["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    let file_target = import_site["site"]["target_ids"][0]
        .as_str()
        .expect("file target ID")
        .to_owned();
    let mut mixed_targets = vec![file_target, definition_target.clone()];
    mixed_targets.sort();
    for event in &mut mixed_repository_and_definition_targets {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["target_ids"] = serde_json::json!(mixed_targets);
            event["site"]["resolution_status"] = serde_json::json!("candidates");
            event["site"]["precision"] = serde_json::json!("overapprox");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["resolution_status"] = serde_json::json!("candidates");
            event["edge"]["precision"] = serde_json::json!("overapprox");
        }
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = serde_json::json!(2);
            event["coverage"]["candidates"] = serde_json::json!(1);
        }
    }
    let mut definition_edge = mixed_repository_and_definition_targets
        .iter()
        .find(|event| event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id)
        .expect("semantic import edge")
        .clone();
    definition_edge["edge"]["target"] = serde_json::json!(definition_target);
    definition_edge["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
        "edge",
        &serde_json::json!({
            "kind":"imports",
            "site_id":site_id,
            "target":definition_target,
        }),
    ));
    let completion_index = mixed_repository_and_definition_targets
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    mixed_repository_and_definition_targets.insert(completion_index, definition_edge);
    let profile = mixed_repository_and_definition_targets
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile");
    let relation_count = profile["profile"]["properties"]["typescript_semantic_relation_count"]
        .as_str()
        .expect("semantic relation count")
        .parse::<usize>()?;
    profile["profile"]["properties"]["typescript_semantic_relation_count"] =
        serde_json::json!((relation_count + 1).to_string());
    cases.push((
        "mixed repository and definition targets",
        mixed_repository_and_definition_targets,
        "mixes repository module and canonical definition targets",
    ));

    let mut wrong_ownership = baseline.clone();
    wrong_ownership
        .iter_mut()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["properties"]
        .as_object_mut()
        .expect("file properties")
        .remove("package_id");
    cases.push((
        "wrong source ownership",
        wrong_ownership,
        "disagree on package ownership",
    ));

    let mut wrong_external_provenance = baseline.clone();
    let external_identity = serde_json::json!({
        "language":"typescript",
        "compiler_version":TYPESCRIPT_COMPILER_VERSION,
        "locator":"npm:external-fixture",
    });
    let external_id = depgraph_protocol::stable_id_from_value("external", &external_identity);
    let completion_index = wrong_external_provenance
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    wrong_external_provenance.insert(
        completion_index,
        serde_json::json!({
            "event":"node_upsert",
            "protocol_version":"1.0",
            "scan_id":"typescript-gate-scan",
            "adapter":"web",
            "adapter_version":env!("CARGO_PKG_VERSION"),
            "seq":0,
            "node":{
                "id":external_id,
                "kind":"external_system",
                "locator":"external://typescript/npm%3Aexternal-fixture",
                "display_name":"external-fixture",
                "properties":{
                    "language":"typescript",
                    "external":true,
                    "canonical_identity":external_identity,
                    "profile_id":"web:other",
                    "compiler_version":TYPESCRIPT_COMPILER_VERSION,
                },
            },
        }),
    );
    let site_id = wrong_external_provenance
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut wrong_external_provenance {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["resolution_status"] = serde_json::json!("external");
            event["site"]["target_ids"] = serde_json::json!([external_id]);
            event["site"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("external_boundary");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["target"] = serde_json::json!(external_id);
            event["edge"]["resolution_status"] = serde_json::json!("external");
            event["edge"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("external_boundary");
            event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "kind":"imports",
                    "site_id":site_id,
                    "target":external_id,
                }),
            ));
        }
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = serde_json::json!(2);
            event["coverage"]["external"] = serde_json::json!(1);
        }
    }
    let mut spoofed_external_presentation = wrong_external_provenance.clone();
    spoofed_external_presentation
        .iter_mut()
        .find(|event| event["event"] == "node_upsert" && event["node"]["id"] == external_id)
        .expect("external target")["node"]["properties"]["profile_id"] =
        serde_json::json!("web:default");
    cases.push((
        "spoofed external presentation",
        spoofed_external_presentation,
        "canonical profile-scoped TypeScript external_system sentinel",
    ));
    cases.push((
        "wrong external provenance",
        wrong_external_provenance,
        "canonical profile-scoped TypeScript external_system sentinel",
    ));

    let mut spoofed_unknown_identity = baseline.clone();
    let repository_identity = "test:web-repository";
    let workspace_id = depgraph_protocol::stable_id_from_value(
        "workspace",
        &serde_json::json!({"repository":repository_identity,"root":"."}),
    );
    let unknown_id = "unknown:spoofed";
    for node in [
        serde_json::json!({
            "id":workspace_id,
            "kind":"workspace",
            "locator":format!("workspace://{repository_identity}"),
            "display_name":"definition-fixture",
            "properties":{
                "repository_identity":repository_identity,
                "package_manager":"npm",
                "safe_scan":true,
            },
        }),
        serde_json::json!({
            "id":unknown_id,
            "kind":"unknown_target",
            "locator":"unknown://web/unresolved-dependency",
            "display_name":"Unresolved web dependency",
            "properties":{"language":"web","profile_id":"web:default"},
        }),
    ]
    .into_iter()
    .rev()
    {
        spoofed_unknown_identity.insert(
            2,
            serde_json::json!({
                "event":"node_upsert",
                "protocol_version":"1.0",
                "scan_id":"typescript-gate-scan",
                "adapter":"web",
                "adapter_version":env!("CARGO_PKG_VERSION"),
                "seq":0,
                "node":node,
            }),
        );
    }
    let site_id = spoofed_unknown_identity
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("Web import site")["site"]["id"]
        .as_str()
        .expect("site ID")
        .to_owned();
    for event in &mut spoofed_unknown_identity {
        if event["event"] == "dependency_site" && event["site"]["id"] == site_id {
            event["site"]["resolution_status"] = serde_json::json!("unresolved");
            event["site"]["precision"] = serde_json::json!("heuristic");
            event["site"]["reason"] = serde_json::json!("typechecker_target_unresolved");
            event["site"]["target_ids"] = serde_json::json!([unknown_id]);
            event["site"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("unresolved");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == site_id {
            event["edge"]["target"] = serde_json::json!(unknown_id);
            event["edge"]["resolution_status"] = serde_json::json!("unresolved");
            event["edge"]["precision"] = serde_json::json!("heuristic");
            event["edge"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("unresolved");
            event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "kind":"imports",
                    "site_id":site_id,
                    "target":unknown_id,
                }),
            ));
        }
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = serde_json::json!(2);
            event["coverage"]["unresolved"] = serde_json::json!(1);
            event["coverage"]["reasons"] = serde_json::json!(["typechecker_target_unresolved"]);
        }
    }
    cases.push((
        "spoofed unknown identity",
        spoofed_unknown_identity,
        "profile-scoped Web unknown_target sentinel",
    ));

    let mut wrong_condition = baseline.clone();
    wrong_condition
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert" && event["edge"]["kind"] == "imports")
        .expect("semantic import edge")["edge"]["condition"] = serde_json::json!({
        "op":"eq",
        "key":"web.condition",
        "value":"spoofed",
    });
    cases.push((
        "condition mismatch",
        wrong_condition,
        "condition is not the union of its target edge conditions",
    ));

    let mut wrong_count = baseline.clone();
    wrong_count
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("profile")["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
        serde_json::json!("99");
    cases.push((
        "semantic site count mismatch",
        wrong_count,
        TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY,
    ));

    for (name, mut events, expected_error) in cases {
        resequence_test_protocol(&mut events);
        let parsed = parse_events_preserving_prefix(
            &serialize_test_protocol(events)?,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{name}: {:?}",
            parsed.error
        );
        assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error)),
            "{name}: {:?}",
            parsed.error
        );
    }
    Ok(())
}

#[test]
fn web_import_type_late_failure_atomically_discards_semantics_and_keeps_syntax() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let source_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let target_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
        .expect("target file")["node"]["id"]
        .as_str()
        .expect("target file ID")
        .to_owned();
    let source_site_id = "site:syntax-import-survives";
    let source_edge_id = "edge:syntax-import-survives";
    let source_evidence = serde_json::json!({
        "kind":"source",
        "extractor":"typescript-static",
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":8,
        "properties":{},
    });
    let insert_at = events
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    events.insert(
        insert_at,
        serde_json::json!({
            "event":"dependency_site",
            "site":{
                "id":source_site_id,
                "source":source_file_id,
                "kind":"import",
                "specifier":"./target",
                "resolution_status":"resolved",
                "target_ids":[target_file_id],
                "profile_id":"web:default",
                "condition":{"op":"all","conditions":[]},
                "precision":"exact",
                "evidence":[source_evidence],
            },
        }),
    );
    events.insert(
        insert_at + 1,
        serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":source_edge_id,
                "source":source_file_id,
                "target":target_file_id,
                "kind":"imports",
                "site_id":source_site_id,
                "phase":"source",
                "environment":"any",
                "profile_id":"web:default",
                "condition":{"op":"all","conditions":[]},
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":false,
                "evidence":[source_evidence],
            },
        }),
    );
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["dependency_sites"] = serde_json::json!(4);
            event["coverage"]["resolved"] = serde_json::json!(4);
        }
    }

    let external_id = "external-system:web:semantic-only";
    events.insert(
        insert_at,
        serde_json::json!({
            "event":"node_upsert",
            "node":{
                "id":external_id,
                "kind":"external_system",
                "locator":"package://semantic-only@1.0.0",
                "display_name":"semantic-only",
                "properties":{
                    "workspace":false,
                    "external":true,
                },
            },
        }),
    );
    let semantic_site_id = events
        .iter()
        .find(|event| event["event"] == "dependency_site" && event["site"]["kind"] == "web_import")
        .expect("semantic import site")["site"]["id"]
        .as_str()
        .expect("semantic site ID")
        .to_owned();
    for event in &mut events {
        if event["event"] == "dependency_site" && event["site"]["id"] == semantic_site_id {
            event["site"]["resolution_status"] = serde_json::json!("external");
            event["site"]["target_ids"] = serde_json::json!([external_id]);
            event["site"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("external_boundary");
        } else if event["event"] == "edge_upsert" && event["edge"]["site_id"] == semantic_site_id {
            event["edge"]["target"] = serde_json::json!(external_id);
            event["edge"]["resolution_status"] = serde_json::json!("external");
            event["edge"]["evidence"][0]["properties"]["target_basis"] =
                serde_json::json!("external_boundary");
            event["edge"]["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
                "edge",
                &serde_json::json!({
                    "kind":"imports",
                    "site_id":semantic_site_id,
                    "target":external_id,
                }),
            ));
        }
    }
    for event in &mut events {
        if matches!(
            event["event"].as_str(),
            Some("profile_completed" | "scan_completed")
        ) {
            event["coverage"]["resolved"] = serde_json::json!(3);
            event["coverage"]["external"] = serde_json::json!(1);
        }
    }
    promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
    events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("profile")["profile"]["properties"][TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] =
        serde_json::json!("99");
    for event in &mut events {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    }
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    let discarded_profile = parsed
        .events
        .iter()
        .find(|event| event["event"] == "profile_declared")
        .expect("discarded Web profile");
    let properties = &discarded_profile["profile"]["properties"];
    assert_eq!(
        properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY],
        "definition-import-type-call-graph-discarded"
    );
    assert_eq!(properties[TYPESCRIPT_DEFINITION_STATUS_PROPERTY], "failed");
    for property in [
        "typescript_semantic_node_count",
        "typescript_semantic_relation_count",
        "typescript_semantic_diagnostics",
        "typescript_emitted_semantic_diagnostics",
        "typescript_semantic_issue_count",
        TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY,
        TYPESCRIPT_SEMANTIC_CALL_SITE_COUNT_PROPERTY,
    ] {
        assert_eq!(properties[property], "0", "{property}");
    }
    assert!(!parsed.events.iter().any(|event| {
        matches!(
            event["event"].as_str(),
            Some("file_completed" | "profile_completed" | "scan_completed")
        )
    }));
    assert!(!parsed.events.iter().any(|event| {
        event["coverage"]["completeness"]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == "semantic-complete"))
    }));
    assert!(parsed.events.iter().any(|event| {
        event["event"] == "dependency_site" && event["site"]["id"] == source_site_id
    }));
    assert!(
        parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["id"] == source_edge_id
        })
    );
    assert!(!parsed.events.iter().any(|event| {
        matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
            || event["node"]["id"] == external_id
            || (event["event"] == "dependency_site"
                && event["site"]["evidence"][0]["kind"] == "semantic")
            || (event["event"] == "edge_upsert" && event["edge"]["phase"] == "semantic")
    }));
    assert!(
        parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["id"] == source_file_id
        })
    );
    assert!(
        parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["id"] == target_file_id
        })
    );
    Ok(())
}

#[test]
fn web_rejected_semantic_node_id_collision_keeps_existing_syntax_graph() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_import_type_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let source_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/index.ts")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let target_file_id = events
        .iter()
        .find(|event| event["node"]["properties"]["path"] == "src/target.ts")
        .expect("target file")["node"]["id"]
        .as_str()
        .expect("target file ID")
        .to_owned();
    let source_site_id = "site:syntax-import-survives-semantic-id-collision";
    let source_edge_id = "edge:syntax-import-survives-semantic-id-collision";
    let source_evidence = serde_json::json!({
        "kind":"source",
        "extractor":"typescript-static",
        "extractor_version":TYPESCRIPT_COMPILER_VERSION,
        "path":"src/index.ts",
        "start_line":1,
        "start_column":1,
        "end_line":1,
        "end_column":8,
        "properties":{},
    });
    let insert_at = events
        .iter()
        .position(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    events.insert(
        insert_at,
        serde_json::json!({
            "event":"dependency_site",
            "site":{
                "id":source_site_id,
                "source":source_file_id,
                "kind":"import",
                "specifier":"./target",
                "resolution_status":"resolved",
                "target_ids":[target_file_id],
                "profile_id":"web:default",
                "condition":{"op":"all","conditions":[]},
                "precision":"exact",
                "evidence":[source_evidence],
            },
        }),
    );
    events.insert(
        insert_at + 1,
        serde_json::json!({
            "event":"edge_upsert",
            "edge":{
                "id":source_edge_id,
                "source":source_file_id,
                "target":target_file_id,
                "kind":"imports",
                "site_id":source_site_id,
                "phase":"source",
                "environment":"any",
                "profile_id":"web:default",
                "condition":{"op":"all","conditions":[]},
                "resolution_status":"resolved",
                "precision":"exact",
                "generated":false,
                "evidence":[source_evidence],
            },
        }),
    );

    let mut colliding_semantic_node = events
        .iter()
        .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
        .expect("semantic node")
        .clone();
    colliding_semantic_node["node"]["id"] = serde_json::json!(source_file_id);
    events.insert(insert_at + 2, colliding_semantic_node);
    for event in &mut events {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
    }
    resequence_test_protocol(&mut events);

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(parsed.events.iter().any(|event| {
        event["event"] == "node_upsert"
            && event["node"]["id"] == source_file_id
            && event["node"]["kind"] == "file"
    }));
    assert!(parsed.events.iter().any(|event| {
        event["event"] == "dependency_site" && event["site"]["id"] == source_site_id
    }));
    assert!(
        parsed.events.iter().any(|event| {
            event["event"] == "edge_upsert" && event["edge"]["id"] == source_edge_id
        })
    );
    assert!(!parsed.events.iter().any(|event| {
        event["event"] == "node_upsert"
            && event["node"]["id"] == source_file_id
            && matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
    }));
    Ok(())
}

#[test]
fn web_import_type_malformed_prefix_discards_orphan_semantic_sentinels() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_gate_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    let properties = &mut events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile")["profile"]["properties"];
    properties[TYPESCRIPT_ANALYSIS_MODE_PROPERTY] =
        serde_json::json!(TYPESCRIPT_ANALYSIS_MODE_IMPORT_TYPE_GRAPH);
    properties[TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_GRAPH_V1);
    properties[TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-import-type-graph-emitted");
    properties[TYPESCRIPT_SEMANTIC_SITE_COUNT_PROPERTY] = serde_json::json!("0");
    let external_identity = serde_json::json!({
        "language":"typescript",
        "compiler_version":TYPESCRIPT_COMPILER_VERSION,
        "locator":"npm:orphan",
    });
    let external_id = depgraph_protocol::stable_id_from_value("external", &external_identity);
    let unknown_id = "unknown:web:orphan";
    for node in [
        serde_json::json!({
            "id":external_id,
            "kind":"external_system",
            "locator":"external://typescript/npm%3Aorphan",
            "display_name":"orphan",
            "properties":{
                "language":"typescript",
                "external":true,
                "canonical_identity":external_identity,
                "profile_id":"web:default",
                "compiler_version":TYPESCRIPT_COMPILER_VERSION,
            },
        }),
        serde_json::json!({
            "id":unknown_id,
            "kind":"unknown_target",
            "locator":"unknown://web/unresolved-dependency",
            "display_name":"Unresolved web dependency",
            "properties":{"language":"web","profile_id":"web:default"},
        }),
    ]
    .into_iter()
    .rev()
    {
        events.insert(2, serde_json::json!({"event":"node_upsert","node":node}));
    }
    let malformed = events
        .iter_mut()
        .find(|event| event["event"] == "profile_completed")
        .expect("profile completion");
    malformed["adapter_version"] = serde_json::json!("spoofed-version");
    for event in &mut events {
        event["protocol_version"] = serde_json::json!("1.0");
        event["scan_id"] = serde_json::json!("typescript-gate-scan");
        event["adapter"] = serde_json::json!("web");
        if event["event"] != "profile_completed" {
            event["adapter_version"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
        }
    }
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("adapter_version mismatch")),
        "{:?}",
        parsed.error
    );
    assert!(
        !parsed.events.iter().any(|event| {
            event["node"]["id"] == external_id || event["node"]["id"] == unknown_id
        })
    );
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["event"] == "profile_declared")
    );
    Ok(())
}

#[test]
fn web_definition_graph_rejects_and_discards_out_of_capability_delta() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let serialized = |events: Vec<Value>| -> Result<Vec<u8>> {
        let mut output = Vec::new();
        for event in events {
            serde_json::to_writer(&mut output, &event)?;
            output.push(b'\n');
        }
        Ok(output)
    };
    let parsed_values = |output: Vec<u8>| -> Result<Vec<Value>> {
        Ok(String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?)
    };

    let mut forbidden_call = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    forbidden_call
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"]["kind"] = serde_json::json!("calls");

    let mut wrong_hash = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    wrong_hash
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"]["id"] =
        serde_json::json!(format!("edge:sha256:{}", "0".repeat(64)));

    let mut wrong_extractor = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    wrong_extractor
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"]["evidence"][0]["extractor"] =
        serde_json::json!("typescript-static");

    let mut wrong_count = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    wrong_count[1]["profile"]["properties"]["typescript_semantic_node_count"] =
        serde_json::json!("99");

    let mut linked_relation = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    linked_relation
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"]["site_id"] = serde_json::json!("site:sha256:forbidden");

    let mut candidate_relation = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let candidate = candidate_relation
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge");
    candidate["edge"]["resolution_status"] = serde_json::json!("candidates");
    candidate["edge"]["precision"] = serde_json::json!("overapprox");

    let mut semantic_site = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let edge_index = semantic_site
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("definition edge index");
    semantic_site.insert(
        edge_index,
        serde_json::json!({
            "event":"dependency_site",
            "protocol_version":"1.0",
            "scan_id":"typescript-gate-scan",
            "adapter":"web",
            "adapter_version":env!("CARGO_PKG_VERSION"),
            "seq":0,
            "site":{
                "id":"site:sha256:forbidden",
                "source":"package:sha256:definition-fixture",
                "kind":"call",
                "specifier":"forbidden",
                "resolution_status":"resolved",
                "target_ids":["package:sha256:definition-fixture"],
                "profile_id":"web:default",
                "condition":{"op":"all","conditions":[]},
                "precision":"exact",
                "evidence":[{
                    "kind":"semantic",
                    "extractor":TYPESCRIPT_SEMANTIC_EXTRACTOR,
                    "extractor_version":TYPESCRIPT_COMPILER_VERSION,
                    "path":"src/index.ts",
                    "start_line":1,
                    "start_column":1,
                    "end_line":1,
                    "end_column":9
                }]
            }
        }),
    );
    for (index, event) in semantic_site.iter_mut().enumerate() {
        event["seq"] = serde_json::json!(index + 1);
    }

    let mut external_package = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    external_package
        .iter_mut()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("workspace package")["node"]["properties"]["workspace"] = serde_json::json!(false);

    let mut wrong_package_id = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    wrong_package_id
        .iter_mut()
        .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
        .expect("semantic node")["node"]["properties"]["package_id"] =
        serde_json::json!(format!("package:sha256:{}", "f".repeat(64)));

    let mut ghost_evidence = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let ghost_edge = &mut ghost_evidence
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"];
    ghost_edge["evidence"][0]["path"] = serde_json::json!("src/ghost.ts");
    let ghost_identity = serde_json::json!({
        "condition": ghost_edge["condition"].clone(),
        "kind": ghost_edge["kind"].clone(),
        "path": ghost_edge["evidence"][0]["path"].clone(),
        "profile_id": ghost_edge["profile_id"].clone(),
        "source": ghost_edge["source"].clone(),
        "span": {
            "end_column": ghost_edge["evidence"][0]["end_column"].clone(),
            "end_line": ghost_edge["evidence"][0]["end_line"].clone(),
            "start_column": ghost_edge["evidence"][0]["start_column"].clone(),
            "start_line": ghost_edge["evidence"][0]["start_line"].clone(),
        },
        "target": ghost_edge["target"].clone(),
    });
    ghost_edge["id"] = serde_json::json!(depgraph_protocol::stable_id_from_value(
        "edge",
        &ghost_identity,
    ));

    let mut orphan_node = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    orphan_node.retain(|event| event["event"] != "edge_upsert");
    orphan_node[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
        serde_json::json!("0");
    for (index, event) in orphan_node.iter_mut().enumerate() {
        event["seq"] = serde_json::json!(index + 1);
    }

    let mut wrong_issue_count = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    wrong_issue_count[1]["profile"]["properties"]["typescript_semantic_issue_count"] =
        serde_json::json!("1");

    let mut invalid_node_shape = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    invalid_node_shape
        .iter_mut()
        .find(|event| matches!(event["node"]["kind"].as_str(), Some("symbol" | "type")))
        .expect("semantic node")["node"]["locator"] = serde_json::json!("");

    let mut discarded_profile = parsed_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    discarded_profile[1]["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
        serde_json::json!("definition-graph-discarded");
    discarded_profile[1]["profile"]["properties"][TYPESCRIPT_DEFINITION_STATUS_PROPERTY] =
        serde_json::json!("failed");

    for (name, events) in [
        ("forbidden call", forbidden_call),
        ("wrong canonical hash", wrong_hash),
        ("wrong semantic extractor", wrong_extractor),
        ("wrong semantic count", wrong_count),
        ("linked definition relation", linked_relation),
        ("candidate definition relation", candidate_relation),
        ("semantic dependency site", semantic_site),
        ("external package ownership", external_package),
        ("wrong package ID", wrong_package_id),
        ("ghost evidence file", ghost_evidence),
        ("orphan semantic node", orphan_node),
        ("wrong semantic issue count", wrong_issue_count),
        ("invalid semantic node shape", invalid_node_shape),
        ("discarded profile emitted a delta", discarded_profile),
    ] {
        let output = serialized(events)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            16 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{name}: {:?}",
            parsed.error
        );
        assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
        assert!(parsed.error.is_some(), "{name}");
        assert!(
            !parsed.events.iter().any(|event| {
                matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                    || event["edge"]["phase"] == "semantic"
            }),
            "{name}: semantic delta survived an atomic rejection"
        );
        assert!(
            parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
            }),
            "{name}: syntax/package graph was not retained"
        );
    }
    Ok(())
}

#[test]
fn web_definition_graph_rejects_compromised_canonical_references_and_shapes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let protocol = |relation_kind| {
        test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            relation_kind,
        )?)
    };
    let mut cases = Vec::<(&str, Vec<Value>, &str)>::new();

    let mut dangling_origin = protocol("instantiates")?;
    let origin_resolver = dangling_origin
        .iter()
        .find(|event| event["node"]["properties"]["type_kind"] == "generic_instance")
        .expect("generic instance")["node"]["properties"]["canonical_identity"]["generic_origin"]
        .as_str()
        .expect("generic origin resolver")
        .to_owned();
    let origin_id = dangling_origin
        .iter()
        .find(|event| {
            event["node"]["properties"]["canonical_identity"]["resolver_identity"].as_str()
                == Some(origin_resolver.as_str())
        })
        .expect("generic origin node")["node"]["id"]
        .as_str()
        .expect("generic origin ID")
        .to_owned();
    dangling_origin.retain(|event| {
        event["node"]["id"].as_str() != Some(origin_id.as_str())
            && event["edge"]["target"].as_str() != Some(origin_id.as_str())
    });
    sync_test_semantic_counts(&mut dangling_origin);
    resequence_test_protocol(&mut dangling_origin);
    cases.push((
        "dangling generic origin",
        dangling_origin,
        "missing generic origin",
    ));

    let mut dangling_argument = protocol("instantiates")?;
    rewrite_test_generic_instance(
        &mut dangling_argument,
        serde_json::json!([{
            "kind": "definition",
            "resolver_identity": "npm:missing::type",
        }]),
        None,
    );
    cases.push((
        "dangling generic type argument",
        dangling_argument,
        "references missing semantic definition",
    ));

    let mut mismatched_resolver = protocol("instantiates")?;
    rewrite_test_generic_instance(
        &mut mismatched_resolver,
        serde_json::json!([{"kind": "intrinsic", "name": "string"}]),
        Some("generic:[\"spoofed\",[]]".to_owned()),
    );
    cases.push((
        "mismatched reconstructed resolver",
        mismatched_resolver,
        "resolver identity does not match",
    ));

    let mut missing_intrinsic_name = protocol("instantiates")?;
    rewrite_test_generic_instance(
        &mut missing_intrinsic_name,
        serde_json::json!([{"kind": "intrinsic"}]),
        None,
    );
    cases.push((
        "missing intrinsic name",
        missing_intrinsic_name,
        "non-canonical shape",
    ));

    let mut non_canonical_bigint = protocol("instantiates")?;
    rewrite_test_generic_instance(
        &mut non_canonical_bigint,
        serde_json::json!([{
            "kind": "literal",
            "value_kind": "bigint",
            "value": "00",
        }]),
        None,
    );
    cases.push((
        "non-canonical bigint literal",
        non_canonical_bigint,
        "non-canonical \"bigint\" literal",
    ));

    let mut oversized_descriptor = protocol("instantiates")?;
    rewrite_test_generic_instance(
        &mut oversized_descriptor,
        serde_json::json!([{
            "kind": "literal",
            "value_kind": "string",
            "value": "x".repeat(TYPESCRIPT_MAX_TYPE_DESCRIPTOR_CHARS + 1),
        }]),
        None,
    );
    cases.push((
        "oversized descriptor",
        oversized_descriptor,
        "exceeds 2048 characters",
    ));

    let mut reordered_descriptor = protocol("instantiates")?;
    let mut reordered_intrinsic = serde_json::Map::new();
    reordered_intrinsic.insert("name".to_owned(), serde_json::json!("string"));
    reordered_intrinsic.insert("kind".to_owned(), serde_json::json!("intrinsic"));
    rewrite_test_generic_instance(
        &mut reordered_descriptor,
        Value::Array(vec![Value::Object(reordered_intrinsic)]),
        None,
    );
    cases.push((
        "reordered descriptor resolver",
        reordered_descriptor,
        "resolver identity does not match",
    ));

    let mut non_generic_metadata = protocol("extends")?;
    let non_generic_index = non_generic_metadata
        .iter()
        .position(|event| event["node"]["properties"]["type_kind"] == "class")
        .expect("non-generic class");
    non_generic_metadata[non_generic_index]["node"]["properties"]["canonical_identity"]["generic_origin"] =
        serde_json::json!("spoofed-origin");
    non_generic_metadata[non_generic_index]["node"]["properties"]["canonical_identity"]["type_arguments"] =
        serde_json::json!([{"kind": "intrinsic", "name": "string"}]);
    non_generic_metadata[non_generic_index]["node"]["properties"]["generic_origin"] =
        serde_json::json!("spoofed-origin");
    non_generic_metadata[non_generic_index]["node"]["properties"]["type_arguments"] =
        serde_json::json!([{"kind": "intrinsic", "name": "string"}]);
    refresh_test_semantic_node_id(&mut non_generic_metadata, non_generic_index);
    cases.push((
        "non-generic type metadata",
        non_generic_metadata,
        "non-generic type",
    ));

    let mut mismatched_top_resolver = protocol("declares")?;
    let named_index = mismatched_top_resolver
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("named symbol");
    mismatched_top_resolver[named_index]["node"]["properties"]["resolver_identity"] =
        serde_json::json!("spoofed-resolver");
    cases.push((
        "mismatched named resolver",
        mismatched_top_resolver,
        "top-level resolver",
    ));

    let mut extra_identity_field = protocol("declares")?;
    let extra_identity_index = extra_identity_field
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("named symbol");
    extra_identity_field[extra_identity_index]["node"]["properties"]["canonical_identity"]["nonce"] =
        serde_json::json!(true);
    refresh_test_semantic_node_id(&mut extra_identity_field, extra_identity_index);
    cases.push((
        "extra canonical identity field",
        extra_identity_field,
        "canonical identity shape",
    ));

    let mut absolute_resolver = protocol("declares")?;
    let absolute_resolver_index = absolute_resolver
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("named symbol");
    let resolver = "/Users/alice/project/src/index.ts#Definition";
    absolute_resolver[absolute_resolver_index]["node"]["properties"]["canonical_identity"]["resolver_identity"] =
        serde_json::json!(resolver);
    absolute_resolver[absolute_resolver_index]["node"]["properties"]["resolver_identity"] =
        serde_json::json!(resolver);
    refresh_test_semantic_node_id(&mut absolute_resolver, absolute_resolver_index);
    cases.push((
        "absolute path resolver",
        absolute_resolver,
        "canonical identity shape",
    ));

    let mut wrong_local_origin_field = protocol("declares")?;
    let file_id = wrong_local_origin_field
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .as_str()
        .expect("source file ID")
        .to_owned();
    let local_index = wrong_local_origin_field
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("symbol node");
    {
        let node = &mut wrong_local_origin_field[local_index]["node"];
        let source_span = node["properties"]["source_span"].clone();
        node["properties"]["symbol_kind"] = serde_json::json!("local_function");
        node["properties"]
            .as_object_mut()
            .expect("symbol properties")
            .remove("resolver_identity");
        let identity = node["properties"]["canonical_identity"]
            .as_object_mut()
            .expect("symbol identity");
        identity.insert(
            "symbol_kind".to_owned(),
            serde_json::json!("local_function"),
        );
        identity.insert("identity_kind".to_owned(), serde_json::json!("local"));
        identity.remove("resolver_identity");
        identity.insert("generated_from".to_owned(), serde_json::json!(file_id));
        identity.insert(
            "relative_path".to_owned(),
            serde_json::json!("src/index.ts"),
        );
        identity.insert("span".to_owned(), source_span);
    }
    refresh_test_semantic_node_id(&mut wrong_local_origin_field, local_index);
    cases.push((
        "local symbol with anonymous origin field",
        wrong_local_origin_field,
        "wrong canonical origin field",
    ));

    let mut incompatible_anonymous_origin = protocol("declares")?;
    let package_id = incompatible_anonymous_origin
        .iter()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("package node")["node"]["id"]
        .as_str()
        .expect("package ID")
        .to_owned();
    let anonymous_index = incompatible_anonymous_origin
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("symbol node");
    {
        let node = &mut incompatible_anonymous_origin[anonymous_index]["node"];
        let source_span = node["properties"]["source_span"].clone();
        node["properties"]["symbol_kind"] = serde_json::json!("anonymous_function");
        node["properties"]
            .as_object_mut()
            .expect("symbol properties")
            .remove("resolver_identity");
        let identity = node["properties"]["canonical_identity"]
            .as_object_mut()
            .expect("symbol identity");
        identity.insert(
            "symbol_kind".to_owned(),
            serde_json::json!("anonymous_function"),
        );
        identity.insert("identity_kind".to_owned(), serde_json::json!("anonymous"));
        identity.remove("resolver_identity");
        identity.insert("generated_from".to_owned(), serde_json::json!(package_id));
        identity.insert(
            "relative_path".to_owned(),
            serde_json::json!("src/index.ts"),
        );
        identity.insert("span".to_owned(), source_span);
    }
    refresh_test_semantic_node_id(&mut incompatible_anonymous_origin, anonymous_index);
    cases.push((
        "anonymous symbol with incompatible origin",
        incompatible_anonymous_origin,
        "incompatible kind, package, or language",
    ));

    let mut unknown_kind = protocol("declares")?;
    let unknown_index = unknown_kind
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("symbol node");
    unknown_kind[unknown_index]["node"]["properties"]["symbol_kind"] =
        serde_json::json!("namespace");
    unknown_kind[unknown_index]["node"]["properties"]["canonical_identity"]["symbol_kind"] =
        serde_json::json!("namespace");
    refresh_test_semantic_node_id(&mut unknown_kind, unknown_index);
    cases.push((
        "unsupported semantic kind",
        unknown_kind,
        "unsupported symbol",
    ));

    let mut source_edge = protocol("declares")?;
    let edge = &mut source_edge
        .iter_mut()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")["edge"];
    edge["kind"] = serde_json::json!("imports");
    edge["phase"] = serde_json::json!("source");
    edge["evidence"][0]["kind"] = serde_json::json!("source");
    rehash_test_definition_edge(edge);
    cases.push((
        "source edge incident to a definition",
        source_edge,
        "must use phase=semantic",
    ));

    let mut incident_site = protocol("declares")?;
    let site_source = incident_site
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .clone();
    let site_target = incident_site
        .iter()
        .find(|event| event["node"]["kind"] == "symbol")
        .expect("semantic symbol")["node"]["id"]
        .clone();
    let edge_index = incident_site
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("definition edge");
    incident_site.insert(
        edge_index,
        serde_json::json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 0,
            "site": {
                "id": format!("site:sha256:{}", "1".repeat(64)),
                "source": site_source,
                "kind": "import",
                "specifier": "./semantic",
                "resolution_status": "resolved",
                "target_ids": [site_target],
                "profile_id": "web:default",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": [{
                    "kind": "source",
                    "extractor": "typescript-static",
                    "extractor_version": "1",
                    "path": "src/index.ts",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9
                }]
            }
        }),
    );
    resequence_test_protocol(&mut incident_site);
    cases.push((
        "dependency site incident to a definition",
        incident_site,
        "forbidden semantic dependency site",
    ));

    let mut semantic_source_site = protocol("declares")?;
    let site_source = semantic_source_site
        .iter()
        .find(|event| event["node"]["kind"] == "symbol")
        .expect("semantic symbol")["node"]["id"]
        .clone();
    let site_target = semantic_source_site
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .clone();
    let edge_index = semantic_source_site
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("definition edge");
    semantic_source_site.insert(
        edge_index,
        serde_json::json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 0,
            "site": {
                "id": format!("site:sha256:{}", "4".repeat(64)),
                "source": site_source,
                "kind": "import",
                "specifier": "./syntax",
                "resolution_status": "resolved",
                "target_ids": [site_target],
                "profile_id": "web:default",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": [{
                    "kind": "source",
                    "extractor": "typescript-static",
                    "extractor_version": "1",
                    "path": "src/index.ts",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9
                }]
            }
        }),
    );
    resequence_test_protocol(&mut semantic_source_site);
    cases.push((
        "dependency site sourced by a definition",
        semantic_source_site,
        "forbidden semantic dependency site",
    ));

    for (name, events, expected_error) in cases {
        let semantic_ids = events
            .iter()
            .filter_map(|event| {
                matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                    .then(|| event["node"]["id"].as_str().map(str::to_owned))
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        let output = serialize_test_protocol(events)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{name}: {:?}",
            parsed.error
        );
        assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
        assert!(
            parsed
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error)),
            "{name}: {:?}",
            parsed.error
        );
        assert!(
            !parsed.events.iter().any(|event| {
                matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                    || event["edge"]["source"]
                        .as_str()
                        .is_some_and(|id| semantic_ids.contains(id))
                    || event["edge"]["target"]
                        .as_str()
                        .is_some_and(|id| semantic_ids.contains(id))
                    || event["site"]["source"]
                        .as_str()
                        .is_some_and(|id| semantic_ids.contains(id))
                    || event["site"]["target_ids"]
                        .as_array()
                        .is_some_and(|targets| {
                            targets.iter().any(|target| {
                                target.as_str().is_some_and(|id| semantic_ids.contains(id))
                            })
                        })
            }),
            "{name}: definition incident survived atomic cleanup"
        );
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
        }));
        assert!(
            parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "file"
            })
        );
    }
    Ok(())
}

#[test]
fn web_definition_cleanup_tracks_forward_references_to_rejected_events() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;

    let mut forward_definition = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let semantic_index = forward_definition
        .iter()
        .position(|event| event["node"]["kind"] == "symbol")
        .expect("semantic symbol");
    forward_definition[semantic_index]["node"]["properties"]["language"] =
        serde_json::json!("rust");
    let semantic_event = forward_definition.remove(semantic_index);
    let semantic_id = semantic_event["node"]["id"].clone();
    let edge_index = forward_definition
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("definition edge");
    let mut forward_edge = forward_definition.remove(edge_index);
    let forward_site_id = format!("site:sha256:{}", "5".repeat(64));
    forward_edge["edge"]["kind"] = serde_json::json!("imports");
    forward_edge["edge"]["phase"] = serde_json::json!("source");
    forward_edge["edge"]["site_id"] = serde_json::json!(forward_site_id);
    forward_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
    rehash_test_definition_edge(&mut forward_edge["edge"]);
    let file_id = forward_definition
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .clone();
    let insert_at = forward_definition
        .iter()
        .position(|event| event["node"]["kind"] == "file")
        .expect("source file")
        + 1;
    forward_definition.insert(insert_at, forward_edge);
    forward_definition.insert(
        insert_at + 1,
        serde_json::json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 0,
            "site": {
                "id": forward_site_id,
                "source": semantic_id,
                "kind": "import",
                "specifier": "./forward",
                "resolution_status": "resolved",
                "target_ids": [file_id],
                "profile_id": "web:default",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": [{
                    "kind": "source",
                    "extractor": "typescript-static",
                    "extractor_version": "1",
                    "path": "src/index.ts",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9
                }]
            }
        }),
    );
    forward_definition.insert(insert_at + 2, semantic_event);
    resequence_test_protocol(&mut forward_definition);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(forward_definition)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("language=typescript or javascript")),
        "{:?}",
        parsed.error
    );
    assert!(!parsed.events.iter().any(|event| {
        event["node"]["id"] == semantic_id
            || event["edge"]["site_id"] == forward_site_id
            || event["site"]["id"] == forward_site_id
    }));
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "package_instance")
    );
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "file")
    );

    let mut rejected_site = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let mut linked_edge = rejected_site
        .iter()
        .find(|event| event["event"] == "edge_upsert")
        .expect("definition edge")
        .clone();
    rejected_site.retain(|event| {
        !matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
            && event["event"] != "edge_upsert"
    });
    sync_test_semantic_counts(&mut rejected_site);
    let package_id = rejected_site
        .iter()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("package node")["node"]["id"]
        .clone();
    let file_id = rejected_site
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .clone();
    let rejected_site_id = format!("site:sha256:{}", "6".repeat(64));
    linked_edge["edge"]["source"] = package_id.clone();
    linked_edge["edge"]["target"] = file_id.clone();
    linked_edge["edge"]["kind"] = serde_json::json!("imports");
    linked_edge["edge"]["phase"] = serde_json::json!("source");
    linked_edge["edge"]["site_id"] = serde_json::json!(rejected_site_id);
    linked_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
    rehash_test_definition_edge(&mut linked_edge["edge"]);
    let insert_at = rejected_site
        .iter()
        .position(|event| event["node"]["kind"] == "file")
        .expect("source file")
        + 1;
    rejected_site.insert(insert_at, linked_edge);
    rejected_site.insert(
        insert_at + 1,
        serde_json::json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 0,
            "site": {
                "id": rejected_site_id,
                "source": file_id,
                "kind": "call",
                "specifier": "forbidden",
                "resolution_status": "resolved",
                "target_ids": [package_id],
                "profile_id": "web:default",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": [{
                    "kind": "source",
                    "extractor": "typescript-static",
                    "extractor_version": "1",
                    "path": "src/index.ts",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9
                }]
            }
        }),
    );
    resequence_test_protocol(&mut rejected_site);
    let mut metadata_invalid_site = rejected_site.clone();
    let invalid_site = metadata_invalid_site
        .iter_mut()
        .find(|event| event["event"] == "dependency_site")
        .expect("forward dependency site");
    invalid_site["adapter_version"] = serde_json::json!("spoofed-version");
    invalid_site["site"]["kind"] = serde_json::json!("import");
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(rejected_site)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(!parsed.events.iter().any(|event| {
        event["edge"]["site_id"] == rejected_site_id || event["site"]["id"] == rejected_site_id
    }));
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "package_instance")
    );
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "file")
    );

    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(metadata_invalid_site)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation, "{:?}", parsed.error);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains("adapter_version mismatch")),
        "{:?}",
        parsed.error
    );
    assert!(!parsed.events.iter().any(|event| {
        event["edge"]["site_id"] == rejected_site_id || event["site"]["id"] == rejected_site_id
    }));
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "package_instance")
    );
    assert!(
        parsed
            .events
            .iter()
            .any(|event| event["node"]["kind"] == "file")
    );
    Ok(())
}

#[test]
fn web_definition_delta_cleanup_closes_over_incident_edge_sites() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "declares",
    )?)?;
    let semantic_id = events
        .iter()
        .find(|event| event["node"]["kind"] == "symbol")
        .expect("semantic symbol")["node"]["id"]
        .clone();
    let file_id = events
        .iter()
        .find(|event| event["node"]["kind"] == "file")
        .expect("source file")["node"]["id"]
        .clone();
    let package_id = events
        .iter()
        .find(|event| event["node"]["kind"] == "package_instance")
        .expect("package node")["node"]["id"]
        .clone();
    let site_id = format!("site:sha256:{}", "2".repeat(64));
    let edge_index = events
        .iter()
        .position(|event| event["event"] == "edge_upsert")
        .expect("definition edge");
    events[edge_index]["edge"]["site_id"] = serde_json::json!(site_id);

    let mut linked_syntax_edge = events[edge_index].clone();
    linked_syntax_edge["edge"]["id"] = serde_json::json!(format!("edge:sha256:{}", "3".repeat(64)));
    linked_syntax_edge["edge"]["source"] = package_id.clone();
    linked_syntax_edge["edge"]["target"] = file_id.clone();
    linked_syntax_edge["edge"]["kind"] = serde_json::json!("imports");
    linked_syntax_edge["edge"]["phase"] = serde_json::json!("source");
    linked_syntax_edge["edge"]["evidence"][0]["kind"] = serde_json::json!("source");
    let missing_site_id = format!("site:sha256:{}", "7".repeat(64));
    let mut missing_site_edge = linked_syntax_edge.clone();
    missing_site_edge["edge"]["id"] = serde_json::json!(format!("edge:sha256:{}", "8".repeat(64)));
    missing_site_edge["edge"]["site_id"] = serde_json::json!(missing_site_id);
    events.insert(edge_index + 1, linked_syntax_edge);
    events.insert(edge_index + 2, missing_site_edge);
    events.insert(
        edge_index,
        serde_json::json!({
            "event": "dependency_site",
            "protocol_version": "1.0",
            "scan_id": "typescript-gate-scan",
            "adapter": "web",
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "seq": 0,
            "site": {
                "id": site_id,
                "source": file_id,
                "kind": "import",
                "specifier": "./syntax-only",
                "resolution_status": "resolved",
                "target_ids": [package_id],
                "profile_id": "web:default",
                "condition": {"op": "all", "conditions": []},
                "precision": "exact",
                "evidence": [{
                    "kind": "source",
                    "extractor": "typescript-static",
                    "extractor_version": "1",
                    "path": "src/index.ts",
                    "start_line": 1,
                    "start_column": 1,
                    "end_line": 1,
                    "end_column": 9
                }]
            }
        }),
    );
    let mut typed = events
        .into_iter()
        .map(serde_json::from_value::<ProtocolEvent>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    discard_web_definition_delta(
        &mut typed,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
        &BTreeSet::new(),
    );

    let values = typed
        .into_iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert!(!values.iter().any(|event| {
        event["node"]["id"] == semantic_id
            || event["site"]["id"] == site_id
            || event["edge"]["site_id"] == site_id
            || event["edge"]["site_id"] == missing_site_id
    }));
    assert!(values.iter().any(|event| event["node"]["id"] == file_id));
    assert!(values.iter().any(|event| event["node"]["id"] == package_id));
    Ok(())
}

#[test]
fn web_definition_graph_accepts_canonical_generic_type_argument_shapes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let template = test_protocol_values(typescript_definition_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
        "instantiates",
    )?)?;
    let origin_resolver = template
        .iter()
        .find(|event| event["node"]["properties"]["type_kind"] == "generic_instance")
        .expect("generic instance")["node"]["properties"]["generic_origin"]
        .as_str()
        .expect("generic origin resolver")
        .to_owned();
    let descriptors = vec![
        (
            "string literal",
            serde_json::json!([{
                "kind": "literal",
                "value_kind": "string",
                "value": "a,b",
            }]),
        ),
        (
            "small exponent number",
            serde_json::json!([{
                "kind": "literal",
                "value_kind": "number",
                "value": "1e-7",
            }]),
        ),
        (
            "large exponent number",
            serde_json::json!([{
                "kind": "literal",
                "value_kind": "number",
                "value": "1e+21",
            }]),
        ),
        (
            "canonical union",
            serde_json::json!([{
                "kind": "union",
                "members": [
                    {"kind": "intrinsic", "name": "number"},
                    {"kind": "intrinsic", "name": "string"},
                ],
            }]),
        ),
        (
            "type parameter",
            serde_json::json!([{
                "kind": "type_parameter",
                "owner": origin_resolver,
                "index": 0,
                "name": "T",
            }]),
        ),
        (
            "generic application",
            serde_json::json!([{
                "kind": "application",
                "target": {
                    "kind": "definition",
                    "resolver_identity": origin_resolver,
                },
                "type_arguments": [
                    {"kind": "intrinsic", "name": "string"},
                ],
            }]),
        ),
    ];

    for (name, descriptor) in descriptors {
        let mut events = test_protocol_values(typescript_definition_protocol(
            &root,
            TYPESCRIPT_RELEASE_GATE_PENDING,
            "instantiates",
        )?)?;
        rewrite_test_generic_instance(&mut events, descriptor, None);
        let output = serialize_test_protocol(events)?;
        let parsed = parse_events_preserving_prefix(
            &output,
            "typescript-gate-scan",
            "web",
            &root,
            64 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.error, None, "{name}: {:?}", parsed.error);
        assert_eq!(parsed.failure_kind, None, "{name}");
        assert!(!parsed.security_violation, "{name}");
        assert!(
            parsed
                .events
                .iter()
                .any(|event| { event["node"]["properties"]["type_kind"] == "generic_instance" })
        );
    }
    Ok(())
}

#[test]
fn web_definition_failure_profiles_preserve_the_syntax_delta() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;

    for (project, typechecker, definition) in [
        ("ready", "definition-graph-discarded", "failed"),
        ("failed", "failed", "failed"),
    ] {
        let output =
            typescript_definition_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING, "declares")?;
        let mut events = String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        events.retain(|event| {
            !matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                && event["edge"]["phase"] != "semantic"
        });
        events[1]["profile"]["properties"][TYPESCRIPT_PROJECT_STATUS_PROPERTY] =
            serde_json::json!(project);
        events[1]["profile"]["properties"][TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY] =
            serde_json::json!(typechecker);
        events[1]["profile"]["properties"][TYPESCRIPT_DEFINITION_STATUS_PROPERTY] =
            serde_json::json!(definition);
        events[1]["profile"]["properties"]["typescript_semantic_node_count"] =
            serde_json::json!("0");
        events[1]["profile"]["properties"]["typescript_semantic_relation_count"] =
            serde_json::json!("0");
        for (index, event) in events.iter_mut().enumerate() {
            event["seq"] = serde_json::json!(index + 1);
        }
        let mut protocol = Vec::new();
        for event in events {
            serde_json::to_writer(&mut protocol, &event)?;
            protocol.push(b'\n');
        }

        let parsed = parse_events_preserving_prefix(
            &protocol,
            "typescript-gate-scan",
            "web",
            &root,
            16 * 1024,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(
            parsed.error, None,
            "state={project}/{typechecker}/{definition}"
        );
        assert_eq!(parsed.failure_kind, None);
        assert!(!parsed.security_violation);
        assert!(parsed.events.iter().any(|event| {
            event["event"] == "node_upsert" && event["node"]["kind"] == "package_instance"
        }));
        assert!(
            parsed.events.iter().any(|event| {
                event["event"] == "node_upsert" && event["node"]["kind"] == "file"
            })
        );
        assert!(!parsed.events.iter().any(|event| {
            matches!(event["node"]["kind"].as_str(), Some("symbol" | "type"))
                || event["edge"]["phase"] == "semantic"
        }));
    }
    Ok(())
}

#[test]
fn web_definition_profile_rejects_inconsistent_state_and_language() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;

    for (name, property, value) in [
        (
            "inconsistent state",
            TYPESCRIPT_TYPECHECKER_STATUS_PROPERTY,
            "failed",
        ),
        ("wrong profile language", "language", "typescript"),
    ] {
        let output = typescript_gate_protocol(&root, TYPESCRIPT_RELEASE_GATE_PENDING)?;
        let mut events = String::from_utf8(output)?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if property == "language" {
            events[1]["profile"]["language"] = serde_json::json!(value);
        } else {
            events[1]["profile"]["properties"][property] = serde_json::json!(value);
        }
        let mut protocol = Vec::new();
        for event in events {
            serde_json::to_writer(&mut protocol, &event)?;
            protocol.push(b'\n');
        }

        let parsed = parse_events_preserving_prefix(
            &protocol,
            "typescript-gate-scan",
            "web",
            &root,
            4096,
            Some(env!("CARGO_PKG_VERSION")),
            Some(false),
        );
        assert_eq!(parsed.events.len(), 1, "{name}: {:?}", parsed.error);
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol),
            "{name}: {:?}",
            parsed.error
        );
        assert!(parsed.security_violation, "{name}: {:?}", parsed.error);
    }
    Ok(())
}

#[test]
fn web_semantic_complete_requires_call_graph_v2_capability() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let mut events = test_protocol_values(typescript_call_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_PENDING,
    )?)?;
    promote_typescript_semantic_complete(&mut events, TYPESCRIPT_RELEASE_GATE_PENDING);
    events
        .iter_mut()
        .find(|event| event["event"] == "profile_declared")
        .expect("Web profile declaration")["profile"]["properties"]
        [TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY] =
        serde_json::json!(TYPESCRIPT_SEMANTIC_EMISSION_IMPORT_TYPE_CALL_GRAPH_V1);
    resequence_test_protocol(&mut events);
    let parsed = parse_events_preserving_prefix(
        &serialize_test_protocol(events)?,
        "typescript-gate-scan",
        "web",
        &root,
        64 * 1024,
        Some(env!("CARGO_PKG_VERSION")),
        Some(false),
    );
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    assert!(
        parsed
            .error
            .as_deref()
            .is_some_and(|error| error.contains(TYPESCRIPT_SEMANTIC_EMISSION_PROPERTY))
    );
    Ok(())
}

#[test]
fn rust_release_handshake_covers_the_backend_compatibility_unit() -> Result<()> {
    let handshake = format!(
        "depgraph-rust-worker {} (protocol 1.0; rust-analyzer {}; rust-analyzer-revision {}; salsa {})",
        env!("CARGO_PKG_VERSION"),
        RUST_BACKEND_VERSION,
        RUST_BACKEND_REVISION,
        RUST_BACKEND_SALSA_VERSION,
    );
    verify_rust_release_handshake(
        &handshake,
        env!("CARGO_PKG_VERSION"),
        RUST_BACKEND_KIND,
        RUST_BACKEND_VERSION,
        RUST_BACKEND_REVISION,
        RUST_BACKEND_SALSA_VERSION,
    )?;

    let mismatch = handshake.replace(RUST_BACKEND_REVISION, "different-revision");
    let error = verify_rust_release_handshake(
        &mismatch,
        env!("CARGO_PKG_VERSION"),
        RUST_BACKEND_KIND,
        RUST_BACKEND_VERSION,
        RUST_BACKEND_REVISION,
        RUST_BACKEND_SALSA_VERSION,
    )
    .unwrap_err();
    assert!(error.to_string().contains("backend handshake mismatch"));
    assert!(is_security_error(&error.to_string()));
    Ok(())
}

#[test]
fn web_release_handshake_covers_the_semantic_compatibility_unit() -> Result<()> {
    let capabilities = WEB_SEMANTIC_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let handshake = format!(
        "depgraph-web-worker {} (protocol 1.0; typescript {}; capabilities {})",
        env!("CARGO_PKG_VERSION"),
        TYPESCRIPT_COMPILER_VERSION,
        capabilities.join(","),
    );
    verify_web_release_handshake(
        &handshake,
        env!("CARGO_PKG_VERSION"),
        TYPESCRIPT_COMPILER_VERSION,
        &capabilities,
    )?;

    for mismatch in [
        handshake.replace(TYPESCRIPT_COMPILER_VERSION, "9.9.9"),
        handshake.replace("capabilities astro", "unknown astro"),
        handshake.replace(
            "astro-component-render-hydration-v1,framework-semantic-completeness-v1",
            "framework-semantic-completeness-v1,astro-component-render-hydration-v1",
        ),
    ] {
        let error = verify_web_release_handshake(
            &mismatch,
            env!("CARGO_PKG_VERSION"),
            TYPESCRIPT_COMPILER_VERSION,
            &capabilities,
        )
        .unwrap_err();
        assert!(is_security_error(&error.to_string()));
    }
    Ok(())
}

#[test]
fn packaged_event_version_must_match_the_manifest() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    let output = format!(
        "{{\"event\":\"scan_started\",\"protocol_version\":\"1.0\",\"scan_id\":\"s\",\"adapter\":\"go\",\"adapter_version\":\"9.9.9\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
        serde_json::to_string(&root.to_string_lossy())?
    );
    let parsed = parse_events_preserving_prefix(
        output.as_bytes(),
        "s",
        "go",
        &root,
        4096,
        Some("0.1.0"),
        None,
    );
    assert!(parsed.events.is_empty());
    assert_eq!(
        parsed.failure_kind,
        Some(WorkerFailureKind::MalformedProtocol)
    );
    assert!(parsed.security_violation);
    let error = parsed.error.unwrap();
    assert!(error.contains("security policy violation"));
    assert!(error.contains("adapter_version mismatch"));
    Ok(())
}

#[test]
fn packaged_event_protocol_and_adapter_identity_mismatches_are_security_failures() -> Result<()> {
    let root = tempfile::tempdir()?;
    let root = root.path().canonicalize()?;
    for (protocol, adapter, expected) in [
        ("9.9", "go", "protocol_version mismatch"),
        ("1.0", "web", "adapter mismatch"),
    ] {
        let output = format!(
            "{{\"event\":\"scan_started\",\"protocol_version\":\"{protocol}\",\"scan_id\":\"s\",\"adapter\":\"{adapter}\",\"adapter_version\":\"0.1.0\",\"seq\":1,\"root\":{},\"project_code_executed\":false,\"safe_mode\":true}}\n",
            serde_json::to_string(&root.to_string_lossy())?
        );
        let parsed = parse_events_preserving_prefix(
            output.as_bytes(),
            "s",
            "go",
            &root,
            4096,
            Some("0.1.0"),
            None,
        );
        assert!(parsed.events.is_empty());
        assert_eq!(
            parsed.failure_kind,
            Some(WorkerFailureKind::MalformedProtocol)
        );
        assert!(parsed.security_violation);
        let error = parsed.error.unwrap();
        assert!(error.contains("security policy violation"));
        assert!(error.contains(expected));
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn verified_rust_release_worker_receives_the_release_gate() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("rust-release-worker.sh");
    let script_contents = r#"#!/bin/sh
if [ "$DEPGRAPH_RUST_RELEASE_GATE" != "release-gate-verified" ]; then
  exit 9
fi
if [ ! -d "$DEPGRAPH_RUST_SYSROOT_ROOT" ]; then
  exit 10
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"__VERSION__","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"scan_completed","protocol_version":"1.0","scan_id":"%s","adapter":"rust","adapter_version":"__VERSION__","seq":2,"coverage":{"profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}}\n' "$scan"
"#
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"));
    std::fs::write(&script, script_contents)?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let attested_sysroot = temp.path().join("rust-sysroot");
    std::fs::create_dir(&attested_sysroot)?;
    let mut spec = WorkerSpec {
        adapter: AdapterKind::Rust,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
        release_attested: true,
        attested_rust_sysroot: Some(attested_sysroot.canonicalize()?),
    };
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "release-gate-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(execution.events.len(), 2);
    assert!(execution.error.is_none(), "{:?}", execution.error);

    spec.attested_rust_sysroot = None;
    let missing_sysroot = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "missing-sysroot-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await
    .expect_err("a verified Rust worker without an attested sysroot must fail closed");
    assert!(
        missing_sysroot
            .to_string()
            .contains("verified Rust worker has no attested sysroot component")
    );

    spec.release_attested = false;
    let unverified = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "unverified-release-gate-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(
        unverified.failure_kind,
        Some(WorkerFailureKind::NonzeroExit)
    );
    assert!(unverified.error.is_some());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn verified_web_release_worker_receives_the_typescript_release_gate() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("web-release-worker.mjs");
    let protocol = String::from_utf8(typescript_gate_protocol(
        &root,
        TYPESCRIPT_RELEASE_GATE_VERIFIED,
    )?)?;
    let script_contents = format!(
        "if (process.env.DEPGRAPH_TYPESCRIPT_RELEASE_GATE !== \"release-gate-verified\") process.exit(9);\nprocess.stdout.write({});\n",
        serde_json::to_string(&protocol)?,
    );
    std::fs::write(&script, script_contents)?;
    let mut spec = worker_spec_from_path(AdapterKind::Web, script, None);
    spec.expected_version = Some(env!("CARGO_PKG_VERSION").to_owned());
    spec.release_attested = true;
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "typescript-gate-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(
        execution.events.len(),
        4,
        "error={:?}, stderr={:?}, failure_kind={:?}",
        execution.error,
        execution.stderr,
        execution.failure_kind
    );
    assert!(execution.error.is_none(), "{:?}", execution.error);

    spec.release_attested = false;
    let unverified = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "typescript-gate-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(
        unverified.failure_kind,
        Some(WorkerFailureKind::NonzeroExit)
    );
    assert!(unverified.error.is_some());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn timeout_keeps_the_worker_prefix_and_caps_stderr() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("fake-worker.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"node_upsert","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"node":{"id":"file:one","kind":"file","locator":"file://one","properties":{}}}\n' "$scan"
printf '0123456789abcdef' >&2
exec sleep 10
"#,
    )?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    // Keep this test independent from the process-wide Ctrl-C listener;
    // cancellation has its own deterministic test below.
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "timeout-scan",
        &ScanConfig {
            // Give the child enough scheduling headroom when the Rust
            // test suite runs process-heavy cases in parallel. The
            // worker still sleeps long enough to deterministically hit
            // the timeout after its protocol prefix has been flushed.
            worker_timeout_seconds: 3,
            max_protocol_line_bytes: 4096,
            max_protocol_bytes: 64 * 1024,
            max_stderr_bytes: 8,
            follow_symlinks: false,
        },
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(execution.events.len(), 2);
    assert!(execution.error.unwrap().contains("timed out"));
    assert_eq!(execution.stderr, "01234567");
    assert!(execution.stderr_truncated);
    assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Timeout));
    assert!(!execution.security_violation);
    Ok(())
}

#[tokio::test]
async fn web_worker_timeout_reaps_its_descendant_cross_platform() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let marker = temp.path().join("descendant-survived");
    let descendant_ready = temp.path().join("descendant-ready");
    let descendant_trigger = temp.path().join("descendant-trigger");
    let script = temp.path().join("timeout-worker.mjs");
    let script_contents = format!(
        r#"import {{ spawn }} from "node:child_process";
const args = process.argv.slice(2);
const value = (name) => args[args.indexOf(name) + 1];
const root = value("--root");
const scanId = value("--scan-id");
process.stdout.write(JSON.stringify({{
  event: "scan_started",
  protocol_version: "1.0",
  scan_id: scanId,
  adapter: "web",
  adapter_version: "0.1.0",
  seq: 1,
  root,
  project_code_executed: false,
  safe_mode: true,
}}) + "\n");
spawn(process.execPath, ["-e", {}], {{ stdio: "ignore" }});
setInterval(() => undefined, 1_000);
"#,
        serde_json::to_string(&format!(
            "const fs = require('node:fs'); fs.writeFileSync({}, 'ready'); setInterval(() => {{ if (fs.existsSync({})) fs.writeFileSync({}, 'survived'); }}, 25);",
            serde_json::to_string(&descendant_ready.to_string_lossy())?,
            serde_json::to_string(&descendant_trigger.to_string_lossy())?,
            serde_json::to_string(&marker.to_string_lossy())?,
        ))?,
    );
    std::fs::write(&script, script_contents)?;
    let spec = worker_spec_from_path(AdapterKind::Web, script, None);
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "web-timeout-scan",
        &ScanConfig {
            // Windows cold-start antivirus scanning can delay the first
            // Node protocol event by several seconds. The descendant
            // handshake below keeps the reap assertion deterministic.
            worker_timeout_seconds: 10,
            max_protocol_line_bytes: 4096,
            max_protocol_bytes: 64 * 1024,
            max_stderr_bytes: 4096,
            follow_symlinks: false,
        },
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(execution.events.len(), 1);
    assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Timeout));
    assert!(
        execution
            .error
            .as_deref()
            .is_some_and(|error| error.contains("timed out"))
    );
    assert!(
        descendant_ready.exists(),
        "timed-out Web worker descendant never reached its ready state"
    );
    std::fs::write(&descendant_trigger, b"check")?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!marker.exists(), "timed-out Web worker descendant survived");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn cancellation_keeps_the_worker_prefix_and_reaps_the_process() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("cancel-worker.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"node_upsert","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"node":{"id":"file:before-cancel","kind":"file","locator":"file://before-cancel","properties":{}}}\n' "$scan"
printf 'worker-log' >&2
: > "${0%/*}/ready"
exec sleep 30
"#,
    )?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let started = Instant::now();
    let ready = temp.path().join("ready");
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "cancel-scan",
        &ScanConfig {
            worker_timeout_seconds: 10,
            max_protocol_line_bytes: 4096,
            max_protocol_bytes: 64 * 1024,
            max_stderr_bytes: 1024,
            follow_symlinks: false,
        },
        &ProfileConfig::default(),
        None,
        async move {
            timeout(Duration::from_secs(5), async {
                while !ready.is_file() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .map_err(std::io::Error::other)
        },
    )
    .await?;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(execution.events.len(), 2);
    assert_eq!(execution.stderr, "worker-log");
    assert!(!execution.stderr_truncated);
    assert!(execution.error.unwrap().contains("cancelled by user"));
    assert_eq!(execution.failure_kind, Some(WorkerFailureKind::Cancelled));
    assert!(!execution.security_violation);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_worker_output_keeps_its_prefix_and_stderr_separate() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("malformed-worker.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf 'not-json\n'
printf 'operational log' >&2
"#,
    )?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let output = execute_worker(
        spec,
        root,
        "malformed-scan".to_owned(),
        ScanConfig {
            worker_timeout_seconds: 5,
            max_protocol_line_bytes: 4096,
            max_protocol_bytes: 64 * 1024,
            max_stderr_bytes: 1024,
            follow_symlinks: false,
        },
        ProfileConfig::default(),
    )
    .await;
    assert_eq!(output.events.len(), 1);
    assert_eq!(output.stderr, "operational log");
    let error = output.error.unwrap();
    assert!(error.contains("malformed NDJSON"));
    assert!(error.contains("stderr: operational log"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn worker_process_starts_from_a_neutral_working_directory() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("neutral-cwd-worker.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --root) root="$2"; shift 2 ;;
    --scan-id) scan="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$PWD" = "$root" ]; then : > "$root/CWD_MARKER"; fi
printf '{"event":"scan_started","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":1,"root":"%s","project_code_executed":false,"safe_mode":true}\n' "$scan" "$root"
printf '{"event":"scan_completed","protocol_version":"1.0","scan_id":"%s","adapter":"go","adapter_version":"0.1.0","seq":2,"coverage":{"profiles":0,"files_discovered":0,"files_analyzed":0,"files_skipped":0,"dependency_sites":0,"resolved":0,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete"],"reasons":[]}}\n' "$scan"
"#,
    )?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let execution = execute_worker_inner_with_cancellation(
        &spec,
        &root,
        "neutral-cwd-scan",
        &ScanConfig::default(),
        &ProfileConfig::default(),
        None,
        std::future::pending::<std::io::Result<()>>(),
    )
    .await?;
    assert_eq!(execution.events.len(), 2);
    assert!(execution.error.is_none(), "{:?}", execution.error);
    assert_eq!(execution.failure_kind, None);
    assert!(!execution.security_violation);
    assert!(!root.join("CWD_MARKER").exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn normal_worker_exit_reaps_pipe_holding_descendants() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    std::fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    let script = temp.path().join("background-worker.sh");
    std::fs::write(&script, "#!/bin/sh\nsleep 30 &\nexit 0\n")?;
    let mut permissions = std::fs::metadata(&script)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions)?;
    let spec = WorkerSpec {
        adapter: AdapterKind::Go,
        program: script.clone().into_os_string(),
        leading_args: Vec::new(),
        display: script.display().to_string(),
        artifact_path: script,
        runtime_requirement: None,
        expected_version: None,
        release_attested: false,
        attested_rust_sysroot: None,
    };
    let started = Instant::now();
    let output = execute_worker(
        spec,
        root,
        "background-scan".to_owned(),
        ScanConfig {
            worker_timeout_seconds: 5,
            max_protocol_line_bytes: 4096,
            max_protocol_bytes: 64 * 1024,
            max_stderr_bytes: 1024,
            follow_symlinks: false,
        },
        ProfileConfig::default(),
    )
    .await;
    assert!(started.elapsed() < Duration::from_millis(1500));
    assert!(output.error.unwrap().contains("incomplete protocol stream"));
    Ok(())
}
