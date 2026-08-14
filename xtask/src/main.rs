use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use depgraph_protocol::{Condition, Profile};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

mod compiler_pack_release;
mod go_semantic_e2e;
mod mcp_package_smoke;
mod rust_semantic_e2e;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STABLE_RELEASE_GATE_SCHEMA_VERSION: &str = "stable-release-gate-v2";
const RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION: &str = "release-post-publish-evidence-v1";
const STABLE_RELEASE_VERSION: &str = "0.5.0";
const STABLE_RELEASE_BASELINE_STATUS: &str = "candidate-unpinned";
const STABLE_RELEASE_MAINTENANCE_BRANCH: &str = "refs/heads/release/0.5";
const V0_4_STABLE_RELEASE_BASELINE_COMMIT: &str = "d5ca92bae4b4fdbbedb2f3cabd4aa3ef731e7c9f";
const V0_4_STABLE_RELEASE_BASELINE_TREE: &str = "46555a059070e94c3ed4567af3c58b278dbb0fb4";
const V0_4_STABLE_RELEASE_BASELINE_DIGEST: &str =
    "0bb7f33d212402025429382489d586956d16f7d63d2e4d9d781d5715a44b00fd";
const V0_4_STABLE_RELEASE_MAINTENANCE_BRANCH: &str = "refs/heads/release/0.4";
const STABLE_UPGRADE_SOURCE_VERSION: &str = "0.4.0-rc.6";
const STABLE_UPGRADE_SOURCE_STORE_SCHEMA_VERSION: i64 = 13;
const STABLE_UPGRADE_SOURCE_FIXTURE_PATH: &str = "xtask/fixtures/v0.4.0-rc.6-store-v13.sql";
const STABLE_UPGRADE_SOURCE_FIXTURE_SHA256: &str =
    "43fe0dda73d03be9b8fff2ed9ff8ce888ad96e41e78335a1117646475c937150";
const V0_4_RC6_TAG_COMMIT: &str = "bb5dbe67e737cf50f07d90e6f4c8b7658c631184";
const V0_4_RC6_AARCH64_APPLE_ARCHIVE_SHA256: &str =
    "9dfde55ce04f940464c1d9215d165fb6786264f1b40fe4dd2c01a7b210eb18c3";
const V0_4_RC6_AARCH64_APPLE_BINARY_SHA256: &str =
    "c7d97ea0b2f4af388b6cd3ad7b69f41ac1ac5df65dadf7c20f749d4082f0fca4";
#[cfg(test)]
const V0_4_RC1_STORE_SCHEMA_VERSION: i64 = 11;
const V0_2_RC1_STORE_SCHEMA_VERSION: i64 = 5;
const BENCHMARK_REPORT_SCHEMA_VERSION: &str = "depgraph-benchmark-report-v7";
const STABLE_BENCHMARK_METRICS: &[(&str, bool)] = &[
    ("safe_initial_scan", true),
    ("one_file_incremental_scan", true),
    ("cold_file_impact", false),
    ("warm_file_impact", true),
    ("cold_package_impact", false),
    ("warm_package_impact", true),
    ("bounded_query_plan", true),
    ("bounded_query_execute", true),
    ("rust_hir_cold_scan", true),
    ("rust_hir_no_cache_scan", true),
    ("rust_hir_warm_scan", true),
    ("warm_rust_symbol_query", true),
    ("cross_adapter_build_observation", true),
];
const BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION: &str = "package-analysis-smoke-v2";
const BOUNDED_QUERY_SBOM_PACKAGE_NAME: &str = "depgraph-bounded-query-contract";
const CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION: &str = "cross-language-package-smoke-v1";
const CROSS_LANGUAGE_SBOM_PACKAGE_NAME: &str = "depgraph-cross-language-contract";
const CROSS_LANGUAGE_RELEASE_FIXTURE_PROFILE_ID: &str = "release:polyglot";
const CROSS_LANGUAGE_RELEASE_FIXTURE_TARGET: &str = "x86_64-unknown-linux-gnu";
const PROJECT_LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
const MCP_SERVER_NAME: &str = "depgraph-mcp";
const MCP_SDK_NAME: &str = "rmcp";
const MCP_SDK_VERSION: &str = "3.1.0";
const MCP_MACROS_VERSION: &str = "3.1.2";
const MCP_PROTOCOL_REVISION: &str = "2026-07-28";
const MCP_TOOL_CONTRACT_VERSION: &str = depgraph_mcp_tools::MCP_TOOLS_CONTRACT_VERSION;
const MCP_OPERATION_CONTRACT_VERSION: &str = depgraph_operation::OPERATION_CONTRACT_VERSION;
const MCP_TOOL_SCHEMA_PATH: &str = "schemas/depgraph-mcp-tools-v1.schema.json";
const MCP_TOOL_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../schemas/depgraph-mcp-tools-v1.schema.json");
const MCP_APACHE_NOTICE: &str = "Apache-2.0 notice: rmcp 3.1.0 and rmcp-macros 3.1.2 are licensed under Apache-2.0; the complete Apache License 2.0 text is packaged as LICENSE-APACHE.";
const MCP_SERVER_DIRECT_DEPENDENCIES: &[&str] = &[
    "anyhow",
    "chrono",
    "clap",
    "depgraph-core",
    "depgraph-mcp-tools",
    "depgraph-operation",
    "rmcp",
    "serde",
    "serde_json",
    "tokio",
    "tracing",
    "tracing-subscriber",
];
const PROJECT_LICENSES: &[(&str, &[u8])] = &[
    ("LICENSE-APACHE", include_bytes!("../../LICENSE-APACHE")),
    ("LICENSE-MIT", include_bytes!("../../LICENSE-MIT")),
];
const RELEASE_TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-gnu", "tar.gz"),
    ("aarch64-unknown-linux-gnu", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-pc-windows-msvc", "zip"),
];
const FULL_CI_JOB_NAMES: &[&str] = &[
    "benchmark",
    "compiler-precise-hostile",
    "go",
    "integration (macos-15, aarch64-apple-darwin)",
    "integration (ubuntu-24.04, x86_64-unknown-linux-gnu)",
    "rust",
    "web",
    "windows-smoke",
];
const RELEASE_CARGO_BUILD_TARGETS: &[(&str, Option<&str>, Option<&str>)] = &[
    ("depgraph-cli", Some("depgraph"), Some("packaged")),
    ("depgraph-mcp", Some("depgraph-mcp"), None),
    (
        "depgraph-operation",
        Some("depgraph-operation-runner"),
        None,
    ),
];
struct TargetNativeSmokeExpectation {
    target: &'static str,
    query_plan_digest: &'static str,
    query_result_digest: &'static str,
    query_output_sha256: &'static str,
    profile_plan_digest: &'static str,
    profile_plan_output_sha256: &'static str,
}

const TARGET_NATIVE_SMOKE_EXPECTATIONS: &[TargetNativeSmokeExpectation] = &[
    TargetNativeSmokeExpectation {
        target: "x86_64-unknown-linux-gnu",
        query_plan_digest: "bounded-query-plan:sha256:cae06d8db032d85c7062998a7d06676a09dff1ee9948245596389ee9b741b364",
        query_result_digest: "bounded-query-result:sha256:ba0505b32283b127764b8b2b826dc05211c61cd498838ef9d4d90842ac279247",
        query_output_sha256: "db91cbfb34e790175c1677b15a1b88722bd21488a443bf64fa30d09c08f88f93",
        profile_plan_digest: "profile-selection-plan:sha256:27c862f2305386cac9ab65aef94e61c0be53cf57744f350e1ada1076cd5a361f",
        profile_plan_output_sha256: "8ffa2c3ba5b3eec35bb6cbf21d0ed51885254eda32ddab5b642df3ecc1ad8f4a",
    },
    TargetNativeSmokeExpectation {
        target: "aarch64-unknown-linux-gnu",
        query_plan_digest: "bounded-query-plan:sha256:9fc87029cd412ab7eac77700feddc7ff623eddc6adc506c6b93729d783bb85ff",
        query_result_digest: "bounded-query-result:sha256:06b24d5c6b1ba2c4528eb710468ce8c71c56fdde30fd65d1c584057635c730d1",
        query_output_sha256: "ad5f3e4e377fed2e3edf0dea248fabd0af0c0dadf9210ceb41a7233aa99f4abd",
        profile_plan_digest: "profile-selection-plan:sha256:363b492f375b041073b317ff0579589545b5ebca37aaef9f8b933de96edd2958",
        profile_plan_output_sha256: "50d5fe0f605efac9a7b9ca7a9d6b6bff9727b20dbc8a75727456328a0fd49211",
    },
    TargetNativeSmokeExpectation {
        target: "x86_64-apple-darwin",
        query_plan_digest: "bounded-query-plan:sha256:d664b46af73b184714ed57a828fc56e65d2b0f2cf837de9f953f926a2e992648",
        query_result_digest: "bounded-query-result:sha256:998496968a872291847d5d9d73b61e63c92377e76e2fb9895577d1643d4c368a",
        query_output_sha256: "4f8637e6b0bf350036c1cbebdca4b177b1f74360e1e65f33905f995817b55704",
        profile_plan_digest: "profile-selection-plan:sha256:f44bce61595b71869cac635acc4256a269e04b7849020766c2c308d5ab4e6632",
        profile_plan_output_sha256: "90e0c0aa6f453cf5277051ef7385ddee047a45d522b955292a179020a3dc1cf6",
    },
    TargetNativeSmokeExpectation {
        target: "aarch64-apple-darwin",
        query_plan_digest: "bounded-query-plan:sha256:5cf0533d47220d99cf033cf879aa7bf1b142330567962bbf75b9245f82dfbfa5",
        query_result_digest: "bounded-query-result:sha256:456cabca0c093cb59ef670407f969ec677102870e4661f306a46b03bc89eb6f8",
        query_output_sha256: "c2ddbfc2348604051d7f61497fcef2cd6c5114ce7e2cce575560fcb7d03e1332",
        profile_plan_digest: "profile-selection-plan:sha256:b8e63fb7da635639c6e5c0d4c7aa844f0f5afe167923420f543f74a3fc8deb5e",
        profile_plan_output_sha256: "1072395911f92adaad1007a11ea53f81bfbcd3a105179d9526ed87136efdae62",
    },
    TargetNativeSmokeExpectation {
        target: "x86_64-pc-windows-msvc",
        query_plan_digest: "bounded-query-plan:sha256:8eb0e0fdd1c0cae9453abe718d73db94e8f4132fe868334c8c7bcb0462d4e8b1",
        query_result_digest: "bounded-query-result:sha256:42ec882b59a1f2284016e531f73efc9d49c59259d9fd524d8466590f0e580675",
        query_output_sha256: "5740ea2b649989babe370c3f03cc7166f17f65dc226810f133ad99eaf35187bb",
        profile_plan_digest: "profile-selection-plan:sha256:aabac99b77622684b20f0d6343c20e14136ce8c5282b5e50e333d61341d9be3b",
        profile_plan_output_sha256: "4ad1e71b0bac7c5bc8c06697c379be1f98712c17a549eb3a7fe98591429496ab",
    },
];
const SBOM_SCOPE: &str = "Scope: package-manager component boundary; system runtimes/toolchains and dependencies embedded inside upstream prebuilt packages are not recursively enumerated.";
const RUST_ANALYZER_CRATE_VERSION: &str = "0.0.330";
const RUST_ANALYZER_REVISION: &str = "8954b66d43225e62c92e8bbcc8500191b5cceb1e";
const SALSA_VERSION: &str = "0.26.1";
const RUST_ANALYZER_DIRECT_DEPENDENCIES: &[&str] =
    &["ra_ap_hir", "ra_ap_ide_db", "ra_ap_syntax", "ra_ap_vfs"];
const SALSA_DIRECT_DEPENDENCIES: &[&str] = &["salsa", "salsa-macro-rules", "salsa-macros"];
const TYPESCRIPT_VERSION: &str = "7.0.2";
const RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION: &str =
    depgraph_core::RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION;
const RUST_SYSROOT_TOOLCHAIN_VERSION: &str = depgraph_core::RUST_SYSROOT_TOOLCHAIN_VERSION;
const RUST_SYSROOT_TOOLCHAIN_COMMIT: &str = depgraph_core::RUST_SYSROOT_TOOLCHAIN_COMMIT;
const RUST_SYSROOT_COMPONENT_NAME: &str = depgraph_core::RUST_SYSROOT_COMPONENT_NAME;
const RUST_SYSROOT_COMPONENT_VERSION: &str = depgraph_core::RUST_SYSROOT_COMPONENT_VERSION;
const RUST_SYSROOT_COMPONENT_ROOT: &str = depgraph_core::RUST_SYSROOT_COMPONENT_ROOT;
const RUST_SYSROOT_SOURCE_LAYOUT: &str = depgraph_core::RUST_SYSROOT_SOURCE_LAYOUT;
const RUST_SYSROOT_LICENSE_EXPRESSION: &str = depgraph_core::RUST_SYSROOT_LICENSE_EXPRESSION;
const RUST_SYSROOT_SBOM_PACKAGE_NAME: &str = depgraph_core::RUST_SYSROOT_SBOM_PACKAGE_NAME;
const RUST_SOURCE_COPYRIGHT: &[u8] = include_bytes!("../../third_party/rust-src/COPYRIGHT");
const RUST_SOURCE_LICENSE_MIT: &[u8] = include_bytes!("../../third_party/rust-src/LICENSE-MIT");
const RUST_SOURCE_COPYRIGHT_SHA256: &str =
    "172020dbfd5b53a226dfde77616190a48dcff519b0bc0e6deb91a8450782c4af";
const RUST_SOURCE_LICENSE_MIT_SHA256: &str =
    "b71bd43a069ca0641a9ecfe585ca7b3c53b5cc1608f8b68321168698e28b5ea1";
const RUST_SYSROOT_COMPONENT_SHA256: &str =
    "cc5465ef70b933d2a80c30472468abb9f8ab297fc767bd6433b2f6f554f4f0e7";
const RUNTIME_COLLECTOR_CONTRACT_VERSION: &str = depgraph_core::RUNTIME_COLLECTOR_CONTRACT_VERSION;
const RUNTIME_COLLECTOR_ARTIFACT: &str = "depgraph-runtime-collector.mjs";
const WEB_SEMANTIC_CAPABILITIES: &[&str] = &[
    "astro-component-render-hydration-v1",
    "framework-semantic-completeness-v1",
    "framework-semantic-graph-v1",
    "next-route-component-boundary-v1",
    "tanstack-router-typed-route-v1",
    "tanstack-start-rpc-middleware-v1",
    "typescript-definition-import-type-call-graph-v2",
    "worker-delta-v1",
];
const WEB_SEMANTIC_RUNTIME_COMPONENTS: &[&str] = &[
    "astro-parser-wasm@4.0.0",
    "typescript-native-compiler@7.0.2",
];
const WEB_SEMANTIC_RUNTIME_ARTIFACTS: &[&str] = &[];
const WEB_RUNTIME_ARTIFACTS: &[&str] = &[
    "next-build-adapter.mjs",
    "astro-build-integration.mjs",
    "tanstack-router-build-observer.mjs",
    "tanstack-start-build-observer.mjs",
    "depgraph-web-build-evidence.mjs",
    RUNTIME_COLLECTOR_ARTIFACT,
];
const WEB_DEFINITION_SELECTOR: &str = r#"type:definition:["package","npm:workspace:@fixture/shared@1.0.0#apps/shared","definition:[\"module\",\"type\",\"apps/shared/src/semantic.ts\",[\"SharedStringCollection\"]]"]"#;
const FORBIDDEN_RUST_ANALYZER_DEPENDENCIES: &[&str] = &[
    "ra_ap_flycheck",
    "ra_ap_load_cargo",
    "ra_ap_load-cargo",
    "ra_ap_proc_macro_srv",
    "ra_ap_project_model",
];

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    Build {
        #[arg(long)]
        release: bool,
    },
    Test,
    GoSemanticE2e,
    RustSemanticE2e,
    Package,
    CompilerPack {
        source: PathBuf,
        output: PathBuf,
        #[arg(long)]
        spec: PathBuf,
    },
    CompilerPackPackage {
        #[arg(long)]
        channel_manifest: PathBuf,
        #[arg(long, default_value = "dist")]
        output_directory: PathBuf,
        #[arg(long)]
        target: Option<String>,
    },
    VerifyCompilerPackAssets {
        directory: PathBuf,
        #[arg(long)]
        target: Vec<String>,
    },
    VerifyReleaseAssets {
        directory: PathBuf,
        #[arg(long)]
        target: Vec<String>,
    },
    StableReleaseGate {
        release_verification: PathBuf,
        benchmark_report: PathBuf,
        compiler_pack_verification: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    ReleasePostPublishEvidence {
        workflow_assets: PathBuf,
        public_assets: PathBuf,
        ci_run: PathBuf,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        source_sha: String,
        #[arg(long)]
        source_tree: String,
        #[arg(long)]
        tag_object_sha: String,
        #[arg(long)]
        tag_signature_verification: String,
        #[arg(long)]
        release_run_id: u64,
        #[arg(long)]
        release_run_url: String,
        #[arg(long)]
        output: PathBuf,
    },
    GithubSettingsVerify {
        snapshot: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    release_version: String,
    protocol_version: String,
    schema_version: String,
    compatibility: ReleaseCompatibility,
    target: String,
    license_expression: String,
    project_licenses: Vec<Artifact>,
    core: Artifact,
    mcp_server: McpServerArtifact,
    operation_runner: OperationRunnerArtifact,
    schema: Artifact,
    mcp_tool_schema: VersionedArtifact,
    query_fixture: Artifact,
    cross_language_fixture: Artifact,
    cross_language_schemas: Vec<Artifact>,
    runtime_artifacts: Vec<Artifact>,
    runtime_components: Vec<RuntimeComponent>,
    workers: Vec<WorkerArtifact>,
    runtime_requirements: BTreeMap<String, String>,
}

type ReleaseCompatibility = depgraph_core::ReleaseCompatibilityHealth;

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
struct Artifact {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VersionedArtifact {
    contract_version: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct McpServerArtifact {
    version: String,
    path: String,
    sha256: String,
    sdk_name: String,
    sdk_version: String,
    protocol_revision: String,
    tool_contract_version: String,
    operation_contract_version: String,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationRunnerArtifact {
    version: String,
    operation_contract_version: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
struct RuntimeComponent {
    name: String,
    kind: String,
    version: String,
    root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    entrypoint: Option<String>,
    license: String,
    sha256: String,
}

#[derive(Serialize)]
struct RustSysrootSourceIdentity {
    contract_version: &'static str,
    toolchain_version: &'static str,
    toolchain_commit: &'static str,
    component_version: &'static str,
    source_layout: &'static str,
    acquisition: &'static str,
    normalized_root: &'static str,
    license_expression: &'static str,
}

#[derive(Clone, Debug, serde::Deserialize, Serialize)]
struct WorkerArtifact {
    adapter: String,
    version: String,
    path: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<WorkerBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic: Option<WebSemanticAttestation>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerBackend {
    kind: String,
    version: String,
    revision: String,
    salsa_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WebSemanticAttestation {
    typescript_version: String,
    capabilities: Vec<String>,
    runtime_components: Vec<String>,
    runtime_artifacts: Vec<String>,
}

#[derive(Debug)]
struct WorkerHandshake<'a> {
    name: &'a str,
    version: &'a str,
    protocol: &'a str,
    details: BTreeMap<&'a str, &'a str>,
    detail_order: Vec<&'a str>,
}

#[derive(Clone, Debug)]
struct DependencyPackage {
    ecosystem: String,
    name: String,
    version: String,
    license: String,
}

#[derive(Clone, Debug)]
struct RuntimeCollectorInventory {
    name: String,
    version: String,
    license: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FirstPartyArtifactInventory {
    name: String,
    version: String,
    license: String,
    path: String,
    sha256: String,
    roles: Vec<String>,
    bundled_packages: Vec<String>,
    framework: Option<String>,
    capability: Option<String>,
    observation_schema: Option<String>,
}

#[derive(Clone, Debug)]
struct ArchiveEntry {
    source: PathBuf,
    path: String,
    is_dir: bool,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseVerificationReport {
    schema_version: u32,
    release_version: String,
    tag: String,
    protocol_version: String,
    schema_compatibility_version: String,
    framework_build_graph_contract_version: String,
    framework_build_gate_contract_version: String,
    framework_build_capabilities: Vec<depgraph_core::FrameworkBuildCapabilityHealth>,
    runtime_collector_contract_version: String,
    compatibility: ReleaseCompatibility,
    license_expression: String,
    targets: Vec<TargetVerificationReport>,
}

fn release_compatibility() -> ReleaseCompatibility {
    depgraph_core::release_compatibility_contract()
}

fn v0_4_stable_release_baseline_record() -> String {
    format!(
        "release-baseline-v1\nrepository=TamaT-LLC/depgraph-cli\nversion=0.4.0\ncommit={V0_4_STABLE_RELEASE_BASELINE_COMMIT}\n"
    )
}

fn v0_4_stable_release_baseline_digest() -> String {
    hex::encode(Sha256::digest(
        v0_4_stable_release_baseline_record().as_bytes(),
    ))
}

fn release_tag() -> Result<String> {
    let tag = if matches!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"))
        && matches!(std::env::var("GITHUB_REF_TYPE").as_deref(), Ok("tag"))
    {
        std::env::var("GITHUB_REF_NAME").context("GitHub Actions release tag is missing")?
    } else {
        format!("v{VERSION}")
    };
    if !supported_release_tag(&tag) {
        bail!("release tag {tag:?} must be v{VERSION} or a canonical v{VERSION}-rc.N prerelease");
    }
    Ok(tag)
}

fn supported_release_tag(tag: &str) -> bool {
    if tag == format!("v{VERSION}") {
        return true;
    }
    let Some(sequence) = tag.strip_prefix(&format!("v{VERSION}-rc.")) else {
        return false;
    };
    !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && !sequence.starts_with('0')
}

fn lowercase_git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_stable_release_source_guard(root: &Path) -> Result<()> {
    let source_guard =
        fs::read_to_string(root.join(".github/workflows/stable-release-source-guard.yml"))?;
    for required in [
        "name: Stable release source guard",
        "workflow_run:",
        "workflows: [\"Release\"]",
        "types: [requested]",
        "github.event.workflow_run.head_branch == 'v0.4.0'",
        "github.event.workflow_run.head_sha",
        V0_4_STABLE_RELEASE_BASELINE_COMMIT,
        "actions/runs/$RELEASE_RUN_ID/cancel",
        "git/refs/tags/$EXPECTED_RELEASE_TAG",
    ] {
        if !source_guard.contains(required) {
            bail!("stable release source guard is missing contract {required:?}");
        }
    }
    for required in [
        "guard-stable-tags:",
        "github.event.workflow_run.head_branch == 'v0.5.0'",
        "UNPINNED_RELEASE_TAG: v0.5.0",
        "STABLE_BASELINE_STATUS: candidate-unpinned",
        "v0.5.0 stable baseline has not been pinned",
    ] {
        if !source_guard.contains(required) {
            bail!("stable release source guard is missing v0.5 contract {required:?}");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetVerificationReport {
    target: String,
    archive: String,
    archive_sha256: String,
    release_manifest_sha256: String,
    sbom_sha256: String,
    third_party_licenses_sha256: String,
    project_licenses: BTreeMap<String, String>,
    mcp_server_sha256: String,
    operation_runner_sha256: String,
    mcp_tool_schema_sha256: String,
    mcp_sdk_version: String,
    mcp_protocol_revision: String,
    mcp_tool_contract_version: String,
    mcp_operation_contract_version: String,
    mcp_smoke_sha256: String,
    mcp_smoke_tool_schema_sha256: String,
    mcp_smoke_discovery_sha256: String,
    mcp_smoke_fixture_result_sha256: String,
    mcp_smoke_submit_deadline_ms: u64,
    mcp_smoke_submit_elapsed_ms: u64,
    mcp_smoke_recovered_after_eof: bool,
    mcp_smoke_stdin_eof_clean_exit: bool,
    mcp_smoke_stdout_json_rpc_only: bool,
    runtime_collector_sha256: String,
    rust_sysroot_sha256: String,
    framework_build_artifacts: BTreeMap<String, String>,
    workers: BTreeMap<String, String>,
    query_smoke_sha256: String,
    query_plan_digest: String,
    query_result_digest: String,
    query_output_sha256: String,
    profile_plan_digest: String,
    profile_plan_output_sha256: String,
    cross_language_smoke_sha256: String,
    cross_language_graph_digest: String,
    cross_language_export_sha256: String,
    cross_language_query_sha256: String,
    cross_language_schemas: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BoundedQueryPackageSmokeReport {
    schema_version: String,
    target: String,
    archive_sha256: String,
    contract: depgraph_core::BoundedQueryReleaseCompatibilityHealth,
    plan_digest: String,
    result_digest: String,
    canonical_output_sha256: String,
    profile_contract: depgraph_core::ProfileSelectionReleaseCompatibilityHealth,
    profile_plan_digest: String,
    profile_canonical_output_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CrossLanguagePackageSmokeReport {
    schema_version: String,
    target: String,
    archive_sha256: String,
    contract: depgraph_core::CrossLanguageReleaseCompatibilityHealth,
    graph_digest: String,
    canonical_export_sha256: String,
    query_output_sha256: String,
}

struct PublishedSmokeReports<'a> {
    query: &'a BoundedQueryPackageSmokeReport,
    query_sha256: String,
    cross_language: &'a CrossLanguagePackageSmokeReport,
    cross_language_sha256: String,
    mcp: &'a mcp_package_smoke::McpPackageSmokeReport,
    mcp_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossLanguageReleaseFixture {
    schema_version: String,
    files: Vec<CrossLanguageReleaseFixtureFile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossLanguageReleaseFixtureFile {
    path: String,
    content: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StableReleaseDecision {
    Allow,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StableReleaseGateCheck {
    id: String,
    passed: bool,
    evidence: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StableReleaseGateReport {
    schema_version: String,
    release_version: String,
    upgrade_source_version: String,
    tag: String,
    decision: StableReleaseDecision,
    release_verification_sha256: String,
    benchmark_report_sha256: String,
    compiler_pack_verification_sha256: String,
    workflow_results: BTreeMap<String, String>,
    checks: Vec<StableReleaseGateCheck>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FullCiRunEvidenceInput {
    database_id: u64,
    head_sha: String,
    head_branch: String,
    event: String,
    conclusion: String,
    url: String,
    jobs: Vec<FullCiJobEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FullCiJobEvidence {
    name: String,
    conclusion: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseAssetEvidence {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseCandidateEvidence {
    commit: String,
    tree: String,
    tag_object: String,
    tag_signature_verification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseWorkflowEvidence {
    run_id: u64,
    url: String,
    head_sha: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FullCiRunEvidence {
    run_id: u64,
    url: String,
    head_sha: String,
    head_branch: String,
    jobs: Vec<FullCiJobEvidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseAggregateEvidence {
    release_verification_sha256: String,
    compiler_pack_verification_sha256: String,
    benchmark_report_sha256: String,
    cache_hit_benchmark_report_sha256: String,
    stable_release_gate_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleasePostPublishEvidence {
    schema_version: String,
    repository: String,
    release_version: String,
    tag: String,
    decision: StableReleaseDecision,
    candidate: ReleaseCandidateEvidence,
    full_ci: FullCiRunEvidence,
    release_workflow: ReleaseWorkflowEvidence,
    workflow_public_asset_identity: bool,
    public_download_reverified: bool,
    asset_set_sha256: String,
    assets: Vec<ReleaseAssetEvidence>,
    aggregates: ReleaseAggregateEvidence,
}

struct ReleasePostPublishEvidenceRequest {
    workflow_assets: PathBuf,
    public_assets: PathBuf,
    ci_run: PathBuf,
    tag: String,
    source_sha: String,
    source_tree: String,
    tag_object_sha: String,
    tag_signature_verification: String,
    release_run_id: u64,
    release_run_url: String,
    output: PathBuf,
}

const ARCHIVE_MTIME: u64 = 1_234_567_890;

fn main() -> Result<()> {
    match Cli::parse().command {
        Task::Build { release } => build(release),
        Task::Test => test(),
        Task::GoSemanticE2e => {
            go_semantic_e2e::run_development(&workspace_root(), &cargo_target_dir())
        }
        Task::RustSemanticE2e => {
            rust_semantic_e2e::run_development(&workspace_root(), &cargo_target_dir())
        }
        Task::Package => package(),
        Task::CompilerPack {
            source,
            output,
            spec,
        } => compiler_pack(&source, &output, &spec),
        Task::CompilerPackPackage {
            channel_manifest,
            output_directory,
            target,
        } => {
            compiler_pack_release::package(&channel_manifest, &output_directory, target.as_deref())
        }
        Task::VerifyCompilerPackAssets { directory, target } => {
            compiler_pack_release::verify_assets(&directory, &target).map(|_| ())
        }
        Task::VerifyReleaseAssets { directory, target } => {
            verify_release_assets(&directory, &target)
        }
        Task::StableReleaseGate {
            release_verification,
            benchmark_report,
            compiler_pack_verification,
            output,
        } => stable_release_gate(
            &release_verification,
            &benchmark_report,
            &compiler_pack_verification,
            &output,
        ),
        Task::ReleasePostPublishEvidence {
            workflow_assets,
            public_assets,
            ci_run,
            tag,
            source_sha,
            source_tree,
            tag_object_sha,
            tag_signature_verification,
            release_run_id,
            release_run_url,
            output,
        } => release_post_publish_evidence(ReleasePostPublishEvidenceRequest {
            workflow_assets,
            public_assets,
            ci_run,
            tag,
            source_sha,
            source_tree,
            tag_object_sha,
            tag_signature_verification,
            release_run_id,
            release_run_url,
            output,
        }),
        Task::GithubSettingsVerify { snapshot, output } => {
            github_settings_verify(&snapshot, &output)
        }
    }
}

fn compiler_pack(source: &Path, output: &Path, spec_path: &Path) -> Result<()> {
    let spec = depgraph_core::read_compiler_pack_build_spec(spec_path)?;
    let verified = depgraph_core::build_compiler_pack(source, output, &spec)?;
    println!(
        "built compiler pack {} for {}/{} (manifest sha256 {})",
        verified.root.display(),
        verified.attestation.host,
        verified.attestation.target,
        verified.attestation.manifest_sha256
    );
    Ok(())
}

fn build(release: bool) -> Result<()> {
    let mut cargo = Command::new("cargo");
    // The running xtask executable cannot be replaced on Windows. It is a
    // build-time tool rather than a release artifact, so exclude it from the
    // product workspace build.
    cargo.args(["build", "--workspace", "--exclude", "xtask", "--locked"]);
    if release {
        cargo.arg("--release");
    }
    run(&mut cargo)?;

    fs::create_dir_all("workers/go/bin")?;
    run(Command::new("go")
        .args(["build", "-trimpath", "-o"])
        .arg(Path::new("bin").join(executable_name("depgraph-go-worker")))
        .arg("./cmd/depgraph-go-worker")
        .env("GOTOOLCHAIN", "local")
        .env("GOFLAGS", "-mod=readonly")
        .current_dir("workers/go"))?;
    run(Command::new(pnpm_program())
        .args(["install", "--frozen-lockfile"])
        .current_dir("workers/web"))?;
    run(Command::new(pnpm_program())
        .arg("build")
        .current_dir("workers/web"))?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubActionsPolicy {
    schema_version: String,
    actions: Vec<GithubActionPin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubActionPin {
    identity: String,
    sha: String,
    reviewed_upstream_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDisclosureDryRun {
    schema_version: String,
    scenario_id: String,
    candidate_digest: String,
    private_route: String,
    raw_report_retained: bool,
    phases: Vec<SecurityDisclosurePhase>,
    fork_secret_access: bool,
    release_secret_access_before_verified_release: bool,
    completed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDisclosurePhase {
    id: String,
    owner_role: String,
    evidence_digest: String,
}

fn verify_github_actions_security(root: &Path) -> Result<()> {
    let policy_path = root.join(".github/actions-policy.json");
    let policy: GithubActionsPolicy = serde_json::from_slice(&fs::read(&policy_path)?)
        .context("GitHub Actions policy is not closed valid JSON")?;
    if policy.schema_version != "github-actions-policy-v1" || policy.actions.is_empty() {
        bail!("GitHub Actions policy version or action inventory is invalid");
    }
    let mut pins = BTreeMap::new();
    let mut prior_identity = None;
    for action in &policy.actions {
        if prior_identity.is_some_and(|prior| prior >= action.identity.as_str())
            || !valid_action_identity(&action.identity)
            || !is_lower_hex_len(&action.sha, 40)
            || !valid_reviewed_action_ref(&action.reviewed_upstream_ref)
            || pins
                .insert(action.identity.as_str(), action.sha.as_str())
                .is_some()
        {
            bail!("GitHub Actions policy pins must be canonical, unique, and immutable");
        }
        prior_identity = Some(action.identity.as_str());
    }

    let workflow_root = root.join(".github/workflows");
    let mut workflows = fs::read_dir(&workflow_root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    workflows.retain(|path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yml" | "yaml")
        )
    });
    workflows.sort();
    if workflows.is_empty() {
        bail!("GitHub workflow inventory is empty");
    }
    let mut used_actions = BTreeSet::new();
    for path in workflows {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("GitHub workflow must be a regular non-symlink file");
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("GitHub workflow has a non-UTF-8 name")?;
        let workflow = fs::read_to_string(&path)?;
        verify_workflow_policy_text(name, &workflow, &pins, &mut used_actions)?;
    }
    if used_actions
        != pins
            .keys()
            .map(|identity| (*identity).to_owned())
            .collect::<BTreeSet<_>>()
    {
        bail!("GitHub Actions policy contains an unused or unlisted action identity");
    }

    let dry_run_bytes = fs::read(root.join("security/disclosure-dry-run-v1.json"))?;
    verify_security_disclosure_dry_run(&dry_run_bytes)?;
    let threat_model = fs::read_to_string(
        root.join("docs/40_arch_design/github-actions-security-threat-model.md"),
    )?
    .replace("\r\n", "\n")
    .replace('\r', "\n");
    for required in [
        "`github-actions-policy-v1`",
        "Pull requests, fork branches",
        "does not interpolate the `secrets` expression",
        "Only the final `publish` job receives job-scoped",
        "`release-post-publish-evidence-v1`",
        "Every one of the 51 pre-evidence public assets",
        "The stable source guard handles `workflow_run` metadata without checking out",
        "No current workflow requests `id-token: write`",
        "Manual dispatches retain the same read-only and\nsecret-free boundary",
        "`.github/actions-policy.json` is the canonical allowlist",
        "A mutable tag or branch is never a temporary fallback.",
        "| Fork changes a workflow to print a secret |",
        "| `workflow_run` executes attacker code with write token |",
    ] {
        if !threat_model.contains(required) {
            bail!("GitHub Actions threat model is missing {required:?}");
        }
    }
    Ok(())
}

fn verify_workflow_policy_text(
    name: &str,
    workflow: &str,
    pins: &BTreeMap<&str, &str>,
    used_actions: &mut BTreeSet<String>,
) -> Result<()> {
    let normalized_workflow = workflow.replace("\r\n", "\n").replace('\r', "\n");
    let workflow = normalized_workflow.as_str();
    let write_permissions = write_permission_scopes(workflow);
    if workflow.contains("pull_request_target")
        || contains_yaml_hex_escape(workflow)
        || write_permissions.contains(&"write-all")
        || write_permissions.contains(&"id-token")
        || has_noncanonical_permissions_declaration(workflow)
    {
        bail!("{name} enables a forbidden trigger or broad credential");
    }
    let top_permissions = top_level_permissions(workflow)?;
    if !matches!(top_permissions.as_slice(), [] | ["contents: read"]) {
        bail!("{name} has broad workflow-level permissions");
    }
    if workflow.contains("\n  pull_request:") && contains_expression_context(workflow, "secrets") {
        bail!("{name} exposes repository secrets to pull request execution");
    }
    for line in workflow.lines() {
        let trimmed = line.trim_start();
        let specification = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"));
        if specification.is_none() && has_workflow_uses_key(trimmed) {
            bail!("{name} contains a noncanonical uses key");
        }
        let Some(specification) = specification else {
            continue;
        };
        let specification = specification
            .split_whitespace()
            .next()
            .context("workflow uses entry is empty")?;
        if specification.starts_with("./") {
            continue;
        }
        let (identity, sha) = specification
            .rsplit_once('@')
            .context("third-party Action is missing an immutable revision")?;
        if !is_lower_hex_len(sha, 40) || pins.get(identity) != Some(&sha) {
            bail!("{name} uses unreviewed or mutable Action {specification}");
        }
        used_actions.insert(identity.to_owned());
    }

    match name {
        "ci.yml" => {
            if top_level_trigger_keys(workflow)? != ["pull_request", "push", "workflow_dispatch"]
                || !workflow.contains("\n  pull_request:")
                || !workflow.contains("\n  workflow_dispatch:")
                || ![
                    "\n  benchmark:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                    "\n  integration:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                    "\n  windows-smoke:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                ]
                .iter()
                .all(|required| workflow.contains(required))
                || workflow.matches("\n      fail-fast: false\n").count() != 1
                || workflow
                    .matches("rustflags: -C linker-features=-lld")
                    .count()
                    != 1
                || workflow
                    .matches("RUSTFLAGS: ${{ matrix.rustflags }}")
                    .count()
                    != 1
                || workflow.matches("CARGO_INCREMENTAL: \"0\"").count() != 2
                || workflow.matches("CARGO_PROFILE_DEV_DEBUG: \"0\"").count() != 2
                || workflow.matches("CARGO_PROFILE_TEST_DEBUG: \"0\"").count() != 2
                || workflow
                    .matches(
                        "Reclaim integration build artifacts before the isolated Rust semantic gate",
                    )
                    .count()
                    != 1
                || top_permissions != ["contents: read"]
                || contains_expression_context(workflow, "secrets")
                || !write_permissions.is_empty()
            {
                bail!(
                    "CI pull requests must remain read-only, secret-free, and pinned to the full-CI linker/resource policy"
                );
            }
        }
        "release.yml" => {
            let publish = workflow
                .split_once("\n  publish:")
                .map(|(_, publish)| publish)
                .context("release workflow is missing the publish job")?;
            if top_level_trigger_keys(workflow)? != ["push"]
                || !workflow.contains("tags: [\"v*\"]")
                || workflow.contains("\n  pull_request:")
                || workflow.contains("\n  workflow_run:")
                || write_permissions != ["contents"]
                || !publish.contains("permissions:\n      contents: write")
                || workflow
                    .matches("rustflags: -C linker-features=-lld")
                    .count()
                    != 2
                || workflow
                    .matches("RUSTFLAGS: ${{ matrix.rustflags }}")
                    .count()
                    != 2
            {
                bail!(
                    "release write permission must remain tag-publish-only and native x86_64 Linux builds must retain the pinned linker policy"
                );
            }
        }
        "stable-release-source-guard.yml" => {
            if top_level_trigger_keys(workflow)? != ["workflow_run"]
                || !workflow.contains("\n  workflow_run:")
                || !top_permissions.is_empty()
                || workflow.contains("actions/checkout@")
                || contains_expression_context(workflow, "secrets")
                || workflow.contains("run: cargo")
                || workflow.contains("run: ./")
                || write_permissions != ["actions", "contents"]
                || !workflow.contains("permissions:\n      actions: write\n      contents: write")
            {
                bail!("stable release source guard must be metadata-only and job-scoped");
            }
        }
        _ => {
            if workflow.lines().any(has_write_permission) {
                bail!("{name} grants an unreviewed write permission");
            }
        }
    }
    Ok(())
}

fn contains_yaml_hex_escape(workflow: &str) -> bool {
    let bytes = workflow.as_bytes();
    (0..bytes.len()).any(|index| {
        if bytes[index] != b'\\' {
            return false;
        }
        let Some(kind) = bytes.get(index + 1).copied() else {
            return false;
        };
        let digits = match kind {
            b'x' => 2,
            b'u' => 4,
            b'U' => 8,
            _ => return false,
        };
        bytes
            .get(index + 2..index + 2 + digits)
            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}

fn top_level_trigger_keys(workflow: &str) -> Result<Vec<&str>> {
    let lines = workflow.lines().collect::<Vec<_>>();
    let Some((index, declaration)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.starts_with("on:"))
    else {
        bail!("workflow is missing an explicit trigger policy");
    };
    if declaration.trim() != "on:" {
        bail!("workflow trigger declaration is malformed");
    }
    let mut triggers = Vec::new();
    for line in &lines[index + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        if line.starts_with("    ") {
            continue;
        }
        let (trigger, _) = line
            .trim()
            .split_once(':')
            .context("workflow trigger entry is malformed")?;
        if !trigger
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            bail!("workflow trigger key is noncanonical");
        }
        triggers.push(trigger);
    }
    triggers.sort_unstable();
    if triggers.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("workflow trigger policy contains a duplicate event");
    }
    Ok(triggers)
}

fn write_permission_scopes(workflow: &str) -> Vec<&str> {
    let mut scopes = workflow
        .lines()
        .filter_map(|line| {
            let code = line.split('#').next().unwrap_or_default().trim();
            let (scope, value) = code.split_once(':')?;
            let scope = scope.trim();
            let value = yaml_scalar(value);
            if scope == "permissions" && value == "write-all" {
                Some("write-all")
            } else if value == "write" {
                Some(scope)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes
}

fn yaml_scalar(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2
        && matches!(
            (value.as_bytes().first(), value.as_bytes().last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        )
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn has_noncanonical_permissions_declaration(workflow: &str) -> bool {
    let mut permissions_indent = None;
    for line in workflow.lines() {
        let code = line.split('#').next().unwrap_or_default().trim();
        if code.is_empty() {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if let Some(block_indent) = permissions_indent {
            if indentation > block_indent {
                let Some((scope, value)) = code.split_once(':') else {
                    return true;
                };
                if indentation != block_indent + 2
                    || scope.trim() != scope
                    || !scope
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                    || !matches!(value.trim(), "read" | "write" | "none")
                {
                    return true;
                }
                continue;
            }
            permissions_indent = None;
        }
        let Some((key, value)) = code.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.contains('\\') && (key.starts_with('"') || key.starts_with('\'')) {
            return true;
        }
        let normalized_key = key.trim_matches(|character| matches!(character, '"' | '\''));
        if normalized_key == "permissions" {
            if key != "permissions" || !matches!(value.trim(), "" | "{}") {
                return true;
            }
            if value.trim().is_empty() {
                permissions_indent = Some(indentation);
            }
        }
    }
    false
}

fn contains_expression_context(workflow: &str, context: &str) -> bool {
    workflow.split("${{").skip(1).any(|suffix| {
        suffix
            .split_once("}}")
            .is_some_and(|(expression, _)| contains_identifier(expression, context))
    })
}

fn contains_identifier(expression: &str, identifier: &str) -> bool {
    let expression = expression.as_bytes();
    let identifier = identifier.as_bytes();
    if identifier.is_empty() || identifier.len() > expression.len() {
        return false;
    }
    (0..=expression.len() - identifier.len()).any(|index| {
        let end = index + identifier.len();
        if !expression[index..end].eq_ignore_ascii_case(identifier) {
            return false;
        }
        let before = index
            .checked_sub(1)
            .and_then(|prior| expression.get(prior))
            .copied();
        let after = expression.get(end).copied();
        before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
            && after.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    })
}

fn has_workflow_uses_key(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default();
    ["uses", "\"uses\"", "'uses'"].iter().any(|marker| {
        code.match_indices(marker).any(|(index, matched)| {
            let boundary = index == 0
                || !code.as_bytes()[index - 1].is_ascii_alphanumeric()
                    && code.as_bytes()[index - 1] != b'_';
            boundary && code[index + matched.len()..].trim_start().starts_with(':')
        })
    })
}

fn has_write_permission(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default().trim();
    code.contains("permissions:") && code.contains("write")
        || code
            .split_once(':')
            .is_some_and(|(_, value)| yaml_scalar(value) == "write")
}

fn top_level_permissions(workflow: &str) -> Result<Vec<&str>> {
    let lines = workflow.lines().collect::<Vec<_>>();
    let Some((index, declaration)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.starts_with("permissions:"))
    else {
        bail!("workflow is missing an explicit top-level permissions policy");
    };
    if declaration.trim() == "permissions: {}" {
        return Ok(Vec::new());
    }
    if declaration.trim() != "permissions:" {
        bail!("workflow top-level permissions declaration is malformed");
    }
    let mut permissions = Vec::new();
    for line in &lines[index + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        if line.starts_with("    ") {
            bail!("workflow top-level permissions nesting is malformed");
        }
        permissions.push(line.trim());
    }
    permissions.sort_unstable();
    Ok(permissions)
}

fn verify_security_disclosure_dry_run(bytes: &[u8]) -> Result<()> {
    let dry_run: SecurityDisclosureDryRun =
        serde_json::from_slice(bytes).context("security disclosure dry run is malformed")?;
    let expected_phases = [
        ("private-report", "security-maintainer"),
        ("triage", "security-maintainer"),
        ("private-advisory", "security-maintainer"),
        ("private-fix", "release-maintainer"),
        ("verified-release", "release-maintainer"),
        ("coordinated-disclosure", "security-maintainer"),
    ];
    if dry_run.schema_version != "security-disclosure-dry-run-v1"
        || !valid_policy_token(&dry_run.scenario_id)
        || !is_lower_hex_len(&dry_run.candidate_digest, 64)
        || dry_run.private_route != "github-security-advisory"
        || dry_run.raw_report_retained
        || dry_run.fork_secret_access
        || dry_run.release_secret_access_before_verified_release
        || !dry_run.completed
        || dry_run.phases.len() != expected_phases.len()
        || dry_run
            .phases
            .iter()
            .zip(expected_phases)
            .any(|(phase, expected)| {
                phase.id != expected.0
                    || phase.owner_role != expected.1
                    || !is_lower_hex_len(&phase.evidence_digest, 64)
            })
    {
        bail!("security disclosure dry run is incomplete, unsafe, or noncanonical");
    }
    Ok(())
}

fn valid_action_identity(value: &str) -> bool {
    let mut components = value.split('/');
    components.next().is_some_and(valid_policy_token)
        && components.next().is_some_and(valid_policy_token)
        && components.next().is_none()
}

fn valid_reviewed_action_ref(value: &str) -> bool {
    value
        .strip_prefix('v')
        .is_some_and(|major| !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_policy_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_lower_hex_len(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_project_metadata(root: &Path) -> Result<()> {
    verify_github_actions_security(root)?;
    verify_mcp_tasks_architecture_decision(root)?;
    mcp_package_smoke::verify_documentation(root, VERSION)?;
    let mcp_operations_path = "docs/50_test/mcp-agent-host-operations.md";
    let mcp_operations = read_lf_normalized_text(&root.join(mcp_operations_path))?;
    verify_local_markdown_links(root, mcp_operations_path, &mcp_operations)?;
    let cargo_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    if !cargo_manifest
        .lines()
        .any(|line| line.trim() == format!("version = \"{VERSION}\""))
    {
        bail!("Cargo workspace version does not match release version {VERSION}");
    }
    let web_package: Value =
        serde_json::from_slice(&fs::read(root.join("workers/web/package.json"))?)?;
    if web_package["name"] != "@depgraph/web-worker"
        || web_package["version"] != VERSION
        || web_package["packageManager"] != "pnpm@10.33.0"
        || web_package["engines"]["node"] != ">=24.0.0"
    {
        bail!("Web package version/runtime metadata is not synchronized with release {VERSION}");
    }

    let go_model = fs::read_to_string(root.join("workers/go/internal/worker/model.go"))?;
    let web_types = fs::read_to_string(root.join("workers/web/src/types.ts"))?;
    if quoted_assignment(&go_model, "AdapterVersion").as_deref() != Some(VERSION)
        || quoted_assignment(&web_types, "ADAPTER_VERSION").as_deref() != Some(VERSION)
    {
        bail!("Go/Web adapter versions must match Cargo release version {VERSION}");
    }
    let framework_build_sources = [
        (
            "astro",
            "workers/web/src/astro-build-observer.ts",
            "ASTRO_BUILD_OBSERVER",
            "ASTRO_BUILD_OBSERVER_VERSION",
            "ASTRO_BUILD_OBSERVER_CAPABILITY",
            "ASTRO_BUILD_OBSERVATION_SCHEMA",
        ),
        (
            "next",
            "workers/web/src/next-build-observer.ts",
            "NEXT_BUILD_OBSERVER",
            "NEXT_BUILD_OBSERVER_VERSION",
            "NEXT_BUILD_OBSERVER_CAPABILITY",
            "NEXT_BUILD_OBSERVATION_SCHEMA",
        ),
        (
            "tanstack-router",
            "workers/web/src/tanstack-router-build-observer.ts",
            "TANSTACK_ROUTER_BUILD_OBSERVER",
            "TANSTACK_ROUTER_BUILD_OBSERVER_VERSION",
            "TANSTACK_ROUTER_BUILD_CAPABILITY",
            "TANSTACK_ROUTER_BUILD_SCHEMA",
        ),
        (
            "tanstack-start",
            "workers/web/src/tanstack-start-build-observer.ts",
            "TANSTACK_START_BUILD_OBSERVER",
            "TANSTACK_START_BUILD_OBSERVER_VERSION",
            "TANSTACK_START_BUILD_CAPABILITY",
            "TANSTACK_START_BUILD_SCHEMA",
        ),
    ];
    let web_build_script = fs::read_to_string(root.join("workers/web/scripts/build.mjs"))?;
    for (framework, source_path, observer, version, capability, schema) in framework_build_sources {
        let expected = depgraph_core::framework_build_capability_contract()
            .into_iter()
            .find(|entry| entry.framework == framework)
            .with_context(|| format!("core has no {framework} framework build capability"))?;
        let source = fs::read_to_string(root.join(source_path))?;
        if quoted_assignment(&source, observer).as_deref() != Some(expected.observer.as_str())
            || quoted_assignment(&source, version).as_deref()
                != Some(expected.observer_version.as_str())
            || quoted_assignment(&source, capability).as_deref()
                != Some(expected.capability.as_str())
            || quoted_assignment(&source, schema).as_deref()
                != Some(expected.observation_schema.as_str())
            || !web_build_script.contains(&format!("framework: \"{framework}\""))
            || !web_build_script.contains(&format!("version: \"{}\"", expected.observer_version))
            || !web_build_script.contains(&format!("capability: \"{}\"", expected.capability))
            || !web_build_script.contains(&format!(
                "observation_schema: \"{}\"",
                expected.observation_schema
            ))
        {
            bail!(
                "{framework} framework build capability is not synchronized across core, observer, and package inventory"
            );
        }
    }

    let go_mod = fs::read_to_string(root.join("workers/go/go.mod"))?;
    let rust_toolchain = fs::read_to_string(root.join("rust-toolchain.toml"))?;
    let rust_worker = fs::read_to_string(root.join("workers/rust/Cargo.toml"))?;
    let protocol_crate = fs::read_to_string(root.join("crates/depgraph-protocol/Cargo.toml"))?;
    if !go_mod.lines().any(|line| line.trim() == "go 1.26.1")
        || !rust_toolchain
            .lines()
            .any(|line| line.trim() == format!("channel = \"{RUST_SYSROOT_TOOLCHAIN_VERSION}\""))
        || !rust_worker
            .lines()
            .any(|line| line.trim() == "version.workspace = true")
        || !protocol_crate
            .lines()
            .any(|line| line.trim() == "version.workspace = true")
    {
        bail!("Rust/Go worker baseline or workspace version metadata is not synchronized");
    }
    if sha256_file(&root.join("third_party/rust-src/COPYRIGHT"))? != RUST_SOURCE_COPYRIGHT_SHA256
        || sha256_file(&root.join("third_party/rust-src/LICENSE-MIT"))?
            != RUST_SOURCE_LICENSE_MIT_SHA256
        || fs::read(root.join("third_party/rust-src/COPYRIGHT"))? != RUST_SOURCE_COPYRIGHT
        || fs::read(root.join("third_party/rust-src/LICENSE-MIT"))? != RUST_SOURCE_LICENSE_MIT
    {
        bail!(
            "pinned Rust {RUST_SYSROOT_TOOLCHAIN_VERSION} source license inputs are missing or modified"
        );
    }

    let readme = read_lf_normalized_text(&root.join("README.md"))?;
    let rc1_release = read_lf_normalized_text(&root.join("docs/releases/v0.4.0-rc.1.md"))?;
    let design = read_lf_normalized_text(
        &root.join("docs/40_arch_design/arch-dependency-graph-cli-system-design.md"),
    )?;
    let docs_index = read_lf_normalized_text(&root.join("docs/00_index/index.md"))?;
    let rust_compiler_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-rust-compiler-precise-backend.md"),
    )?;
    let rust_compiler_hostile =
        read_lf_normalized_text(&root.join("docs/50_test/compiler-precise-hostile-e2e.md"))?;
    let rust_compiler_release = read_lf_normalized_text(
        &root.join("docs/50_test/compiler-precise-five-target-release.md"),
    )?;
    let rust_compiler_hostile_gate =
        fs::read_to_string(root.join("scripts/compiler-precise-hostile-e2e.sh"))?;
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    let cross_language_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-cross-language-adapter-contract.md"),
    )?;
    let default_profile_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-default-profile-selection-budget.md"),
    )?;
    let graph_query_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-bounded-graph-query-language.md"),
    )?;
    let public_oss_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-public-oss-release-governance.md"),
    )?;
    let v0_5_release_adr =
        read_lf_normalized_text(&root.join("docs/40_arch_design/adr-v0.5-release-contract.md"))?;
    verify_public_community_surface(root)?;
    for required in [
        "Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0",
        "TypeScript/JavaScript symbol/type/import/re-export/type-use",
        "[the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md)",
        "[`v0.4.0` contract](docs/releases/v0.4.0.md)",
        "[`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md)",
        "[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md)",
        "[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)",
        "[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md)",
        "dynamic-framework-evidence-release-gate-v1",
        "rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf",
        "[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)",
        "depgraph runtime validate --file runtime-trace.json --json",
        "Every v0.5 archive includes the native MCP server, durable\noperation runner, and versioned Agent tool/operation schema.",
        "binds the MCP server and runner digests to `rmcp 3.1.0`, MCP revision `2026-07-28`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v1`",
        "no `v0.4.0` stable GitHub Release was published",
        "Store\nschema `17`, operation journal schema `5`, `depgraph-mcp-tools-v1`, and\n`depgraph-operation-v1`",
    ] {
        if !readme.contains(required) {
            bail!("README release metadata is missing {required:?}");
        }
    }
    if !rc1_release.contains("depgraph runtime validate --file runtime-trace.json --json") {
        bail!("v0.4.0-rc.1 runtime validate example is not synchronized with the CLI");
    }
    let release_note = format!("docs/releases/v{VERSION}.md");
    let release_link = format!("[`v{VERSION}` release notes]({release_note})");
    if !readme.contains(&release_link) || !root.join(&release_note).is_file() {
        bail!("README release note link is not synchronized with {VERSION}");
    }
    for required in [
        "updated: 2026-08-13",
        "| Product / Rust / Go / Web adapter | `0.5.0` |",
        "| SQLite store / scan cache / impact query cache | `17` / `2` / `1` |",
        "| Operation journal / MCP tool / operation DTO | `5` / `depgraph-mcp-tools-v1` / `depgraph-operation-v1` |",
        "Milestone 4のrelease candidateは`v0.4.0-rc.1`",
        "stable GitHub Releaseは公開されなかった",
        "`stable-release-gate-v2`",
        "Issue #355として",
        "`candidate-unpinned`",
        "Issue #55ではこのWeb semantic compatibility unitをrelease manifest",
        "Issue #145のrelease gate contractは`dynamic-framework-evidence-release-gate-v1`",
        "Issue #146でRust `1.93.1`",
        "`PROJ-ARC-001-ADR-002`",
        "`compiler-precise-rust-v1`",
        "Issue #149として`compiler-precise-rust-v1`",
        "`PROJ-ARC-001-ADR-003`",
        "`cross-language-contract-v1`",
        "Issue #150として`cross-language-contract-v1`",
        "`PROJ-ARC-001-ADR-004`",
        "`default-profile-selection-v1`",
        "Issue #151として`default-profile-selection-v1`",
        "`PROJ-ARC-001-ADR-005`",
        "`bounded-graph-query-v1`",
        "Issue #152として`bounded-graph-query-v1`",
        "Issue #178で`bounded-query-types-v1`のclosed type checker",
        "Issue #179で`bounded-query-statistics-v1`、`bounded-query-plan-v1`、`bounded-query-limits-v1`",
        "Issue #180で`bounded-query-result-v1`のstaged executor",
        "Issue #181でpublic `depgraph query`",
        "Issue #182で`bounded-query-release-smoke-v1`",
        "`PROJ-ARC-001-ADR-006`",
        "`public-readiness-v1`",
        "Issue #153として`public-readiness-v1`",
        "Issue #176でgreen確認済みのmain commit `d5ca92bae4b4fdbbedb2f3cabd4aa3ef731e7c9f`を`release-baseline-v1`",
        "### ADR-015: Exact Stable Baseline with a Separate Maintenance Line",
        "2026-07-26: Issue #176としてgreenなmain commit",
    ] {
        if !design.contains(required) {
            bail!("system design release metadata is missing {required:?}");
        }
    }
    for required in [
        "| PROJ-ARC-001-ADR-002 | PROJ-ARC-001 | [Opt-in Rust compiler-precise backend](../40_arch_design/adr-rust-compiler-precise-backend.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-002` を追加",
        "| PROJ-ARC-001-ADR-003 | PROJ-ARC-001 | [Cross-language adapter common contract](../40_arch_design/adr-cross-language-adapter-contract.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-003` を追加",
        "| PROJ-ARC-001-ADR-004 | PROJ-ARC-001 | [Default profile selection and exploration budget](../40_arch_design/adr-default-profile-selection-budget.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-004` を追加",
        "| PROJ-ARC-001-ADR-005 | PROJ-ARC-001 | [Bounded read-only graph query language](../40_arch_design/adr-bounded-graph-query-language.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-005` を追加",
        "| PROJ-ARC-001-ADR-006 | PROJ-ARC-001 | [Public OSS readiness and release governance](../40_arch_design/adr-public-oss-release-governance.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-006` を追加",
        "| PROJ-ARC-001-ADR-007 | PROJ-ARC-001 | [v0.5 release, migration, and source contract](../40_arch_design/adr-v0.5-release-contract.md) | Accepted |",
        "2026-08-13: `PROJ-ARC-001-ADR-007` と v0.5 release contractを追加",
    ] {
        if !docs_index.contains(required) {
            bail!("documentation index is missing Rust compiler ADR metadata {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-002`",
        "- Contract: `compiler-precise-rust-v1`",
        "| Toolchain channel | `nightly-2026-07-17` |",
        "| rustc commit | `3d50c25bc66853bf0ad205529d0f305a1d841b5e` |",
        "depgraph resolve --build PATH --allow-project-code --rust-compiler-precise",
        "| wrapper process after rustc starts |",
        "There is no automatic retry with another toolchain",
        "## Options considered",
        "## Security review gates",
        "## Staged implementation and acceptance matrix",
        "`linux-bubblewrap-v1`",
        "`compiler-precise-hostile-e2e-v1`",
        "Hostile execution and rollback E2E (implemented in #248)",
        "every admitted Cargo unit invocation, including dependency, build-script, and proc-macro units",
        "Five-target release gate (implemented in #249)",
        "`compiler-pack-five-target-release-v1`",
        "| Safe invariant |",
    ] {
        if !rust_compiler_adr.contains(required) {
            bail!("Rust compiler-precise ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "Evidence contract: `compiler-precise-hostile-e2e-v1`",
        "filesystem isolation: enforced",
        "network isolation: enforced",
        "process isolation: enforced",
        "`rust-compiler-invocation-child-signalled`",
        "`repeated_promotion_is_byte_stable_and_failure_rolls_back`",
        "`mcp_security_matrix`",
        "| MCP security matrix |",
        "The hostile gate fails if",
    ] {
        if !rust_compiler_hostile.contains(required) {
            bail!("compiler-precise hostile evidence is missing {required:?}");
        }
    }
    for required in [
        "compiler-precise-hostile-e2e-v1",
        "enforced_hostile_boundary_denies_parent_secret_network_and_private_paths",
        "cargo test --offline -p depgraph-mcp --test process --locked issue_317_",
        "mcp-cli-capability-path-cancel-recovery-security-matrix",
        "mcp_security_matrix",
        "unsafe[[:space:]]*\\{",
        "previous_completed_build_layer_preserved",
    ] {
        if !rust_compiler_hostile_gate.contains(required) {
            bail!("compiler-precise hostile gate is missing {required:?}");
        }
    }
    for required in [
        "`compiler-pack-five-target-release-v1`",
        "`x86_64-unknown-linux-gnu`",
        "`aarch64-unknown-linux-gnu`",
        "`x86_64-apple-darwin`",
        "`aarch64-apple-darwin`",
        "`x86_64-pc-windows-msvc`",
        "`depgraph-compiler-component-handshake-v1`",
        "`compiler-pack-five-target-verification-v1`",
        "`unsupported-no-fallback`",
        "cargo xtask verify-compiler-pack-assets compiler-artifacts",
    ] {
        if !rust_compiler_release.contains(required) {
            bail!("compiler-pack release evidence is missing {required:?}");
        }
    }
    for required in [
        "compiler-precise-hostile:",
        "sudo apt-get install --yes --no-install-recommends bubblewrap",
        "scripts/compiler-precise-hostile-e2e.sh",
        "compiler-precise-hostile-${{ github.sha }}",
        "id: decide",
        "steps.decide.outputs.run",
        r#"github.event_name }}" = "workflow_dispatch""#,
        r#"github.event_name }}" = "push""#,
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        r#"Cargo\.(toml|lock)"#,
        "crates/depgraph-core/",
        "crates/depgraph-rustc-wrapper/",
        "crates/depgraph-rustc-query/",
        "crates/depgraph-cli/",
        "crates/depgraph-store/",
        "scripts/compiler-precise-hostile",
        "docs/50_test/compiler-precise-hostile",
        r#"\.github/workflows/ci\.yml"#,
        "if: steps.decide.outputs.run == 'true'",
        "if: steps.decide.outputs.run != 'true'",
    ] {
        if !ci_workflow.contains(required) {
            bail!("CI is missing compiler-precise hostile gate {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-003`",
        "- Contract: `cross-language-contract-v1`",
        "1. OpenAPI;",
        "2. Protocol Buffers;",
        "3. GraphQL;",
        "4. HTTP runtime correlation;",
        "5. FFI.",
        "| `service` |",
        "| `schema` |",
        "| `operation` |",
        "| `message` |",
        "| `native_symbol` |",
        "`depgraph-cross-language-mapping-v1`",
        "A unique spelling is not format-aware proof.",
        "Items 1-2 may support a static `exact` edge",
        "Item 3 emits `phase=build`, `precision=observed`; item 4 emits",
        "never satisfies or promotes a static exact mapping by itself.",
        "## Format capability boundaries",
        "## Security boundary",
        "## Rollout order and issue-sized plan",
        "| 1 | Common node/site/edge DTO, validator, coverage ledger, and cross-format golden harness | Implemented in #191 |",
        "| 2 | OpenAPI 3.1 repository parser and contract graph | Implemented in #192 |",
        "| 3 | OpenAPI generated-client/provider repository mapping | Implemented in #193 |",
        "| 4 | Protobuf source/descriptor contract graph | Implemented in #194 |",
        "| 5 | Protobuf generated-code mapping | Implemented in #195 |",
        "| 6 | GraphQL SDL and executable-document graph | Implemented in #196 |",
        "| 7 | GraphQL client/resolver repository mapping | Implemented in #197 |",
        "| 8 | HTTP trace-to-operation correlation | Implemented in #198 |",
        "| 9 | Rust/Go/Web static FFI declaration inventory | Implemented in #199 |",
        "| 10 | FFI supervised link/export evidence | Implemented in #200 |",
        "| 11 | Five-target package/query/release gate | Implemented in #201 |",
        "## Acceptance matrix",
        "| Safe invariant |",
        "## Security and release gates",
    ] {
        if !cross_language_adr.contains(required) {
            bail!("cross-language adapter ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-004`",
        "- Contract: `default-profile-selection-v1`",
        "never enumerates a target × feature × mode × environment",
        "| `tiny` | `<= 1,000` | `<= 25` | `16` |",
        "| `small` | `<= 10,000` | `<= 100` | `10` |",
        "| `medium` | `<= 50,000` | `<= 500` | `6` |",
        "| `large` | otherwise within inventory limits | otherwise within inventory limits | `4` |",
        "The hard cap is `32` selected root profiles",
        "A set that exactly exhausts the admitted input at",
        "## Mandatory language baselines",
        "## Automatic candidate generation",
        "## Ranking and canonical selection",
        "depgraph profiles plan PATH [--profile-budget N] [--json]",
        "depgraph scan PATH --profiles-file FILE",
        "The core does not truncate it,",
        "`default_profile_budget_exhausted`",
        "`default_profile_candidate_limit_exceeded`",
        "profiles: 10 selected / 14 eligible; 4 omitted by small-repository budget 10",
        "`default_profile_matrix_complete=false`",
        "## Security and resource boundary",
        "## Staged implementation",
        "| 8 | Cache/incremental binding and five-target package/release gate | Implemented in #190 |",
        "## Acceptance matrix",
        "| Explicit set above 32 or with unsupported target |",
    ] {
        if !default_profile_adr.contains(required) {
            bail!("default profile ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-005`",
        "- Contract: `bounded-graph-query-v1`",
        "Existing dedicated commands remain stable and preferred.",
        "## Scope boundary",
        "## Query input and CLI",
        "depgraph query --query QUERY --explain [--json]",
        "## MVP grammar",
        "The parser accepts exactly one statement.",
        "Implemented in #178",
        "Implemented in #179",
        "Implemented in #180",
        "Implemented in #181",
        "## Type system",
        "`EVIDENCE(p)` contains canonical evidence owned by those edges",
        "## Traversal semantics",
        "emits at most one path for a `(source_id, target_id)` pair.",
        "satisfied_existential_predicate_bitset",
        "predicate bits or used-edge sets remain distinct",
        "## Planner and cost model",
        "1 * admitted source-node tests",
        "| Query bytes / tokens / AST nodes | `64 KiB` / `4,096` / `512` |",
        "| Minimum/maximum path depth | `1` / `8` |",
        "| Deterministic cost units | `1,000,000` |",
        "## Explain contract",
        "`query_plan_budget_exceeded`",
        "There is no partial-success mode in v1.",
        "## Security boundary",
        "## Staged implementation",
        "| 1 | Lexer/parser, bounded input reader, canonical AST, and malformed corpus | Implemented in #177 |",
        "| 3 | Snapshot cardinality statistics, fixed operator planner, cost admission, and explain schema | Implemented in #179 |",
        "| 4 | Canonical forward/reverse BFS executor, site/evidence filters, staging, and cancellation | Implemented in #180 |",
        "| 5 | CLI human/JSON output, read-only store integration, profile/phase/condition/evidence fixtures | Implemented in #181 |",
        "| 6 | Fuzz/property tests, hostile large-graph benchmark, and five-target package/release gate | Implemented in #182 |",
        "## Acceptance matrix",
        "| Plan above node/edge/evidence/cost cap despite `LIMIT 1` |",
    ] {
        if !graph_query_adr.contains(required) {
            bail!("bounded graph query ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-006`",
        "- Contract: `public-readiness-v1`",
        "| Current visibility | `private` |",
        "| Current public readiness | `reject` / no-go |",
        "| Accountable owner | TamaT-LLC organization owner |",
        "Passing the current `stable-release-gate-v2` is mandatory but insufficient.",
        "The readiness record is evidence, not an actuator.",
        "[`schemas/public-readiness-v1.schema.json`](../../schemas/public-readiness-v1.schema.json)",
        "`evidence-only-no-visibility-actuator`",
        "## Authority and separation of duties",
        "## Decision record",
        "1. `candidate-and-surface`;",
        "4. `incident-readiness`;",
        "9. `security-and-disclosure`.",
        "## Executable pre-publication checklist",
        "### Gate 2: history and secrets",
        "History rewriting alone never remediates a",
        "`public-history-audit-v1`",
        "Rotation or revocation, purge evidence, and a clean fresh-mirror rescan",
        "### Gate 3: legal, license, and provenance",
        "`public-provenance-review-v1`",
        "Missing assets or notices, unresolved provenance",
        "Developer Certificate of Origin",
        "### Gate 4: security and disclosure",
        "Pin every third-party GitHub Action to a reviewed full commit SHA.",
        "`github-actions-policy-v1`",
        "`security-disclosure-dry-run-v1`",
        "### Gate 5: governance and community",
        "### Gate 6: repository controls",
        "`github-settings-desired-v1`",
        "`read-only-no-settings-actuator`",
        "### Gate 7: release and support",
        "### Gate 8: migration dry run and change window",
        "`public-migration-rehearsal-input-v1`",
        "`temporary-repository-no-production-actuator`",
        "### Gate 9: incident readiness",
        "changing back to private cannot retract clones, forks,",
        "## Maintainer, review, release, support, and contribution policy",
        "## Staged implementation",
        "| 1 | Community/governance documents, issue forms, PR template, DCO/CLA decision | Implemented in #202 |",
        "| 2 | Closed readiness/evidence schemas and deterministic verifier | Implemented in #203 |",
        "| 3 | All-ref/history/collaboration secret audit tooling and redacted ledger | Implemented in #204 |",
        "| 4 | Dependency/license/provenance inventory and legal review package | Implemented in #205 |",
        "| 5 | Workflow SHA pinning, threat model, disclosure policy, and security dry run | Implemented in #206 |",
        "| 6 | Desired GitHub settings/rulesets manifest, access review, and verifier | Implemented in #207 |",
        "| 7 | Temporary-repository migration rehearsal and anonymous smoke suite | Implemented in #208 |",
        "| 8 | Candidate-bound final audit, owner decision, authorized change window, and observation | 2-3 days |",
        "## Acceptance matrix",
        "| Stable release gate passes but history audit is missing |",
        "| All gates pass but organization owner has not authorized visibility | remain private |",
        "### Preserved v0.4 baseline and v0.5 maintenance line",
        "`refs/heads/release/0.4`",
        "`refs/heads/release/0.5`",
        "`candidate-unpinned`",
    ] {
        if !public_oss_adr.contains(required) {
            bail!("public OSS governance ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-007`",
        "- Issue: `PROJ-ARC-003-TASK-001` / #355",
        "- Contract: `stable-release-gate-v2`",
        "No `v0.4.0` stable GitHub Release was published",
        "| Product and adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        V0_4_RC6_TAG_COMMIT,
        V0_4_RC6_AARCH64_APPLE_ARCHIVE_SHA256,
        V0_4_RC6_AARCH64_APPLE_BINARY_SHA256,
        "The stable baseline status is `candidate-unpinned`.",
    ] {
        if !v0_5_release_adr.contains(required) {
            bail!("v0.5 release ADR is missing required contract {required:?}");
        }
    }
    let migration_rehearsal =
        read_lf_normalized_text(&root.join("docs/50_test/public-migration-rehearsal.md"))?;
    for required in [
        "`temporary-repository-no-production-actuator`",
        "The production repository must retain its original visibility",
        "`freeze_writes`",
        "`verify_desired_settings`",
        "`run_anonymous_smoke`",
        "`reopen_writes`",
        "`cleanup_temporary_repository`",
        "`activity_after_no_go`",
        "schemas/public-migration-rehearsal-input-v1.schema.json",
    ] {
        if !migration_rehearsal.contains(required) {
            bail!("public migration rehearsal is missing required contract {required:?}");
        }
    }
    let v0_4_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.4.0.md"))?;
    if v0_4_stable_release_baseline_digest() != V0_4_STABLE_RELEASE_BASELINE_DIGEST {
        bail!("compiled v0.4 release baseline digest does not match its canonical record");
    }
    for required in [
        "## Release baseline and maintenance line",
        V0_4_STABLE_RELEASE_BASELINE_COMMIT,
        V0_4_STABLE_RELEASE_BASELINE_TREE,
        V0_4_STABLE_RELEASE_BASELINE_DIGEST,
        V0_4_STABLE_RELEASE_MAINTENANCE_BRANCH,
        "git cherry-pick -x",
        "default-disabled or explicitly opt-in",
        "Stable release source guard",
    ] {
        if !v0_4_release_note.contains(required) {
            bail!("v0.4 release note is missing preserved baseline contract {required:?}");
        }
    }
    let stable_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0.md"))?;
    for required in [
        STABLE_RELEASE_VERSION,
        STABLE_RELEASE_GATE_SCHEMA_VERSION,
        STABLE_RELEASE_BASELINE_STATUS,
        STABLE_RELEASE_MAINTENANCE_BRANCH,
        STABLE_UPGRADE_SOURCE_VERSION,
        STABLE_UPGRADE_SOURCE_FIXTURE_PATH,
        STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        "depgraph-mcp-tools-v1",
        "depgraph-operation-v1",
        "operation journal schema `5`",
    ] {
        if !stable_release_note.contains(required) {
            bail!("v0.5 release note is missing contract {required:?}");
        }
    }
    let rc_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.1.md"))?;
    for required in [
        "first v0.5 release candidate",
        "signed annotated `v0.5.0-rc.1` tag",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.1.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc_release_note.contains(required) {
            bail!("v0.5.0-rc.1 release note is missing contract {required:?}");
        }
    }
    let rc2_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.2.md"))?;
    for required in [
        "second v0.5 release candidate",
        "signed annotated `v0.5.0-rc.2` tag",
        "`v0.5.0-rc.1` tag remains immutable and was not published",
        "canonicalizes the relative",
        "checkout-built CLI path before switching",
        "`x86_64-pc-windows-msvc` only receives the 15-minute semantic ceiling; all four supported Linux and macOS targets retain the 10-minute semantic ceiling.",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.2.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc2_release_note.contains(required) {
            bail!("v0.5.0-rc.2 release note is missing contract {required:?}");
        }
    }
    let rc3_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.3.md"))?;
    for required in [
        "third v0.5 release candidate",
        "signed annotated `v0.5.0-rc.3` tag",
        "`v0.5.0-rc.1` and `v0.5.0-rc.2` tags remain immutable",
        "validates each rollback failure by its exact typed",
        "removing only execution",
        "`/etc/alternatives/cc`",
        "canonical root-owned compiler executable",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.3.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc3_release_note.contains(required) {
            bail!("v0.5.0-rc.3 release note is missing contract {required:?}");
        }
    }
    let release_procedure =
        read_lf_normalized_text(&root.join("docs/50_test/release-procedure.md"))?;
    for required in [
        "git tag -s \"$release_tag\" \"$candidate\"",
        "git verify-tag \"$release_tag\"",
        "## 公開後の再取得検証",
        "`release-post-publish-evidence-v1`",
        "計51点",
        "checkout内のproduct binaryや未公開package artifact",
    ] {
        if !release_procedure.contains(required) {
            bail!("release procedure is missing post-publish contract {required:?}");
        }
    }
    if sha256_file(&root.join(STABLE_UPGRADE_SOURCE_FIXTURE_PATH))?
        != STABLE_UPGRADE_SOURCE_FIXTURE_SHA256
    {
        bail!("official v0.4.0-rc.6 store fixture was modified");
    }
    let compatibility = release_compatibility();
    if compatibility.worker_protocol_version != depgraph_protocol::PROTOCOL_VERSION
        || compatibility.store_schema_version != depgraph_store::STORE_SCHEMA_VERSION
        || compatibility.operation_journal_schema_version
            != depgraph_operation::JOURNAL_SCHEMA_VERSION
        || compatibility.mcp_tool_contract_version != MCP_TOOL_CONTRACT_VERSION
        || compatibility.mcp_operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
        || compatibility.stable_release_version != VERSION
        || compatibility.stable_upgrade_source_fixture_path != STABLE_UPGRADE_SOURCE_FIXTURE_PATH
        || compatibility.stable_upgrade_source_fixture_sha256
            != format!("sha256:{STABLE_UPGRADE_SOURCE_FIXTURE_SHA256}")
    {
        bail!("v0.5 release compatibility tuple is not synchronized");
    }
    verify_stable_release_source_guard(root)?;
    let git_attributes = fs::read_to_string(root.join(".gitattributes"))?;
    if !git_attributes
        .lines()
        .any(|line| line.trim() == "README.md text eol=lf")
    {
        bail!("README release metadata is not pinned to LF in .gitattributes");
    }
    for (path, expected) in PROJECT_LICENSES {
        let required_attribute = format!("{path} text eol=lf");
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
        {
            bail!("project license {path} is not pinned to LF in .gitattributes");
        }
        if expected.contains(&b'\r') {
            bail!("project license source {path} is not LF-normalized");
        }
        let actual = fs::read(root.join(path))?;
        if actual != *expected {
            bail!("project license source {path} differs from its compiled release input");
        }
    }
    for (path, expected) in [
        ("third_party/rust-src/COPYRIGHT", RUST_SOURCE_COPYRIGHT),
        ("third_party/rust-src/LICENSE-MIT", RUST_SOURCE_LICENSE_MIT),
    ] {
        let required_attribute = format!("{path} text eol=lf");
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
            || expected.contains(&b'\r')
        {
            bail!("Rust source legal input {path} is not pinned to LF");
        }
    }
    for required_attribute in [
        "fixtures/** text eol=lf",
        "xtask/fixtures/** text eol=lf",
        "queries/** text eol=lf",
        "schemas/** text eol=lf",
    ] {
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
        {
            bail!("release contract text is missing checkout normalization {required_attribute}");
        }
    }
    for link in [
        "docs/40_arch_design/arch-dependency-graph-cli-system-design.md",
        "docs/40_arch_design/adr-rust-compiler-precise-backend.md",
        "docs/40_arch_design/adr-cross-language-adapter-contract.md",
        "docs/40_arch_design/adr-default-profile-selection-budget.md",
        "docs/40_arch_design/adr-bounded-graph-query-language.md",
        "docs/40_arch_design/adr-v0.5-release-contract.md",
        "docs/50_test/mcp-agent-host-operations.md",
        "docs/releases/v0.4.0.md",
        "docs/releases/v0.5.0.md",
        "docs/releases/v0.5.0-rc.3.md",
        "docs/releases/v0.5.0-rc.2.md",
        "docs/releases/v0.5.0-rc.1.md",
        "docs/releases/v0.4.0-rc.6.md",
        "docs/releases/v0.4.0-rc.3.md",
        "docs/releases/v0.4.0-rc.2.md",
        "docs/releases/v0.4.0-rc.1.md",
        "docs/releases/v0.2.0-rc.1.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ] {
        if !root.join(link).is_file() {
            bail!("README local documentation link does not resolve: {link}");
        }
    }
    let schema: Value = serde_json::from_slice(&fs::read(
        root.join("schemas/depgraph-protocol-v1.schema.json"),
    )?)?;
    if schema["title"] != "depgraph worker protocol v1.0"
        || schema["$defs"]["common"]["properties"]["protocol_version"]["const"] != "1.0"
    {
        bail!("protocol schema compatibility reference is not synchronized with 1.0");
    }
    let release_workflow = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
    for (target, _) in RELEASE_TARGETS {
        if !release_workflow.contains(target) {
            bail!("release workflow is missing target {target}");
        }
    }
    for required in [
        "cargo xtask verify-release-assets artifacts",
        "docs/releases/${GITHUB_REF_NAME}.md",
        "artifacts/release-verification.json",
        "benchmark-report-${{ github.sha }}",
        "dist/*.query-smoke.json",
        "compiler-precise-hostile:",
        "sudo apt-get install --yes --no-install-recommends bubblewrap",
        "run: scripts/compiler-precise-hostile-e2e.sh",
        "needs: [quality, compiler-precise-hostile]",
        "DEPGRAPH_INCREMENTAL_LIMIT_MS: \"10000\"",
        "DEPGRAPH_QUERY_LIMIT_MS: \"4000\"",
        "DEPGRAPH_BOUNDED_QUERY_PLAN_LIMIT_MS: \"7000\"",
        "DEPGRAPH_BOUNDED_QUERY_EXECUTE_LIMIT_MS: \"10000\"",
        "DEPGRAPH_RUST_SCAN_LIMIT_MS: \"12000\"",
        "DEPGRAPH_RUST_NO_CACHE_SCAN_LIMIT_MS: \"12000\"",
        "node scripts/benchmark-report.mjs verify benchmark/benchmark-report.json",
        "node scripts/cache-hit-benchmark.mjs verify benchmark/cache-hit-benchmark-report.json",
        "compiler-pack:",
        "verify-compiler-packs:",
        "rustup toolchain install nightly-2026-07-17 --profile minimal --component rust-src,rustc-dev,llvm-tools-preview",
        "cargo xtask compiler-pack-package --channel-manifest channel-rust-nightly-2026-07-17.toml",
        "cargo xtask verify-compiler-pack-assets compiler-artifacts",
        "needs: [quality, compiler-precise-hostile, benchmark, package, verify-assets, compiler-pack, verify-compiler-packs]",
        "cargo xtask stable-release-gate artifacts/release-verification.json benchmark/benchmark-report.json compiler-artifacts/compiler-pack-verification.json --output artifacts/stable-release-gate.json",
        "DEPGRAPH_RELEASE_QUALITY_RESULT: ${{ needs.quality.result }}",
        "DEPGRAPH_RELEASE_COMPILER_PRECISE_HOSTILE_RESULT: ${{ needs.compiler-precise-hostile.result }}",
        "DEPGRAPH_RELEASE_BENCHMARK_RESULT: ${{ needs.benchmark.result }}",
        "DEPGRAPH_RELEASE_PACKAGE_RESULT: ${{ needs.package.result }}",
        "DEPGRAPH_RELEASE_VERIFY_ASSETS_RESULT: ${{ needs.verify-assets.result }}",
        "DEPGRAPH_RELEASE_COMPILER_PACK_RESULT: ${{ needs.compiler-pack.result }}",
        "DEPGRAPH_RELEASE_VERIFY_COMPILER_PACKS_RESULT: ${{ needs.verify-compiler-packs.result }}",
        "name: stable-release-gate",
        "needs: stable-gate",
        "name: Verify the signed annotated release tag",
        "git rev-parse \"${GITHUB_REF_NAME}^{tag}\"",
        "git ls-remote origin refs/heads/main",
        ".verification.signature != null",
        "gh release download \"$GITHUB_REF_NAME\" --dir post-publish/public",
        "cargo xtask verify-release-assets post-publish/normal",
        "cargo xtask verify-compiler-pack-assets post-publish/compiler",
        "gh run list --workflow CI --event workflow_dispatch --commit \"$GITHUB_SHA\" --status success",
        "cargo xtask release-post-publish-evidence",
        "gh release upload \"$GITHUB_REF_NAME\" \"$evidence\"",
        "cmp --silent \"$evidence\"",
    ] {
        if !release_workflow.contains(required) {
            bail!("release workflow is missing {required:?}");
        }
    }
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    for required in [
        "needs: [rust, go, web]",
        "node --test scripts/tests/benchmark.test.mjs scripts/tests/cache-hit-benchmark.test.mjs",
        "scripts/benchmark-mvp.sh",
        "benchmark-report-${{ github.sha }}",
        "dist/cache-hit-benchmark-report.json",
        "DEPGRAPH_CACHE_HIT_MIN_IMPROVEMENT_PERCENT: \"5\"",
        "DEPGRAPH_INCREMENTAL_LIMIT_MS: \"10000\"",
        "DEPGRAPH_QUERY_LIMIT_MS: \"4000\"",
        "DEPGRAPH_BOUNDED_QUERY_PLAN_LIMIT_MS: \"7000\"",
        "DEPGRAPH_BOUNDED_QUERY_EXECUTE_LIMIT_MS: \"10000\"",
        "DEPGRAPH_RUST_SCAN_LIMIT_MS: \"12000\"",
        "DEPGRAPH_RUST_NO_CACHE_SCAN_LIMIT_MS: \"12000\"",
    ] {
        if !ci_workflow.contains(required) {
            bail!("CI workflow is missing {required:?}");
        }
    }
    Ok(())
}

fn markdown_table_rows_between(
    document: &str,
    start: Option<&str>,
    end: &str,
) -> Result<Vec<Vec<String>>> {
    let section = match start {
        Some(heading) => {
            document
                .split_once(heading)
                .with_context(|| format!("missing markdown section {heading:?}"))?
                .1
        }
        None => document,
    };
    let section = section
        .split_once(end)
        .with_context(|| format!("missing markdown section boundary {end:?}"))?
        .0;
    Ok(section
        .lines()
        .filter(|line| line.starts_with('|') && !line.contains("---"))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        .skip(1)
        .collect())
}

fn markdown_count_table(document: &str, start: &str, end: &str) -> Result<BTreeMap<String, usize>> {
    markdown_table_rows_between(document, Some(start), end)?
        .into_iter()
        .map(|row| {
            if row.len() != 2 {
                bail!("count table {start:?} contains a malformed row: {row:?}");
            }
            let count = row[1]
                .parse::<usize>()
                .with_context(|| format!("count table {start:?} has a nonnumeric count"))?;
            Ok((row[0].clone(), count))
        })
        .collect()
}

fn verify_mcp_tasks_architecture_decision(root: &Path) -> Result<()> {
    const DOCUMENT_PATH: &str = "docs/40_arch_design/arch-mcp-agent-tools.md";
    const EXPECTED_FRONTMATTER: &str = "---\n\
id: PROJ-ARC-002\n\
layer: L4\n\
feature: mcp-agent-tools\n\
scope: feature\n\
status: Active\n\
upstream: [PROJ-ARC-001]\n\
downstream: []\n\
owner: TakehiroT\n\
updated: 2026-08-12\n\
open_questions: 0\n\
---\n";

    let attributes = fs::read_to_string(root.join(".gitattributes"))?;
    if !attributes
        .lines()
        .any(|line| line == "docs/**/*.md text eol=lf")
    {
        bail!("repository documentation is not pinned to LF checkout bytes");
    }
    let decision = fs::read_to_string(root.join(DOCUMENT_PATH))?;
    if !decision.starts_with(EXPECTED_FRONTMATTER) || !decision.ends_with('\n') {
        bail!("MCP Agent Tools architecture frontmatter is missing, open, or noncanonical");
    }
    for required in [
        "# アーキテクチャ設計: MCP Agent Tools",
        "| `Q-002` | baseline handleへMCP Tasksを追加するか | **Resolved: Option Aを採用する** |",
        "**Option A（baseline operation handle + MCP Tasks）を採用する。**",
        "`rmcp 3.1.0`",
        "1f9358eddca42d3a510c70ae6446dd6548c7c856",
        "`io.modelcontextprotocol/tasks`",
        "`taskId == operation_id`",
        "## Portable baseline operation contract",
        "`operation_get`",
        "`operation_result`",
        "`operation_cancel`",
        "## MCP Tasks additive contract",
        "### Capability negotiation and legacy fallback",
        "`2025-11-25` experimental",
        "baseline `OperationAccepted`",
        "`-32021` Missing Required Client Capability",
        "CallToolResponse = Complete(CallToolResult<OperationAccepted>)",
        "| `queued` / `running` / `cancelling` | `working` |",
        "### `tasks/cancel` authorization",
        "不足時は`CAPABILITY_DENIED`",
        "journal digest、lease、runnerを\n   変更しない",
        "### Disconnect, restart, and reconnection",
        "再接続先がTasks非対応、extension未宣言、またはlegacy protocolでも",
        "## Compatibility and conformance tests",
        "| Legacy fallback |",
        "| Cancel authorization |",
        "| `Q-002` | **Resolved** | Option Aを採用する。",
        "`open_questions`は`0`である。",
        "| `#316` | resolve buildを共有project-exec serviceとdurable MCP operationへ接続する |",
        "## Issue #316 resolve-build project-exec evidence",
        "`source_non_mutation_guaranteed=true`",
        "### Issue #316 acceptance mapping",
        "| `#317` | 全CLI mapping、capability、path confinement、operation recovery、hostile project executionを横断検証する |",
        "## Issue #317 cross-cutting security E2E evidence",
        "baseline-only assertionには置き換えず",
        "### Issue #317 acceptance mapping",
        "| `#318` | MCP server、operation runner、schema、SDK/legal metadataを5 target release closureへ含める |",
        "## Issue #318 five-target MCP release closure",
        "`rmcp 3.1.0`とprotocol revision `2026-07-28`",
        "stable gate schema 9の`mcp-five-target` check",
        "### Issue #318 acceptance mapping",
        "| `#319` | 抽出済みarchiveのMCP stdio smokeと5 target digest gateを追加する |",
        "## Issue #319 packaged MCP smoke and digest gate",
        "`mcp-package-smoke-v1`",
        "handle受領を2,000 ms未満",
        "stdin close後5,000 ms以内",
        "### Issue #319 acceptance mapping",
        "## Issue #292 acceptance mapping",
    ] {
        if !decision.contains(required) {
            bail!("MCP Tasks architecture decision is missing {required:?}");
        }
    }
    for forbidden in [
        "open_questions: 1",
        "| `Q-002` | Open |",
        "| `Q-002` | Pending |",
        "TODO",
        "TBD",
    ] {
        if decision.contains(forbidden) {
            bail!("MCP Tasks architecture decision contains unresolved marker {forbidden:?}");
        }
    }
    if decision.matches("```").count() % 2 != 0 {
        bail!("MCP Tasks architecture decision contains an unclosed code fence");
    }
    verify_local_markdown_links(root, DOCUMENT_PATH, &decision)?;

    let index = fs::read_to_string(root.join("docs/00_index/index.md"))?;
    let architecture_rows =
        markdown_table_rows_between(&index, None, "## Architecture Decision Records")?;
    let mut ids = BTreeSet::new();
    let mut layers = BTreeMap::from([
        ("L0".to_owned(), 0),
        ("L1".to_owned(), 0),
        ("L2".to_owned(), 0),
        ("L3".to_owned(), 0),
        ("L4".to_owned(), 0),
        ("L5".to_owned(), 0),
    ]);
    let mut statuses = BTreeMap::from([
        ("Draft".to_owned(), 0),
        ("Active".to_owned(), 0),
        ("Deprecated".to_owned(), 0),
    ]);
    let mut features = BTreeMap::new();
    let mut found_mcp_entry = false;
    for row in &architecture_rows {
        if row.len() != 6 {
            bail!("documentation index contains a malformed architecture row: {row:?}");
        }
        if !ids.insert(row[0].clone()) {
            bail!(
                "documentation index contains duplicate architecture ID {:?}",
                row[0]
            );
        }
        *layers
            .get_mut(&row[1])
            .with_context(|| format!("documentation index uses unknown layer {:?}", row[1]))? += 1;
        *statuses
            .get_mut(&row[5])
            .with_context(|| format!("documentation index uses unknown status {:?}", row[5]))? += 1;
        *features.entry(row[2].clone()).or_insert(0) += 1;
        found_mcp_entry |= row
            == &[
                "PROJ-ARC-002",
                "L4",
                "mcp-agent-tools",
                "feature",
                "[アーキテクチャ設計: MCP Agent Tools](../40_arch_design/arch-mcp-agent-tools.md)",
                "Active",
            ];
    }
    if !found_mcp_entry {
        bail!("documentation index is missing the canonical MCP Agent Tools entry");
    }

    let mut expected_layers = layers;
    expected_layers.insert("Total".to_owned(), architecture_rows.len());
    let indexed_layers = markdown_count_table(&index, "### レイヤー別", "### ステータス別")?;
    let indexed_statuses = markdown_count_table(&index, "### ステータス別", "### 機能別")?;
    let indexed_features = markdown_count_table(&index, "### 機能別", "## 更新履歴")?;
    if indexed_layers != expected_layers
        || indexed_statuses != statuses
        || indexed_features != features
    {
        bail!("documentation index statistics do not match its architecture entries");
    }
    verify_local_markdown_links(root, "docs/00_index/index.md", &index)?;
    Ok(())
}

fn verify_public_community_surface(root: &Path) -> Result<()> {
    let documents: &[(&str, &[&str])] = &[
        (
            "README.md",
            &[
                "## Project status and public collaboration",
                "There is currently no supported stable release.",
                "[SUPPORT.md](SUPPORT.md)",
                "[CONTRIBUTING.md](CONTRIBUTING.md)",
                "[GOVERNANCE.md](GOVERNANCE.md)",
                "[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)",
                "[SECURITY.md](SECURITY.md)",
            ],
        ),
        (
            "CONTRIBUTING.md",
            &[
                "## Developer Certificate of Origin",
                "git commit -s",
                "Signed-off-by",
                "cargo xtask test",
                "[SECURITY.md](SECURITY.md)",
                "[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)",
            ],
        ),
        (
            "CODE_OF_CONDUCT.md",
            &[
                "## Scope and enforcement",
                "private route in [SECURITY.md](SECURITY.md)",
                "may appeal once",
                "The appeal reviewer must not be the sole person",
            ],
        ),
        (
            "SECURITY.md",
            &[
                "## Supported versions",
                "## Report a vulnerability privately",
                "https://github.com/TamaT-LLC/depgraph-cli/security/advisories/new",
                "Do not open a public issue",
                "best effort and does not create a response-time SLA",
            ],
        ),
        (
            "SUPPORT.md",
            &[
                "best-effort basis",
                "does not provide an SLA",
                "There is currently no supported stable release.",
                "[SECURITY.md](SECURITY.md)",
                "There is no automatic stale deadline",
            ],
        ),
        (
            "GOVERNANCE.md",
            &[
                "## Maintainer lifecycle and team boundary",
                "`CODEOWNERS` is added only after",
                "Personal accounts, invented team names, and",
                "Authors do not approve their own work.",
                "Developer Certificate of Origin",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/config.yml",
            &[
                "blank_issues_enabled: false",
                "Private vulnerability report",
                "https://github.com/TamaT-LLC/depgraph-cli/security/advisories/new",
                "SUPPORT.md",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            &[
                "name: Bug report",
                "id: reproduction",
                "id: expected",
                "id: actual",
                "This is not a suspected security vulnerability.",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            &[
                "name: Feature request",
                "id: problem",
                "id: proposal",
                "id: alternatives",
                "Security reports belong in the private",
            ],
        ),
        (
            ".github/PULL_REQUEST_TEMPLATE.md",
            &[
                "## Scope and compatibility",
                "cargo xtask test",
                "## Security and provenance",
                "DCO `Signed-off-by`",
                "the author is not the independent approver",
            ],
        ),
    ];
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize community surface root {}", root.display()))?;
    for (path, markers) in documents {
        let document_path = root.join(path);
        let content = fs::read_to_string(&document_path)
            .with_context(|| format!("public community profile is missing {path}"))?;
        for marker in *markers {
            if !content.contains(marker) {
                bail!("public community document {path} is missing marker {marker:?}");
            }
        }
        for forbidden in ["TODO", "TBD", "CHANGEME", "<contact>", "@team-name"] {
            if content.contains(forbidden) {
                bail!("public community document {path} contains placeholder {forbidden:?}");
            }
        }
        verify_local_markdown_links(&root, path, &content)?;
    }
    if root.join(".github/CODEOWNERS").exists() {
        bail!(
            "CODEOWNERS must remain absent until an organization owner attests a live assigned team"
        );
    }
    Ok(())
}

fn verify_local_markdown_links(root: &Path, source: &str, content: &str) -> Result<()> {
    let mut remainder = content;
    while let Some(label_end) = remainder.find("](") {
        remainder = &remainder[label_end + 2..];
        let Some(target_end) = markdown_link_target_end(remainder) else {
            bail!("public community document {source} contains an unterminated Markdown link");
        };
        let target = remainder[..target_end].trim();
        remainder = &remainder[target_end + 1..];
        if target.is_empty()
            || target.starts_with('#')
            || target.starts_with("https://")
            || target.starts_with("http://")
            || target.starts_with("mailto:")
        {
            continue;
        }
        let target = target.split('#').next().unwrap_or_default();
        let source_parent = Path::new(source).parent().unwrap_or_else(|| Path::new(""));
        let resolved = root.join(source_parent).join(target);
        let resolved = resolved.canonicalize().with_context(|| {
            format!("public community document {source} has broken local link {target:?}")
        })?;
        if !resolved.is_file() || !path_is_within_directory_by_identity(root, &resolved)? {
            bail!("public community document {source} has unsafe local link {target:?}");
        }
    }
    Ok(())
}

fn path_is_within_directory_by_identity(root: &Path, path: &Path) -> Result<bool> {
    for ancestor in path.ancestors() {
        if same_file::is_same_file(root, ancestor).with_context(|| {
            format!(
                "compare community link ancestor {} with root {}",
                ancestor.display(),
                root.display()
            )
        })? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn markdown_link_target_end(input: &str) -> Option<usize> {
    let mut depth = 1_usize;
    let mut escaped = false;
    for (offset, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted_assignment(source: &str, name: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let (left, right) = line.split_once('=')?;
        left.split_whitespace().any(|token| token == name).then(|| {
            right
                .trim()
                .trim_end_matches(';')
                .trim_end_matches("as const")
                .trim()
                .trim_matches('"')
                .to_owned()
        })
    })
}

fn test() -> Result<()> {
    verify_project_metadata(&workspace_root())?;
    let cargo = cargo_metadata(&["--features", "depgraph-cli/packaged"])?;
    verify_rust_analyzer_dependencies(&cargo)?;
    run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))?;
    run(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ]))?;
    run(Command::new("cargo").args(["test", "--workspace", "--locked"]))?;
    run(Command::new("node").args([
        "--test",
        "scripts/tests/benchmark.test.mjs",
        "scripts/tests/cache-hit-benchmark.test.mjs",
    ]))?;
    let gofmt = Command::new("gofmt")
        .arg("-l")
        .arg(".")
        .current_dir("workers/go")
        .output()?;
    if !gofmt.status.success() || !gofmt.stdout.is_empty() {
        bail!(
            "gofmt check failed:\n{}",
            String::from_utf8_lossy(&gofmt.stdout)
        );
    }
    run(Command::new("go")
        .args(["test", "-race", "./..."])
        .env("GOTOOLCHAIN", "local")
        .env("GOFLAGS", "-mod=readonly")
        .current_dir("workers/go"))?;
    run(Command::new("go")
        .args(["vet", "./..."])
        .env("GOTOOLCHAIN", "local")
        .env("GOFLAGS", "-mod=readonly")
        .current_dir("workers/go"))?;
    go_semantic_e2e::run_development(&workspace_root(), &cargo_target_dir())?;
    rust_semantic_e2e::run_development(&workspace_root(), &cargo_target_dir())?;
    run(Command::new(pnpm_program())
        .args(["install", "--frozen-lockfile"])
        .current_dir("workers/web"))?;
    run(Command::new(pnpm_program())
        .arg("check")
        .current_dir("workers/web"))?;
    run(Command::new(pnpm_program())
        .arg("test")
        .current_dir("workers/web"))?;
    Ok(())
}

fn package() -> Result<()> {
    verify_release_tag()?;
    verify_project_metadata(&workspace_root())?;
    build(true)?;
    // The distributed CLI must never fall back to development worker
    // overrides when its signed layout is incomplete.
    for (package, binary, features) in RELEASE_CARGO_BUILD_TARGETS {
        let mut command = Command::new("cargo");
        command.args(["build", "--locked", "--release", "-p", package]);
        if let Some(binary) = binary {
            command.args(["--bin", binary]);
        }
        if let Some(features) = features {
            command.args(["--features", features]);
        }
        run(&mut command)?;
    }
    let host = host_target()?;
    let target = std::env::var("DEPGRAPH_TARGET").unwrap_or_else(|_| host.clone());
    if target != host {
        bail!("DEPGRAPH_TARGET {target} does not match native build target {host}");
    }
    let name = format!("depgraph-{VERSION}-{target}");
    let dist = Path::new("dist");
    let staging = dist.join(&name);
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("failed to clear {}", staging.display()))?;
    }
    fs::create_dir_all(staging.join("bin"))?;
    fs::create_dir_all(staging.join("libexec"))?;
    fs::create_dir_all(staging.join("schemas"))?;
    fs::create_dir_all(staging.join("queries"))?;
    fs::create_dir_all(staging.join("fixtures"))?;

    let mut project_licenses = Vec::new();
    for (path, _) in PROJECT_LICENSES {
        copy_lf_normalized_text(Path::new(path), &staging.join(path))?;
        project_licenses.push(Artifact {
            path: (*path).to_owned(),
            sha256: sha256_file(&staging.join(path))?,
        });
    }

    let release_dir = cargo_target_dir().join("release");
    copy(
        &release_dir.join(executable_name("depgraph")),
        &staging.join("bin").join(executable_name("depgraph")),
    )?;
    copy(
        &release_dir.join(executable_name(MCP_SERVER_NAME)),
        &staging.join("bin").join(executable_name(MCP_SERVER_NAME)),
    )?;
    copy(
        &release_dir.join(executable_name("depgraph-rust-worker")),
        &staging
            .join("libexec")
            .join(executable_name("depgraph-rust-worker")),
    )?;
    copy(
        &release_dir.join(executable_name("depgraph-operation-runner")),
        &staging
            .join("libexec")
            .join(executable_name("depgraph-operation-runner")),
    )?;
    copy(
        &Path::new("workers/go/bin").join(executable_name("depgraph-go-worker")),
        &staging
            .join("libexec")
            .join(executable_name("depgraph-go-worker")),
    )?;
    copy(
        Path::new("workers/web/dist/worker.mjs"),
        &staging.join("libexec/depgraph-web-worker.mjs"),
    )?;
    for artifact in WEB_RUNTIME_ARTIFACTS {
        copy(
            &Path::new("workers/web/dist").join(artifact),
            &staging.join("libexec").join(artifact),
        )?;
    }
    copy_directory(
        Path::new("workers/web/dist/astro"),
        &staging.join("libexec/astro"),
    )?;
    copy_directory(
        Path::new("workers/web/dist/typescript"),
        &staging.join("libexec/typescript"),
    )?;
    verify_typescript_compiler(&staging)?;
    copy_lf_normalized_text(
        Path::new("schemas/depgraph-protocol-v1.schema.json"),
        &staging.join("schemas/depgraph-protocol-v1.schema.json"),
    )?;
    let schema_path = staging.join("schemas/depgraph-protocol-v1.schema.json");
    copy_lf_normalized_text(
        Path::new(MCP_TOOL_SCHEMA_PATH),
        &staging.join(MCP_TOOL_SCHEMA_PATH),
    )?;
    let mcp_tool_schema_path = staging.join(MCP_TOOL_SCHEMA_PATH);
    let query_fixture_path = staging.join(depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH);
    copy_lf_normalized_text(
        Path::new(depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH),
        &query_fixture_path,
    )?;
    let cross_language_contract = depgraph_core::cross_language_release_compatibility_contract();
    let cross_language_fixture_path =
        staging.join(depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH);
    copy_lf_normalized_text(
        Path::new(depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH),
        &cross_language_fixture_path,
    )?;
    let cross_language_schemas = cross_language_contract
        .schemas
        .iter()
        .map(|schema| {
            let source = Path::new(&schema.path);
            let destination = staging.join(&schema.path);
            copy_lf_normalized_text(source, &destination)?;
            Ok(Artifact {
                path: schema.path.clone(),
                sha256: sha256_file(&destination)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rust_sysroot_component = prepare_rust_sysroot_component(&staging)?;
    let rust_sysroot_sha256 = rust_sysroot_component.sha256.clone();

    let workers = vec![
        worker_artifact(
            "rust",
            &staging
                .join("libexec")
                .join(executable_name("depgraph-rust-worker")),
            &staging,
        )?,
        worker_artifact(
            "go",
            &staging
                .join("libexec")
                .join(executable_name("depgraph-go-worker")),
            &staging,
        )?,
        worker_artifact(
            "web",
            &staging.join("libexec/depgraph-web-worker.mjs"),
            &staging,
        )?,
    ];
    let core_path = staging.join("bin").join(executable_name("depgraph"));
    let mcp_server_path = staging.join("bin").join(executable_name(MCP_SERVER_NAME));
    let operation_runner_path = staging
        .join("libexec")
        .join(executable_name("depgraph-operation-runner"));
    let manifest = ReleaseManifest {
        release_version: VERSION.to_owned(),
        protocol_version: "1.0".to_owned(),
        schema_version: "1.0".to_owned(),
        compatibility: release_compatibility(),
        target: target.clone(),
        license_expression: PROJECT_LICENSE_EXPRESSION.to_owned(),
        project_licenses,
        core: Artifact {
            path: relative_slash(&staging, &core_path)?,
            sha256: sha256_file(&core_path)?,
        },
        mcp_server: mcp_server_artifact(&mcp_server_path, &staging)?,
        operation_runner: operation_runner_artifact(&operation_runner_path, &staging)?,
        schema: Artifact {
            path: relative_slash(&staging, &schema_path)?,
            sha256: sha256_file(&schema_path)?,
        },
        mcp_tool_schema: VersionedArtifact {
            contract_version: MCP_TOOL_CONTRACT_VERSION.to_owned(),
            path: relative_slash(&staging, &mcp_tool_schema_path)?,
            sha256: sha256_file(&mcp_tool_schema_path)?,
        },
        query_fixture: Artifact {
            path: relative_slash(&staging, &query_fixture_path)?,
            sha256: sha256_file(&query_fixture_path)?,
        },
        cross_language_fixture: Artifact {
            path: relative_slash(&staging, &cross_language_fixture_path)?,
            sha256: sha256_file(&cross_language_fixture_path)?,
        },
        cross_language_schemas,
        runtime_artifacts: WEB_RUNTIME_ARTIFACTS
            .iter()
            .map(|name| {
                let path = staging.join("libexec").join(name);
                Ok(Artifact {
                    path: relative_slash(&staging, &path)?,
                    sha256: sha256_file(&path)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        runtime_components: vec![
            RuntimeComponent {
                name: "astro-parser-wasm".to_owned(),
                kind: "data-tree".to_owned(),
                version: "4.0.0".to_owned(),
                root: "libexec/astro".to_owned(),
                entrypoint: Some("libexec/astro/astro.wasm".to_owned()),
                license: "MIT".to_owned(),
                sha256: sha256_tree(&staging.join("libexec/astro"))?,
            },
            RuntimeComponent {
                name: "typescript-native-compiler".to_owned(),
                kind: "executable-tree".to_owned(),
                version: TYPESCRIPT_VERSION.to_owned(),
                root: "libexec/typescript/lib".to_owned(),
                entrypoint: Some(format!("libexec/typescript/lib/{}", executable_name("tsc"))),
                license: "Apache-2.0".to_owned(),
                sha256: sha256_tree(&staging.join("libexec/typescript/lib"))?,
            },
            rust_sysroot_component,
        ],
        workers,
        runtime_requirements: BTreeMap::from([("web".to_owned(), "Node.js >=24.0.0".to_owned())]),
    };
    let web_runtime_inventory: Value =
        serde_json::from_slice(&fs::read("workers/web/dist/runtime-packages.json")?)?;
    if manifest_framework_build_artifact_checksums(&manifest)?
        != framework_build_artifact_checksums(&web_runtime_inventory)?
    {
        bail!("release manifest framework build checksums differ from the Web runtime inventory");
    }
    fs::write(
        staging.join("release-manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::write(
        staging.join("THIRD_PARTY_LICENSES.txt"),
        third_party_licenses(&target)?,
    )?;
    fs::write(
        staging.join("sbom.spdx.json"),
        serde_json::to_vec_pretty(&sbom(&target, &rust_sysroot_sha256)?)?,
    )?;

    let archive = create_archive(dist, &name)?;
    let (query_smoke, cross_language_smoke, mcp_smoke) = verify_archive(&archive, &name)?;
    fs::write(
        dist.join(format!("{name}.query-smoke.json")),
        format!("{}\n", serde_json::to_string_pretty(&query_smoke)?),
    )?;
    fs::write(
        dist.join(format!("{name}.cross-language-smoke.json")),
        format!("{}\n", serde_json::to_string_pretty(&cross_language_smoke)?),
    )?;
    fs::write(
        dist.join(format!("{name}.mcp-smoke.json")),
        format!("{}\n", serde_json::to_string_pretty(&mcp_smoke)?),
    )?;
    let checksum = sha256_file(&archive)?;
    fs::write(
        archive.with_extension(format!(
            "{}sha256",
            archive
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| format!("{extension}."))
                .unwrap_or_default()
        )),
        format!(
            "{checksum}  {}\n",
            archive.file_name().unwrap().to_string_lossy()
        ),
    )?;
    println!("packaged {}", archive.display());
    Ok(())
}

fn prepare_rust_sysroot_component(staging: &Path) -> Result<RuntimeComponent> {
    let version_output = Command::new("rustup")
        .args(["run", RUST_SYSROOT_TOOLCHAIN_VERSION, "rustc", "-vV"])
        .output()
        .context("failed to inspect the pinned rustup toolchain used for packaging")?;
    if !version_output.status.success() {
        bail!(
            "rustup could not run the pinned rustc while preparing the Rust sysroot source: {}",
            String::from_utf8_lossy(&version_output.stderr).trim()
        );
    }
    let version_output =
        String::from_utf8(version_output.stdout).context("rustc -vV returned non-UTF-8 output")?;
    let (release, commit) = rustc_source_identity(&version_output)?;
    if release != RUST_SYSROOT_TOOLCHAIN_VERSION || commit != RUST_SYSROOT_TOOLCHAIN_COMMIT {
        bail!(
            "Rust sysroot source packaging requires rustc {RUST_SYSROOT_TOOLCHAIN_VERSION} ({RUST_SYSROOT_TOOLCHAIN_COMMIT}), found {release} ({commit})"
        );
    }

    let sysroot_output = Command::new("rustup")
        .args([
            "run",
            RUST_SYSROOT_TOOLCHAIN_VERSION,
            "rustc",
            "--print",
            "sysroot",
        ])
        .output()
        .context("failed to locate the pinned rustup toolchain sysroot")?;
    if !sysroot_output.status.success() {
        bail!(
            "rustup could not report the pinned Rust sysroot while preparing source: {}",
            String::from_utf8_lossy(&sysroot_output.stderr).trim()
        );
    }
    let sysroot = PathBuf::from(
        String::from_utf8(sysroot_output.stdout)
            .context("rustc --print sysroot returned non-UTF-8 output")?
            .trim(),
    );
    if sysroot.as_os_str().is_empty() {
        bail!("rustc --print sysroot returned an empty path");
    }
    let source = sysroot.join("lib/rustlib/src/rust/library");
    let source_metadata = fs::symlink_metadata(&source).with_context(|| {
        format!(
            "pinned rust-src is missing at {}; install it with `rustup component add rust-src --toolchain {RUST_SYSROOT_TOOLCHAIN_VERSION}`",
            source.display()
        )
    })?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        bail!(
            "pinned rust-src source root must be a real directory, not a symlink: {}",
            source.display()
        );
    }
    let source = source.canonicalize()?;
    let workspace = workspace_root().canonicalize()?;
    if source.starts_with(&workspace) {
        bail!(
            "refusing project-local Rust source fallback while packaging: {}",
            source.display()
        );
    }
    for required in [
        "Cargo.toml",
        "core/src/lib.rs",
        "alloc/src/lib.rs",
        "std/src/lib.rs",
        "proc_macro/src/lib.rs",
    ] {
        let path = source.join(required);
        if !path.is_file()
            || fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!(
                "pinned rust-src is incomplete or symlinked: required file {}",
                path.display()
            );
        }
    }

    let component_root = staging.join(RUST_SYSROOT_COMPONENT_ROOT);
    copy_directory(&source, &component_root.join("library"))?;
    fs::write(component_root.join("COPYRIGHT"), RUST_SOURCE_COPYRIGHT)?;
    fs::write(component_root.join("LICENSE-MIT"), RUST_SOURCE_LICENSE_MIT)?;
    fs::write(
        component_root.join("LICENSE-APACHE"),
        PROJECT_LICENSES
            .iter()
            .find_map(|(path, content)| (*path == "LICENSE-APACHE").then_some(*content))
            .context("project Apache-2.0 license input is missing")?,
    )?;
    fs::write(
        component_root.join("SOURCE.json"),
        serde_json::to_vec_pretty(&RustSysrootSourceIdentity {
            contract_version: RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION,
            toolchain_version: RUST_SYSROOT_TOOLCHAIN_VERSION,
            toolchain_commit: RUST_SYSROOT_TOOLCHAIN_COMMIT,
            component_version: RUST_SYSROOT_COMPONENT_VERSION,
            source_layout: RUST_SYSROOT_SOURCE_LAYOUT,
            acquisition: "rustup-component:rust-src",
            normalized_root: "library",
            license_expression: RUST_SYSROOT_LICENSE_EXPRESSION,
        })?,
    )?;
    let sha256 = sha256_tree(&component_root)?;
    verify_pinned_rust_sysroot_digest(&sha256)?;

    Ok(RuntimeComponent {
        name: RUST_SYSROOT_COMPONENT_NAME.to_owned(),
        kind: "data-tree".to_owned(),
        version: RUST_SYSROOT_COMPONENT_VERSION.to_owned(),
        root: RUST_SYSROOT_COMPONENT_ROOT.to_owned(),
        entrypoint: None,
        license: RUST_SYSROOT_LICENSE_EXPRESSION.to_owned(),
        sha256,
    })
}

fn verify_pinned_rust_sysroot_digest(sha256: &str) -> Result<()> {
    if sha256 != RUST_SYSROOT_COMPONENT_SHA256 {
        bail!(
            "pinned Rust sysroot source tree digest mismatch: expected {RUST_SYSROOT_COMPONENT_SHA256}, found {sha256}; refusing modified or unknown rust-src content"
        );
    }
    Ok(())
}

fn rustc_source_identity(output: &str) -> Result<(&str, &str)> {
    let release = output
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .filter(|value| !value.is_empty())
        .context("rustc -vV did not report a release")?;
    let commit = output
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .filter(|value| !value.is_empty() && *value != "unknown")
        .context("rustc -vV did not report an exact source commit")?;
    Ok((release, commit))
}

fn worker_artifact(adapter: &'static str, path: &Path, staging: &Path) -> Result<WorkerArtifact> {
    let output = if adapter == "web" {
        Command::new("node")
            .arg(process_argument_path(path))
            .arg("--version")
            .output()?
    } else {
        Command::new(path).arg("--version").output()?
    };
    if !output.status.success() {
        bail!(
            "{adapter} worker version handshake failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let handshake = String::from_utf8(output.stdout)?.trim().to_owned();
    let parsed = parse_worker_handshake(&handshake)
        .with_context(|| format!("{adapter} worker reported a malformed handshake: {handshake}"))?;
    let expected_name = format!("depgraph-{adapter}-worker");
    if parsed.name != expected_name || parsed.protocol != "1.0" {
        bail!("{adapter} worker reported an incompatible handshake: {handshake}");
    }
    let backend = if adapter == "rust" {
        let backend = rust_backend_from_handshake(&parsed)?;
        verify_rust_backend(&backend)?;
        Some(backend)
    } else {
        None
    };
    let semantic = if adapter == "web" {
        let semantic = web_semantic_from_handshake(&parsed)?;
        verify_web_semantic_attestation(&semantic)?;
        Some(semantic)
    } else {
        None
    };
    Ok(WorkerArtifact {
        adapter: adapter.to_owned(),
        version: parsed.version.to_owned(),
        path: relative_slash(staging, path)?,
        sha256: sha256_file(path)?,
        backend,
        semantic,
    })
}

fn operation_runner_artifact(path: &Path, staging: &Path) -> Result<OperationRunnerArtifact> {
    let output = Command::new(path).arg("--version").output()?;
    let expected = format!("depgraph-operation-runner {VERSION}");
    if !output.status.success() || String::from_utf8(output.stdout)?.trim() != expected {
        bail!("operation runner version handshake failed");
    }
    Ok(OperationRunnerArtifact {
        version: VERSION.to_owned(),
        operation_contract_version: MCP_OPERATION_CONTRACT_VERSION.to_owned(),
        path: relative_slash(staging, path)?,
        sha256: sha256_file(path)?,
    })
}

fn mcp_server_artifact(path: &Path, staging: &Path) -> Result<McpServerArtifact> {
    let output = Command::new(path).arg("--version").output()?;
    let expected = format!("{MCP_SERVER_NAME} {VERSION}");
    if !output.status.success() || String::from_utf8(output.stdout)?.trim() != expected {
        bail!("MCP server version handshake failed");
    }
    Ok(McpServerArtifact {
        version: VERSION.to_owned(),
        path: relative_slash(staging, path)?,
        sha256: sha256_file(path)?,
        sdk_name: MCP_SDK_NAME.to_owned(),
        sdk_version: MCP_SDK_VERSION.to_owned(),
        protocol_revision: MCP_PROTOCOL_REVISION.to_owned(),
        tool_contract_version: MCP_TOOL_CONTRACT_VERSION.to_owned(),
        operation_contract_version: MCP_OPERATION_CONTRACT_VERSION.to_owned(),
    })
}

fn parse_worker_handshake(handshake: &str) -> Option<WorkerHandshake<'_>> {
    let (identity, details) = handshake.split_once(" (protocol ")?;
    let details = details.strip_suffix(')')?;
    let mut segments = details.split("; ");
    let protocol = segments.next()?;
    let mut parsed_details = BTreeMap::new();
    let mut detail_order = Vec::new();
    for detail in segments {
        let (key, value) = detail.split_once(' ')?;
        if key.is_empty() || value.is_empty() || parsed_details.insert(key, value).is_some() {
            return None;
        }
        detail_order.push(key);
    }
    let mut identity = identity.split_whitespace();
    let name = identity.next()?;
    let version = identity.next()?;
    if identity.next().is_some() || name.is_empty() || version.is_empty() || protocol.is_empty() {
        return None;
    }
    Some(WorkerHandshake {
        name,
        version,
        protocol,
        details: parsed_details,
        detail_order,
    })
}

fn rust_backend_from_handshake(handshake: &WorkerHandshake<'_>) -> Result<WorkerBackend> {
    if handshake.detail_order != ["rust-analyzer", "rust-analyzer-revision", "salsa"] {
        bail!("Rust worker handshake has an incomplete or unknown backend compatibility unit");
    }
    Ok(WorkerBackend {
        kind: "rust-analyzer-library".to_owned(),
        version: handshake.details["rust-analyzer"].to_owned(),
        revision: handshake.details["rust-analyzer-revision"].to_owned(),
        salsa_version: handshake.details["salsa"].to_owned(),
    })
}

fn verify_rust_backend(backend: &WorkerBackend) -> Result<()> {
    if backend.kind != "rust-analyzer-library"
        || backend.version != RUST_ANALYZER_CRATE_VERSION
        || backend.revision != RUST_ANALYZER_REVISION
        || backend.salsa_version != SALSA_VERSION
    {
        bail!("Rust worker backend does not match the verified compatibility unit: {backend:?}");
    }
    Ok(())
}

fn web_semantic_from_handshake(handshake: &WorkerHandshake<'_>) -> Result<WebSemanticAttestation> {
    if handshake.detail_order != ["typescript", "capabilities"] {
        bail!("Web worker handshake has an incomplete or unknown semantic compatibility unit");
    }
    let capabilities = handshake.details["capabilities"]
        .split(',')
        .map(str::to_owned)
        .collect();
    Ok(WebSemanticAttestation {
        typescript_version: handshake.details["typescript"].to_owned(),
        capabilities,
        runtime_components: WEB_SEMANTIC_RUNTIME_COMPONENTS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        runtime_artifacts: WEB_SEMANTIC_RUNTIME_ARTIFACTS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    })
}

fn verify_web_semantic_attestation(attestation: &WebSemanticAttestation) -> Result<()> {
    let expected_capabilities = WEB_SEMANTIC_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let expected_components = WEB_SEMANTIC_RUNTIME_COMPONENTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let expected_artifacts = WEB_SEMANTIC_RUNTIME_ARTIFACTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if attestation.typescript_version != TYPESCRIPT_VERSION
        || attestation.capabilities != expected_capabilities
        || attestation.runtime_components != expected_components
        || attestation.runtime_artifacts != expected_artifacts
    {
        bail!(
            "Web worker semantic attestation does not match the verified compatibility unit: {attestation:?}"
        );
    }
    Ok(())
}

fn third_party_licenses(target: &str) -> Result<String> {
    let web_inventory: Value = serde_json::from_slice(
        &fs::read("workers/web/dist/runtime-packages.json")
            .context("Web runtime package inventory is missing; run the Web worker build first")?,
    )?;
    runtime_collector_inventory(&web_inventory)?;
    let first_party = first_party_artifact_inventory(&web_inventory)?;
    let entries = dependency_inventory(target)?
        .into_iter()
        .map(|package| {
            format!(
                "{}:{} {} — {}",
                package.ecosystem, package.name, package.version, package.license
            )
        })
        .collect::<Vec<_>>();
    let mut notices = first_party
        .iter()
        .map(|artifact| {
            format!(
                "First-party artifact {} ({}) is licensed under {} by LICENSE-MIT and LICENSE-APACHE; its dependency-free bundle adds no third-party license entry.",
                artifact.path, artifact.version, artifact.license
            )
        })
        .collect::<Vec<_>>();
    notices.push(format!(
        "First-party bounded query contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION} by LICENSE-MIT and LICENSE-APACHE.",
        depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
        depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION,
    ));
    notices.push(format!(
        "First-party cross-language contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION} by LICENSE-MIT and LICENSE-APACHE.",
        depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
        depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION,
    ));
    notices.push(MCP_APACHE_NOTICE.to_owned());
    let notices = notices.join("\n");
    let rust_notice = rust_sysroot_license_notice();
    let mut output = format!(
        "depgraph third-party license inventory\nGenerated from every shipped Rust executable (including the MCP server and durable operation runner), the Go runtime dependency graph, the pinned Rust standard-library source tree, and the Web bundle/runtime artifact inventory.\n{notices}\n{rust_notice}\n{SBOM_SCOPE}\n\n{}\n",
        entries.join("\n")
    );
    for (label, content) in web_legal_documents()? {
        output.push_str(&legal_document_section(&label, &content));
    }
    Ok(output)
}

fn rust_sysroot_license_notice() -> String {
    format!(
        "Rust standard-library source {RUST_SYSROOT_COMPONENT_VERSION} (rustc commit {RUST_SYSROOT_TOOLCHAIN_COMMIT}) — {RUST_SYSROOT_LICENSE_EXPRESSION}; complete COPYRIGHT, LICENSE-MIT, and LICENSE-APACHE texts are packaged under {RUST_SYSROOT_COMPONENT_ROOT}."
    )
}

fn cross_language_contract_sha256(
    contract: &depgraph_core::CrossLanguageReleaseCompatibilityHealth,
) -> String {
    let value = serde_json::to_value(contract)
        .expect("cross-language release compatibility is always serializable");
    hex::encode(Sha256::digest(
        depgraph_protocol::canonical_json(&value).as_bytes(),
    ))
}

fn sbom(target: &str, rust_sysroot_sha256: &str) -> Result<Value> {
    let web_inventory: Value = serde_json::from_slice(
        &fs::read("workers/web/dist/runtime-packages.json")
            .context("Web runtime package inventory is missing; run the Web worker build first")?,
    )?;
    runtime_collector_inventory(&web_inventory)?;
    let first_party = first_party_artifact_inventory(&web_inventory)?;
    let dependencies = dependency_inventory(target)?;
    let dependency_ids = dependencies
        .iter()
        .map(|package| {
            format!(
                "SPDXRef-{}-{}-{}",
                spdx_component(&package.ecosystem),
                spdx_component(&package.name),
                spdx_component(&package.version)
            )
        })
        .collect::<Vec<_>>();
    let mut packages = dependencies
        .into_iter()
        .map(|package| {
            let license = normalized_spdx_license(&package.license)
                .unwrap_or_else(|| "NOASSERTION".to_owned());
            json!({
                "SPDXID": format!(
                    "SPDXRef-{}-{}-{}",
                    spdx_component(&package.ecosystem),
                    spdx_component(&package.name),
                    spdx_component(&package.version)
                ),
                "name": package.name,
                "versionInfo": package.version,
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license,
                "downloadLocation": "NOASSERTION",
                "externalRefs":[{
                    "referenceCategory":"PACKAGE-MANAGER",
                    "referenceType":"purl",
                    "referenceLocator":package_url(&package)
                }]
            })
        })
        .collect::<Vec<_>>();
    packages.insert(
        0,
        json!({
            "SPDXID":"SPDXRef-Package-depgraph",
            "name":"depgraph",
            "versionInfo":VERSION,
            "filesAnalyzed":false,
            "licenseConcluded":"NOASSERTION",
            "licenseDeclared":"MIT OR Apache-2.0",
            "downloadLocation":"NOASSERTION",
            "comment":SBOM_SCOPE
        }),
    );
    let query_contract = depgraph_core::bounded_query_release_compatibility_contract();
    let query_package_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(BOUNDED_QUERY_SBOM_PACKAGE_NAME)
    );
    let query_fixture_sha256 = query_contract
        .fixture_sha256
        .strip_prefix("sha256:")
        .context("bounded query fixture digest is not prefixed")?
        .to_owned();
    let query_contract_comment = format!(
        "First-party bounded query contract: language {}; types {}; statistics {}; plan {}; limits {}; result {}; fixture {}",
        query_contract.language_contract_version,
        query_contract.type_contract_version,
        query_contract.statistics_version,
        query_contract.plan_schema_version,
        query_contract.limit_version,
        query_contract.result_schema_version,
        query_contract.fixture_path,
    );
    packages.insert(
        1,
        json!({
            "SPDXID":query_package_id,
            "name":BOUNDED_QUERY_SBOM_PACKAGE_NAME,
            "versionInfo":query_contract.release_smoke_contract_version,
            "filesAnalyzed":false,
            "licenseConcluded":"NOASSERTION",
            "licenseDeclared":PROJECT_LICENSE_EXPRESSION,
            "downloadLocation":"NOASSERTION",
            "checksums":[{
                "algorithm":"SHA256",
                "checksumValue":query_fixture_sha256
            }],
            "comment":query_contract_comment
        }),
    );
    let cross_language_contract = depgraph_core::cross_language_release_compatibility_contract();
    let cross_language_package_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(CROSS_LANGUAGE_SBOM_PACKAGE_NAME)
    );
    packages.insert(
        1,
        json!({
            "SPDXID":cross_language_package_id,
            "name":CROSS_LANGUAGE_SBOM_PACKAGE_NAME,
            "versionInfo":cross_language_contract.release_smoke_contract_version,
            "filesAnalyzed":false,
            "licenseConcluded":"NOASSERTION",
            "licenseDeclared":PROJECT_LICENSE_EXPRESSION,
            "downloadLocation":"NOASSERTION",
            "checksums":[{
                "algorithm":"SHA256",
                "checksumValue":cross_language_contract_sha256(&cross_language_contract)
            }],
            "comment":format!(
                "First-party cross-language contract: {}; completeness {}; capabilities {}; schemas {}; fixture {}",
                cross_language_contract.contract_version,
                cross_language_contract.completeness_version,
                cross_language_contract.capabilities.len(),
                cross_language_contract.schemas.len(),
                cross_language_contract.fixture_path,
            )
        }),
    );
    let rust_sysroot_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(RUST_SYSROOT_SBOM_PACKAGE_NAME)
    );
    packages.insert(
        1,
        json!({
            "SPDXID":rust_sysroot_id,
            "name":RUST_SYSROOT_SBOM_PACKAGE_NAME,
            "versionInfo":RUST_SYSROOT_COMPONENT_VERSION,
            "filesAnalyzed":false,
            "licenseConcluded":"NOASSERTION",
            "licenseDeclared":RUST_SYSROOT_LICENSE_EXPRESSION,
            "downloadLocation":"NOASSERTION",
            "checksums":[{
                "algorithm":"SHA256",
                "checksumValue":rust_sysroot_sha256
            }],
            "comment":format!(
                "Pinned rust-src data tree: contract {}; rustc {} ({}); layout {}; root {}",
                RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION,
                RUST_SYSROOT_TOOLCHAIN_VERSION,
                RUST_SYSROOT_TOOLCHAIN_COMMIT,
                RUST_SYSROOT_SOURCE_LAYOUT,
                RUST_SYSROOT_COMPONENT_ROOT
            )
        }),
    );
    let first_party_ids = first_party
        .iter()
        .map(|artifact| {
            (
                format!("SPDXRef-Package-{}", spdx_component(&artifact.name)),
                artifact,
            )
        })
        .collect::<Vec<_>>();
    for (index, (id, artifact)) in first_party_ids.iter().enumerate() {
        packages.insert(
            index + 1,
            json!({
                "SPDXID":id,
                "name":artifact.name,
                "versionInfo":artifact.version,
                "filesAnalyzed":false,
                "licenseConcluded":"NOASSERTION",
                "licenseDeclared":artifact.license,
                "downloadLocation":"NOASSERTION",
                "checksums":[{
                    "algorithm":"SHA256",
                    "checksumValue":artifact.sha256
                }],
                "comment":format!("First-party release artifact: libexec/{}", artifact.path)
            }),
        );
    }
    let mut relationships = vec![
        json!({
            "spdxElementId":"SPDXRef-DOCUMENT",
            "relationshipType":"DESCRIBES",
            "relatedSpdxElement":"SPDXRef-Package-depgraph"
        }),
        json!({
            "spdxElementId":"SPDXRef-Package-depgraph",
            "relationshipType":"CONTAINS",
            "relatedSpdxElement":rust_sysroot_id
        }),
        json!({
            "spdxElementId":"SPDXRef-Package-depgraph",
            "relationshipType":"CONTAINS",
            "relatedSpdxElement":query_package_id
        }),
        json!({
            "spdxElementId":"SPDXRef-Package-depgraph",
            "relationshipType":"CONTAINS",
            "relatedSpdxElement":cross_language_package_id
        }),
    ];
    relationships.extend(first_party_ids.into_iter().map(|(id, _)| {
        json!({
            "spdxElementId":"SPDXRef-Package-depgraph",
            "relationshipType":"CONTAINS",
            "relatedSpdxElement":id
        })
    }));
    relationships.extend(dependency_ids.into_iter().map(|id| {
        json!({
            "spdxElementId":"SPDXRef-Package-depgraph",
            "relationshipType":"DEPENDS_ON",
            "relatedSpdxElement":id
        })
    }));
    Ok(json!({
        "spdxVersion":"SPDX-2.3",
        "dataLicense":"CC0-1.0",
        "SPDXID":"SPDXRef-DOCUMENT",
        "name":format!("depgraph-{VERSION}-{target}"),
        "documentNamespace":format!("https://github.com/TamaT-LLC/depgraph-cli/releases/{VERSION}/{target}"),
        "creationInfo":{"creators":["Tool: depgraph-xtask"],"created":"1970-01-01T00:00:00Z"},
        "packages":packages,
        "relationships":relationships
    }))
}

fn verify_runtime_collector_sbom(sbom: &Value, expected_sha256: &str, context: &str) -> Result<()> {
    let packages = sbom["packages"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no packages"))?;
    let collectors = packages
        .iter()
        .filter(|package| package["name"] == "depgraph-runtime-collector")
        .collect::<Vec<_>>();
    if collectors.len() != 1 {
        bail!("{context} SBOM must contain exactly one runtime collector package");
    }
    let collector = collectors[0];
    if collector["SPDXID"] != "SPDXRef-Package-depgraph-runtime-collector"
        || collector["versionInfo"] != RUNTIME_COLLECTOR_CONTRACT_VERSION
        || collector["filesAnalyzed"] != Value::Bool(false)
        || collector["licenseDeclared"] != PROJECT_LICENSE_EXPRESSION
        || collector["checksums"]
            != json!([{
                "algorithm": "SHA256",
                "checksumValue": expected_sha256,
            }])
        || collector["comment"]
            != format!("First-party release artifact: libexec/{RUNTIME_COLLECTOR_ARTIFACT}")
    {
        bail!("{context} SBOM runtime collector package is incompatible");
    }
    let relationships = sbom["relationships"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no relationships"))?;
    let contains = relationships
        .iter()
        .filter(|relationship| {
            relationship["spdxElementId"] == "SPDXRef-Package-depgraph"
                && relationship["relationshipType"] == "CONTAINS"
                && relationship["relatedSpdxElement"]
                    == "SPDXRef-Package-depgraph-runtime-collector"
        })
        .count();
    if contains != 1 {
        bail!("{context} SBOM does not contain the runtime collector from the root package");
    }
    Ok(())
}

fn verify_rust_sysroot_sbom(sbom: &Value, expected_sha256: &str, context: &str) -> Result<()> {
    let packages = sbom["packages"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no packages"))?;
    let matches = packages
        .iter()
        .filter(|package| package["name"] == RUST_SYSROOT_SBOM_PACKAGE_NAME)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("{context} SBOM must contain exactly one pinned Rust sysroot source package");
    }
    let package = matches[0];
    let expected_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(RUST_SYSROOT_SBOM_PACKAGE_NAME)
    );
    let expected_comment = format!(
        "Pinned rust-src data tree: contract {}; rustc {} ({}); layout {}; root {}",
        RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION,
        RUST_SYSROOT_TOOLCHAIN_VERSION,
        RUST_SYSROOT_TOOLCHAIN_COMMIT,
        RUST_SYSROOT_SOURCE_LAYOUT,
        RUST_SYSROOT_COMPONENT_ROOT
    );
    if package["SPDXID"] != expected_id
        || package["versionInfo"] != RUST_SYSROOT_COMPONENT_VERSION
        || package["licenseDeclared"] != RUST_SYSROOT_LICENSE_EXPRESSION
        || package["filesAnalyzed"] != false
        || package["checksums"]
            != json!([{
                "algorithm": "SHA256",
                "checksumValue": expected_sha256,
            }])
        || package["comment"] != expected_comment
    {
        bail!("{context} SBOM Rust sysroot source package does not match the pinned data-tree");
    }
    let contains = sbom["relationships"]
        .as_array()
        .map(|relationships| {
            relationships
                .iter()
                .filter(|relationship| {
                    relationship["spdxElementId"] == "SPDXRef-Package-depgraph"
                        && relationship["relationshipType"] == "CONTAINS"
                        && relationship["relatedSpdxElement"] == expected_id
                })
                .count()
        })
        .unwrap_or_default();
    if contains != 1 {
        bail!("{context} SBOM does not relate the Rust sysroot source to the release package");
    }
    Ok(())
}

fn verify_bounded_query_sbom(sbom: &Value, context: &str) -> Result<()> {
    let contract = depgraph_core::bounded_query_release_compatibility_contract();
    let packages = sbom["packages"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no packages"))?;
    let matches = packages
        .iter()
        .filter(|package| package["name"] == BOUNDED_QUERY_SBOM_PACKAGE_NAME)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("{context} SBOM must contain exactly one bounded query contract package");
    }
    let expected_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(BOUNDED_QUERY_SBOM_PACKAGE_NAME)
    );
    let expected_comment = format!(
        "First-party bounded query contract: language {}; types {}; statistics {}; plan {}; limits {}; result {}; fixture {}",
        contract.language_contract_version,
        contract.type_contract_version,
        contract.statistics_version,
        contract.plan_schema_version,
        contract.limit_version,
        contract.result_schema_version,
        contract.fixture_path,
    );
    if matches[0]["SPDXID"] != expected_id
        || matches[0]["versionInfo"] != contract.release_smoke_contract_version
        || matches[0]["filesAnalyzed"] != Value::Bool(false)
        || matches[0]["licenseDeclared"] != PROJECT_LICENSE_EXPRESSION
        || matches[0]["checksums"]
            != json!([{
                "algorithm": "SHA256",
                "checksumValue": contract
                    .fixture_sha256
                    .strip_prefix("sha256:")
                    .context("bounded query fixture digest is not prefixed")?,
            }])
        || matches[0]["comment"] != expected_comment
    {
        bail!("{context} SBOM bounded query contract package is incompatible");
    }
    let contains = sbom["relationships"]
        .as_array()
        .map(|relationships| {
            relationships
                .iter()
                .filter(|relationship| {
                    relationship["spdxElementId"] == "SPDXRef-Package-depgraph"
                        && relationship["relationshipType"] == "CONTAINS"
                        && relationship["relatedSpdxElement"] == expected_id
                })
                .count()
        })
        .unwrap_or_default();
    if contains != 1 {
        bail!("{context} SBOM does not contain the bounded query contract from the root package");
    }
    Ok(())
}

fn verify_cross_language_sbom(
    sbom: &Value,
    contract: &depgraph_core::CrossLanguageReleaseCompatibilityHealth,
    context: &str,
) -> Result<()> {
    let packages = sbom["packages"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no packages"))?;
    let matches = packages
        .iter()
        .filter(|package| package["name"] == CROSS_LANGUAGE_SBOM_PACKAGE_NAME)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("{context} SBOM must contain exactly one cross-language contract package");
    }
    let expected_id = format!(
        "SPDXRef-Package-{}",
        spdx_component(CROSS_LANGUAGE_SBOM_PACKAGE_NAME)
    );
    let expected_comment = format!(
        "First-party cross-language contract: {}; completeness {}; capabilities {}; schemas {}; fixture {}",
        contract.contract_version,
        contract.completeness_version,
        contract.capabilities.len(),
        contract.schemas.len(),
        contract.fixture_path,
    );
    if matches[0]["SPDXID"] != expected_id
        || matches[0]["versionInfo"] != contract.release_smoke_contract_version
        || matches[0]["filesAnalyzed"] != Value::Bool(false)
        || matches[0]["licenseDeclared"] != PROJECT_LICENSE_EXPRESSION
        || matches[0]["checksums"]
            != json!([{
                "algorithm": "SHA256",
                "checksumValue": cross_language_contract_sha256(contract),
            }])
        || matches[0]["comment"] != expected_comment
    {
        bail!("{context} SBOM cross-language contract package is incompatible");
    }
    let contains = sbom["relationships"]
        .as_array()
        .map(|relationships| {
            relationships
                .iter()
                .filter(|relationship| {
                    relationship["spdxElementId"] == "SPDXRef-Package-depgraph"
                        && relationship["relationshipType"] == "CONTAINS"
                        && relationship["relatedSpdxElement"] == expected_id
                })
                .count()
        })
        .unwrap_or_default();
    if contains != 1 {
        bail!("{context} SBOM does not contain the cross-language contract from the root package");
    }
    Ok(())
}

fn verify_framework_build_sbom(
    sbom: &Value,
    expected_artifacts: &BTreeMap<String, String>,
    context: &str,
) -> Result<()> {
    let mut expected = depgraph_core::framework_build_capability_contract()
        .into_iter()
        .map(|capability| {
            (
                capability.observer_runtime_artifact,
                (
                    format!("depgraph-{}-build-observer", capability.framework),
                    capability.observer_version,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    expected.insert(
        depgraph_core::FRAMEWORK_BUILD_CONVERTER_ARTIFACT.to_owned(),
        (
            "depgraph-web-build-evidence".to_owned(),
            depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
        ),
    );
    if expected_artifacts.keys().collect::<BTreeSet<_>>()
        != expected.keys().collect::<BTreeSet<_>>()
    {
        bail!("{context} framework build artifact checksum ledger is incomplete or unknown");
    }
    let packages = sbom["packages"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no packages"))?;
    let relationships = sbom["relationships"]
        .as_array()
        .with_context(|| format!("{context} SBOM has no relationships"))?;
    for (path, (name, version)) in expected {
        let matches = packages
            .iter()
            .filter(|package| package["name"] == name)
            .collect::<Vec<_>>();
        let sha256 = expected_artifacts
            .get(&path)
            .with_context(|| format!("{context} has no checksum for {path}"))?;
        let id = format!("SPDXRef-Package-{}", spdx_component(&name));
        if matches.len() != 1
            || matches[0]["SPDXID"] != id
            || matches[0]["versionInfo"] != version
            || matches[0]["filesAnalyzed"] != Value::Bool(false)
            || matches[0]["licenseDeclared"] != PROJECT_LICENSE_EXPRESSION
            || matches[0]["checksums"]
                != json!([{
                    "algorithm": "SHA256",
                    "checksumValue": sha256,
                }])
            || matches[0]["comment"] != format!("First-party release artifact: {path}")
        {
            bail!("{context} SBOM framework build artifact {path} is incompatible");
        }
        let contains = relationships
            .iter()
            .filter(|relationship| {
                relationship["spdxElementId"] == "SPDXRef-Package-depgraph"
                    && relationship["relationshipType"] == "CONTAINS"
                    && relationship["relatedSpdxElement"] == id
            })
            .count();
        if contains != 1 {
            bail!("{context} SBOM does not contain framework build artifact {path}");
        }
    }
    Ok(())
}

fn manifest_framework_build_artifact_checksums(
    manifest: &ReleaseManifest,
) -> Result<BTreeMap<String, String>> {
    let mut required = depgraph_core::framework_build_capability_contract()
        .into_iter()
        .map(|capability| capability.observer_runtime_artifact)
        .collect::<BTreeSet<_>>();
    required.insert(depgraph_core::FRAMEWORK_BUILD_CONVERTER_ARTIFACT.to_owned());
    let artifacts = manifest
        .runtime_artifacts
        .iter()
        .filter(|artifact| required.contains(&artifact.path))
        .map(|artifact| (artifact.path.clone(), artifact.sha256.clone()))
        .collect::<BTreeMap<_, _>>();
    if artifacts.keys().collect::<BTreeSet<_>>() != required.iter().collect::<BTreeSet<_>>() {
        bail!("release manifest framework build runtime artifact closure is incomplete");
    }
    Ok(artifacts)
}

fn normalized_spdx_license(reported: &str) -> Option<String> {
    let reported = reported.trim();
    if reported.is_empty() || reported == "license metadata unavailable" {
        return None;
    }
    let normalized = reported
        .replace("MIT / Apache-2.0", "MIT OR Apache-2.0")
        .replace("Apache-2.0 / MIT", "Apache-2.0 OR MIT")
        .replace("MIT/Apache-2.0", "MIT OR Apache-2.0")
        .replace("Apache-2.0/MIT", "Apache-2.0 OR MIT")
        .replace("Unlicense/MIT", "Unlicense OR MIT");
    spdx::Expression::parse(&normalized).ok()?;
    Some(normalized)
}

fn package_url(package: &DependencyPackage) -> String {
    let name = if package.ecosystem == "npm" {
        package
            .name
            .strip_prefix('@')
            .and_then(|name| name.split_once('/'))
            .map(|(scope, name)| {
                format!(
                    "{}/{}",
                    purl_encode_segment(&format!("@{scope}")),
                    purl_encode_segment(name)
                )
            })
            .unwrap_or_else(|| purl_encode_segment(&package.name))
    } else if package.ecosystem == "golang" {
        package
            .name
            .split('/')
            .map(purl_encode_segment)
            .collect::<Vec<_>>()
            .join("/")
    } else {
        purl_encode_segment(&package.name)
    };
    format!(
        "pkg:{}/{}@{}",
        package.ecosystem,
        name,
        purl_encode_segment(&package.version)
    )
}

fn purl_encode_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn dependency_inventory(target: &str) -> Result<Vec<DependencyPackage>> {
    let cargo = cargo_metadata(&[
        "--filter-platform",
        target,
        "--features",
        "depgraph-cli/packaged",
    ])?;
    verify_rust_analyzer_dependencies(&cargo)?;
    verify_mcp_dependencies(&cargo)?;
    let mut packages = cargo_runtime_packages(&cargo)?;

    let go_output = Command::new("go")
        .args([
            "list",
            "-mod=readonly",
            "-deps",
            "-f",
            "{{with .Module}}{{if .Version}}{{.Path}}\t{{.Version}}{{end}}{{end}}",
            "./cmd/depgraph-go-worker",
        ])
        .env("GOTOOLCHAIN", "local")
        .env("GOPROXY", "off")
        .current_dir("workers/go")
        .output()?;
    if !go_output.status.success() {
        bail!(
            "go module inventory failed: {}",
            String::from_utf8_lossy(&go_output.stderr)
        );
    }
    for line in String::from_utf8(go_output.stdout)?.lines() {
        let (name, version) = line.split_once('\t').unwrap_or((line, "workspace"));
        if version.is_empty() || version == "workspace" {
            continue;
        }
        packages.push(DependencyPackage {
            ecosystem: "golang".to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            license: "license metadata unavailable".to_owned(),
        });
    }

    let web_inventory: Value = serde_json::from_slice(
        &fs::read("workers/web/dist/runtime-packages.json")
            .context("Web runtime package inventory is missing; run the Web worker build first")?,
    )?;
    runtime_collector_inventory(&web_inventory)?;
    packages.extend(web_runtime_packages(&web_inventory)?);
    packages.sort_by(|left, right| {
        (&left.ecosystem, &left.name, &left.version).cmp(&(
            &right.ecosystem,
            &right.name,
            &right.version,
        ))
    });
    packages.dedup_by(|left, right| {
        left.ecosystem == right.ecosystem
            && left.name == right.name
            && left.version == right.version
    });
    Ok(packages)
}

fn cargo_metadata(arguments: &[&str]) -> Result<Value> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .args(arguments)
        .output()
        .context("failed to start cargo metadata")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("cargo metadata returned invalid JSON")
}

fn verify_rust_analyzer_dependencies(metadata: &Value) -> Result<()> {
    let pin = &metadata["metadata"]["depgraph"]["rust-analyzer"];
    let crate_version = pin["crate-version"]
        .as_str()
        .context("workspace rust-analyzer crate version is missing")?;
    let revision = pin["revision"]
        .as_str()
        .context("workspace rust-analyzer revision is missing")?;
    let salsa_version = pin["salsa-version"]
        .as_str()
        .context("workspace Salsa version is missing")?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("workspace rust-analyzer revision must be a lowercase 40-character Git SHA");
    }
    if crate_version != RUST_ANALYZER_CRATE_VERSION
        || revision != RUST_ANALYZER_REVISION
        || salsa_version != SALSA_VERSION
    {
        bail!(
            "workspace rust-analyzer pin must be crate {}, revision {}, Salsa {}",
            RUST_ANALYZER_CRATE_VERSION,
            RUST_ANALYZER_REVISION,
            SALSA_VERSION
        );
    }

    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no package inventory")?;
    let workers = packages
        .iter()
        .filter(|package| package["name"] == "depgraph-rust-worker" && package["source"].is_null())
        .collect::<Vec<_>>();
    if workers.len() != 1 {
        bail!(
            "cargo metadata must contain exactly one local depgraph-rust-worker package, found {}",
            workers.len()
        );
    }
    let direct_dependencies = workers[0]["dependencies"]
        .as_array()
        .context("depgraph-rust-worker has no dependency inventory")?;
    let expected_direct_dependencies = RUST_ANALYZER_DIRECT_DEPENDENCIES
        .iter()
        .chain(SALSA_DIRECT_DEPENDENCIES)
        .copied()
        .collect::<BTreeSet<_>>();
    let actual_direct_dependencies = direct_dependencies
        .iter()
        .filter_map(|dependency| dependency["name"].as_str())
        .filter(|name| {
            name.starts_with("ra_ap_")
                || name.starts_with("ra-ap-")
                || *name == "salsa"
                || name.starts_with("salsa-")
        })
        .collect::<BTreeSet<_>>();
    if actual_direct_dependencies != expected_direct_dependencies {
        bail!(
            "depgraph-rust-worker direct rust-analyzer/Salsa dependency set must be exactly {expected_direct_dependencies:?}, found {actual_direct_dependencies:?}"
        );
    }
    for (name, version) in RUST_ANALYZER_DIRECT_DEPENDENCIES
        .iter()
        .map(|name| (*name, RUST_ANALYZER_CRATE_VERSION))
        .chain(
            SALSA_DIRECT_DEPENDENCIES
                .iter()
                .map(|name| (*name, SALSA_VERSION)),
        )
    {
        let matches = direct_dependencies
            .iter()
            .filter(|dependency| dependency["name"] == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!(
                "depgraph-rust-worker must declare exactly one direct {name} dependency, found {}",
                matches.len()
            );
        }
        let dependency = matches[0];
        if dependency["req"] != format!("={version}")
            || !dependency["kind"].is_null()
            || !dependency["rename"].is_null()
            || dependency["optional"] != Value::Bool(false)
            || dependency["uses_default_features"] != Value::Bool(true)
            || !dependency["features"].as_array().is_some_and(Vec::is_empty)
            || !dependency["target"].is_null()
            || !dependency["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("registry+"))
        {
            bail!(
                "depgraph-rust-worker dependency {name} must be an unconditional normal registry dependency pinned to ={version}"
            );
        }
    }

    let resolved_ra = packages
        .iter()
        .filter(|package| {
            package["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("ra_ap_"))
        })
        .collect::<Vec<_>>();
    if resolved_ra.is_empty() {
        bail!("cargo metadata resolved no ra_ap_* packages");
    }
    for package in resolved_ra {
        let name = package["name"].as_str().unwrap_or("<unknown>");
        if package["version"] != RUST_ANALYZER_CRATE_VERSION
            || !package["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("registry+"))
        {
            bail!(
                "resolved rust-analyzer package {name} must be registry version {RUST_ANALYZER_CRATE_VERSION}"
            );
        }
    }
    for name in SALSA_DIRECT_DEPENDENCIES {
        let matches = packages
            .iter()
            .filter(|package| package["name"] == *name)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || matches[0]["version"] != SALSA_VERSION
            || !matches[0]["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("registry+"))
        {
            bail!("resolved package {name} must be registry version {SALSA_VERSION}");
        }
    }
    for forbidden in FORBIDDEN_RUST_ANALYZER_DEPENDENCIES {
        if packages.iter().any(|package| package["name"] == *forbidden) {
            bail!("forbidden rust-analyzer project-loading package resolved: {forbidden}");
        }
    }
    Ok(())
}

fn verify_mcp_dependencies(metadata: &Value) -> Result<()> {
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no package inventory")?;
    let mcp_servers = packages
        .iter()
        .filter(|package| package["name"] == "depgraph-mcp" && package["source"].is_null())
        .collect::<Vec<_>>();
    if mcp_servers.len() != 1 {
        bail!(
            "cargo metadata must contain exactly one local depgraph-mcp package, found {}",
            mcp_servers.len()
        );
    }
    let direct_dependencies = mcp_servers[0]["dependencies"]
        .as_array()
        .context("depgraph-mcp has no dependency inventory")?;
    let actual_direct_dependencies = direct_dependencies
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .filter_map(|dependency| dependency["name"].as_str())
        .collect::<BTreeSet<_>>();
    let expected_direct_dependencies = MCP_SERVER_DIRECT_DEPENDENCIES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if actual_direct_dependencies != expected_direct_dependencies {
        bail!(
            "depgraph-mcp direct dependency set must be exactly {expected_direct_dependencies:?}, found {actual_direct_dependencies:?}"
        );
    }
    let rmcp_dependency = direct_dependencies
        .iter()
        .filter(|dependency| dependency["name"] == MCP_SDK_NAME)
        .collect::<Vec<_>>();
    if rmcp_dependency.len() != 1 {
        bail!(
            "depgraph-mcp must declare exactly one direct {MCP_SDK_NAME} dependency, found {}",
            rmcp_dependency.len()
        );
    }
    let rmcp_dependency = rmcp_dependency[0];
    let features = rmcp_dependency["features"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if rmcp_dependency["req"] != format!("={MCP_SDK_VERSION}")
        || !rmcp_dependency["kind"].is_null()
        || !rmcp_dependency["rename"].is_null()
        || rmcp_dependency["optional"] != Value::Bool(false)
        || rmcp_dependency["uses_default_features"] != Value::Bool(false)
        || features != BTreeSet::from(["macros", "server", "transport-io"])
        || !rmcp_dependency["target"].is_null()
        || !rmcp_dependency["source"]
            .as_str()
            .is_some_and(|source| source.starts_with("registry+"))
    {
        bail!(
            "depgraph-mcp must pin {MCP_SDK_NAME} ={MCP_SDK_VERSION} with exactly macros, server, and transport-io"
        );
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
            || matches[0]["version"] != version
            || matches[0]["license"] != "Apache-2.0"
            || !matches[0]["source"]
                .as_str()
                .is_some_and(|source| source.starts_with("registry+"))
        {
            bail!("resolved {name} package must be registry version {version} licensed Apache-2.0");
        }
    }

    let rmcp_id = packages
        .iter()
        .find(|package| package["name"] == MCP_SDK_NAME)
        .and_then(|package| package["id"].as_str())
        .context("resolved rmcp package has no ID")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata has no resolved dependency graph")?;
    let rmcp_node = nodes
        .iter()
        .find(|node| node["id"] == rmcp_id)
        .context("cargo metadata resolve graph has no rmcp node")?;
    let resolved_features = rmcp_node["features"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if !["macros", "server", "transport-io"]
        .iter()
        .all(|feature| resolved_features.contains(feature))
    {
        bail!("resolved rmcp feature set omits the packaged MCP compatibility features");
    }
    let packages_by_id = packages
        .iter()
        .filter_map(|package| Some((package["id"].as_str()?, package["name"].as_str()?)))
        .collect::<BTreeMap<_, _>>();
    if !rmcp_node["deps"].as_array().is_some_and(|dependencies| {
        dependencies.iter().any(|dependency| {
            dependency["pkg"]
                .as_str()
                .and_then(|id| packages_by_id.get(id))
                .is_some_and(|name| *name == "rmcp-macros")
        })
    }) {
        bail!("resolved rmcp runtime closure is missing rmcp-macros");
    }
    Ok(())
}

fn cargo_runtime_packages(metadata: &Value) -> Result<Vec<DependencyPackage>> {
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no package inventory")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata has no resolved dependency graph")?;
    let packages_by_id = packages
        .iter()
        .filter_map(|package| Some((package["id"].as_str()?.to_owned(), package)))
        .collect::<BTreeMap<_, _>>();
    let nodes_by_id = nodes
        .iter()
        .filter_map(|node| Some((node["id"].as_str()?.to_owned(), node)))
        .collect::<BTreeMap<_, _>>();

    // Every Rust executable shipped in the release archive must be a root so
    // its runtime-only dependencies are represented in licenses and the SBOM.
    let root_names = [
        "depgraph-cli",
        "depgraph-rust-worker",
        "depgraph-mcp",
        "depgraph-operation",
    ];
    let mut pending = VecDeque::new();
    for root_name in root_names {
        let roots = packages
            .iter()
            .filter(|package| package["name"] == root_name && package["source"].is_null())
            .filter_map(|package| package["id"].as_str())
            .collect::<Vec<_>>();
        if roots.len() != 1 {
            bail!(
                "cargo metadata must contain exactly one local {root_name} package, found {}",
                roots.len()
            );
        }
        pending.push_back(roots[0].to_owned());
    }

    let mut reachable = BTreeSet::new();
    while let Some(id) = pending.pop_front() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let node = nodes_by_id
            .get(&id)
            .with_context(|| format!("cargo metadata resolve graph is missing {id}"))?;
        for dependency in node["deps"].as_array().into_iter().flatten() {
            let kinds = dependency["dep_kinds"].as_array();
            let included = kinds.is_none_or(|kinds| {
                kinds.is_empty() || kinds.iter().any(|kind| kind["kind"].is_null())
            });
            if included {
                let dependency_id = dependency["pkg"]
                    .as_str()
                    .context("cargo metadata dependency has no package ID")?;
                pending.push_back(dependency_id.to_owned());
            }
        }
    }

    reachable
        .into_iter()
        .filter_map(|id| {
            let package = packages_by_id.get(&id)?;
            if package["source"].is_null() {
                return None;
            }
            Some(Ok(DependencyPackage {
                ecosystem: "cargo".to_owned(),
                name: package["name"].as_str().unwrap_or_default().to_owned(),
                version: package["version"].as_str().unwrap_or_default().to_owned(),
                license: package["license"]
                    .as_str()
                    .unwrap_or("license metadata unavailable")
                    .to_owned(),
            }))
        })
        .collect()
}

fn web_runtime_packages(inventory: &Value) -> Result<Vec<DependencyPackage>> {
    if inventory["schema_version"] != 1 {
        bail!("Web runtime package inventory has an unsupported schema version");
    }
    inventory["packages"]
        .as_array()
        .context("Web runtime package inventory has no packages")?
        .iter()
        .map(|package| {
            let name = package["name"]
                .as_str()
                .filter(|name| !name.is_empty())
                .context("Web runtime package has no name")?;
            let version = package["version"]
                .as_str()
                .filter(|version| !version.is_empty())
                .context("Web runtime package has no version")?;
            let _roles = package["roles"]
                .as_array()
                .filter(|roles| {
                    !roles.is_empty() && roles.iter().all(|role| role.as_str().is_some())
                })
                .context("Web runtime package has no valid artifact role")?;
            Ok(DependencyPackage {
                ecosystem: "npm".to_owned(),
                name: name.to_owned(),
                version: version.to_owned(),
                license: package["license"]
                    .as_str()
                    .unwrap_or("license metadata unavailable")
                    .to_owned(),
            })
        })
        .collect()
}

fn first_party_artifact_inventory(inventory: &Value) -> Result<Vec<FirstPartyArtifactInventory>> {
    if inventory["schema_version"] != 1 {
        bail!("Web runtime package inventory has an unsupported schema version");
    }
    let artifacts = inventory["artifacts"]
        .as_array()
        .context("Web runtime package inventory has no first-party artifacts")?;
    if artifacts.len() != 6 {
        bail!(
            "Web runtime package inventory must contain the runtime collector, four framework observers, and their converter"
        );
    }
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut parsed = Vec::new();
    for artifact in artifacts {
        let object = artifact
            .as_object()
            .context("Web first-party artifact is not an object")?;
        let field = |name: &str| {
            object
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .with_context(|| format!("Web first-party artifact has no {name}"))
        };
        let optional = |name: &str| {
            object
                .get(name)
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .with_context(|| format!("Web first-party artifact has an invalid {name}"))
                })
                .transpose()
        };
        let artifact = FirstPartyArtifactInventory {
            name: field("name")?.to_owned(),
            version: field("version")?.to_owned(),
            license: field("license")?.to_owned(),
            path: field("path")?.to_owned(),
            sha256: field("sha256")?.to_owned(),
            roles: object
                .get("roles")
                .and_then(Value::as_array)
                .context("Web first-party artifact has no roles")?
                .iter()
                .map(|role| {
                    role.as_str()
                        .filter(|role| !role.is_empty())
                        .map(str::to_owned)
                        .context("Web first-party artifact has an invalid role")
                })
                .collect::<Result<Vec<_>>>()?,
            bundled_packages: object
                .get("bundled_packages")
                .and_then(Value::as_array)
                .context("Web first-party artifact has no bundled package ledger")?
                .iter()
                .map(|package| {
                    package
                        .as_str()
                        .filter(|package| !package.is_empty())
                        .map(str::to_owned)
                        .context("Web first-party artifact has an invalid bundled package")
                })
                .collect::<Result<Vec<_>>>()?,
            framework: optional("framework")?,
            capability: optional("capability")?,
            observation_schema: optional("observation_schema")?,
        };
        let expected_fields = if artifact.framework.is_some() {
            BTreeSet::from([
                "bundled_packages",
                "capability",
                "framework",
                "license",
                "name",
                "observation_schema",
                "path",
                "roles",
                "sha256",
                "version",
            ])
        } else {
            BTreeSet::from([
                "bundled_packages",
                "license",
                "name",
                "path",
                "roles",
                "sha256",
                "version",
            ])
        };
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_fields
            || artifact.license != PROJECT_LICENSE_EXPRESSION
            || artifact.sha256.len() != 64
            || !artifact
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !artifact.bundled_packages.is_empty()
            || !names.insert(artifact.name.clone())
            || !paths.insert(artifact.path.clone())
        {
            bail!("Web first-party artifact inventory is malformed or duplicated");
        }
        let path = Path::new("workers/web/dist").join(&artifact.path);
        if !path.is_file() || sha256_file(&path)? != artifact.sha256 {
            bail!(
                "Web first-party artifact inventory checksum does not match {}",
                artifact.path
            );
        }
        parsed.push(artifact);
    }
    Ok(parsed)
}

fn framework_build_artifact_inventory(
    inventory: &Value,
) -> Result<Vec<FirstPartyArtifactInventory>> {
    let artifacts = first_party_artifact_inventory(inventory)?;
    let converter_path = depgraph_core::FRAMEWORK_BUILD_CONVERTER_ARTIFACT
        .strip_prefix("libexec/")
        .context("framework build converter path is not release-relative")?;
    let converter = artifacts
        .iter()
        .find(|artifact| artifact.path == converter_path)
        .context("Web first-party inventory has no framework build converter")?;
    if converter.name != "depgraph-web-build-evidence"
        || converter.version != depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION
        || converter.roles != ["framework-build-converter"]
        || converter.framework.is_some()
        || converter.capability.is_some()
        || converter.observation_schema.is_some()
    {
        bail!("framework build converter inventory is incompatible");
    }
    let mut result = Vec::new();
    for capability in depgraph_core::framework_build_capability_contract() {
        let observer_path = capability
            .observer_runtime_artifact
            .strip_prefix("libexec/")
            .context("framework build observer path is not release-relative")?;
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.path == observer_path)
            .with_context(|| {
                format!(
                    "Web first-party inventory has no {} observer",
                    capability.framework
                )
            })?;
        if artifact.name != format!("depgraph-{}-build-observer", capability.framework)
            || artifact.version != capability.observer_version
            || artifact.roles != ["framework-build-observer"]
            || artifact.framework.as_deref() != Some(capability.framework.as_str())
            || artifact.capability.as_deref() != Some(capability.capability.as_str())
            || artifact.observation_schema.as_deref()
                != Some(capability.observation_schema.as_str())
        {
            bail!(
                "{} framework build observer inventory is incompatible",
                capability.framework
            );
        }
        result.push(artifact.clone());
    }
    result.push(converter.clone());
    if artifacts
        .iter()
        .filter(|artifact| {
            artifact.roles == ["framework-build-observer"]
                || artifact.roles == ["framework-build-converter"]
        })
        .count()
        != result.len()
    {
        bail!("Web first-party inventory contains an unknown framework build artifact");
    }
    Ok(result)
}

fn framework_build_artifact_checksums(inventory: &Value) -> Result<BTreeMap<String, String>> {
    framework_build_artifact_inventory(inventory)?
        .into_iter()
        .map(|artifact| Ok((format!("libexec/{}", artifact.path), artifact.sha256)))
        .collect()
}

fn runtime_collector_inventory(inventory: &Value) -> Result<RuntimeCollectorInventory> {
    let artifacts = first_party_artifact_inventory(inventory)?;
    framework_build_artifact_inventory(inventory)?;
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.name == "depgraph-runtime-collector")
        .context("Web runtime package inventory has no runtime collector")?;
    let collector = RuntimeCollectorInventory {
        name: artifact.name.clone(),
        version: artifact.version.clone(),
        license: artifact.license.clone(),
        path: artifact.path.clone(),
        sha256: artifact.sha256.clone(),
    };
    if collector.name != "depgraph-runtime-collector"
        || collector.version != RUNTIME_COLLECTOR_CONTRACT_VERSION
        || collector.license != PROJECT_LICENSE_EXPRESSION
        || collector.path != RUNTIME_COLLECTOR_ARTIFACT
        || collector.sha256.len() != 64
        || !collector
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || artifact.roles != ["reference-runtime-collector"]
        || !artifact.bundled_packages.is_empty()
        || artifact.framework.is_some()
        || artifact.capability.is_some()
        || artifact.observation_schema.is_some()
    {
        bail!("runtime collector inventory does not match the release compatibility unit");
    }
    let path = Path::new("workers/web/dist").join(&collector.path);
    if !path.is_file() || sha256_file(&path)? != collector.sha256 {
        bail!("runtime collector inventory checksum does not match the built artifact");
    }
    Ok(collector)
}

fn web_legal_documents() -> Result<Vec<(String, String)>> {
    let inventory: Value = serde_json::from_slice(
        &fs::read("workers/web/dist/runtime-packages.json")
            .context("Web runtime package inventory is missing; run the Web worker build first")?,
    )?;
    runtime_collector_inventory(&inventory)?;
    let packages = web_runtime_packages(&inventory)?;
    let package_by_name = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let astro = package_by_name
        .get("@astrojs/compiler")
        .copied()
        .context("Web runtime inventory is missing @astrojs/compiler")?;
    let typescript = package_by_name
        .get("typescript")
        .copied()
        .context("Web runtime inventory is missing typescript")?;
    let platform = packages
        .iter()
        .find(|package| package.name.starts_with("@typescript/typescript-"))
        .context("Web runtime inventory is missing its target TypeScript compiler")?;
    if package_by_name.len() != 3 {
        bail!(
            "Web runtime inventory must describe exactly Astro, TypeScript, and one target compiler"
        );
    }

    let astro_root = Path::new("workers/web/node_modules/@astrojs/compiler").canonicalize()?;
    let typescript_root = Path::new("workers/web/node_modules/typescript").canonicalize()?;
    let platform_component = platform
        .name
        .strip_prefix("@typescript/")
        .context("target TypeScript compiler has an invalid package name")?;
    let platform_root = typescript_root
        .parent()
        .context("TypeScript package has no node_modules parent")?
        .join("@typescript")
        .join(platform_component)
        .canonicalize()?;

    let sources = [
        (astro, astro_root, &["LICENSE"][..]),
        (typescript, typescript_root, &["LICENSE", "NOTICE.txt"][..]),
        (platform, platform_root, &["LICENSE", "NOTICE.txt"][..]),
    ];
    let mut documents = Vec::new();
    for (package, root, names) in sources {
        for name in names {
            let path = root
                .join(name)
                .canonicalize()
                .with_context(|| format!("missing legal document {} for {}", name, package.name))?;
            if !path.starts_with(&root) || !path.is_file() {
                bail!(
                    "legal document for {} escapes its installed package: {}",
                    package.name,
                    path.display()
                );
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("legal document {} is not UTF-8", path.display()))?;
            documents.push((
                format!("npm:{}@{}/{}", package.name, package.version, name),
                content,
            ));
        }
    }
    documents.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(documents)
}

fn legal_document_section(label: &str, content: &str) -> String {
    format!(
        "\n----- BEGIN {label} -----\n{}{}----- END {label} -----\n",
        content,
        if content.ends_with('\n') { "" } else { "\n" }
    )
}

fn spdx_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn create_archive(dist: &Path, name: &str) -> Result<PathBuf> {
    let source = dist.join(name);
    let entries = archive_entries(&source, name)?;
    #[cfg(windows)]
    {
        let archive = dist.join(format!("{name}.zip"));
        create_zip_archive(&archive, &entries)?;
        Ok(archive)
    }
    #[cfg(not(windows))]
    {
        let archive = dist.join(format!("{name}.tar.gz"));
        create_tar_archive(&archive, &entries)?;
        Ok(archive)
    }
}

fn archive_entries(source: &Path, name: &str) -> Result<Vec<ArchiveEntry>> {
    let mut root_components = Path::new(name).components();
    if !matches!(
        (root_components.next(), root_components.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) || name.contains(['/', '\\'])
    {
        bail!("invalid release archive root name {name:?}");
    }
    let mut entries = Vec::new();
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            bail!(
                "refusing symlink in release archive: {}",
                entry.path().display()
            );
        }
        if !file_type.is_dir() && !file_type.is_file() {
            bail!(
                "unsupported release archive entry: {}",
                entry.path().display()
            );
        }
        let relative = entry.path().strip_prefix(source)?;
        let mut path = name.to_owned();
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                bail!(
                    "invalid release archive path component in {}",
                    entry.path().display()
                );
            };
            let component = component.to_str().with_context(|| {
                format!(
                    "release archive path is not valid UTF-8: {}",
                    entry.path().display()
                )
            })?;
            if component.contains(['/', '\\']) {
                bail!(
                    "release archive path contains an unsafe separator: {}",
                    entry.path().display()
                );
            }
            path.push('/');
            path.push_str(component);
        }
        let mode = if file_type.is_dir() || is_executable(entry.path())? {
            0o755
        } else {
            0o644
        };
        entries.push(ArchiveEntry {
            source: entry.path().to_path_buf(),
            path,
            is_dir: file_type.is_dir(),
            mode,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries
        .first()
        .is_none_or(|entry| entry.path != name || !entry.is_dir)
    {
        bail!(
            "release archive source {} is not a directory",
            source.display()
        );
    }
    Ok(entries)
}

fn is_executable(path: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(fs::metadata(path)?.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        Ok(has_windows_executable_extension(path))
    }
}

#[cfg(any(not(unix), test))]
fn has_windows_executable_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        ["exe", "cmd", "bat"]
            .iter()
            .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    })
}

fn create_tar_archive(archive: &Path, entries: &[ArchiveEntry]) -> Result<()> {
    let output = fs::File::create(archive)?;
    let encoder = flate2::GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(output, flate2::Compression::best());
    let mut builder = tar::Builder::new(encoder);
    builder.follow_symlinks(false);
    builder.sparse(false);
    for entry in entries {
        let metadata = fs::metadata(&entry.source)?;
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(ARCHIVE_MTIME);
        header.set_mode(entry.mode);
        if entry.is_dir {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            builder.append_data(&mut header, &entry.path, std::io::empty())?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.len());
            let mut input = fs::File::open(&entry.source)?;
            builder.append_data(&mut header, &entry.path, &mut input)?;
        }
    }
    let encoder = builder.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn create_zip_archive(archive: &Path, entries: &[ArchiveEntry]) -> Result<()> {
    let output = fs::File::create(archive)?;
    let mut writer = zip::ZipWriter::new(output);
    for entry in entries {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(9))
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(entry.mode);
        if entry.is_dir {
            writer.add_directory(format!("{}/", entry.path), options)?;
        } else {
            let size = fs::metadata(&entry.source)?.len();
            writer.start_file(&entry.path, options.large_file(size > u32::MAX.into()))?;
            let mut input = fs::File::open(&entry.source)?;
            std::io::copy(&mut input, &mut writer)?;
        }
    }
    writer.finish()?;
    Ok(())
}

fn extract_archive(archive: &Path, destination: &Path) -> Result<()> {
    if archive
        .extension()
        .is_some_and(|extension| extension == "zip")
    {
        let input = fs::File::open(archive)?;
        zip::ZipArchive::new(input)?.extract(destination)?;
    } else {
        let input = fs::File::open(archive)?;
        let decoder = flate2::read::GzDecoder::new(input);
        tar::Archive::new(decoder).unpack(destination)?;
    }
    Ok(())
}

fn verify_release_assets(directory: &Path, requested_targets: &[String]) -> Result<()> {
    verify_project_metadata(&workspace_root())?;
    if !directory.is_dir()
        || fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "release asset directory is missing or symlinked: {}",
            directory.display()
        );
    }

    let requested_target_count = requested_targets.len();
    let requested_targets = requested_targets
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if requested_targets.len() != requested_target_count
        || requested_targets.iter().any(|requested| {
            !RELEASE_TARGETS
                .iter()
                .any(|(target, _)| target == requested)
        })
    {
        bail!("release verification requested an unknown or duplicate target");
    }
    let selected_targets = RELEASE_TARGETS
        .iter()
        .copied()
        .filter(|(target, _)| requested_targets.is_empty() || requested_targets.contains(target))
        .collect::<Vec<_>>();
    let expected_files = selected_targets
        .iter()
        .flat_map(|(target, extension)| {
            let archive = format!("depgraph-{VERSION}-{target}.{extension}");
            vec![
                archive.clone(),
                format!("{archive}.sha256"),
                format!("depgraph-{VERSION}-{target}.query-smoke.json"),
                format!("depgraph-{VERSION}-{target}.cross-language-smoke.json"),
                format!("depgraph-{VERSION}-{target}.mcp-smoke.json"),
            ]
        })
        .collect::<BTreeSet<_>>();
    let actual_files = fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                bail!(
                    "release asset directory contains a non-file entry: {}",
                    entry.path().display()
                );
            }
            Ok(entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let mut permitted_files = expected_files.clone();
    permitted_files.insert("release-verification.json".to_owned());
    if !expected_files.is_subset(&actual_files) || !actual_files.is_subset(&permitted_files) {
        bail!(
            "release asset set differs from the five-target contract: expected {expected_files:?}, found {actual_files:?}"
        );
    }

    let mut targets = Vec::new();
    let mut mcp_smoke_identities = BTreeSet::new();
    for (target, extension) in &selected_targets {
        let archive_name = format!("depgraph-{VERSION}-{target}.{extension}");
        let archive = directory.join(&archive_name);
        let checksum = directory.join(format!("{archive_name}.sha256"));
        let archive_sha256 = verify_checksum_sidecar(&archive, &checksum)?;
        let temp = tempfile::tempdir()?;
        extract_archive(&archive, temp.path())?;
        let release_name = format!("depgraph-{VERSION}-{target}");
        let top_level = fs::read_dir(temp.path())?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<BTreeSet<_>>>()?;
        if top_level != BTreeSet::from([release_name.clone()]) {
            bail!("archive {archive_name} has an unexpected top-level layout: {top_level:?}");
        }
        let extracted = temp.path().join(release_name);
        let query_smoke_path =
            directory.join(format!("depgraph-{VERSION}-{target}.query-smoke.json"));
        let query_smoke_bytes = fs::read(&query_smoke_path)?;
        let query_smoke: BoundedQueryPackageSmokeReport =
            serde_json::from_slice(&query_smoke_bytes)
                .context("packaged bounded query smoke report has an invalid schema")?;
        validate_bounded_query_package_smoke(&query_smoke, target, &archive_sha256)?;
        let cross_language_smoke_path = directory.join(format!(
            "depgraph-{VERSION}-{target}.cross-language-smoke.json"
        ));
        let cross_language_smoke_bytes = fs::read(&cross_language_smoke_path)?;
        let cross_language_smoke: CrossLanguagePackageSmokeReport =
            serde_json::from_slice(&cross_language_smoke_bytes)
                .context("packaged cross-language smoke report has an invalid schema")?;
        verify_cross_language_package_smoke(
            &cross_language_smoke,
            &extracted,
            target,
            &archive_sha256,
        )?;
        let mcp_smoke_path = directory.join(format!("depgraph-{VERSION}-{target}.mcp-smoke.json"));
        let mcp_smoke_bytes = fs::read(&mcp_smoke_path)?;
        let mcp_smoke: mcp_package_smoke::McpPackageSmokeReport =
            serde_json::from_slice(&mcp_smoke_bytes)
                .context("packaged MCP smoke report has an invalid schema")?;
        mcp_package_smoke::validate(&mcp_smoke, target, &archive_sha256, VERSION)?;
        mcp_smoke_identities.insert(mcp_smoke.cross_target_identity());
        targets.push(verify_published_release_tree(
            &extracted,
            target,
            archive_name,
            archive_sha256,
            PublishedSmokeReports {
                query: &query_smoke,
                query_sha256: hex::encode(Sha256::digest(&query_smoke_bytes)),
                cross_language: &cross_language_smoke,
                cross_language_sha256: hex::encode(Sha256::digest(&cross_language_smoke_bytes)),
                mcp: &mcp_smoke,
                mcp_sha256: hex::encode(Sha256::digest(&mcp_smoke_bytes)),
            },
        )?);
    }
    if mcp_smoke_identities.len() != 1 {
        bail!(
            "release targets do not attest identical packaged MCP discovery, fixture, recovery, and transport contracts"
        );
    }
    if targets
        .iter()
        .map(|target| target.runtime_collector_sha256.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        bail!("release targets do not contain identical runtime collector artifact bytes");
    }
    if targets
        .iter()
        .map(|target| target.rust_sysroot_sha256.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        bail!("release targets do not contain the identical pinned Rust sysroot data-tree");
    }
    if targets
        .iter()
        .map(|target| {
            (
                target.mcp_tool_schema_sha256.as_str(),
                target.mcp_sdk_version.as_str(),
                target.mcp_protocol_revision.as_str(),
                target.mcp_tool_contract_version.as_str(),
                target.mcp_operation_contract_version.as_str(),
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        bail!("release targets do not share one MCP schema and compatibility unit");
    }
    if targets
        .iter()
        .map(|target| &target.framework_build_artifacts)
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        bail!("release targets do not contain identical framework build artifact bytes");
    }
    // Bounded-query and profile-plan digests bind the target-native graph and
    // host contexts. The sidecar validator binds each one to its target's
    // compiled expectation, while checkout-equivalent runs prove repeatability.
    if targets
        .iter()
        .map(|target| {
            (
                target.cross_language_graph_digest.as_str(),
                target.cross_language_export_sha256.as_str(),
                target.cross_language_query_sha256.as_str(),
                &target.cross_language_schemas,
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
        != 1
    {
        bail!("release targets do not attest identical cross-language graph/query/schema bytes");
    }

    fs::write(
        directory.join("release-verification.json"),
        serde_json::to_vec_pretty(&ReleaseVerificationReport {
            schema_version: 9,
            release_version: VERSION.to_owned(),
            tag: release_tag()?,
            protocol_version: "1.0".to_owned(),
            schema_compatibility_version: "1.0".to_owned(),
            framework_build_graph_contract_version:
                depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION.to_owned(),
            framework_build_gate_contract_version:
                depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
            framework_build_capabilities: depgraph_core::framework_build_capability_contract(),
            runtime_collector_contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
            compatibility: release_compatibility(),
            license_expression: PROJECT_LICENSE_EXPRESSION.to_owned(),
            targets,
        })?,
    )?;
    println!(
        "verified {} release targets in {}",
        selected_targets.len(),
        directory.display()
    );
    Ok(())
}

fn validate_bounded_query_package_smoke(
    report: &BoundedQueryPackageSmokeReport,
    target: &str,
    archive_sha256: &str,
) -> Result<()> {
    let expected = target_native_smoke_expectation(target)
        .with_context(|| format!("target-native smoke contract is missing for {target}"))?;
    if report.schema_version != BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION
        || report.target != target
        || report.archive_sha256 != archive_sha256
        || !lowercase_sha256(&report.archive_sha256)
        || report.contract != depgraph_core::bounded_query_release_compatibility_contract()
        || !report
            .plan_digest
            .strip_prefix("bounded-query-plan:sha256:")
            .is_some_and(lowercase_sha256)
        || !report
            .result_digest
            .strip_prefix("bounded-query-result:sha256:")
            .is_some_and(lowercase_sha256)
        || !lowercase_sha256(&report.canonical_output_sha256)
        || report.profile_contract
            != depgraph_core::profile_selection_release_compatibility_contract()
        || !report
            .profile_plan_digest
            .strip_prefix("profile-selection-plan:sha256:")
            .is_some_and(lowercase_sha256)
        || !lowercase_sha256(&report.profile_canonical_output_sha256)
        || report.plan_digest != expected.query_plan_digest
        || report.result_digest != expected.query_result_digest
        || report.canonical_output_sha256 != expected.query_output_sha256
        || report.profile_plan_digest != expected.profile_plan_digest
        || report.profile_canonical_output_sha256 != expected.profile_plan_output_sha256
    {
        bail!(
            "packaged bounded query smoke report is incompatible for {target}: observed query=({}, {}, {}), profile=({}, {}); expected query=({}, {}, {}), profile=({}, {})",
            report.plan_digest,
            report.result_digest,
            report.canonical_output_sha256,
            report.profile_plan_digest,
            report.profile_canonical_output_sha256,
            expected.query_plan_digest,
            expected.query_result_digest,
            expected.query_output_sha256,
            expected.profile_plan_digest,
            expected.profile_plan_output_sha256,
        );
    }
    Ok(())
}

fn target_native_smoke_expectation(target: &str) -> Option<&TargetNativeSmokeExpectation> {
    TARGET_NATIVE_SMOKE_EXPECTATIONS
        .iter()
        .find(|expected| expected.target == target)
}

fn validate_cross_language_package_smoke(
    report: &CrossLanguagePackageSmokeReport,
    target: &str,
    archive_sha256: &str,
) -> Result<()> {
    if report.schema_version != CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION
        || report.target != target
        || report.archive_sha256 != archive_sha256
        || !lowercase_sha256(&report.archive_sha256)
        || report.contract != depgraph_core::cross_language_release_compatibility_contract()
        || !prefixed_lowercase_sha256(&report.graph_digest, "cross-language-release-graph:sha256:")
        || !lowercase_sha256(&report.canonical_export_sha256)
        || !lowercase_sha256(&report.query_output_sha256)
    {
        bail!("packaged cross-language smoke report is incompatible for {target}");
    }
    Ok(())
}

fn verify_cross_language_package_smoke(
    report: &CrossLanguagePackageSmokeReport,
    extracted: &Path,
    target: &str,
    archive_sha256: &str,
) -> Result<()> {
    validate_cross_language_package_smoke(report, target, archive_sha256)?;
    let recomputed = verify_packaged_cross_language(extracted, target, archive_sha256)?;
    if report != &recomputed {
        bail!(
            "packaged cross-language smoke report does not match outputs recomputed from {target}"
        );
    }
    Ok(())
}

fn lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prefixed_lowercase_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(lowercase_sha256)
}

fn github_settings_verify(snapshot_path: &Path, output: &Path) -> Result<()> {
    let desired_path = workspace_root().join(".github/settings-desired-v1.json");
    let desired = depgraph_core::parse_github_settings_desired(
        &fs::read(&desired_path).with_context(|| {
            format!(
                "failed to read canonical GitHub settings manifest {}",
                desired_path.display()
            )
        })?,
    )
    .context("canonical GitHub settings manifest is invalid")?;
    let snapshot: depgraph_core::GitHubSettingsApiSnapshot =
        serde_json::from_slice(&fs::read(snapshot_path).with_context(|| {
            format!(
                "failed to read redacted GitHub settings snapshot {}",
                snapshot_path.display()
            )
        })?)
        .context("redacted GitHub settings snapshot does not satisfy its closed schema")?;
    let evaluation = depgraph_core::evaluate_github_settings(&desired, &snapshot)?;
    fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&evaluation)?),
    )
    .with_context(|| {
        format!(
            "failed to write redacted GitHub settings evaluation {}",
            output.display()
        )
    })?;

    if evaluation.decision == depgraph_core::PublicReadinessDecision::Reject {
        bail!(
            "GitHub settings verification rejected; redacted evaluation={}",
            output.display()
        );
    }
    println!(
        "GitHub settings verification allowed; redacted evaluation={}",
        output.display()
    );
    Ok(())
}

fn stable_release_gate(
    release_verification_path: &Path,
    benchmark_report_path: &Path,
    compiler_pack_verification_path: &Path,
    output: &Path,
) -> Result<()> {
    verify_project_metadata(&workspace_root())?;
    let release_verification: ReleaseVerificationReport =
        serde_json::from_slice(&fs::read(release_verification_path).with_context(|| {
            format!(
                "failed to read release verification {}",
                release_verification_path.display()
            )
        })?)
        .context("release verification report does not satisfy its closed schema")?;
    let benchmark_report: Value =
        serde_json::from_slice(&fs::read(benchmark_report_path).with_context(|| {
            format!(
                "failed to read benchmark report {}",
                benchmark_report_path.display()
            )
        })?)
        .context("benchmark report is not valid JSON")?;
    let compiler_pack_verification: compiler_pack_release::CompilerPackVerificationReport =
        serde_json::from_slice(&fs::read(compiler_pack_verification_path).with_context(|| {
            format!(
                "failed to read compiler pack verification {}",
                compiler_pack_verification_path.display()
            )
        })?)
        .context("compiler pack verification report does not satisfy its closed schema")?;
    let compiler_pack_verified =
        compiler_pack_release::validate_verification_report(&compiler_pack_verification).is_ok()
            && compiler_pack_release_binding(&release_verification, &compiler_pack_verification);

    let report = evaluate_stable_release_gate(
        &release_verification,
        &benchmark_report,
        sha256_file(release_verification_path)?,
        sha256_file(benchmark_report_path)?,
        sha256_file(compiler_pack_verification_path)?,
        compiler_pack_verified,
        stable_release_workflow_results(),
    );
    fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )
    .with_context(|| format!("failed to write stable release gate {}", output.display()))?;

    if report.decision == StableReleaseDecision::Reject {
        let failed = report
            .checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| check.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "stable release gate rejected {STABLE_RELEASE_VERSION}: {failed}; report={}",
            output.display()
        );
    }
    println!(
        "stable release gate allowed v{STABLE_RELEASE_VERSION}; report={}",
        output.display()
    );
    Ok(())
}

fn release_post_publish_evidence(request: ReleasePostPublishEvidenceRequest) -> Result<()> {
    verify_project_metadata(&workspace_root())?;
    if !supported_release_tag(&request.tag)
        || request.tag == format!("v{VERSION}")
        || !lowercase_git_sha(&request.source_sha)
        || !lowercase_git_sha(&request.source_tree)
        || !lowercase_git_sha(&request.tag_object_sha)
        || !matches!(
            request.tag_signature_verification.as_str(),
            "valid" | "unknown_key" | "unverified_email"
        )
    {
        bail!("post-publish evidence requires a signed canonical v{VERSION}-rc.N tag");
    }
    if request.release_run_id == 0
        || request.release_run_url != canonical_actions_run_url(request.release_run_id)
    {
        bail!("post-publish evidence has a non-canonical Release workflow run");
    }

    let workflow_assets = release_asset_inventory(&request.workflow_assets)?;
    let public_assets = release_asset_inventory(&request.public_assets)?;
    let expected_assets = expected_release_asset_names();
    let workflow_names = workflow_assets
        .iter()
        .map(|asset| asset.name.clone())
        .collect::<BTreeSet<_>>();
    let public_names = public_assets
        .iter()
        .map(|asset| asset.name.clone())
        .collect::<BTreeSet<_>>();
    if workflow_names != expected_assets
        || public_names != expected_assets
        || workflow_assets != public_assets
    {
        bail!(
            "published release assets differ from the exact workflow-produced v{VERSION} closure"
        );
    }

    let full_ci = validate_full_ci_run(&request.ci_run, &request.source_sha)?;
    let aggregates = validate_post_publish_aggregates(
        &request.public_assets,
        &request.tag,
        &request.source_sha,
        &public_assets,
    )?;
    let evidence = ReleasePostPublishEvidence {
        schema_version: RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION.to_owned(),
        repository: "TamaT-LLC/depgraph-cli".to_owned(),
        release_version: VERSION.to_owned(),
        tag: request.tag,
        decision: StableReleaseDecision::Allow,
        candidate: ReleaseCandidateEvidence {
            commit: request.source_sha.clone(),
            tree: request.source_tree,
            tag_object: request.tag_object_sha,
            tag_signature_verification: request.tag_signature_verification,
        },
        full_ci,
        release_workflow: ReleaseWorkflowEvidence {
            run_id: request.release_run_id,
            url: request.release_run_url,
            head_sha: request.source_sha,
        },
        workflow_public_asset_identity: true,
        public_download_reverified: true,
        asset_set_sha256: release_asset_set_sha256(&public_assets),
        assets: public_assets,
        aggregates,
    };
    let output_parent = request
        .output
        .parent()
        .context("post-publish evidence output has no parent")?;
    fs::create_dir_all(output_parent)?;
    let mut encoded = serde_json::to_vec_pretty(&evidence)?;
    encoded.push(b'\n');
    fs::write(&request.output, encoded).with_context(|| {
        format!(
            "failed to write post-publish evidence {}",
            request.output.display()
        )
    })?;
    println!(
        "verified {} public release assets; evidence={}",
        evidence.assets.len(),
        request.output.display()
    );
    Ok(())
}

fn canonical_actions_run_url(run_id: u64) -> String {
    format!("https://github.com/TamaT-LLC/depgraph-cli/actions/runs/{run_id}")
}

fn expected_release_asset_names() -> BTreeSet<String> {
    let mut expected = [
        "benchmark-report.json",
        "cache-hit-benchmark-report.json",
        "compiler-pack-verification.json",
        "compiler-precise-hostile-e2e.json",
        "release-verification.json",
        "stable-release-gate.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for (target, extension) in RELEASE_TARGETS {
        let archive = format!("depgraph-{VERSION}-{target}.{extension}");
        expected.extend([
            archive.clone(),
            format!("{archive}.sha256"),
            format!("depgraph-{VERSION}-{target}.query-smoke.json"),
            format!("depgraph-{VERSION}-{target}.cross-language-smoke.json"),
            format!("depgraph-{VERSION}-{target}.mcp-smoke.json"),
        ]);
        let compiler_pack = format!("depgraph-compiler-pack-{VERSION}-{target}");
        let compiler_archive = format!("{compiler_pack}.{extension}");
        expected.extend([
            compiler_archive.clone(),
            format!("{compiler_archive}.sha256"),
            format!("{compiler_pack}.requirement.json"),
            format!("{compiler_pack}.smoke.json"),
        ]);
    }
    expected
}

fn release_asset_inventory(directory: &Path) -> Result<Vec<ReleaseAssetEvidence>> {
    if !directory.is_dir()
        || fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "release evidence asset directory is missing or symlinked: {}",
            directory.display()
        );
    }
    let mut assets = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!(
                "release evidence asset directory contains a non-regular entry: {}",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("release evidence asset name is not UTF-8"))?;
        assets.push(ReleaseAssetEvidence {
            name,
            bytes: metadata.len(),
            sha256: sha256_file_streaming(&entry.path())?,
        });
    }
    assets.sort_by(|left, right| left.name.cmp(&right.name));
    if assets.len() > 128 || assets.windows(2).any(|pair| pair[0].name >= pair[1].name) {
        bail!("release evidence asset inventory is duplicated or unbounded");
    }
    Ok(assets)
}

fn sha256_file_streaming(path: &Path) -> Result<String> {
    let mut input = fs::File::open(path)
        .with_context(|| format!("failed to open release asset {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .with_context(|| format!("failed to read release asset {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn release_asset_set_sha256(assets: &[ReleaseAssetEvidence]) -> String {
    let mut hasher = Sha256::new();
    for asset in assets {
        hasher.update(asset.name.as_bytes());
        hasher.update([0]);
        hasher.update(asset.bytes.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(asset.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    hex::encode(hasher.finalize())
}

fn validate_full_ci_run(path: &Path, source_sha: &str) -> Result<FullCiRunEvidence> {
    let input: FullCiRunEvidenceInput = serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("failed to read full CI evidence {}", path.display()))?,
    )
    .context("full CI evidence does not satisfy its closed schema")?;
    let mut jobs = input.jobs;
    jobs.sort_by(|left, right| left.name.cmp(&right.name));
    let expected = FULL_CI_JOB_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    if input.database_id == 0
        || input.head_sha != source_sha
        || input.head_branch != "main"
        || input.event != "workflow_dispatch"
        || input.conclusion != "success"
        || input.url != canonical_actions_run_url(input.database_id)
        || jobs.iter().map(|job| job.name.clone()).collect::<Vec<_>>() != expected
        || jobs.iter().any(|job| job.conclusion != "success")
    {
        bail!("full CI evidence is not the exact all-green candidate run");
    }
    Ok(FullCiRunEvidence {
        run_id: input.database_id,
        url: input.url,
        head_sha: input.head_sha,
        head_branch: input.head_branch,
        jobs,
    })
}

fn validate_post_publish_aggregates(
    directory: &Path,
    tag: &str,
    source_sha: &str,
    assets: &[ReleaseAssetEvidence],
) -> Result<ReleaseAggregateEvidence> {
    let digests = assets
        .iter()
        .map(|asset| (asset.name.as_str(), asset.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let release: Value =
        serde_json::from_slice(&fs::read(directory.join("release-verification.json"))?)
            .context("public release verification report is invalid JSON")?;
    let release_targets = release["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["target"].as_str())
        .collect::<Vec<_>>();
    let expected_targets = RELEASE_TARGETS
        .iter()
        .map(|(target, _)| *target)
        .collect::<Vec<_>>();
    if release["schema_version"] != 9
        || release["release_version"] != VERSION
        || release["tag"] != tag
        || release_targets != expected_targets
    {
        bail!("public release aggregate does not bind the exact five-target candidate");
    }

    let compiler: Value = serde_json::from_slice(&fs::read(
        directory.join("compiler-pack-verification.json"),
    )?)
    .context("public compiler-pack verification report is invalid JSON")?;
    let compiler_targets = compiler["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|target| target["target"].as_str())
        .collect::<Vec<_>>();
    if compiler["schema_version"]
        != compiler_pack_release::COMPILER_PACK_VERIFICATION_SCHEMA_VERSION
        || compiler["release_version"] != VERSION
        || compiler_targets != expected_targets
    {
        bail!("public compiler-pack aggregate does not bind the exact five-target candidate");
    }

    let benchmark: Value =
        serde_json::from_slice(&fs::read(directory.join("benchmark-report.json"))?)
            .context("public benchmark report is invalid JSON")?;
    let cache_hit: Value = serde_json::from_slice(&fs::read(
        directory.join("cache-hit-benchmark-report.json"),
    )?)
    .context("public cache-hit benchmark report is invalid JSON")?;
    if benchmark["schema_version"] != BENCHMARK_REPORT_SCHEMA_VERSION
        || benchmark["gate"]["passed"] != Value::Bool(true)
        || cache_hit["schema_version"] != "depgraph-cache-hit-benchmark-v1"
        || cache_hit["commit"] != source_sha
        || cache_hit["passed"] != Value::Bool(true)
    {
        bail!("public benchmark evidence is incompatible or failed");
    }

    let stable: StableReleaseGateReport =
        serde_json::from_slice(&fs::read(directory.join("stable-release-gate.json"))?)
            .context("public stable release gate does not satisfy its closed schema")?;
    let release_sha = required_asset_digest(&digests, "release-verification.json")?;
    let compiler_sha = required_asset_digest(&digests, "compiler-pack-verification.json")?;
    let benchmark_sha = required_asset_digest(&digests, "benchmark-report.json")?;
    if stable.schema_version != STABLE_RELEASE_GATE_SCHEMA_VERSION
        || stable.release_version != VERSION
        || stable.upgrade_source_version != STABLE_UPGRADE_SOURCE_VERSION
        || stable.tag != tag
        || stable.decision != StableReleaseDecision::Allow
        || stable.release_verification_sha256 != release_sha
        || stable.compiler_pack_verification_sha256 != compiler_sha
        || stable.benchmark_report_sha256 != benchmark_sha
        || stable.checks.is_empty()
        || stable.checks.iter().any(|check| !check.passed)
        || stable
            .workflow_results
            .get("github_actions")
            .map(String::as_str)
            != Some("true")
        || stable.workflow_results.get("ref_type").map(String::as_str) != Some("tag")
        || stable.workflow_results.get("ref_name").map(String::as_str) != Some(tag)
        || stable
            .workflow_results
            .get("source_sha")
            .map(String::as_str)
            != Some(source_sha)
        || [
            "quality",
            "compiler-precise-hostile",
            "benchmark",
            "package",
            "verify-assets",
            "compiler-pack",
            "verify-compiler-packs",
        ]
        .iter()
        .any(|job| stable.workflow_results.get(*job).map(String::as_str) != Some("success"))
    {
        bail!("public stable release gate is not the exact all-green candidate gate");
    }

    Ok(ReleaseAggregateEvidence {
        release_verification_sha256: release_sha.to_owned(),
        compiler_pack_verification_sha256: compiler_sha.to_owned(),
        benchmark_report_sha256: benchmark_sha.to_owned(),
        cache_hit_benchmark_report_sha256: required_asset_digest(
            &digests,
            "cache-hit-benchmark-report.json",
        )?
        .to_owned(),
        stable_release_gate_sha256: required_asset_digest(&digests, "stable-release-gate.json")?
            .to_owned(),
    })
}

fn required_asset_digest<'a>(digests: &'a BTreeMap<&str, &str>, name: &str) -> Result<&'a str> {
    digests
        .get(name)
        .copied()
        .with_context(|| format!("release asset inventory is missing {name}"))
}

fn compiler_pack_release_binding(
    release: &ReleaseVerificationReport,
    compiler_pack: &compiler_pack_release::CompilerPackVerificationReport,
) -> bool {
    let compiler_pack_targets = compiler_pack
        .targets
        .iter()
        .map(|target| target.target.clone())
        .collect::<Vec<_>>();
    compiler_pack_identity_binding(
        release,
        &compiler_pack.release_version,
        &compiler_pack.compatibility,
        &compiler_pack_targets,
    )
}

fn compiler_pack_identity_binding(
    release: &ReleaseVerificationReport,
    compiler_pack_version: &str,
    compiler_pack_compatibility: &depgraph_core::CompilerPreciseReleaseCompatibilityHealth,
    compiler_pack_targets: &[String],
) -> bool {
    let release_targets = release
        .targets
        .iter()
        .map(|target| target.target.as_str())
        .collect::<BTreeSet<_>>();
    let compiler_pack_target_set = compiler_pack_targets
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    compiler_pack_version == release.release_version
        && compiler_pack_compatibility == &release.compatibility.compiler_precise
        && compiler_pack_targets.len() == release.targets.len()
        && compiler_pack_target_set == release_targets
}

fn evaluate_stable_release_gate(
    release: &ReleaseVerificationReport,
    benchmark: &Value,
    release_verification_sha256: String,
    benchmark_report_sha256: String,
    compiler_pack_verification_sha256: String,
    compiler_pack_verified: bool,
    workflow_results: BTreeMap<String, String>,
) -> StableReleaseGateReport {
    let compatibility = release_compatibility();
    let expected_targets = RELEASE_TARGETS
        .iter()
        .map(|(target, _)| *target)
        .collect::<BTreeSet<_>>();
    let actual_targets = release
        .targets
        .iter()
        .map(|target| target.target.as_str())
        .collect::<BTreeSet<_>>();
    let release_source_matches_tag = workflow_results
        .get("source_sha")
        .is_some_and(|source_sha| {
            if release.tag == format!("v{STABLE_RELEASE_VERSION}") {
                false
            } else {
                supported_release_tag(&release.tag) && lowercase_git_sha(source_sha)
            }
        });
    let metrics = benchmark["metrics"].as_array();
    let benchmark_metrics_pass = metrics.is_some_and(|metrics| {
        metrics.len() == STABLE_BENCHMARK_METRICS.len()
            && metrics.iter().zip(STABLE_BENCHMARK_METRICS).all(
                |(metric, (expected_name, expected_gated))| {
                    let passed = metric["passed"].as_bool();
                    metric["name"].as_str() == Some(*expected_name)
                        && metric["gated"].as_bool() == Some(*expected_gated)
                        && passed.is_some()
                        && (!expected_gated || passed == Some(true))
                },
            )
    });
    let bounded_query_contract = depgraph_core::bounded_query_release_compatibility_contract();
    // Native query/profile identities are target-bound. Package and aggregate
    // verification bind the measured archive outputs to these same compiled
    // expectations; this stable gate preserves that exact five-target binding.
    let bounded_query_target_gate = release.targets.len() == RELEASE_TARGETS.len()
        && release.compatibility.bounded_query == bounded_query_contract
        && release.targets.iter().all(|target| {
            let Some(expected) = target_native_smoke_expectation(&target.target) else {
                return false;
            };
            prefixed_lowercase_sha256(&target.query_plan_digest, "bounded-query-plan:sha256:")
                && prefixed_lowercase_sha256(
                    &target.query_result_digest,
                    "bounded-query-result:sha256:",
                )
                && lowercase_sha256(&target.query_output_sha256)
                && lowercase_sha256(&target.query_smoke_sha256)
                && target.query_plan_digest == expected.query_plan_digest
                && target.query_result_digest == expected.query_result_digest
                && target.query_output_sha256 == expected.query_output_sha256
        });
    let profile_selection_contract =
        depgraph_core::profile_selection_release_compatibility_contract();
    let profile_selection_target_gate = release.targets.len() == RELEASE_TARGETS.len()
        && release.compatibility.profile_selection == profile_selection_contract
        && release.targets.iter().all(|target| {
            let Some(expected) = target_native_smoke_expectation(&target.target) else {
                return false;
            };
            prefixed_lowercase_sha256(
                &target.profile_plan_digest,
                "profile-selection-plan:sha256:",
            ) && lowercase_sha256(&target.profile_plan_output_sha256)
                && target.profile_plan_digest == expected.profile_plan_digest
                && target.profile_plan_output_sha256 == expected.profile_plan_output_sha256
        });
    let cross_language_contract = depgraph_core::cross_language_release_compatibility_contract();
    let cross_language_outputs = release
        .targets
        .iter()
        .map(|target| {
            (
                target.cross_language_graph_digest.as_str(),
                target.cross_language_export_sha256.as_str(),
                target.cross_language_query_sha256.as_str(),
                &target.cross_language_schemas,
            )
        })
        .collect::<BTreeSet<_>>();
    let cross_language_target_gate = release.targets.len() == RELEASE_TARGETS.len()
        && release.compatibility.cross_language == cross_language_contract
        && cross_language_outputs.len() == 1
        && release.targets.iter().all(|target| {
            target
                .cross_language_graph_digest
                .strip_prefix("cross-language-release-graph:sha256:")
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                && [
                    target.cross_language_smoke_sha256.as_str(),
                    target.cross_language_export_sha256.as_str(),
                    target.cross_language_query_sha256.as_str(),
                ]
                .iter()
                .all(|value| {
                    value.len() == 64
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                && target.cross_language_schemas
                    == cross_language_contract
                        .schemas
                        .iter()
                        .map(|schema| {
                            (
                                schema.path.clone(),
                                schema.sha256.trim_start_matches("sha256:").to_owned(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>()
        });
    let mcp_release_target_gate = release.targets.len() == RELEASE_TARGETS.len()
        && release.targets.iter().all(|target| {
            [
                target.mcp_server_sha256.as_str(),
                target.operation_runner_sha256.as_str(),
                target.mcp_tool_schema_sha256.as_str(),
                target.mcp_smoke_sha256.as_str(),
                target.mcp_smoke_tool_schema_sha256.as_str(),
                target.mcp_smoke_discovery_sha256.as_str(),
                target.mcp_smoke_fixture_result_sha256.as_str(),
                target.sbom_sha256.as_str(),
                target.third_party_licenses_sha256.as_str(),
            ]
            .iter()
            .all(|digest| lowercase_sha256(digest))
                && target.mcp_sdk_version == MCP_SDK_VERSION
                && target.mcp_protocol_revision == MCP_PROTOCOL_REVISION
                && target.mcp_tool_contract_version == MCP_TOOL_CONTRACT_VERSION
                && target.mcp_operation_contract_version == MCP_OPERATION_CONTRACT_VERSION
                && target.mcp_smoke_tool_schema_sha256 == target.mcp_tool_schema_sha256
                && target.mcp_smoke_submit_deadline_ms == mcp_package_smoke::SUBMIT_DEADLINE_MS
                && target.mcp_smoke_submit_elapsed_ms < target.mcp_smoke_submit_deadline_ms
                && target.mcp_smoke_recovered_after_eof
                && target.mcp_smoke_stdin_eof_clean_exit
                && target.mcp_smoke_stdout_json_rpc_only
        })
        && release
            .targets
            .iter()
            .map(|target| target.mcp_tool_schema_sha256.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == 1
        && release
            .targets
            .iter()
            .map(|target| {
                (
                    target.mcp_smoke_discovery_sha256.as_str(),
                    target.mcp_smoke_fixture_result_sha256.as_str(),
                )
            })
            .collect::<BTreeSet<_>>()
            .len()
            == 1;

    let checks = vec![
        StableReleaseGateCheck {
            id: "release-identity".to_owned(),
            passed: release.schema_version == 9
                && release.release_version == STABLE_RELEASE_VERSION
                && supported_release_tag(&release.tag),
            evidence:
                "release-verification.json schema 9 and an exact stable or canonical rc tag"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "protocol-store-cache-compatibility".to_owned(),
            passed: release.protocol_version == "1.0"
                && release.schema_compatibility_version == "1.0"
                && release.compatibility == compatibility
                && release.compatibility.worker_protocol_version
                    == depgraph_protocol::PROTOCOL_VERSION
                && release.compatibility.store_schema_version == depgraph_store::STORE_SCHEMA_VERSION
                && release.compatibility.operation_journal_schema_version
                    == depgraph_operation::JOURNAL_SCHEMA_VERSION
                && release.compatibility.mcp_tool_contract_version == MCP_TOOL_CONTRACT_VERSION
                && release.compatibility.mcp_operation_contract_version
                    == MCP_OPERATION_CONTRACT_VERSION
                && release.compatibility.cache_contract_version
                    == depgraph_store::CACHE_CONTRACT_VERSION,
            evidence: "release manifest closure uses the compiled compatibility contract".to_owned(),
        },
        StableReleaseGateCheck {
            id: "rc6-upgrade-and-rollback".to_owned(),
            passed: release.compatibility.stable_release_gate_contract_version
                == STABLE_RELEASE_GATE_SCHEMA_VERSION
                && release.compatibility.stable_release_version == STABLE_RELEASE_VERSION
                && release.compatibility.stable_upgrade_source_version
                    == STABLE_UPGRADE_SOURCE_VERSION
                && release
                    .compatibility
                    .stable_upgrade_source_store_schema_version
                    == STABLE_UPGRADE_SOURCE_STORE_SCHEMA_VERSION
                && release.compatibility.stable_upgrade_source_fixture_path
                    == STABLE_UPGRADE_SOURCE_FIXTURE_PATH
                && release.compatibility.stable_upgrade_source_fixture_sha256
                    == format!("sha256:{STABLE_UPGRADE_SOURCE_FIXTURE_SHA256}")
                && release.compatibility.packaged_smoke_contract
                    == "stable-v0.5.0-packaged-smoke-v1",
            evidence:
                "checksum-pinned official v0.4.0-rc.6 schema-13 fixture, migration, immutable graph, writable name, and byte-unchanged rollback backup"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "five-target-package-closure".to_owned(),
            passed: release.targets.len() == RELEASE_TARGETS.len()
                && actual_targets == expected_targets
                && release.license_expression == PROJECT_LICENSE_EXPRESSION,
            evidence:
                "five native archives, checksums, manifests, SBOMs, licenses, and attestations"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "mcp-five-target".to_owned(),
            passed: mcp_release_target_gate,
            evidence: "five native archives attest identical packaged MCP discovery/fixture digests, bounded durable safe-scan submit with post-EOF recovery, clean stdin EOF, JSON-RPC-only stdout, server/runner binaries, and versioned compatibility metadata".to_owned(),
        },
        StableReleaseGateCheck {
            id: "performance-budget".to_owned(),
            passed: benchmark["schema_version"] == BENCHMARK_REPORT_SCHEMA_VERSION
                && benchmark["fixture"]["source_file_count"] == 10_000
                && benchmark["gate"]["passed"] == Value::Bool(true)
                && benchmark_metrics_pass,
            evidence:
                "depgraph-benchmark-report-v7 exact fixtures and thirteen exact metrics, including eleven gated canonical-impact, bounded-query, Rust HIR, cache, and build-observation metrics"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "bounded-query-five-target".to_owned(),
            passed: bounded_query_target_gate
                && benchmark["evidence"]["bounded_query"]["contract"]
                    == serde_json::to_value(&bounded_query_contract)
                        .unwrap_or(Value::Null)
                && benchmark["evidence"]["bounded_query"]["admitted"] == Value::Bool(true)
                && benchmark["evidence"]["bounded_query"]["hostile_rejected"]
                    == Value::Bool(true),
            evidence:
                "five native archives match their compiled target-native bounded query identities and canonical smoke outputs"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "profile-selection-five-target".to_owned(),
            passed: profile_selection_target_gate,
            evidence:
                "five native archives match their compiled target-native profile-selection identities and canonical plan outputs"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "cross-language-five-target".to_owned(),
            passed: cross_language_target_gate,
            evidence:
                "five native archives share the OpenAPI/Protobuf/GraphQL/HTTP/FFI capability ledger, schemas, graph, query, and export bytes"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "compiler-pack-five-target".to_owned(),
            passed: compiler_pack_verified
                && release.compatibility.compiler_precise
                    == depgraph_core::compiler_precise_release_compatibility_contract(),
            evidence:
                "five separate target-specific compiler packs share the exact toolchain, contract, schema, query capability, semantic, resource, legal, provenance, tamper, and rollback closure"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "safety-framework-collector".to_owned(),
            passed: release.framework_build_graph_contract_version
                == depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION
                && release.framework_build_gate_contract_version
                    == depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION
                && release.framework_build_capabilities
                    == depgraph_core::framework_build_capability_contract()
                && release.runtime_collector_contract_version
                    == RUNTIME_COLLECTOR_CONTRACT_VERSION,
            evidence:
                "safe static analysis, framework Build Evidence, and runtime collector contracts"
                    .to_owned(),
        },
        StableReleaseGateCheck {
            id: "tag-source-guard-contract".to_owned(),
            passed: verify_stable_release_source_guard(&workspace_root()).is_ok()
                && release_source_matches_tag,
            evidence: format!(
                "the immutable v0.4.0 baseline remains enforced, canonical v0.5.0-rc.N tags bind their exact source SHA, and stable v0.5.0 remains blocked while baseline status is {STABLE_RELEASE_BASELINE_STATUS}"
            ),
        },
        StableReleaseGateCheck {
            id: "workflow-quality-closure".to_owned(),
            passed: workflow_results.get("github_actions").map(String::as_str) == Some("true")
                && workflow_results.get("ref_type").map(String::as_str) == Some("tag")
                && workflow_results.get("ref_name").map(String::as_str)
                    == Some(release.tag.as_str())
                && [
                    "quality",
                    "compiler-precise-hostile",
                    "benchmark",
                    "package",
                    "verify-assets",
                    "compiler-pack",
                    "verify-compiler-packs",
                ]
                    .iter()
                    .all(|job| workflow_results.get(*job).map(String::as_str) == Some("success")),
            evidence: "stable-gate needs quality, compiler-precise-hostile, benchmark, package, verify-assets, compiler-pack, and verify-compiler-packs in release.yml".to_owned(),
        },
    ];
    let decision = if checks.iter().all(|check| check.passed) {
        StableReleaseDecision::Allow
    } else {
        StableReleaseDecision::Reject
    };
    StableReleaseGateReport {
        schema_version: STABLE_RELEASE_GATE_SCHEMA_VERSION.to_owned(),
        release_version: STABLE_RELEASE_VERSION.to_owned(),
        upgrade_source_version: STABLE_UPGRADE_SOURCE_VERSION.to_owned(),
        tag: release.tag.clone(),
        decision,
        release_verification_sha256,
        benchmark_report_sha256,
        compiler_pack_verification_sha256,
        workflow_results,
        checks,
    }
}

fn stable_release_workflow_results() -> BTreeMap<String, String> {
    [
        ("github_actions", "GITHUB_ACTIONS"),
        ("ref_type", "GITHUB_REF_TYPE"),
        ("ref_name", "GITHUB_REF_NAME"),
        ("source_sha", "GITHUB_SHA"),
        ("quality", "DEPGRAPH_RELEASE_QUALITY_RESULT"),
        (
            "compiler-precise-hostile",
            "DEPGRAPH_RELEASE_COMPILER_PRECISE_HOSTILE_RESULT",
        ),
        ("benchmark", "DEPGRAPH_RELEASE_BENCHMARK_RESULT"),
        ("package", "DEPGRAPH_RELEASE_PACKAGE_RESULT"),
        ("verify-assets", "DEPGRAPH_RELEASE_VERIFY_ASSETS_RESULT"),
        ("compiler-pack", "DEPGRAPH_RELEASE_COMPILER_PACK_RESULT"),
        (
            "verify-compiler-packs",
            "DEPGRAPH_RELEASE_VERIFY_COMPILER_PACKS_RESULT",
        ),
    ]
    .into_iter()
    .map(|(key, variable)| {
        (
            key.to_owned(),
            std::env::var(variable).unwrap_or_else(|_| "missing".to_owned()),
        )
    })
    .collect()
}

fn verify_checksum_sidecar(archive: &Path, checksum: &Path) -> Result<String> {
    let digest = sha256_file(archive)?;
    let archive_name = archive
        .file_name()
        .context("release archive has no file name")?
        .to_string_lossy();
    let expected = format!("{digest}  {archive_name}\n");
    let actual = fs::read_to_string(checksum)
        .with_context(|| format!("release checksum is missing: {}", checksum.display()))?;
    if actual != expected {
        bail!(
            "release checksum sidecar {} does not attest {}",
            checksum.display(),
            archive.display()
        );
    }
    Ok(digest)
}

fn verify_published_release_tree(
    extracted: &Path,
    expected_target: &str,
    archive: String,
    archive_sha256: String,
    smoke: PublishedSmokeReports<'_>,
) -> Result<TargetVerificationReport> {
    if fs::symlink_metadata(extracted)?.file_type().is_symlink() {
        bail!("published release root must not be a symlink");
    }
    for entry in WalkDir::new(extracted).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "published release contains a symlink: {}",
                entry.path().display()
            );
        }
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
        if !extracted.join(required).is_file() {
            bail!("published release is missing {required}");
        }
    }
    for schema in depgraph_core::cross_language_release_compatibility_contract().schemas {
        if !extracted.join(&schema.path).is_file() {
            bail!("published release is missing {}", schema.path);
        }
    }

    let manifest_path = extracted.join("release-manifest.json");
    let manifest: ReleaseManifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("published release manifest is invalid")?;
    if manifest.release_version != VERSION
        || manifest.protocol_version != "1.0"
        || manifest.schema_version != "1.0"
        || manifest.compatibility != release_compatibility()
        || manifest.target != expected_target
        || manifest.license_expression != PROJECT_LICENSE_EXPRESSION
    {
        bail!(
            "published release compatibility metadata does not match {VERSION}/{expected_target}"
        );
    }

    let mut artifact_paths = BTreeSet::new();
    let expected_core = format!(
        "bin/{}",
        executable_name_for_target("depgraph", expected_target)
    );
    if manifest.core.path != expected_core {
        bail!("published release core path does not match {expected_core}");
    }
    artifact_paths.insert(manifest.core.path.as_str());
    let core = verify_release_artifact(extracted, &manifest.core, "core")?;
    if !expected_target.contains("windows") && !is_executable(&core)? {
        bail!("published release core is not executable");
    }
    let expected_mcp_server = format!(
        "bin/{}",
        executable_name_for_target(MCP_SERVER_NAME, expected_target)
    );
    if manifest.mcp_server.version != VERSION
        || manifest.mcp_server.path != expected_mcp_server
        || manifest.mcp_server.sdk_name != MCP_SDK_NAME
        || manifest.mcp_server.sdk_version != MCP_SDK_VERSION
        || manifest.mcp_server.protocol_revision != MCP_PROTOCOL_REVISION
        || manifest.mcp_server.tool_contract_version != MCP_TOOL_CONTRACT_VERSION
        || manifest.mcp_server.operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
        || !artifact_paths.insert(manifest.mcp_server.path.as_str())
    {
        bail!("published release MCP server compatibility unit is incompatible or duplicated");
    }
    let mcp_server = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.mcp_server.path.clone(),
            sha256: manifest.mcp_server.sha256.clone(),
        },
        "MCP server",
    )?;
    if !expected_target.contains("windows") && !is_executable(&mcp_server)? {
        bail!("published release MCP server is not executable");
    }
    let expected_operation_runner = format!(
        "libexec/{}",
        executable_name_for_target("depgraph-operation-runner", expected_target)
    );
    if manifest.operation_runner.version != VERSION
        || manifest.operation_runner.operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
        || manifest.operation_runner.path != expected_operation_runner
        || !artifact_paths.insert(manifest.operation_runner.path.as_str())
    {
        bail!("published release operation runner metadata is incompatible or duplicated");
    }
    let operation_runner = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.operation_runner.path.clone(),
            sha256: manifest.operation_runner.sha256.clone(),
        },
        "operation runner",
    )?;
    if !expected_target.contains("windows") && !is_executable(&operation_runner)? {
        bail!("published release operation runner is not executable");
    }
    if manifest.schema.path != "schemas/depgraph-protocol-v1.schema.json" {
        bail!("published release schema path is not the protocol 1.0 schema");
    }
    artifact_paths.insert(manifest.schema.path.as_str());
    verify_release_artifact(extracted, &manifest.schema, "schema")?;
    if manifest.mcp_tool_schema.contract_version != MCP_TOOL_CONTRACT_VERSION
        || manifest.mcp_tool_schema.path != MCP_TOOL_SCHEMA_PATH
        || !artifact_paths.insert(manifest.mcp_tool_schema.path.as_str())
    {
        bail!("published release MCP tool schema compatibility unit is incompatible or duplicated");
    }
    let mcp_tool_schema = verify_release_artifact(
        extracted,
        &Artifact {
            path: manifest.mcp_tool_schema.path.clone(),
            sha256: manifest.mcp_tool_schema.sha256.clone(),
        },
        "MCP tool schema",
    )?;
    verify_mcp_tool_schema_bytes(&mcp_tool_schema, "published release")?;
    if smoke.mcp.tool_schema_sha256 != manifest.mcp_tool_schema.sha256 {
        bail!("published MCP smoke schema digest differs from the extracted release manifest");
    }
    if manifest.query_fixture.path != depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH {
        bail!("published release query fixture path does not match the query contract");
    }
    if !artifact_paths.insert(manifest.query_fixture.path.as_str()) {
        bail!(
            "published release reuses query fixture path {}",
            manifest.query_fixture.path
        );
    }
    let query_fixture =
        verify_release_artifact(extracted, &manifest.query_fixture, "bounded query fixture")?;
    if fs::read_to_string(query_fixture)? != depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_QUERY
        || format!("sha256:{}", manifest.query_fixture.sha256)
            != manifest.compatibility.bounded_query.fixture_sha256
    {
        bail!("published bounded query fixture differs from its compiled contract");
    }
    let cross_language_contract = depgraph_core::cross_language_release_compatibility_contract();
    if manifest.cross_language_fixture.path != cross_language_contract.fixture_path
        || format!("sha256:{}", manifest.cross_language_fixture.sha256)
            != cross_language_contract.fixture_sha256
        || !artifact_paths.insert(manifest.cross_language_fixture.path.as_str())
    {
        bail!("published cross-language fixture identity is incompatible or duplicated");
    }
    let cross_language_fixture = verify_release_artifact(
        extracted,
        &manifest.cross_language_fixture,
        "cross-language fixture",
    )?;
    if fs::read_to_string(cross_language_fixture)?
        != depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE
    {
        bail!("published cross-language fixture differs from its compiled contract");
    }
    let declared_cross_language_schemas = manifest
        .cross_language_schemas
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if declared_cross_language_schemas.len() != cross_language_contract.schemas.len()
        || manifest.cross_language_schemas.len() != cross_language_contract.schemas.len()
    {
        bail!("published cross-language schema closure is incomplete or duplicated");
    }
    let mut cross_language_schemas = BTreeMap::new();
    for schema in &cross_language_contract.schemas {
        let artifact = declared_cross_language_schemas
            .get(schema.path.as_str())
            .with_context(|| format!("published release is missing {}", schema.path))?;
        if format!("sha256:{}", artifact.sha256) != schema.sha256
            || !artifact_paths.insert(artifact.path.as_str())
        {
            bail!(
                "published cross-language schema {} is incompatible or duplicated",
                schema.path
            );
        }
        verify_release_artifact(extracted, artifact, "cross-language schema")?;
        cross_language_schemas.insert(schema.path.clone(), artifact.sha256.clone());
    }

    if manifest.project_licenses.len() != PROJECT_LICENSES.len() {
        bail!("published release must attest exactly both project licenses");
    }
    let project_licenses = manifest
        .project_licenses
        .iter()
        .map(|artifact| (artifact.path.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    if project_licenses.len() != PROJECT_LICENSES.len() {
        bail!("published release contains duplicate project license paths");
    }
    let mut verified_licenses = BTreeMap::new();
    for (path, expected) in PROJECT_LICENSES {
        let artifact = project_licenses
            .get(path)
            .with_context(|| format!("published release is missing project license {path}"))?;
        if !artifact_paths.insert(artifact.path.as_str()) {
            bail!("published release reuses artifact path {}", artifact.path);
        }
        let verified = verify_release_artifact(extracted, artifact, "project license")?;
        if fs::read(verified)? != *expected {
            bail!("published project license {path} differs from the repository source");
        }
        verified_licenses.insert((*path).to_owned(), artifact.sha256.clone());
    }

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
        bail!("published release Web runtime artifact closure is incomplete or unknown");
    }
    for artifact in &manifest.runtime_artifacts {
        if !artifact_paths.insert(artifact.path.as_str()) {
            bail!("published release reuses artifact path {}", artifact.path);
        }
        verify_release_artifact(extracted, artifact, "runtime artifact")?;
    }
    let runtime_collector_sha256 = manifest
        .runtime_artifacts
        .iter()
        .find(|artifact| artifact.path == format!("libexec/{RUNTIME_COLLECTOR_ARTIFACT}"))
        .context("published release has no runtime collector artifact")?
        .sha256
        .clone();
    let mut components = BTreeMap::new();
    for component in &manifest.runtime_components {
        if component.name.trim().is_empty()
            || component.version.trim().is_empty()
            || component.license.trim().is_empty()
            || component.root.trim().is_empty()
        {
            bail!("published runtime component name, version, license, and root must be non-empty");
        }
        if components
            .insert(component.name.as_str(), component)
            .is_some()
        {
            bail!(
                "published release contains duplicate runtime component {}",
                component.name
            );
        }
        let root = verified_release_path(extracted, &component.root, "runtime component")?;
        if !root.is_dir() || sha256_tree(&root)? != component.sha256 {
            bail!(
                "published runtime component {} failed its whole-tree checksum",
                component.name
            );
        }
        if let Some(entrypoint) = &component.entrypoint {
            let entrypoint = verified_release_path(extracted, entrypoint, "component entrypoint")?;
            if !entrypoint.is_file() || !entrypoint.starts_with(&root) {
                bail!(
                    "published runtime component {} has an invalid entrypoint",
                    component.name
                );
            }
            if component.kind == "executable-tree"
                && !expected_target.contains("windows")
                && !is_executable(&entrypoint)?
            {
                bail!(
                    "published runtime component {} entrypoint is not executable",
                    component.name
                );
            }
        } else if component.kind == "executable-tree" {
            bail!(
                "published executable runtime component {} has no entrypoint",
                component.name
            );
        }
        if !matches!(component.kind.as_str(), "executable-tree" | "data-tree") {
            bail!(
                "published runtime component {} has unsupported kind {}",
                component.name,
                component.kind
            );
        }
    }
    let astro = components
        .get("astro-parser-wasm")
        .context("published release has no Astro runtime component")?;
    if astro.version != "4.0.0"
        || astro.kind != "data-tree"
        || astro.root != "libexec/astro"
        || astro.entrypoint.as_deref() != Some("libexec/astro/astro.wasm")
        || astro.license != "MIT"
    {
        bail!("published Astro compatibility unit is invalid");
    }
    let typescript = components
        .get("typescript-native-compiler")
        .context("published release has no TypeScript runtime component")?;
    let expected_typescript_entrypoint = format!(
        "libexec/typescript/lib/{}",
        executable_name_for_target("tsc", expected_target)
    );
    if typescript.version != TYPESCRIPT_VERSION
        || typescript.kind != "executable-tree"
        || typescript.root != "libexec/typescript/lib"
        || typescript.entrypoint.as_deref() != Some(expected_typescript_entrypoint.as_str())
        || typescript.license != "Apache-2.0"
    {
        bail!("published TypeScript compatibility unit is invalid");
    }
    let rust_sysroot = components
        .get(RUST_SYSROOT_COMPONENT_NAME)
        .context("published release has no pinned Rust sysroot source component")?;
    if rust_sysroot.version != RUST_SYSROOT_COMPONENT_VERSION
        || rust_sysroot.kind != "data-tree"
        || rust_sysroot.root != RUST_SYSROOT_COMPONENT_ROOT
        || rust_sysroot.entrypoint.is_some()
        || rust_sysroot.license != RUST_SYSROOT_LICENSE_EXPRESSION
        || rust_sysroot.sha256 != RUST_SYSROOT_COMPONENT_SHA256
    {
        bail!("published Rust sysroot source compatibility unit is invalid");
    }
    verify_rust_sysroot_tree(extracted, rust_sysroot, "published release")?;
    let rust_sysroot_sha256 = rust_sysroot.sha256.clone();

    let mut workers = BTreeMap::new();
    for worker in &manifest.workers {
        let expected_path = if worker.adapter == "web" {
            "libexec/depgraph-web-worker.mjs".to_owned()
        } else {
            format!(
                "libexec/{}",
                executable_name_for_target(
                    &format!("depgraph-{}-worker", worker.adapter),
                    expected_target,
                )
            )
        };
        if !matches!(worker.adapter.as_str(), "rust" | "go" | "web")
            || worker.version != VERSION
            || worker.path != expected_path
            || workers
                .insert(worker.adapter.clone(), worker.sha256.clone())
                .is_some()
        {
            bail!(
                "published worker metadata is invalid for {}",
                worker.adapter
            );
        }
        if !artifact_paths.insert(worker.path.as_str()) {
            bail!("published release reuses artifact path {}", worker.path);
        }
        let artifact = verify_release_artifact(
            extracted,
            &Artifact {
                path: worker.path.clone(),
                sha256: worker.sha256.clone(),
            },
            "worker",
        )?;
        if worker.adapter != "web"
            && !expected_target.contains("windows")
            && !is_executable(&artifact)?
        {
            bail!("published {} worker is not executable", worker.adapter);
        }
        if worker.adapter == "rust" {
            verify_rust_backend(
                worker
                    .backend
                    .as_ref()
                    .context("published Rust worker has no backend attestation")?,
            )?;
        } else if worker.backend.is_some() {
            bail!("published non-Rust worker has a Rust backend attestation");
        }
        if worker.adapter == "web" {
            verify_web_semantic_attestation(
                worker
                    .semantic
                    .as_ref()
                    .context("published Web worker has no semantic attestation")?,
            )?;
        } else if worker.semantic.is_some() {
            bail!("published non-Web worker has a Web semantic attestation");
        }
    }
    if workers.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["go", "rust", "web"])
        || manifest.runtime_requirements.get("web").map(String::as_str) != Some("Node.js >=24.0.0")
    {
        bail!("published release worker/runtime closure is incomplete");
    }

    let sbom_path = extracted.join("sbom.spdx.json");
    let sbom: Value = serde_json::from_slice(&fs::read(&sbom_path)?)?;
    let packages = sbom["packages"]
        .as_array()
        .context("published release SBOM has no packages")?;
    let root_package = packages
        .iter()
        .find(|package| package["SPDXID"] == "SPDXRef-Package-depgraph")
        .context("published release SBOM has no depgraph package")?;
    if sbom["spdxVersion"] != "SPDX-2.3"
        || sbom["name"] != format!("depgraph-{VERSION}-{expected_target}")
        || root_package["versionInfo"] != VERSION
        || root_package["licenseDeclared"] != PROJECT_LICENSE_EXPRESSION
        || root_package["comment"] != SBOM_SCOPE
    {
        bail!("published release SBOM root metadata is incompatible");
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
        "typescript",
        "golang.org/x/tools",
        "ra_ap_hir",
        "ra_ap_ide_db",
        "ra_ap_syntax",
        "ra_ap_vfs",
        "rmcp",
        "rmcp-macros",
        "salsa",
    ] {
        if !package_names.contains(required) {
            bail!("published release SBOM is missing {required}");
        }
    }
    verify_runtime_collector_sbom(&sbom, &runtime_collector_sha256, "published release")?;
    verify_rust_sysroot_sbom(&sbom, &rust_sysroot_sha256, "published release")?;
    verify_bounded_query_sbom(&sbom, "published release")?;
    verify_cross_language_sbom(&sbom, &cross_language_contract, "published release")?;
    let framework_build_artifacts = manifest_framework_build_artifact_checksums(&manifest)?;
    verify_framework_build_sbom(&sbom, &framework_build_artifacts, "published release")?;
    if package_names
        .iter()
        .filter(|name| name.starts_with("@typescript/typescript-"))
        .count()
        != 1
    {
        bail!("published release SBOM must contain one target TypeScript compiler");
    }
    let third_party_path = extracted.join("THIRD_PARTY_LICENSES.txt");
    let third_party = fs::read_to_string(&third_party_path)?;
    if !third_party.starts_with("depgraph third-party license inventory\n")
        || !third_party.contains(&format!(
            "First-party artifact {RUNTIME_COLLECTOR_ARTIFACT} ({RUNTIME_COLLECTOR_CONTRACT_VERSION}) is licensed under {PROJECT_LICENSE_EXPRESSION}"
        ))
        || !third_party.contains(&format!(
            "First-party bounded query contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION}",
            depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH,
            depgraph_core::BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION,
        ))
        || !third_party.contains(&format!(
            "First-party cross-language contract fixture {} ({}) is licensed under {PROJECT_LICENSE_EXPRESSION}",
            depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
            depgraph_core::CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION,
        ))
        || !third_party.contains(&rust_sysroot_license_notice())
        || !third_party.lines().any(|line| line == MCP_APACHE_NOTICE)
        || PROJECT_LICENSES.iter().any(|(_, project_text)| {
            third_party
                .as_bytes()
                .windows(project_text.len())
                .any(|window| window == *project_text)
        })
    {
        bail!("published third-party license inventory is missing or mixes project licenses");
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
                "published release SBOM must contain exactly one cargo:{name} {version} licensed Apache-2.0"
            );
        }
        let expected = format!("cargo:{name} {version} — Apache-2.0");
        if !third_party.lines().any(|line| line == expected) {
            bail!("published third-party license inventory is missing {expected}");
        }
    }
    for (path, version) in depgraph_core::framework_build_capability_contract()
        .into_iter()
        .map(|capability| {
            (
                capability.observer_runtime_artifact,
                capability.observer_version,
            )
        })
        .chain(std::iter::once((
            depgraph_core::FRAMEWORK_BUILD_CONVERTER_ARTIFACT.to_owned(),
            depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
        )))
    {
        let path = path
            .strip_prefix("libexec/")
            .context("framework build artifact path is not release-relative")?;
        if !third_party.contains(&format!(
            "First-party artifact {path} ({version}) is licensed under {PROJECT_LICENSE_EXPRESSION} by LICENSE-MIT and LICENSE-APACHE; its dependency-free bundle adds no third-party license entry."
        )) {
            bail!("published third-party license inventory is missing {path}");
        }
    }
    verify_runtime_collector_module(
        &verified_release_path(
            extracted,
            &format!("libexec/{RUNTIME_COLLECTOR_ARTIFACT}"),
            "runtime collector",
        )?,
        "published release",
    )?;

    Ok(TargetVerificationReport {
        target: expected_target.to_owned(),
        archive,
        archive_sha256,
        release_manifest_sha256: sha256_file(&manifest_path)?,
        sbom_sha256: sha256_file(&sbom_path)?,
        third_party_licenses_sha256: sha256_file(&third_party_path)?,
        project_licenses: verified_licenses,
        mcp_server_sha256: manifest.mcp_server.sha256.clone(),
        operation_runner_sha256: manifest.operation_runner.sha256.clone(),
        mcp_tool_schema_sha256: manifest.mcp_tool_schema.sha256.clone(),
        mcp_sdk_version: manifest.mcp_server.sdk_version.clone(),
        mcp_protocol_revision: manifest.mcp_server.protocol_revision.clone(),
        mcp_tool_contract_version: manifest.mcp_server.tool_contract_version.clone(),
        mcp_operation_contract_version: manifest.mcp_server.operation_contract_version.clone(),
        mcp_smoke_sha256: smoke.mcp_sha256,
        mcp_smoke_tool_schema_sha256: smoke.mcp.tool_schema_sha256.clone(),
        mcp_smoke_discovery_sha256: smoke.mcp.discovery_sha256.clone(),
        mcp_smoke_fixture_result_sha256: smoke.mcp.fixture_result_sha256.clone(),
        mcp_smoke_submit_deadline_ms: smoke.mcp.safe_scan_submit_deadline_ms,
        mcp_smoke_submit_elapsed_ms: smoke.mcp.safe_scan_submit_elapsed_ms,
        mcp_smoke_recovered_after_eof: smoke.mcp.safe_scan_recovered_after_eof,
        mcp_smoke_stdin_eof_clean_exit: smoke.mcp.stdin_eof_clean_exit,
        mcp_smoke_stdout_json_rpc_only: smoke.mcp.stdout_json_rpc_only,
        runtime_collector_sha256,
        rust_sysroot_sha256,
        framework_build_artifacts,
        workers,
        query_smoke_sha256: smoke.query_sha256,
        query_plan_digest: smoke.query.plan_digest.clone(),
        query_result_digest: smoke.query.result_digest.clone(),
        query_output_sha256: smoke.query.canonical_output_sha256.clone(),
        profile_plan_digest: smoke.query.profile_plan_digest.clone(),
        profile_plan_output_sha256: smoke.query.profile_canonical_output_sha256.clone(),
        cross_language_smoke_sha256: smoke.cross_language_sha256,
        cross_language_graph_digest: smoke.cross_language.graph_digest.clone(),
        cross_language_export_sha256: smoke.cross_language.canonical_export_sha256.clone(),
        cross_language_query_sha256: smoke.cross_language.query_output_sha256.clone(),
        cross_language_schemas,
    })
}

fn executable_name_for_target(name: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

// Windows canonicalization returns a verbatim path (`\\\\?\\...`). Node.js
// cannot use that form as its entry-script argument, even though it is the
// correct form for the integrity and confinement checks above. Normalize only
// the argument passed to the external runtime.
#[cfg(windows)]
fn process_argument_path(path: &Path) -> std::ffi::OsString {
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    std::ffi::OsString::from_wide(&without_windows_verbatim_prefix(&wide))
}

#[cfg(not(windows))]
fn process_argument_path(path: &Path) -> std::ffi::OsString {
    path.as_os_str().to_owned()
}

#[cfg(any(windows, test))]
fn without_windows_verbatim_prefix(path: &[u16]) -> Vec<u16> {
    const VERBATIM: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const VERBATIM_UNC: &[u16] = &[
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'U' as u16,
        b'N' as u16,
        b'C' as u16,
        b'\\' as u16,
    ];

    if let Some(rest) = path.strip_prefix(VERBATIM_UNC) {
        [b'\\' as u16, b'\\' as u16]
            .into_iter()
            .chain(rest.iter().copied())
            .collect()
    } else if let Some(rest) = path.strip_prefix(VERBATIM) {
        rest.to_vec()
    } else {
        path.to_vec()
    }
}

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

fn verify_packaged_cross_language(
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

fn verify_archive(
    archive: &Path,
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

fn remove_transient_build_run_ids(value: &mut Value) {
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
        "flate2",
        "jsonschema",
        "predicates",
        "pretty_assertions",
        "spdx",
        "tar",
        "tsx",
        "zip",
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
    if sbom != crate::sbom(&manifest.target, &rust_sysroot_sha256)? {
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

fn verify_runtime_collector_module(path: &Path, context: &str) -> Result<()> {
    let output = Command::new("node")
        .args([
            "--input-type=module",
            "--eval",
            r#"import { pathToFileURL } from "node:url";
const sdk = await import(pathToFileURL(process.argv[1]).href);
process.stdout.write(`${sdk.RUNTIME_COLLECTOR_CONTRACT_VERSION}\t${sdk.RUNTIME_TRACE_SCHEMA_VERSION}\n`);
"#,
        ])
        .arg(process_argument_path(path))
        .output()
        .with_context(|| format!("failed to inspect {context} runtime collector"))?;
    let expected = format!(
        "{RUNTIME_COLLECTOR_CONTRACT_VERSION}\t{}\n",
        depgraph_core::RUNTIME_TRACE_SCHEMA_VERSION
    );
    if !output.status.success()
        || !output.stderr.is_empty()
        || String::from_utf8(output.stdout)? != expected
    {
        bail!("{context} runtime collector module has an incompatible version handshake");
    }
    Ok(())
}

fn verify_release_artifact(
    extracted: &Path,
    artifact: &Artifact,
    description: &str,
) -> Result<PathBuf> {
    let path = verified_release_path(extracted, &artifact.path, description)?;
    if !path.is_file() || sha256_file(&path)? != artifact.sha256 {
        bail!(
            "release {description} {} failed its checksum",
            artifact.path
        );
    }
    Ok(path)
}

fn verify_mcp_tool_schema_bytes(path: &Path, context: &str) -> Result<()> {
    if fs::read(path)? != MCP_TOOL_SCHEMA_BYTES {
        bail!(
            "{context} MCP tool schema differs from the compiled {MCP_TOOL_CONTRACT_VERSION} contract"
        );
    }
    Ok(())
}

fn verified_release_path(extracted: &Path, declared: &str, description: &str) -> Result<PathBuf> {
    let declared = Path::new(declared);
    if declared.is_absolute()
        || declared
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!(
            "release {description} has an unsafe path {}",
            declared.display()
        );
    }
    let canonical_root = extracted.canonicalize()?;
    let mut path = extracted.to_path_buf();
    for component in declared.components() {
        let std::path::Component::Normal(component) = component else {
            unreachable!();
        };
        path.push(component);
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!(
                "release {description} path contains a symlink: {}",
                path.display()
            );
        }
    }
    let path = path
        .canonicalize()
        .with_context(|| format!("release {description} is missing: {}", declared.display()))?;
    if !path.starts_with(canonical_root) {
        bail!("release {description} escapes the release root");
    }
    Ok(path)
}

fn verify_rust_sysroot_tree(
    extracted: &Path,
    component: &RuntimeComponent,
    context: &str,
) -> Result<()> {
    let expected_source = serde_json::to_vec_pretty(&RustSysrootSourceIdentity {
        contract_version: RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION,
        toolchain_version: RUST_SYSROOT_TOOLCHAIN_VERSION,
        toolchain_commit: RUST_SYSROOT_TOOLCHAIN_COMMIT,
        component_version: RUST_SYSROOT_COMPONENT_VERSION,
        source_layout: RUST_SYSROOT_SOURCE_LAYOUT,
        acquisition: "rustup-component:rust-src",
        normalized_root: "library",
        license_expression: RUST_SYSROOT_LICENSE_EXPRESSION,
    })?;
    let apache = PROJECT_LICENSES
        .iter()
        .find_map(|(path, content)| (*path == "LICENSE-APACHE").then_some(*content))
        .context("project Apache-2.0 license input is missing")?;
    for (relative, expected) in [
        ("COPYRIGHT", RUST_SOURCE_COPYRIGHT),
        ("LICENSE-MIT", RUST_SOURCE_LICENSE_MIT),
        ("LICENSE-APACHE", apache),
        ("SOURCE.json", expected_source.as_slice()),
    ] {
        let declared = format!("{}/{relative}", component.root);
        let path = verified_release_path(extracted, &declared, "Rust sysroot legal metadata")?;
        if !path.is_file() || fs::read(&path)? != expected {
            bail!("{context} Rust sysroot source metadata {declared} is missing or incompatible");
        }
    }
    for relative in [
        "library/Cargo.toml",
        "library/core/src/lib.rs",
        "library/alloc/src/lib.rs",
        "library/std/src/lib.rs",
        "library/proc_macro/src/lib.rs",
    ] {
        let declared = format!("{}/{relative}", component.root);
        let path = verified_release_path(extracted, &declared, "Rust sysroot source")?;
        if !path.is_file() {
            bail!("{context} Rust sysroot source is missing {declared}");
        }
    }
    Ok(())
}

fn verify_typescript_compiler(release_root: &Path) -> Result<()> {
    let compiler = release_root
        .join("libexec/typescript/lib")
        .join(executable_name("tsc"))
        .canonicalize()
        .with_context(|| "bundled TypeScript compiler entrypoint is missing")?;
    let version = Command::new(&compiler)
        .arg("--version")
        .current_dir(std::env::temp_dir())
        .output()
        .with_context(|| {
            format!(
                "failed to start bundled TypeScript compiler {}",
                compiler.display()
            )
        })?;
    if !version.status.success()
        || String::from_utf8_lossy(&version.stdout).trim() != "Version 7.0.2"
        || !version.stderr.is_empty()
    {
        bail!(
            "bundled TypeScript compiler version gate failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&version.stdout),
            String::from_utf8_lossy(&version.stderr)
        );
    }
    let fixture = tempfile::tempdir()?;
    let model = fixture.path().join("model.ts");
    let source = fixture.path().join("semantic-smoke.ts");
    let invalid = fixture.path().join("semantic-failure.ts");
    let type_roots = fixture.path().join("empty-type-roots");
    fs::create_dir(&type_roots)?;
    fs::write(
        &model,
        "export interface Item { value: string }\nexport const items: Array<Item> = [];\n",
    )?;
    fs::write(
        &source,
        "import { items } from './model';\nexport const value: Promise<string> = Promise.resolve(items[0]?.value ?? 'safe');\n",
    )?;
    fs::write(&invalid, "const mismatch: string = 1;\n")?;
    let smoke = Command::new(&compiler)
        .args([
            "--noEmit",
            "--pretty",
            "false",
            "--module",
            "preserve",
            "--moduleResolution",
            "bundler",
            "--target",
            "esnext",
            "--strict",
            "--skipLibCheck",
            "--typeRoots",
        ])
        .arg(&type_roots)
        .arg(&source)
        .arg(&model)
        .current_dir(fixture.path())
        .output()?;
    if !smoke.status.success() {
        bail!(
            "bundled TypeScript compiler semantic smoke failed: {}{}",
            String::from_utf8_lossy(&smoke.stdout),
            String::from_utf8_lossy(&smoke.stderr)
        );
    }
    let semantic_failure = Command::new(&compiler)
        .args([
            "--noEmit",
            "--pretty",
            "false",
            "--target",
            "esnext",
            "--strict",
            "--skipLibCheck",
            "--typeRoots",
        ])
        .arg(&type_roots)
        .arg(&invalid)
        .current_dir(fixture.path())
        .output()?;
    let failure_output = format!(
        "{}{}",
        String::from_utf8_lossy(&semantic_failure.stdout),
        String::from_utf8_lossy(&semantic_failure.stderr)
    );
    if semantic_failure.status.success() || !failure_output.contains("TS2322") {
        bail!(
            "bundled TypeScript compiler did not enforce its TypeChecker smoke: {failure_output}"
        );
    }
    Ok(())
}

fn host_target() -> Result<String> {
    let output = Command::new("rustc").arg("-vV").output()?;
    let text = String::from_utf8(output.stdout)?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: ").map(ToOwned::to_owned))
        .context("rustc -vV did not report a host target")
}

fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be located directly under the workspace root")
        .to_path_buf()
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

fn pnpm_program() -> &'static str {
    if cfg!(windows) { "pnpm.cmd" } else { "pnpm" }
}

fn verify_release_tag() -> Result<()> {
    verify_release_tag_values(
        std::env::var_os("GITHUB_REF_TYPE").as_deref(),
        std::env::var_os("GITHUB_REF_NAME").as_deref(),
    )
}

fn verify_release_tag_values(
    ref_type: Option<&std::ffi::OsStr>,
    tag: Option<&std::ffi::OsStr>,
) -> Result<()> {
    if ref_type != Some(std::ffi::OsStr::new("tag")) {
        return Ok(());
    }
    let Some(tag) = tag else {
        bail!("release tag workflow did not expose GITHUB_REF_NAME");
    };
    let tag = tag.to_string_lossy();
    if !supported_release_tag(&tag) {
        bail!("release tag {tag} must be v{VERSION} or a canonical v{VERSION}-rc.N prerelease");
    }
    Ok(())
}

fn copy(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn read_lf_normalized_text(path: &Path) -> Result<String> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read text {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("text {} is not UTF-8", path.display()))?;
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn copy_lf_normalized_text(source: &Path, destination: &Path) -> Result<()> {
    let normalized = read_lf_normalized_text(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(destination, normalized).with_context(|| {
        format!(
            "failed to write LF-normalized release text {}",
            destination.display()
        )
    })?;
    Ok(())
}

fn copy_directory(source: &Path, destination: &Path) -> Result<()> {
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "refusing symlink in runtime component: {}",
                entry.path().display()
            );
        }
        let relative = entry.path().strip_prefix(source)?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            copy(entry.path(), &target)?;
            fs::set_permissions(&target, entry.metadata()?.permissions())?;
        } else {
            bail!(
                "unsupported runtime component entry: {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn relative_slash(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path).with_context(
        || format!("failed to read {}", path.display()),
    )?)))
}

fn sha256_tree(root: &Path) -> Result<String> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).min_depth(1) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            bail!(
                "refusing symlink in runtime component: {}",
                entry.path().display()
            );
        }
        if entry.file_type().is_file() {
            entries.push((
                relative_slash(root, entry.path())?,
                true,
                entry.path().to_path_buf(),
            ));
        } else if entry.file_type().is_dir() {
            entries.push((
                relative_slash(root, entry.path())?,
                false,
                entry.path().to_path_buf(),
            ));
        } else {
            bail!(
                "unsupported runtime component entry: {}",
                entry.path().display()
            );
        }
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if !entries.iter().any(|(_, is_file, _)| *is_file) {
        bail!("runtime component {} is empty", root.display());
    }
    let mut digest = Sha256::new();
    digest.update(b"depgraph-runtime-tree-v2\0");
    for (relative, is_file, path) in entries {
        digest.update([if is_file { b'f' } else { b'd' }]);
        let relative = relative.as_bytes();
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative);
        if is_file {
            let content = fs::read(&path)?;
            digest.update((content.len() as u64).to_be_bytes());
            digest.update(content);
        } else {
            digest.update(0_u64.to_be_bytes());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

fn run(command: &mut Command) -> Result<()> {
    let display = format!("{command:?}");
    let status = command
        .status()
        .with_context(|| format!("failed to start {display}"))?;
    if !status.success() {
        bail!("{display} exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
        time::{Duration, SystemTime},
    };

    use anyhow::Result;
    use serde_json::{Value, json};

    use super::{
        ARCHIVE_MTIME, BENCHMARK_REPORT_SCHEMA_VERSION, BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION,
        BoundedQueryPackageSmokeReport, CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION, Cli,
        CrossLanguagePackageSmokeReport, DependencyPackage, FULL_CI_JOB_NAMES, GithubActionsPolicy,
        MCP_OPERATION_CONTRACT_VERSION, MCP_PROTOCOL_REVISION, MCP_SDK_VERSION,
        MCP_TOOL_CONTRACT_VERSION, PROJECT_LICENSE_EXPRESSION, RELEASE_CARGO_BUILD_TARGETS,
        RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION, RELEASE_TARGETS,
        RUNTIME_COLLECTOR_CONTRACT_VERSION, RUST_SYSROOT_COMPONENT_SHA256,
        ReleasePostPublishEvidence, ReleasePostPublishEvidenceRequest, ReleaseVerificationReport,
        STABLE_BENCHMARK_METRICS, STABLE_RELEASE_GATE_SCHEMA_VERSION, STABLE_RELEASE_VERSION,
        STABLE_UPGRADE_SOURCE_FIXTURE_PATH, STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        STABLE_UPGRADE_SOURCE_STORE_SCHEMA_VERSION, STABLE_UPGRADE_SOURCE_VERSION,
        StableReleaseDecision, TYPESCRIPT_VERSION, TargetVerificationReport, Task,
        V0_2_RC1_STORE_SCHEMA_VERSION, V0_4_RC1_STORE_SCHEMA_VERSION,
        V0_4_STABLE_RELEASE_BASELINE_DIGEST, VERSION, WEB_SEMANTIC_CAPABILITIES,
        WEB_SEMANTIC_RUNTIME_ARTIFACTS, WEB_SEMANTIC_RUNTIME_COMPONENTS, WebSemanticAttestation,
        WorkerBackend, archive_entries, cargo_metadata, cargo_runtime_packages,
        compiler_pack_identity_binding, create_tar_archive, create_zip_archive,
        evaluate_stable_release_gate, executable_name_for_target, expected_release_asset_names,
        extract_archive, github_settings_verify, has_windows_executable_extension,
        normalized_spdx_license, package_url, parse_worker_handshake, release_compatibility,
        release_post_publish_evidence, remove_transient_build_run_ids, rust_backend_from_handshake,
        rustc_source_identity, supported_release_tag, target_native_smoke_expectation,
        v0_4_stable_release_baseline_digest, validate_bounded_query_package_smoke,
        validate_cross_language_package_smoke, verify_checksum_sidecar,
        verify_cross_language_package_smoke, verify_github_actions_security,
        verify_local_markdown_links, verify_mcp_dependencies,
        verify_mcp_tasks_architecture_decision, verify_packaged_cross_language,
        verify_pinned_rust_sysroot_digest, verify_project_metadata,
        verify_public_community_surface, verify_release_tag_values,
        verify_rust_analyzer_dependencies, verify_rust_backend, verify_security_disclosure_dry_run,
        verify_stable_release_source_guard, verify_web_semantic_attestation,
        verify_workflow_policy_text, web_runtime_packages, web_semantic_from_handshake,
        without_windows_verbatim_prefix, workspace_root,
    };

    fn post_publish_evidence_fixture()
    -> Result<(tempfile::TempDir, ReleasePostPublishEvidenceRequest)> {
        let temp = tempfile::tempdir()?;
        let workflow = temp.path().join("workflow");
        let public = temp.path().join("public");
        fs::create_dir_all(&workflow)?;
        fs::create_dir_all(&public)?;
        let source_sha = "a".repeat(40);
        let source_tree = "b".repeat(40);
        let tag_object_sha = "c".repeat(40);
        let tag = "v0.5.0-rc.1";

        let expected = expected_release_asset_names();
        assert_eq!(expected.len(), 51);
        for name in &expected {
            fs::write(workflow.join(name), format!("fixture:{name}\n"))?;
        }
        let targets = RELEASE_TARGETS
            .iter()
            .map(|(target, _)| json!({"target": target}))
            .collect::<Vec<_>>();
        fs::write(
            workflow.join("release-verification.json"),
            serde_json::to_vec(&json!({
                "schema_version": 9,
                "release_version": VERSION,
                "tag": tag,
                "targets": targets,
            }))?,
        )?;
        fs::write(
            workflow.join("compiler-pack-verification.json"),
            serde_json::to_vec(&json!({
                "schema_version": super::compiler_pack_release::COMPILER_PACK_VERIFICATION_SCHEMA_VERSION,
                "release_version": VERSION,
                "targets": RELEASE_TARGETS.iter().map(|(target, _)| json!({"target": target})).collect::<Vec<_>>(),
            }))?,
        )?;
        fs::write(
            workflow.join("benchmark-report.json"),
            serde_json::to_vec(&json!({
                "schema_version": BENCHMARK_REPORT_SCHEMA_VERSION,
                "gate": {"passed": true},
            }))?,
        )?;
        fs::write(
            workflow.join("cache-hit-benchmark-report.json"),
            serde_json::to_vec(&json!({
                "schema_version": "depgraph-cache-hit-benchmark-v1",
                "commit": source_sha,
                "passed": true,
            }))?,
        )?;
        let release_sha =
            super::sha256_file_streaming(&workflow.join("release-verification.json"))?;
        let compiler_sha =
            super::sha256_file_streaming(&workflow.join("compiler-pack-verification.json"))?;
        let benchmark_sha = super::sha256_file_streaming(&workflow.join("benchmark-report.json"))?;
        fs::write(
            workflow.join("stable-release-gate.json"),
            serde_json::to_vec(&json!({
                "schema_version": STABLE_RELEASE_GATE_SCHEMA_VERSION,
                "release_version": VERSION,
                "upgrade_source_version": STABLE_UPGRADE_SOURCE_VERSION,
                "tag": tag,
                "decision": "allow",
                "release_verification_sha256": release_sha,
                "benchmark_report_sha256": benchmark_sha,
                "compiler_pack_verification_sha256": compiler_sha,
                "workflow_results": {
                    "github_actions": "true",
                    "ref_type": "tag",
                    "ref_name": tag,
                    "source_sha": source_sha,
                    "quality": "success",
                    "compiler-precise-hostile": "success",
                    "benchmark": "success",
                    "package": "success",
                    "verify-assets": "success",
                    "compiler-pack": "success",
                    "verify-compiler-packs": "success"
                },
                "checks": [{"id": "fixture", "passed": true, "evidence": "fixture"}],
            }))?,
        )?;
        for name in expected {
            fs::copy(workflow.join(&name), public.join(name))?;
        }

        let full_ci = temp.path().join("full-ci.json");
        fs::write(
            &full_ci,
            serde_json::to_vec(&json!({
                "database_id": 123,
                "head_sha": source_sha,
                "head_branch": "main",
                "event": "workflow_dispatch",
                "conclusion": "success",
                "url": "https://github.com/TamaT-LLC/depgraph-cli/actions/runs/123",
                "jobs": FULL_CI_JOB_NAMES.iter().rev().map(|name| json!({
                    "name": name,
                    "conclusion": "success",
                })).collect::<Vec<_>>(),
            }))?,
        )?;
        let request = ReleasePostPublishEvidenceRequest {
            workflow_assets: workflow,
            public_assets: public,
            ci_run: full_ci,
            tag: tag.to_owned(),
            source_sha,
            source_tree,
            tag_object_sha,
            tag_signature_verification: "valid".to_owned(),
            release_run_id: 456,
            release_run_url: "https://github.com/TamaT-LLC/depgraph-cli/actions/runs/456"
                .to_owned(),
            output: temp.path().join("evidence.json"),
        };
        Ok((temp, request))
    }

    fn release_tree() -> Result<(tempfile::TempDir, String)> {
        let temp = tempfile::tempdir()?;
        let name = "depgraph-test-target".to_owned();
        let root = temp.path().join(&name);
        fs::create_dir_all(root.join("bin"))?;
        fs::create_dir_all(root.join("empty"))?;
        fs::write(root.join("README.txt"), b"release\n")?;
        let executable = root.join("bin/depgraph.exe");
        fs::write(&executable, b"binary\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o751))?;
        }
        Ok((temp, name))
    }

    #[test]
    fn repository_release_metadata_is_synchronized() -> Result<()> {
        verify_project_metadata(&workspace_root())
    }

    #[test]
    fn post_publish_evidence_binds_exact_public_assets_and_full_ci() -> Result<()> {
        let (_temp, request) = post_publish_evidence_fixture()?;
        let output = request.output.clone();
        release_post_publish_evidence(request)?;
        let evidence: ReleasePostPublishEvidence = serde_json::from_slice(&fs::read(output)?)?;
        assert_eq!(
            evidence.schema_version,
            RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION
        );
        assert_eq!(evidence.decision, StableReleaseDecision::Allow);
        assert_eq!(evidence.assets.len(), 51);
        assert_eq!(evidence.full_ci.jobs.len(), FULL_CI_JOB_NAMES.len());
        assert!(evidence.workflow_public_asset_identity);
        assert!(evidence.public_download_reverified);
        Ok(())
    }

    #[test]
    fn post_publish_evidence_rejects_public_tamper_and_skipped_full_ci() -> Result<()> {
        let (_temp, request) = post_publish_evidence_fixture()?;
        fs::write(
            request.public_assets.join("benchmark-report.json"),
            b"tampered\n",
        )?;
        assert!(release_post_publish_evidence(request).is_err());

        let (_temp, request) = post_publish_evidence_fixture()?;
        let mut full_ci: Value = serde_json::from_slice(&fs::read(&request.ci_run)?)?;
        full_ci["jobs"].as_array_mut().expect("fixture jobs").pop();
        fs::write(&request.ci_run, serde_json::to_vec(&full_ci)?)?;
        assert!(release_post_publish_evidence(request).is_err());
        Ok(())
    }

    #[test]
    fn release_contract_text_is_utf8_and_lf_normalized_during_staging() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("contract.json");
        let destination = temp.path().join("staging/schemas/contract.json");
        fs::write(&source, b"{\r\n  \"value\": true\r}\r\n")?;
        super::copy_lf_normalized_text(&source, &destination)?;
        assert_eq!(fs::read(&destination)?, b"{\n  \"value\": true\n}\n");

        fs::write(&source, [0xff])?;
        assert!(super::copy_lf_normalized_text(&source, &destination).is_err());
        Ok(())
    }

    #[test]
    fn public_community_surface_is_closed_and_linked() -> Result<()> {
        verify_public_community_surface(&workspace_root())
    }

    #[test]
    fn mcp_tasks_architecture_decision_is_closed_and_linked() -> Result<()> {
        verify_mcp_tasks_architecture_decision(&workspace_root())
    }

    #[test]
    fn github_actions_policy_permissions_and_security_dry_run_fail_closed() -> Result<()> {
        let root = workspace_root();
        verify_github_actions_security(&root)?;
        let policy: GithubActionsPolicy =
            serde_json::from_slice(&fs::read(root.join(".github/actions-policy.json"))?)?;
        let pins = policy
            .actions
            .iter()
            .map(|action| (action.identity.as_str(), action.sha.as_str()))
            .collect::<BTreeMap<_, _>>();
        let ci = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
        let release = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
        let release_quality = release
            .split_once("\n  compiler-precise-hostile:\n")
            .map(|(quality, _)| quality)
            .expect("release workflow has no bounded quality job");
        for resource_bound in [
            "CARGO_INCREMENTAL: \"0\"",
            "CARGO_PROFILE_DEV_DEBUG: \"0\"",
            "CARGO_PROFILE_TEST_DEBUG: \"0\"",
        ] {
            assert!(
                release_quality.contains(resource_bound),
                "release quality job must retain runner disk bound {resource_bound}"
            );
        }

        for workflow_name in ["ci.yml", "release.yml", "stable-release-source-guard.yml"] {
            let workflow = fs::read_to_string(root.join(".github/workflows").join(workflow_name))?;
            let crlf_workflow = workflow.replace('\n', "\r\n");
            verify_workflow_policy_text(
                workflow_name,
                &crlf_workflow,
                &pins,
                &mut BTreeSet::new(),
            )?;
        }

        let mutable = ci.replacen(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "actions/checkout@v4",
            1,
        );
        assert!(
            verify_workflow_policy_text("ci.yml", &mutable, &pins, &mut BTreeSet::new()).is_err()
        );

        for escaped_trigger in [
            ci.replacen("  pull_request:", r#"  "\u0070ull_request_target":"#, 1),
            ci.replacen("on:", r#"on: ["\u0070ull_request_target"]"#, 1),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "ci.yml",
                    &escaped_trigger,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

        let missing_manual_dispatch = ci.replacen("  workflow_dispatch:\n", "", 1);
        assert!(
            verify_workflow_policy_text(
                "ci.yml",
                &missing_manual_dispatch,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );

        let expensive_jobs_on_main = ci.replace(
            "github.event_name == 'workflow_dispatch'",
            "github.event_name != 'pull_request'",
        );
        assert!(
            verify_workflow_policy_text(
                "ci.yml",
                &expensive_jobs_on_main,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );

        for linker_policy_drift in [
            ci.replacen("      fail-fast: false", "      fail-fast: true", 1),
            ci.replacen("rustflags: -C linker-features=-lld", "rustflags: \"\"", 1),
            ci.replacen("RUSTFLAGS: ${{ matrix.rustflags }}", "RUSTFLAGS: \"\"", 1),
            ci.replacen("CARGO_INCREMENTAL: \"0\"", "CARGO_INCREMENTAL: \"1\"", 1),
            ci.replacen(
                "CARGO_PROFILE_DEV_DEBUG: \"0\"",
                "CARGO_PROFILE_DEV_DEBUG: \"1\"",
                1,
            ),
            ci.replacen(
                "CARGO_PROFILE_TEST_DEBUG: \"0\"",
                "CARGO_PROFILE_TEST_DEBUG: \"1\"",
                1,
            ),
            ci.replacen(
                "Reclaim integration build artifacts before the isolated Rust semantic gate",
                "Do not reclaim integration artifacts before Rust semantic verification",
                1,
            ),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "ci.yml",
                    &linker_policy_drift,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

        let escaped_secret = ci.replacen(
            "GOTOOLCHAIN: local",
            r#"GOTOOLCHAIN: "${{ \u0073ecrets.RELEASE_TOKEN }}""#,
            1,
        );
        assert!(
            verify_workflow_policy_text("ci.yml", &escaped_secret, &pins, &mut BTreeSet::new(),)
                .is_err()
        );

        let inline_mutable = ci.replacen(
            "- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
            "- { uses: actions/checkout@v4 }",
            1,
        );
        assert!(
            verify_workflow_policy_text("ci.yml", &inline_mutable, &pins, &mut BTreeSet::new(),)
                .is_err()
        );

        let broad = ci.replacen("contents: read", "contents: write", 1);
        assert!(
            verify_workflow_policy_text("ci.yml", &broad, &pins, &mut BTreeSet::new()).is_err()
        );

        for inline_permissions in [
            "    permissions: { contents: write }\n",
            "    \"permissions\": { contents: write }\n",
        ] {
            let inline_write = ci.replacen(
                "  rust:\n    runs-on:",
                &format!("  rust:\n{inline_permissions}    runs-on:"),
                1,
            );
            assert!(
                verify_workflow_policy_text("ci.yml", &inline_write, &pins, &mut BTreeSet::new(),)
                    .is_err()
            );
        }

        for expression in [
            "${{ secrets.RELEASE_TOKEN }}",
            "${{secrets.RELEASE_TOKEN}}",
            "${{ secrets ['RELEASE_TOKEN'] }}",
            "${{ SeCrEtS.RELEASE_TOKEN }}",
        ] {
            let secret = format!("{ci}\n# {expression}\n");
            assert!(
                verify_workflow_policy_text("ci.yml", &secret, &pins, &mut BTreeSet::new())
                    .is_err()
            );
        }

        let unreviewed_write = "name: Auxiliary\non: workflow_dispatch\npermissions: {}\njobs:\n  mutate:\n    permissions:\n      issues: write\n";
        assert!(
            verify_workflow_policy_text(
                "auxiliary.yml",
                unreviewed_write,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );

        for quoted in ["\"write\"", "'write'"] {
            let unreviewed_quoted_write = format!(
                "name: Auxiliary\non: workflow_dispatch\npermissions: {{}}\njobs:\n  mutate:\n    permissions:\n      issues: {quoted}\n"
            );
            assert!(
                verify_workflow_policy_text(
                    "auxiliary.yml",
                    &unreviewed_quoted_write,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

        for escaped in [r#""\u0077rite""#, r#""\x77rite""#] {
            let escaped_write = format!(
                "name: Auxiliary\non: workflow_dispatch\npermissions: {{}}\njobs:\n  mutate:\n    permissions:\n      issues: {escaped}\n"
            );
            assert!(
                verify_workflow_policy_text(
                    "auxiliary.yml",
                    &escaped_write,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

        let escaped_permissions_key = r#"name: Auxiliary
on: workflow_dispatch
permissions: {}
jobs:
  mutate:
    "permi\u0073sions":
      issues: "\u0077rite"
"#;
        assert!(
            verify_workflow_policy_text(
                "auxiliary.yml",
                escaped_permissions_key,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );

        let release = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
        let overprivileged_release = release.replacen(
            "      contents: write",
            "      contents: write\n      issues: write",
            1,
        );
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &overprivileged_release,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
        let quoted_overprivileged_release = release.replacen(
            "      contents: write",
            "      contents: write\n      issues: \"write\"",
            1,
        );
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &quoted_overprivileged_release,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
        for linker_policy_drift in [
            release.replacen("rustflags: -C linker-features=-lld", "rustflags: \"\"", 1),
            release.replacen("RUSTFLAGS: ${{ matrix.rustflags }}", "RUSTFLAGS: \"\"", 1),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "release.yml",
                    &linker_policy_drift,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

        let guard =
            fs::read_to_string(root.join(".github/workflows/stable-release-source-guard.yml"))?;
        let overprivileged_guard = guard.replacen(
            "      contents: write",
            "      contents: write\n      packages: write",
            1,
        );
        assert!(
            verify_workflow_policy_text(
                "stable-release-source-guard.yml",
                &overprivileged_guard,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );

        let dry_run = fs::read(root.join("security/disclosure-dry-run-v1.json"))?;
        verify_security_disclosure_dry_run(&dry_run)?;
        let mut tampered: Value = serde_json::from_slice(&dry_run)?;
        tampered["fork_secret_access"] = json!(true);
        assert!(verify_security_disclosure_dry_run(&serde_json::to_vec(&tampered)?).is_err());
        tampered["fork_secret_access"] = json!(false);
        tampered["unknown"] = json!(true);
        assert!(verify_security_disclosure_dry_run(&serde_json::to_vec(&tampered)?).is_err());
        Ok(())
    }

    #[test]
    fn local_markdown_links_allow_balanced_parentheses_and_reject_unterminated_targets()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::create_dir_all(root.join("guides"))?;
        fs::write(root.join("guides/setup_(safe).md"), b"# Safe setup\n")?;

        verify_local_markdown_links(
            &root,
            "README.md",
            "[Safe setup](guides/setup_(safe).md#install)",
        )?;
        assert!(
            verify_local_markdown_links(&root, "README.md", "[Broken](guides/setup_(safe).md")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn cross_language_package_smoke_is_deterministic_and_tamper_closed() -> Result<()> {
        let target = "x86_64-unknown-linux-gnu";
        let archive_sha256 = "a".repeat(64);
        let report = verify_packaged_cross_language(&workspace_root(), target, &archive_sha256)?;
        validate_cross_language_package_smoke(&report, target, &archive_sha256)?;
        assert_eq!(
            report.schema_version,
            CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION
        );
        assert!(
            report
                .graph_digest
                .starts_with("cross-language-release-graph:sha256:")
        );

        let mut archive_drifted = report.clone();
        archive_drifted.archive_sha256 = "b".repeat(64);
        assert!(
            validate_cross_language_package_smoke(&archive_drifted, target, &archive_sha256)
                .is_err()
        );

        let mut output_drifted = report.clone();
        output_drifted.graph_digest =
            format!("cross-language-release-graph:sha256:{}", "0".repeat(64));
        assert!(
            validate_cross_language_package_smoke(&output_drifted, target, &archive_sha256).is_ok()
        );
        assert!(
            verify_cross_language_package_smoke(
                &output_drifted,
                &workspace_root(),
                target,
                &archive_sha256,
            )
            .is_err()
        );

        let mut drifted = CrossLanguagePackageSmokeReport {
            contract: report.contract.clone(),
            ..report
        };
        drifted.contract.capabilities.pop();
        assert!(validate_cross_language_package_smoke(&drifted, target, &archive_sha256).is_err());
        Ok(())
    }

    #[test]
    fn v0_4_stable_release_baseline_digest_is_reproducible() {
        assert_eq!(
            v0_4_stable_release_baseline_digest(),
            V0_4_STABLE_RELEASE_BASELINE_DIGEST
        );
    }

    #[test]
    fn stable_release_source_guard_is_pinned_to_baseline() -> Result<()> {
        verify_stable_release_source_guard(&workspace_root())
    }

    #[test]
    fn rustc_source_identity_requires_an_exact_release_and_commit() -> Result<()> {
        assert_eq!(
            rustc_source_identity(
                "rustc 1.93.1\ncommit-hash: 01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf\nrelease: 1.93.1\n"
            )?,
            ("1.93.1", "01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf")
        );
        assert!(rustc_source_identity("release: 1.93.1\n").is_err());
        assert!(rustc_source_identity("commit-hash: unknown\nrelease: 1.93.1\n").is_err());
        assert!(rustc_source_identity("commit-hash: abc\n").is_err());
        verify_pinned_rust_sysroot_digest(RUST_SYSROOT_COMPONENT_SHA256)?;
        assert!(
            verify_pinned_rust_sysroot_digest(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn framework_build_determinism_ignores_only_transient_run_ids() {
        let mut graph = json!({
            "build_run_id": "top-level-run",
            "nodes": [{
                "id": "stable-node",
                "properties": {
                    "build_run_id": "nested-run",
                    "artifact_digest": "stable-digest"
                }
            }]
        });
        remove_transient_build_run_ids(&mut graph);
        assert_eq!(
            graph,
            json!({
                "nodes": [{
                    "id": "stable-node",
                    "properties": {
                        "artifact_digest": "stable-digest"
                    }
                }]
            })
        );
    }

    #[test]
    fn official_v0_2_store_fixture_migrates_without_losing_the_completed_snapshot() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("legacy.db");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(include_str!("../fixtures/v0.2.0-rc.1-store-v5.sql"))?;
        let schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(schema, V0_2_RC1_STORE_SCHEMA_VERSION);
        drop(connection);

        let store = depgraph_store::Store::open(&path)?;
        assert_eq!(
            store.schema_version()?,
            release_compatibility().store_schema_version
        );
        let snapshot_id = store.current_snapshot_id()?.unwrap();
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        assert_eq!(snapshot.scan.id, "legacy-v0.2.0-rc.1-scan");
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.evidence.len(), 2);
        assert!(store.verify_snapshot_integrity(&snapshot_id)?.valid);
        Ok(())
    }

    #[test]
    fn historical_v0_4_rc_1_store_fixture_still_migrates_without_graph_drift() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("release-candidate.db");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(include_str!("../fixtures/v0.4.0-rc.1-store-v11.sql"))?;
        let schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(schema, V0_4_RC1_STORE_SCHEMA_VERSION);
        drop(connection);

        let mut store = depgraph_store::Store::open(&path)?;
        assert_eq!(
            store.schema_version()?,
            release_compatibility().store_schema_version
        );
        let snapshot_id = store.current_snapshot_id()?.unwrap();
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        assert_eq!(snapshot.scan.id, "official-v0.4.0-rc.1-scan");
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.evidence.len(), 2);
        assert!(store.verify_snapshot_integrity(&snapshot_id)?.valid);
        store.create_snapshot_name("stable-v0.4.0-upgrade", &snapshot_id)?;
        assert_eq!(
            store.resolve_completed_snapshot_selector("stable-v0.4.0-upgrade")?,
            snapshot_id
        );
        Ok(())
    }

    #[test]
    fn official_v0_4_rc_6_store_fixture_is_pinned_and_migrates_with_byte_safe_rollback()
    -> Result<()> {
        let fixture_path = workspace_root().join(STABLE_UPGRADE_SOURCE_FIXTURE_PATH);
        assert_eq!(
            super::sha256_file(&fixture_path)?,
            STABLE_UPGRADE_SOURCE_FIXTURE_SHA256
        );
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("release-candidate.db");
        let backup = temp.path().join("release-candidate.backup.db");
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(include_str!("../fixtures/v0.4.0-rc.6-store-v13.sql"))?;
        let schema: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(
            schema,
            release_compatibility().stable_upgrade_source_store_schema_version
        );
        drop(connection);
        fs::copy(&path, &backup)?;
        let backup_bytes = fs::read(&backup)?;

        let mut store = depgraph_store::Store::open(&path)?;
        assert_eq!(
            store.schema_version()?,
            release_compatibility().store_schema_version
        );
        let snapshot_id = store.current_snapshot_id()?.unwrap();
        let snapshot = store.load_completed_snapshot(&snapshot_id)?;
        assert_eq!(
            snapshot_id,
            "snapshot:sha256:9586aa1acd653d75c867037b8d7ebc16241c29197b32217eb878e5f46888dd28"
        );
        assert_eq!(snapshot.scan.id, "official-v0.4.0-rc.1-scan");
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(snapshot.edges.len(), 1);
        assert_eq!(snapshot.evidence.len(), 2);
        assert!(store.verify_snapshot_integrity(&snapshot_id)?.valid);
        store.create_snapshot_name("stable-v0.5.0-upgrade", &snapshot_id)?;
        assert_eq!(
            store.resolve_completed_snapshot_selector("stable-v0.5.0-upgrade")?,
            snapshot_id
        );
        drop(store);
        assert_eq!(fs::read(&backup)?, backup_bytes);
        let backup_connection = rusqlite::Connection::open_with_flags(
            &backup,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let backup_schema: i64 =
            backup_connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(backup_schema, STABLE_UPGRADE_SOURCE_STORE_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn github_settings_verify_command_writes_allow_and_rejects_drift() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let snapshot_path = temp.path().join("snapshot.json");
        let output_path = temp.path().join("evaluation.json");
        let cli = <Cli as clap::Parser>::try_parse_from([
            "cargo-xtask",
            "github-settings-verify",
            snapshot_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ])?;
        assert!(matches!(
            cli.command,
            Task::GithubSettingsVerify {
                snapshot,
                output
            } if snapshot == snapshot_path && output == output_path
        ));

        let desired = depgraph_core::parse_github_settings_desired(include_bytes!(
            "../../.github/settings-desired-v1.json"
        ))?;
        let allow_snapshot = depgraph_core::GitHubSettingsApiSnapshot {
            collection_status: depgraph_core::GitHubSettingsCollectionStatus::Complete,
            settings: Some(desired.clone()),
        };
        fs::write(&snapshot_path, serde_json::to_vec(&allow_snapshot)?)?;
        github_settings_verify(&snapshot_path, &output_path)?;
        let allow: depgraph_core::GitHubSettingsEvaluation =
            serde_json::from_slice(&fs::read(&output_path)?)?;
        assert_eq!(
            allow.decision,
            depgraph_core::PublicReadinessDecision::Allow
        );
        assert!(allow.drift.is_empty());

        let mut drifted = desired;
        drifted.rulesets[0].enforcement = depgraph_core::GitHubRulesetEnforcement::Disabled;
        let reject_snapshot = depgraph_core::GitHubSettingsApiSnapshot {
            collection_status: depgraph_core::GitHubSettingsCollectionStatus::Complete,
            settings: Some(drifted),
        };
        fs::write(&snapshot_path, serde_json::to_vec(&reject_snapshot)?)?;
        let error = github_settings_verify(&snapshot_path, &output_path).unwrap_err();
        assert!(error.to_string().contains("verification rejected"));
        let reject: depgraph_core::GitHubSettingsEvaluation =
            serde_json::from_slice(&fs::read(&output_path)?)?;
        assert_eq!(
            reject.decision,
            depgraph_core::PublicReadinessDecision::Reject
        );
        assert!(
            reject
                .drift
                .iter()
                .any(|drift| drift.reason
                    == depgraph_core::GitHubSettingsDriftReason::RulesetDisabled)
        );
        Ok(())
    }

    #[test]
    fn stable_release_gate_allows_exact_rc_evidence_blocks_unpinned_ga_and_rejects_drift() {
        let target = |target: &str| TargetVerificationReport {
            target: target.to_owned(),
            archive: format!("depgraph-{VERSION}-{target}.tar.gz"),
            archive_sha256: "a".repeat(64),
            release_manifest_sha256: "b".repeat(64),
            sbom_sha256: "c".repeat(64),
            third_party_licenses_sha256: "d".repeat(64),
            project_licenses: BTreeMap::new(),
            mcp_server_sha256: "0".repeat(64),
            operation_runner_sha256: "1".repeat(64),
            mcp_tool_schema_sha256: "2".repeat(64),
            mcp_sdk_version: MCP_SDK_VERSION.to_owned(),
            mcp_protocol_revision: MCP_PROTOCOL_REVISION.to_owned(),
            mcp_tool_contract_version: MCP_TOOL_CONTRACT_VERSION.to_owned(),
            mcp_operation_contract_version: MCP_OPERATION_CONTRACT_VERSION.to_owned(),
            mcp_smoke_sha256: "3".repeat(64),
            mcp_smoke_tool_schema_sha256: "2".repeat(64),
            mcp_smoke_discovery_sha256: "4".repeat(64),
            mcp_smoke_fixture_result_sha256: "5".repeat(64),
            mcp_smoke_submit_deadline_ms: super::mcp_package_smoke::SUBMIT_DEADLINE_MS,
            mcp_smoke_submit_elapsed_ms: 1,
            mcp_smoke_recovered_after_eof: true,
            mcp_smoke_stdin_eof_clean_exit: true,
            mcp_smoke_stdout_json_rpc_only: true,
            runtime_collector_sha256: "d".repeat(64),
            rust_sysroot_sha256: "e".repeat(64),
            framework_build_artifacts: BTreeMap::new(),
            workers: BTreeMap::new(),
            query_smoke_sha256: "f".repeat(64),
            query_plan_digest: format!("bounded-query-plan:sha256:{}", "1".repeat(64)),
            query_result_digest: format!("bounded-query-result:sha256:{}", "2".repeat(64)),
            query_output_sha256: "3".repeat(64),
            profile_plan_digest: format!("profile-selection-plan:sha256:{}", "4".repeat(64)),
            profile_plan_output_sha256: "5".repeat(64),
            cross_language_smoke_sha256: "6".repeat(64),
            cross_language_graph_digest: format!(
                "cross-language-release-graph:sha256:{}",
                "7".repeat(64)
            ),
            cross_language_export_sha256: "8".repeat(64),
            cross_language_query_sha256: "9".repeat(64),
            cross_language_schemas: depgraph_core::cross_language_release_compatibility_contract()
                .schemas
                .into_iter()
                .map(|schema| {
                    (
                        schema.path,
                        schema.sha256.trim_start_matches("sha256:").to_owned(),
                    )
                })
                .collect(),
        };
        let mut release = ReleaseVerificationReport {
            schema_version: 9,
            release_version: STABLE_RELEASE_VERSION.to_owned(),
            tag: format!("v{STABLE_RELEASE_VERSION}"),
            protocol_version: "1.0".to_owned(),
            schema_compatibility_version: "1.0".to_owned(),
            framework_build_graph_contract_version:
                depgraph_core::FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION.to_owned(),
            framework_build_gate_contract_version:
                depgraph_core::FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
            framework_build_capabilities: depgraph_core::framework_build_capability_contract(),
            runtime_collector_contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
            compatibility: release_compatibility(),
            license_expression: PROJECT_LICENSE_EXPRESSION.to_owned(),
            targets: RELEASE_TARGETS
                .iter()
                .map(|(name, _)| target(name))
                .collect(),
        };
        for (index, target) in release.targets.iter_mut().enumerate() {
            let expected = target_native_smoke_expectation(&target.target).unwrap();
            target.query_smoke_sha256 = format!("{:064x}", index + 1);
            target.query_plan_digest = expected.query_plan_digest.to_owned();
            target.query_result_digest = expected.query_result_digest.to_owned();
            target.query_output_sha256 = expected.query_output_sha256.to_owned();
            target.profile_plan_digest = expected.profile_plan_digest.to_owned();
            target.profile_plan_output_sha256 = expected.profile_plan_output_sha256.to_owned();
        }
        let compiler_targets = RELEASE_TARGETS
            .iter()
            .map(|(target, _)| (*target).to_owned())
            .collect::<Vec<_>>();
        let compiler_compatibility =
            depgraph_core::compiler_precise_release_compatibility_contract();
        assert!(compiler_pack_identity_binding(
            &release,
            STABLE_RELEASE_VERSION,
            &compiler_compatibility,
            &compiler_targets,
        ));
        assert!(!compiler_pack_identity_binding(
            &release,
            STABLE_UPGRADE_SOURCE_VERSION,
            &compiler_compatibility,
            &compiler_targets,
        ));
        let mut missing_compiler_target = compiler_targets.clone();
        missing_compiler_target.pop();
        assert!(!compiler_pack_identity_binding(
            &release,
            STABLE_RELEASE_VERSION,
            &compiler_compatibility,
            &missing_compiler_target,
        ));
        let metrics = STABLE_BENCHMARK_METRICS
            .iter()
            .map(|(name, gated)| json!({"name": name, "gated": gated, "passed": true}))
            .collect::<Vec<_>>();
        let benchmark = json!({
            "schema_version": BENCHMARK_REPORT_SCHEMA_VERSION,
            "fixture": {"source_file_count": 10_000},
            "gate": {"passed": true},
            "metrics": metrics,
            "evidence": {
                "bounded_query": {
                    "contract": depgraph_core::bounded_query_release_compatibility_contract(),
                    "admitted": true,
                    "hostile_rejected": true
                }
            }
        });
        let mut workflow_results = BTreeMap::from([
            ("github_actions".to_owned(), "true".to_owned()),
            ("ref_type".to_owned(), "tag".to_owned()),
            ("ref_name".to_owned(), format!("v{STABLE_RELEASE_VERSION}")),
            ("source_sha".to_owned(), "1".repeat(40)),
            ("quality".to_owned(), "success".to_owned()),
            ("compiler-precise-hostile".to_owned(), "success".to_owned()),
            ("benchmark".to_owned(), "success".to_owned()),
            ("package".to_owned(), "success".to_owned()),
            ("verify-assets".to_owned(), "success".to_owned()),
            ("compiler-pack".to_owned(), "success".to_owned()),
            ("verify-compiler-packs".to_owned(), "success".to_owned()),
        ]);

        assert_eq!(
            evaluate_stable_release_gate(
                &release,
                &benchmark,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                true,
                workflow_results.clone(),
            )
            .decision,
            StableReleaseDecision::Reject
        );

        release.tag = format!("v{STABLE_RELEASE_VERSION}-rc.2");
        workflow_results.insert("ref_name".to_owned(), release.tag.clone());
        workflow_results.insert("source_sha".to_owned(), "1".repeat(40));
        let evaluate = |release: &ReleaseVerificationReport, benchmark: &Value| {
            evaluate_stable_release_gate(
                release,
                benchmark,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                true,
                workflow_results.clone(),
            )
        };
        assert_eq!(
            evaluate(&release, &benchmark).decision,
            StableReleaseDecision::Allow
        );

        let mut malformed_prerelease = release.clone();
        malformed_prerelease.tag = format!("v{STABLE_RELEASE_VERSION}-rc.02");
        let mut malformed_prerelease_workflow = workflow_results.clone();
        malformed_prerelease_workflow
            .insert("ref_name".to_owned(), malformed_prerelease.tag.clone());
        malformed_prerelease_workflow.insert("source_sha".to_owned(), "1".repeat(40));
        assert_eq!(
            evaluate_stable_release_gate(
                &malformed_prerelease,
                &benchmark,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                true,
                malformed_prerelease_workflow,
            )
            .decision,
            StableReleaseDecision::Reject
        );

        let mut wrong_version = release.clone();
        wrong_version.release_version = STABLE_UPGRADE_SOURCE_VERSION.to_owned();
        assert_eq!(
            evaluate(&wrong_version, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut missing_target = release.clone();
        missing_target.targets.pop();
        assert_eq!(
            evaluate(&missing_target, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut mcp_sdk_drift = release.clone();
        mcp_sdk_drift.targets[0].mcp_sdk_version = "3.2.0".to_owned();
        assert_eq!(
            evaluate(&mcp_sdk_drift, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut mcp_schema_drift = release.clone();
        mcp_schema_drift.targets[0].mcp_tool_schema_sha256 = "f".repeat(64);
        assert_eq!(
            evaluate(&mcp_schema_drift, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut malformed_mcp_binary_digest = release.clone();
        malformed_mcp_binary_digest.targets[0].mcp_server_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            evaluate(&malformed_mcp_binary_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut mcp_discovery_drift = release.clone();
        mcp_discovery_drift.targets[0].mcp_smoke_discovery_sha256 = "6".repeat(64);
        assert_eq!(
            evaluate(&mcp_discovery_drift, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut mcp_submit_timeout = release.clone();
        mcp_submit_timeout.targets[0].mcp_smoke_submit_elapsed_ms =
            super::mcp_package_smoke::SUBMIT_DEADLINE_MS + 1;
        assert_eq!(
            evaluate(&mcp_submit_timeout, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut mcp_transport_drift = release.clone();
        mcp_transport_drift.targets[0].mcp_smoke_stdout_json_rpc_only = false;
        assert_eq!(
            evaluate(&mcp_transport_drift, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut failed_benchmark = benchmark.clone();
        failed_benchmark["gate"]["passed"] = Value::Bool(false);
        assert_eq!(
            evaluate(&release, &failed_benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut missing_benchmark_metric = benchmark.clone();
        missing_benchmark_metric["metrics"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(
            evaluate(&release, &missing_benchmark_metric).decision,
            StableReleaseDecision::Reject
        );

        let mut unexpected_benchmark_metric = benchmark.clone();
        unexpected_benchmark_metric["metrics"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "unexpected", "gated": true, "passed": true}));
        assert_eq!(
            evaluate(&release, &unexpected_benchmark_metric).decision,
            StableReleaseDecision::Reject
        );

        let mut reordered_benchmark_metrics = benchmark.clone();
        reordered_benchmark_metrics["metrics"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert_eq!(
            evaluate(&release, &reordered_benchmark_metrics).decision,
            StableReleaseDecision::Reject
        );

        let mut benchmark_gated_drift = benchmark.clone();
        benchmark_gated_drift["metrics"][2]["gated"] = Value::Bool(true);
        assert_eq!(
            evaluate(&release, &benchmark_gated_drift).decision,
            StableReleaseDecision::Reject
        );

        let mut missing_observed_metric_result = benchmark.clone();
        missing_observed_metric_result["metrics"][2]
            .as_object_mut()
            .unwrap()
            .remove("passed");
        assert_eq!(
            evaluate(&release, &missing_observed_metric_result).decision,
            StableReleaseDecision::Reject
        );

        let mut failed_gated_metric = benchmark.clone();
        failed_gated_metric["metrics"][0]["passed"] = Value::Bool(false);
        assert_eq!(
            evaluate(&release, &failed_gated_metric).decision,
            StableReleaseDecision::Reject
        );

        let mut malformed_query_digest = release.clone();
        malformed_query_digest.targets[0].query_result_digest =
            "bounded-query-result:sha256:not-a-digest".to_owned();
        assert_eq!(
            evaluate(&malformed_query_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut malformed_profile_digest = release.clone();
        malformed_profile_digest.targets[0].profile_plan_digest =
            "profile-selection-plan:sha256:not-a-digest".to_owned();
        assert_eq!(
            evaluate(&malformed_profile_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut forged_query_digest = release.clone();
        forged_query_digest.targets[0].query_result_digest =
            format!("bounded-query-result:sha256:{}", "9".repeat(64));
        assert_eq!(
            evaluate(&forged_query_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut forged_profile_digest = release.clone();
        forged_profile_digest.targets[0].profile_plan_digest =
            format!("profile-selection-plan:sha256:{}", "9".repeat(64));
        assert_eq!(
            evaluate(&forged_profile_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut cross_language_drift = release.clone();
        cross_language_drift.targets[0].cross_language_query_sha256 = "0".repeat(64);
        assert_eq!(
            evaluate(&cross_language_drift, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut malformed_cross_language_digest = release.clone();
        for target in &mut malformed_cross_language_digest.targets {
            target.cross_language_graph_digest =
                format!("cross-language-release-graph:sha256:{}", "7".repeat(65));
        }
        assert_eq!(
            evaluate(&malformed_cross_language_digest, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut malformed_profile_plan = release.clone();
        for target in &mut malformed_profile_plan.targets {
            target.profile_plan_digest = "profile-selection-plan:sha256:not-a-sha256".to_owned();
        }
        assert_eq!(
            evaluate(&malformed_profile_plan, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut uppercase_profile_plan = release.clone();
        for target in &mut uppercase_profile_plan.targets {
            target.profile_plan_digest =
                format!("profile-selection-plan:sha256:{}", "A".repeat(64));
        }
        assert_eq!(
            evaluate(&uppercase_profile_plan, &benchmark).decision,
            StableReleaseDecision::Reject
        );

        let mut failed_workflow = workflow_results.clone();
        failed_workflow.insert("quality".to_owned(), "failure".to_owned());
        assert_eq!(
            evaluate_stable_release_gate(
                &release,
                &benchmark,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                true,
                failed_workflow,
            )
            .decision,
            StableReleaseDecision::Reject
        );

        let mut failed_hostile = workflow_results.clone();
        failed_hostile.insert("compiler-precise-hostile".to_owned(), "failure".to_owned());
        assert_eq!(
            evaluate_stable_release_gate(
                &release,
                &benchmark,
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                true,
                failed_hostile,
            )
            .decision,
            StableReleaseDecision::Reject
        );

        let mut incompatible_upgrade = release;
        incompatible_upgrade
            .compatibility
            .stable_upgrade_source_store_schema_version += 1;
        assert_eq!(
            evaluate(&incompatible_upgrade, &benchmark).decision,
            StableReleaseDecision::Reject
        );
    }

    #[test]
    fn release_target_matrix_and_executable_names_are_exact() {
        assert_eq!(RELEASE_TARGETS.len(), 5);
        assert_eq!(
            RELEASE_TARGETS
                .iter()
                .map(|(target, _)| *target)
                .collect::<Vec<_>>(),
            vec![
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
            ]
        );
        assert_eq!(
            executable_name_for_target("depgraph", "x86_64-pc-windows-msvc"),
            "depgraph.exe"
        );
        assert_eq!(
            executable_name_for_target("depgraph", "aarch64-apple-darwin"),
            "depgraph"
        );
        assert_eq!(
            RELEASE_CARGO_BUILD_TARGETS,
            [
                ("depgraph-cli", Some("depgraph"), Some("packaged")),
                ("depgraph-mcp", Some("depgraph-mcp"), None),
                (
                    "depgraph-operation",
                    Some("depgraph-operation-runner"),
                    None,
                ),
            ]
        );
    }

    #[test]
    fn windows_archive_executable_extensions_match_compiler_pack_verification() {
        for path in [
            "bin/depgraph.exe",
            "toolchain/run.CMD",
            "toolchain/setup.Bat",
        ] {
            assert!(has_windows_executable_extension(Path::new(path)), "{path}");
        }
        for path in ["toolchain/library.dll", "rust-src/build.sh", "README"] {
            assert!(!has_windows_executable_extension(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn bounded_query_package_smoke_rejects_target_version_and_output_drift() {
        let expected = target_native_smoke_expectation("aarch64-apple-darwin").unwrap();
        let report = BoundedQueryPackageSmokeReport {
            schema_version: BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION.to_owned(),
            target: "aarch64-apple-darwin".to_owned(),
            archive_sha256: "0".repeat(64),
            contract: depgraph_core::bounded_query_release_compatibility_contract(),
            plan_digest: expected.query_plan_digest.to_owned(),
            result_digest: expected.query_result_digest.to_owned(),
            canonical_output_sha256: expected.query_output_sha256.to_owned(),
            profile_contract: depgraph_core::profile_selection_release_compatibility_contract(),
            profile_plan_digest: expected.profile_plan_digest.to_owned(),
            profile_canonical_output_sha256: expected.profile_plan_output_sha256.to_owned(),
        };
        validate_bounded_query_package_smoke(&report, "aarch64-apple-darwin", &"0".repeat(64))
            .unwrap();
        assert!(
            validate_bounded_query_package_smoke(&report, "x86_64-apple-darwin", &"0".repeat(64),)
                .is_err()
        );

        let mut version_drift = report.clone();
        version_drift.contract.limit_version = "bounded-query-limits-v2".to_owned();
        assert!(
            validate_bounded_query_package_smoke(
                &version_drift,
                "aarch64-apple-darwin",
                &"0".repeat(64),
            )
            .is_err()
        );

        let mut archive_drift = report.clone();
        archive_drift.archive_sha256 = "4".repeat(64);
        assert!(
            validate_bounded_query_package_smoke(
                &archive_drift,
                "aarch64-apple-darwin",
                &"0".repeat(64),
            )
            .is_err()
        );

        let mut output_drift = report;
        output_drift.canonical_output_sha256 = "not-a-digest".to_owned();
        assert!(
            validate_bounded_query_package_smoke(
                &output_drift,
                "aarch64-apple-darwin",
                &"0".repeat(64),
            )
            .is_err()
        );

        let mut forged_native_digest = output_drift;
        forged_native_digest.canonical_output_sha256 = expected.query_output_sha256.to_owned();
        forged_native_digest.result_digest =
            format!("bounded-query-result:sha256:{}", "9".repeat(64));
        assert!(
            validate_bounded_query_package_smoke(
                &forged_native_digest,
                "aarch64-apple-darwin",
                &"0".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    fn normalizes_windows_verbatim_paths_for_packaged_external_runtimes() {
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
    fn release_checksum_sidecar_is_filename_and_content_bound() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let archive = temp.path().join("depgraph-test.tar.gz");
        let checksum = temp.path().join("depgraph-test.tar.gz.sha256");
        fs::write(&archive, b"release archive")?;
        let digest = super::sha256_file(&archive)?;
        fs::write(&checksum, format!("{digest}  depgraph-test.tar.gz\n"))?;
        assert_eq!(verify_checksum_sidecar(&archive, &checksum)?, digest);

        fs::write(&checksum, format!("{digest}  renamed.tar.gz\n"))?;
        assert!(verify_checksum_sidecar(&archive, &checksum).is_err());
        Ok(())
    }

    #[test]
    fn release_tag_gate_ignores_non_tag_github_refs() {
        use std::ffi::OsStr;

        verify_release_tag_values(Some(OsStr::new("branch")), Some(OsStr::new("97/merge")))
            .expect("pull-request merge refs are not release tags");
        assert!(verify_release_tag_values(Some(OsStr::new("tag")), None).is_err());
        assert!(
            verify_release_tag_values(Some(OsStr::new("tag")), Some(OsStr::new("v9.9.9")),)
                .is_err()
        );
        verify_release_tag_values(
            Some(OsStr::new("tag")),
            Some(OsStr::new(concat!("v", env!("CARGO_PKG_VERSION")))),
        )
        .expect("the workspace release tag must remain valid");
        verify_release_tag_values(
            Some(OsStr::new("tag")),
            Some(OsStr::new(concat!("v", env!("CARGO_PKG_VERSION"), "-rc.2"))),
        )
        .expect("a canonical workspace release candidate tag must remain valid");
        assert!(
            verify_release_tag_values(
                Some(OsStr::new("tag")),
                Some(OsStr::new(concat!(
                    "v",
                    env!("CARGO_PKG_VERSION"),
                    "-rc.02"
                ))),
            )
            .is_err()
        );
        assert!(!supported_release_tag("v0.4.0"));
        assert!(!supported_release_tag("v0.4.0-rc.7"));
        assert!(supported_release_tag("v0.5.0"));
        assert!(supported_release_tag("v0.5.0-rc.1"));
    }

    fn change_source_mtime(path: &std::path::Path) -> Result<()> {
        let file = fs::File::options().write(true).open(path)?;
        file.set_times(
            fs::FileTimes::new()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)),
        )?;
        Ok(())
    }

    #[test]
    fn rust_worker_handshake_captures_the_exact_backend_compatibility_unit() -> Result<()> {
        let parsed = parse_worker_handshake(
            "depgraph-rust-worker 0.5.0 (protocol 1.0; rust-analyzer 0.0.330; rust-analyzer-revision 8954b66d43225e62c92e8bbcc8500191b5cceb1e; salsa 0.26.1)",
        )
        .expect("valid Rust worker handshake");
        assert_eq!(parsed.name, "depgraph-rust-worker");
        assert_eq!(parsed.version, "0.5.0");
        assert_eq!(parsed.protocol, "1.0");
        let backend = rust_backend_from_handshake(&parsed)?;
        verify_rust_backend(&backend)?;
        assert_eq!(backend.kind, "rust-analyzer-library");
        assert_eq!(backend.version, "0.0.330");
        assert_eq!(backend.revision, "8954b66d43225e62c92e8bbcc8500191b5cceb1e");
        assert_eq!(backend.salsa_version, "0.26.1");
        Ok(())
    }

    #[test]
    fn rust_worker_handshake_rejects_missing_duplicate_or_unknown_backend_fields() {
        for handshake in [
            "depgraph-rust-worker 0.1.0 (protocol 1.0; rust-analyzer 0.0.330; salsa 0.26.1)",
            "depgraph-rust-worker 0.1.0 (protocol 1.0; rust-analyzer 0.0.330; rust-analyzer 0.0.330; rust-analyzer-revision rev; salsa 0.26.1)",
            "depgraph-rust-worker 0.1.0 (protocol 1.0; rust-analyzer 0.0.330; rust-analyzer-revision rev; salsa 0.26.1; sysroot system)",
            "depgraph-rust-worker 0.1.0 (protocol 1.0; rust-analyzer 0.0.330; salsa 0.26.1; rust-analyzer-revision rev)",
        ] {
            let parsed = parse_worker_handshake(handshake);
            assert!(
                parsed
                    .as_ref()
                    .is_none_or(|parsed| rust_backend_from_handshake(parsed).is_err()),
                "{handshake}"
            );
        }
    }

    #[test]
    fn web_worker_handshake_captures_the_release_semantic_compatibility_unit() -> Result<()> {
        let parsed = parse_worker_handshake(
            "depgraph-web-worker 0.5.0 (protocol 1.0; typescript 7.0.2; capabilities astro-component-render-hydration-v1,framework-semantic-completeness-v1,framework-semantic-graph-v1,next-route-component-boundary-v1,tanstack-router-typed-route-v1,tanstack-start-rpc-middleware-v1,typescript-definition-import-type-call-graph-v2,worker-delta-v1)",
        )
        .expect("valid Web worker handshake");
        let semantic = web_semantic_from_handshake(&parsed)?;
        verify_web_semantic_attestation(&semantic)?;
        assert_eq!(semantic.capabilities.len(), WEB_SEMANTIC_CAPABILITIES.len());
        assert_eq!(
            semantic.runtime_components,
            vec![
                "astro-parser-wasm@4.0.0",
                "typescript-native-compiler@7.0.2"
            ]
        );
        assert!(semantic.runtime_artifacts.is_empty());
        Ok(())
    }

    #[test]
    fn web_worker_handshake_rejects_missing_unknown_or_unsorted_capabilities() {
        for handshake in [
            "depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2)",
            "depgraph-web-worker 0.1.0 (protocol 1.0; capabilities framework-semantic-graph-v1; typescript 7.0.2)",
            "depgraph-web-worker 0.1.0 (protocol 1.0; typescript 7.0.2; capabilities framework-semantic-graph-v1)",
        ] {
            let parsed = parse_worker_handshake(handshake);
            assert!(
                parsed.as_ref().is_none_or(|parsed| {
                    web_semantic_from_handshake(parsed)
                        .and_then(|semantic| verify_web_semantic_attestation(&semantic))
                        .is_err()
                }),
                "{handshake}"
            );
        }
    }

    #[test]
    fn web_semantic_manifest_rejects_unknown_compatibility_fields() {
        let result = serde_json::from_value::<WebSemanticAttestation>(json!({
            "typescript_version": TYPESCRIPT_VERSION,
            "capabilities": WEB_SEMANTIC_CAPABILITIES,
            "runtime_components": WEB_SEMANTIC_RUNTIME_COMPONENTS,
            "runtime_artifacts": WEB_SEMANTIC_RUNTIME_ARTIFACTS,
            "project_typescript": "allowed"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn rust_backend_manifest_rejects_unknown_compatibility_fields() {
        let result = serde_json::from_value::<WorkerBackend>(json!({
            "kind": "rust-analyzer-library",
            "version": "0.0.330",
            "revision": "8954b66d43225e62c92e8bbcc8500191b5cceb1e",
            "salsa_version": "0.26.1",
            "undeclared_backend_input": "system"
        }));
        assert!(result.is_err());
    }

    fn rust_analyzer_metadata() -> serde_json::Value {
        json!({
            "metadata": {"depgraph": {"rust-analyzer": {
                "crate-version": "0.0.330",
                "revision": "8954b66d43225e62c92e8bbcc8500191b5cceb1e",
                "salsa-version": "0.26.1"
            }}},
            "packages": [
                {
                    "name": "depgraph-rust-worker",
                    "source": null,
                    "dependencies": [
                        {"name":"ra_ap_hir","req":"=0.0.330","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"ra_ap_ide_db","req":"=0.0.330","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"ra_ap_syntax","req":"=0.0.330","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"ra_ap_vfs","req":"=0.0.330","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"salsa","req":"=0.26.1","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"salsa-macro-rules","req":"=0.26.1","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]},
                        {"name":"salsa-macros","req":"=0.26.1","kind":null,"source":"registry+test","optional":false,"uses_default_features":true,"features":[]}
                    ]
                },
                {"name":"ra_ap_hir","version":"0.0.330","source":"registry+test"},
                {"name":"ra_ap_ide_db","version":"0.0.330","source":"registry+test"},
                {"name":"ra_ap_syntax","version":"0.0.330","source":"registry+test"},
                {"name":"ra_ap_vfs","version":"0.0.330","source":"registry+test"},
                {"name":"salsa","version":"0.26.1","source":"registry+test"},
                {"name":"salsa-macro-rules","version":"0.26.1","source":"registry+test"},
                {"name":"salsa-macros","version":"0.26.1","source":"registry+test"}
            ]
        })
    }

    #[test]
    fn tar_and_zip_archives_are_deterministic_and_normalized() -> Result<()> {
        let (temp, name) = release_tree()?;
        let root = temp.path().join(&name);
        let entries = archive_entries(&root, &name)?;
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            [
                "depgraph-test-target",
                "depgraph-test-target/README.txt",
                "depgraph-test-target/bin",
                "depgraph-test-target/bin/depgraph.exe",
                "depgraph-test-target/empty",
            ]
        );

        let tar_path = temp.path().join("release.tar.gz");
        create_tar_archive(&tar_path, &entries)?;
        let first_tar = fs::read(&tar_path)?;
        change_source_mtime(&root.join("README.txt"))?;
        create_tar_archive(&tar_path, &entries)?;
        assert_eq!(first_tar, fs::read(&tar_path)?);
        assert_eq!(&first_tar[4..8], &0u32.to_le_bytes());
        assert_eq!(first_tar[9], 255);

        let decoder = flate2::read::GzDecoder::new(first_tar.as_slice());
        let mut tar = tar::Archive::new(decoder);
        let mut tar_names = Vec::new();
        for entry in tar.entries()? {
            let entry = entry?;
            tar_names.push(entry.path()?.to_string_lossy().into_owned());
            assert_eq!(entry.header().uid()?, 0);
            assert_eq!(entry.header().gid()?, 0);
            assert_eq!(entry.header().mtime()?, ARCHIVE_MTIME);
            let expected_mode = if entry.path()?.ends_with("bin/depgraph.exe")
                || entry.header().entry_type().is_dir()
            {
                0o755
            } else {
                0o644
            };
            assert_eq!(entry.header().mode()? & 0o777, expected_mode);
        }
        assert_eq!(
            tar_names,
            entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>()
        );

        let zip_path = temp.path().join("release.zip");
        create_zip_archive(&zip_path, &entries)?;
        let first_zip = fs::read(&zip_path)?;
        change_source_mtime(&root.join("README.txt"))?;
        create_zip_archive(&zip_path, &entries)?;
        assert_eq!(first_zip, fs::read(&zip_path)?);

        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(first_zip))?;
        let mut zip_names = Vec::new();
        for index in 0..zip.len() {
            let entry = zip.by_index(index)?;
            zip_names.push(entry.name().trim_end_matches('/').to_owned());
            assert_eq!(entry.last_modified(), Some(zip::DateTime::default()));
            let expected_mode = if entry.name().ends_with("bin/depgraph.exe") || entry.is_dir() {
                0o755
            } else {
                0o644
            };
            assert_eq!(entry.unix_mode().unwrap_or_default() & 0o777, expected_mode);
        }
        assert_eq!(
            zip_names,
            entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>()
        );

        let tar_extract = temp.path().join("tar-extract");
        fs::create_dir(&tar_extract)?;
        extract_archive(&tar_path, &tar_extract)?;
        assert_eq!(
            fs::read(tar_extract.join(&name).join("README.txt"))?,
            b"release\n"
        );
        let zip_extract = temp.path().join("zip-extract");
        fs::create_dir(&zip_extract)?;
        extract_archive(&zip_path, &zip_extract)?;
        assert_eq!(
            fs::read(zip_extract.join(&name).join("README.txt"))?,
            b"release\n"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn release_archives_reject_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let (temp, name) = release_tree()?;
        let root = temp.path().join(&name);
        symlink("README.txt", root.join("linked.txt"))?;
        let error = archive_entries(&root, &name).unwrap_err().to_string();
        assert!(error.contains("refusing symlink in release archive"));
        Ok(())
    }

    #[test]
    fn release_archives_reject_unsafe_root_names() -> Result<()> {
        let (temp, name) = release_tree()?;
        let root = temp.path().join(&name);
        for unsafe_name in ["", ".", "..", "nested/name", "nested\\name"] {
            assert!(
                archive_entries(&root, unsafe_name).is_err(),
                "{unsafe_name:?}"
            );
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn release_archives_reject_cross_platform_separators_in_entries() -> Result<()> {
        let (temp, name) = release_tree()?;
        let root = temp.path().join(&name);
        fs::write(root.join("unsafe\\name"), b"unsafe\n")?;
        let error = archive_entries(&root, &name).unwrap_err().to_string();
        assert!(error.contains("unsafe separator"));
        Ok(())
    }

    #[test]
    fn legacy_licenses_are_normalized_and_invalid_metadata_fails_safe() {
        assert_eq!(
            normalized_spdx_license("MIT / Apache-2.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            normalized_spdx_license("Apache-2.0 / MIT").as_deref(),
            Some("Apache-2.0 OR MIT")
        );
        assert_eq!(
            normalized_spdx_license("MIT/Apache-2.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            normalized_spdx_license("Apache-2.0/MIT").as_deref(),
            Some("Apache-2.0 OR MIT")
        );
        assert_eq!(
            normalized_spdx_license("Unlicense/MIT").as_deref(),
            Some("Unlicense OR MIT")
        );
        assert_eq!(
            normalized_spdx_license("(MIT OR Apache-2.0) AND Unicode-3.0").as_deref(),
            Some("(MIT OR Apache-2.0) AND Unicode-3.0")
        );
        assert_eq!(normalized_spdx_license("SEE LICENSE IN LICENSE.txt"), None);
        assert_eq!(
            normalized_spdx_license("license metadata unavailable"),
            None
        );
    }

    #[test]
    fn rust_analyzer_dependency_gate_accepts_the_exact_lockstep_pin() -> Result<()> {
        verify_rust_analyzer_dependencies(&rust_analyzer_metadata())
    }

    #[test]
    fn rust_analyzer_dependency_gate_rejects_non_exact_direct_requirements() {
        let mut metadata = rust_analyzer_metadata();
        metadata["packages"][0]["dependencies"][0]["req"] = json!("^0.0.330");
        let error = verify_rust_analyzer_dependencies(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("pinned to =0.0.330"), "{error}");
    }

    #[test]
    fn rust_analyzer_dependency_gate_rejects_extra_direct_backend_dependencies() {
        let mut metadata = rust_analyzer_metadata();
        metadata["packages"][0]["dependencies"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name": "ra_ap_base_db",
                "req": "=0.0.330",
                "kind": null,
                "source": "registry+test",
                "optional": false,
                "uses_default_features": true,
                "features": []
            }));
        let error = verify_rust_analyzer_dependencies(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dependency set must be exactly"), "{error}");
    }

    #[test]
    fn rust_analyzer_dependency_gate_rejects_mixed_resolved_versions() {
        let mut metadata = rust_analyzer_metadata();
        metadata["packages"][1]["version"] = json!("0.0.331");
        let error = verify_rust_analyzer_dependencies(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("registry version 0.0.330"), "{error}");
    }

    #[test]
    fn rust_analyzer_dependency_gate_rejects_malformed_revision() {
        let mut metadata = rust_analyzer_metadata();
        metadata["metadata"]["depgraph"]["rust-analyzer"]["revision"] = json!("NOT-A-SHA");
        let error = verify_rust_analyzer_dependencies(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("lowercase 40-character Git SHA"), "{error}");
    }

    #[test]
    fn rust_analyzer_dependency_gate_rejects_project_loading_crates() {
        let mut metadata = rust_analyzer_metadata();
        metadata["packages"].as_array_mut().unwrap().push(json!({
            "name": "ra_ap_project_model",
            "version": "0.0.330",
            "source": "registry+test"
        }));
        let error = verify_rust_analyzer_dependencies(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("project-loading package"), "{error}");
    }

    #[test]
    fn cargo_inventory_follows_release_roots_and_excludes_build_dev_and_xtask_dependencies()
    -> Result<()> {
        let metadata = json!({
            "packages": [
                {"id":"cli","name":"depgraph-cli","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"worker","name":"depgraph-rust-worker","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"mcp","name":"depgraph-mcp","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"operation","name":"depgraph-operation","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"internal","name":"depgraph-core","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"xtask","name":"xtask","version":"0.1.0","source":null,"license":"MIT"},
                {"id":"runtime","name":"runtime-crate","version":"1.0.0","source":"registry+test","license":"MIT"},
                {"id":"runner-runtime","name":"runner-runtime-crate","version":"1.0.0","source":"registry+test","license":"MIT"},
                {"id":"mcp-runtime","name":"mcp-runtime-crate","version":"1.0.0","source":"registry+test","license":"Apache-2.0"},
                {"id":"build","name":"bundled-source-build","version":"2.0.0","source":"registry+test","license":"Apache-2.0"},
                {"id":"dev","name":"test-only","version":"3.0.0","source":"registry+test","license":"MIT"},
                {"id":"spdx","name":"spdx","version":"4.0.0","source":"registry+test","license":"MIT"}
            ],
            "resolve": {"nodes": [
                {"id":"cli","deps":[
                    {"pkg":"internal","dep_kinds":[{"kind":null}]},
                    {"pkg":"runtime","dep_kinds":[{"kind":null}]},
                    {"pkg":"dev","dep_kinds":[{"kind":"dev"}]}
                ]},
                {"id":"worker","deps":[{"pkg":"runtime","dep_kinds":[{"kind":null}]}]},
                {"id":"mcp","deps":[{"pkg":"mcp-runtime","dep_kinds":[{"kind":null}]}]},
                {"id":"operation","deps":[{"pkg":"runner-runtime","dep_kinds":[{"kind":null}]}]},
                {"id":"internal","deps":[{"pkg":"build","dep_kinds":[{"kind":"build"}]}]},
                {"id":"xtask","deps":[{"pkg":"spdx","dep_kinds":[{"kind":null}]}]},
                {"id":"runtime","deps":[]},
                {"id":"runner-runtime","deps":[]},
                {"id":"mcp-runtime","deps":[]},
                {"id":"build","deps":[]},
                {"id":"dev","deps":[]},
                {"id":"spdx","deps":[]}
            ]}
        });
        let names = cargo_runtime_packages(&metadata)?
            .into_iter()
            .map(|package| package.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            names,
            std::collections::BTreeSet::from([
                "runner-runtime-crate".to_owned(),
                "mcp-runtime-crate".to_owned(),
                "runtime-crate".to_owned(),
            ])
        );
        Ok(())
    }

    #[test]
    fn mcp_sdk_dependency_contract_is_locked_and_version_drift_closed() -> Result<()> {
        let metadata = cargo_metadata(&["--features", "depgraph-cli/packaged"])?;
        verify_mcp_dependencies(&metadata)?;

        let mut version_drift = metadata.clone();
        version_drift["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["name"] == "rmcp")
            .unwrap()["version"] = json!("3.2.0");
        assert!(verify_mcp_dependencies(&version_drift).is_err());

        let mut missing_macros = metadata.clone();
        missing_macros["packages"]
            .as_array_mut()
            .unwrap()
            .retain(|package| package["name"] != "rmcp-macros");
        assert!(verify_mcp_dependencies(&missing_macros).is_err());

        let mut direct_dependency_drift = metadata;
        direct_dependency_drift["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["name"] == "depgraph-mcp")
            .unwrap()["dependencies"]
            .as_array_mut()
            .unwrap()
            .retain(|dependency| dependency["name"] != "rmcp");
        assert!(verify_mcp_dependencies(&direct_dependency_drift).is_err());
        Ok(())
    }

    #[test]
    fn web_inventory_requires_artifact_roles() -> Result<()> {
        let inventory = json!({
            "schema_version": 1,
            "packages": [
                {"name":"@astrojs/compiler","version":"4.0.0","license":"MIT","roles":["bundle","runtime-artifact"]},
                {"name":"typescript","version":"7.0.2","license":"Apache-2.0","roles":["bundle"]}
            ]
        });
        let packages = web_runtime_packages(&inventory)?;
        assert_eq!(packages.len(), 2);

        let invalid = json!({
            "schema_version": 1,
            "packages": [{"name":"esbuild","version":"1.0.0","roles":[]}]
        });
        assert!(web_runtime_packages(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn package_urls_encode_scoped_npm_names_and_versions() {
        assert_eq!(
            package_url(&DependencyPackage {
                ecosystem: "npm".to_owned(),
                name: "@typescript/typescript-darwin-arm64".to_owned(),
                version: "7.0.2+native".to_owned(),
                license: "Apache-2.0".to_owned(),
            }),
            "pkg:npm/%40typescript/typescript-darwin-arm64@7.0.2%2Bnative"
        );
        assert_eq!(
            package_url(&DependencyPackage {
                ecosystem: "golang".to_owned(),
                name: "golang.org/x/tools".to_owned(),
                version: "v0.48.0".to_owned(),
                license: "BSD-3-Clause".to_owned(),
            }),
            "pkg:golang/golang.org/x/tools@v0.48.0"
        );
    }
}
