use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

mod compiler_pack_release;
mod go_semantic_e2e;
mod mcp_package_smoke;
mod project_metadata;
mod release_verify_packaged;
mod rust_semantic_e2e;
mod sbom;
mod util;

pub(crate) use util::*;

use project_metadata::verify_project_metadata;
use release_verify_packaged::{verify_archive, verify_packaged_cross_language};
use sbom::{
    cargo_metadata, framework_build_artifact_checksums,
    manifest_framework_build_artifact_checksums, rust_sysroot_license_notice, sbom,
    third_party_licenses, verify_bounded_query_sbom, verify_cross_language_sbom,
    verify_framework_build_sbom, verify_runtime_collector_sbom, verify_rust_analyzer_dependencies,
    verify_rust_sysroot_sbom,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STABLE_RELEASE_GATE_SCHEMA_VERSION: &str = "stable-release-gate-v2";
const RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION: &str = "release-post-publish-evidence-v1";
const STABLE_RELEASE_VERSION: &str = "0.5.4";
const STABLE_RELEASE_BASELINE_STATUS: &str = "maintenance-ref-pinned";
const STABLE_RELEASE_MAINTENANCE_BRANCH: &str = "refs/heads/release/0.5";
const AGENT_DOGFOOD_REPORT_SCHEMA_VERSION: &str = "agent-dogfood-report-v1";
const AGENT_DOGFOOD_REPORT_PATH: &str =
    "fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7/report.json";
const AGENT_DOGFOOD_REPORT_SHA256: &str =
    "3e80eef4481e990984577b8269c5c2eee4c9f17df7a5b4a8ffd3648f6342f12b";
const AGENT_DOGFOOD_SPEC_PATH: &str = "fixtures/agent-dogfood-v1/spec.json";
const AGENT_DOGFOOD_EVIDENCE_DIRECTORY: &str = "fixtures/agent-dogfood-v1/evidence/v0.5.0-rc.7";
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
const MCP_SDK_NAME: &str = depgraph_mcp_tools::MCP_SDK_NAME;
const MCP_SDK_VERSION: &str = depgraph_mcp_tools::MCP_SDK_VERSION;
const MCP_MACROS_VERSION: &str = "3.1.2";
const MCP_PROTOCOL_REVISION: &str = depgraph_mcp_tools::MCP_PROTOCOL_REVISION;
const MCP_TOOL_CONTRACT_VERSION: &str = depgraph_mcp_tools::MCP_TOOLS_CONTRACT_VERSION;
const MCP_OPERATION_CONTRACT_VERSION: &str = depgraph_operation::OPERATION_CONTRACT_VERSION;
const MCP_TOOL_SCHEMA_PATH: &str = "schemas/depgraph-mcp-tools-v1.schema.json";
const MCP_TOOL_SCHEMA_BYTES: &[u8] =
    include_bytes!("../../schemas/depgraph-mcp-tools-v1.schema.json");
const MCP_APACHE_NOTICE: &str = "Apache-2.0 notice: rmcp 3.1.0 and rmcp-macros 3.1.2 are licensed under Apache-2.0; the complete Apache License 2.0 text is packaged as LICENSE-APACHE.";
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
    "integration (ubuntu-24.04, x86_64-unknown-linux-gnu, -C linker-features=-lld)",
    "rust",
    "web",
    "windows-smoke",
];
const STABLE_RELEASE_GATE_CHECK_IDS: &[&str] = &[
    "release-identity",
    "protocol-store-cache-compatibility",
    "rc6-upgrade-and-rollback",
    "five-target-package-closure",
    "mcp-five-target",
    "agent-dogfood-ga",
    "performance-budget",
    "bounded-query-five-target",
    "profile-selection-five-target",
    "cross-language-five-target",
    "compiler-pack-five-target",
    "safety-framework-collector",
    "tag-source-guard-contract",
    "ga-baseline-full-ci",
    "workflow-quality-closure",
];
const V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH: &str =
    "xtask/fixtures/v0.5.0-rc.6-full-ci-run-31867648482.json";
const V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256: &str =
    "335945d35d3b99f169a55c3a7101806a21a6a75cd7b3249ee502cee89eb806cf";
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
        query_plan_digest: "bounded-query-plan:sha256:55eaac2a5f6be85d707ebf402c31995e073641b34bf4627984e68cca7c7a7a3e",
        query_result_digest: "bounded-query-result:sha256:20c747c06fa2cad26fcf6b559e3288aaaf4cc95cb65b6f74cdabfcdffd892246",
        query_output_sha256: "6cbe86c5b11e4a4ac94ac20ceea35d0bcfed7488650000e7d1058681969aff9b",
        profile_plan_digest: "profile-selection-plan:sha256:2d6ae1975930464929de3dba67f62f2290f6aaa10c549d909a1cfcf4eb717b61",
        profile_plan_output_sha256: "12bc417acd93327d558c62744a688d7b704dc4d43e3ca7cd7ada2b6f4f4691af",
    },
    TargetNativeSmokeExpectation {
        target: "aarch64-unknown-linux-gnu",
        query_plan_digest: "bounded-query-plan:sha256:cc99b9e933804d1dfffc6b0e97a3a04c01aa0fecbb36e85a43f03f009fcd33aa",
        query_result_digest: "bounded-query-result:sha256:6717de358653baad6f4f4e2abf86e91822e68fcb54dbe2900dc1f30c37b38c26",
        query_output_sha256: "42b960a16f9842d8040f17866c928c5128e96fa9662006e3eb54625e23b162a0",
        profile_plan_digest: "profile-selection-plan:sha256:70125b85631b7b4be67a98ca951369c8f9b443180aabdd6858f9e78707692a8b",
        profile_plan_output_sha256: "e5b8343b56b4227920873c1106454dff28f866117f23f05990e6796f9137c20b",
    },
    TargetNativeSmokeExpectation {
        target: "x86_64-apple-darwin",
        query_plan_digest: "bounded-query-plan:sha256:32e7bf4742fcfb3d871587f05271cdf9cc1e4a031fcddb8b87ef67119fd95062",
        query_result_digest: "bounded-query-result:sha256:35edbd747a75de3dc132b80e3ff8a3a6c1278389b3421a452342023cb97cbdc0",
        query_output_sha256: "e52109b441a013705f351eda737ad50724f3d46a1d31f63b06dfd0b1712be45f",
        profile_plan_digest: "profile-selection-plan:sha256:8f62b9ef2cd022b8a25146045fb23e7e5982be77b63bacc23d7a570acbd30056",
        profile_plan_output_sha256: "d16c8902cd70289261004985a649a2ab73efa6fda9bf3fe7c0fe218dc35da2e8",
    },
    TargetNativeSmokeExpectation {
        target: "aarch64-apple-darwin",
        query_plan_digest: "bounded-query-plan:sha256:b48c42ce3b8b8b1223ff83265b7d5549b38357df63134f4774443e9109c4d93c",
        query_result_digest: "bounded-query-result:sha256:994d092cbaf879f6c6faa0550c68faa2f534f93dbd6ece60bfa12509da4c17fa",
        query_output_sha256: "36bbc8df8104205d479ed659007310d4b007aa2c1ae3bb6ca13440bdd79ec739",
        profile_plan_digest: "profile-selection-plan:sha256:10f4c03150c9626bb7e96d0fc7975d38d0c0a831b1de1c8f9d407efd30551a9c",
        profile_plan_output_sha256: "b9763738ac03eea4826ba3a7d25d8be0a4c1c85a74d46e392706fbc393f8baec",
    },
    TargetNativeSmokeExpectation {
        target: "x86_64-pc-windows-msvc",
        query_plan_digest: "bounded-query-plan:sha256:70afd8054abde350419f914bcb444b3c1c481b24680ed4e1fd9aa857f4c61bc6",
        query_result_digest: "bounded-query-result:sha256:de6ac0a07a773b30f5c74f6f06e53076bc5657dfe46be153844d4d8359f86d3f",
        query_output_sha256: "2788552b6737c2e501e221ce7e61a6dcd6656e15464d723fd9d6b74f799fe16d",
        profile_plan_digest: "profile-selection-plan:sha256:7264907427af6b7c80911a1fb1e3e4d67d446b5feaff21b426b83521a2f4714c",
        profile_plan_output_sha256: "7379fe0698d3c49b14a1b3a26dbad1ad873a0eb5c93599d49bf31f6024d09a82",
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
        agent_dogfood_report: PathBuf,
        full_ci_run: PathBuf,
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
    /// Verify a public-readiness-v1 bundle without changing repository visibility.
    PublicReadinessVerify {
        /// Closed public-readiness-v1 bundle to verify.
        bundle: PathBuf,
        /// Independently observed default-branch head.
        #[arg(long)]
        candidate_commit: String,
        /// Digest from the independently collected final ref inventory.
        #[arg(long)]
        audited_refs_digest: String,
        /// Digest from the independently collected GitHub settings snapshot.
        #[arg(long)]
        github_settings_digest: String,
        /// Digest from the independently reviewed governance tree.
        #[arg(long)]
        governance_tree_digest: String,
        /// Digest from the stable release gate for the same candidate.
        #[arg(long)]
        release_gate_digest: String,
        /// Redacted deterministic evaluation output.
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

fn v0_5_stable_release_baseline_record(commit: &str) -> String {
    format!(
        "release-baseline-v1\nrepository=TamaT-LLC/depgraph-cli\nversion={STABLE_RELEASE_VERSION}\ncommit={commit}\n"
    )
}

fn v0_5_stable_release_baseline_digest(commit: &str) -> String {
    hex::encode(Sha256::digest(
        v0_5_stable_release_baseline_record(commit).as_bytes(),
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
        "git/refs/tags/$RELEASE_TAG",
    ] {
        if !source_guard.contains(required) {
            bail!("stable release source guard is missing contract {required:?}");
        }
    }
    for required in [
        "guard-stable-tags:",
        "github.event.workflow_run.head_branch == 'v0.5.0'",
        "V0_5_0_RELEASE_SOURCE_SHA: f1071178d3888503b6e02d4aec5e058f0b87d035",
        "github.event.workflow_run.head_branch == 'v0.5.1'",
        "V0_5_1_RELEASE_SOURCE_SHA: 87f3f54d7568b1302be4c15c5377f669ec161396",
        "github.event.workflow_run.head_branch == 'v0.5.2'",
        "V0_5_2_RELEASE_SOURCE_SHA: 08e077b9b2f7dbe6dd919ae75e0c20f559b14cbb",
        "github.event.workflow_run.head_branch == 'v0.5.3'",
        "V0_5_3_RELEASE_SOURCE_SHA: ebac6e8836905164d5e1522f7c87844d5d8e2fe7",
        "STABLE_MAINTENANCE_REF: heads/release/0.5",
        "STABLE_MAIN_REF: heads/main",
        "STABLE_BASELINE_STATUS: maintenance-ref-pinned",
        "signed tag preserved for retry",
        "http_status\" == \"404\"",
        "$STABLE_RELEASE_TAG source $RELEASE_SOURCE_SHA is not the exact main/release/0.5 baseline",
    ] {
        if !source_guard.contains(required) {
            bail!("stable release source guard is missing v0.5 contract {required:?}");
        }
    }
    for required in [
        format!("github.event.workflow_run.head_branch == 'v{STABLE_RELEASE_VERSION}'"),
        format!("STABLE_RELEASE_TAG: v{STABLE_RELEASE_VERSION}"),
    ] {
        if !source_guard.contains(&required) {
            bail!("stable release source guard is missing current contract {required:?}");
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

struct StableReleaseGateInput<'a> {
    release_verification_sha256: String,
    benchmark_report_sha256: String,
    compiler_pack_verification_sha256: String,
    agent_dogfood_report_sha256: String,
    compiler_pack_verified: bool,
    full_ci: &'a FullCiRunEvidence,
    workflow_results: BTreeMap<String, String>,
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
            agent_dogfood_report,
            full_ci_run,
            output,
        } => stable_release_gate(
            &release_verification,
            &benchmark_report,
            &compiler_pack_verification,
            &agent_dogfood_report,
            &full_ci_run,
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
        Task::PublicReadinessVerify {
            bundle,
            candidate_commit,
            audited_refs_digest,
            github_settings_digest,
            governance_tree_digest,
            release_gate_digest,
            output,
        } => public_readiness_verify(
            &bundle,
            depgraph_core::PublicReadinessExpectedState {
                repository: depgraph_core::PUBLIC_READINESS_REPOSITORY.into(),
                candidate_commit,
                audited_refs_digest,
                github_settings_digest,
                governance_tree_digest,
                release_gate_digest,
            },
            &output,
        ),
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
        "npm/test/launcher.test.mjs",
        "npm/test/package-metadata.test.mjs",
        "scripts/tests/benchmark.test.mjs",
        "scripts/tests/cache-hit-benchmark.test.mjs",
        "scripts/tests/agent-dogfood.test.mjs",
        "scripts/tests/release-post-publish-canary.test.mjs",
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
    let checksum = sha256_file(&archive)?;
    let checksum_path = archive.with_extension(format!(
        "{}sha256",
        archive
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| format!("{extension}."))
            .unwrap_or_default()
    ));
    fs::write(
        &checksum_path,
        format!(
            "{checksum}  {}\n",
            archive.file_name().unwrap().to_string_lossy()
        ),
    )?;
    let (query_smoke, cross_language_smoke, mcp_smoke) =
        verify_archive(&archive, &checksum_path, &name)?;
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

fn public_readiness_verify(
    bundle_path: &Path,
    expected: depgraph_core::PublicReadinessExpectedState,
    output: &Path,
) -> Result<()> {
    let bundle: depgraph_core::PublicReadinessBundle =
        serde_json::from_slice(&fs::read(bundle_path).with_context(|| {
            format!(
                "failed to read public readiness bundle {}",
                bundle_path.display()
            )
        })?)
        .context("public readiness bundle does not satisfy its closed schema")?;
    let evaluation = depgraph_core::evaluate_public_readiness(&bundle, &expected)?;
    fs::write(
        output,
        format!("{}\n", serde_json::to_string_pretty(&evaluation)?),
    )
    .with_context(|| {
        format!(
            "failed to write redacted public readiness evaluation {}",
            output.display()
        )
    })?;

    if evaluation.decision == depgraph_core::PublicReadinessDecision::Reject {
        bail!(
            "public readiness verification rejected; redacted evaluation={}",
            output.display()
        );
    }
    println!(
        "public readiness verification allowed; redacted evaluation={}",
        output.display()
    );
    Ok(())
}

fn stable_release_gate(
    release_verification_path: &Path,
    benchmark_report_path: &Path,
    compiler_pack_verification_path: &Path,
    agent_dogfood_report_path: &Path,
    full_ci_run_path: &Path,
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
    let agent_dogfood_report_sha256 = verify_agent_dogfood_release_gate(agent_dogfood_report_path)?;
    let mut workflow_results = stable_release_workflow_results();
    let source_sha = workflow_results
        .get("source_sha")
        .filter(|source_sha| lowercase_git_sha(source_sha))
        .context("stable release gate requires the exact GitHub Actions source SHA")?;
    let full_ci = validate_full_ci_run(full_ci_run_path, source_sha)?;
    workflow_results.insert("full_ci_run_id".to_owned(), full_ci.run_id.to_string());
    workflow_results.insert("full_ci_url".to_owned(), full_ci.url.clone());
    workflow_results.insert("full_ci_head_sha".to_owned(), full_ci.head_sha.clone());
    workflow_results.insert(
        "full_ci_head_branch".to_owned(),
        full_ci.head_branch.clone(),
    );
    workflow_results.insert(
        "full_ci_jobs_sha256".to_owned(),
        hex::encode(Sha256::digest(serde_json::to_vec(&full_ci.jobs)?)),
    );
    workflow_results.insert(
        "agent_dogfood_report_sha256".to_owned(),
        agent_dogfood_report_sha256.clone(),
    );

    let report = evaluate_stable_release_gate(
        &release_verification,
        &benchmark_report,
        StableReleaseGateInput {
            release_verification_sha256: sha256_file(release_verification_path)?,
            benchmark_report_sha256: sha256_file(benchmark_report_path)?,
            compiler_pack_verification_sha256: sha256_file(compiler_pack_verification_path)?,
            agent_dogfood_report_sha256,
            compiler_pack_verified,
            full_ci: &full_ci,
            workflow_results,
        },
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

fn verify_agent_dogfood_release_gate(report_path: &Path) -> Result<String> {
    let report_sha256 = sha256_file(report_path)?;
    if report_sha256 != AGENT_DOGFOOD_REPORT_SHA256 {
        bail!(
            "Agent dogfood report digest mismatch: expected {AGENT_DOGFOOD_REPORT_SHA256}, found {report_sha256}"
        );
    }
    let report: Value = serde_json::from_slice(&fs::read(report_path).with_context(|| {
        format!(
            "failed to read Agent dogfood report {}",
            report_path.display()
        )
    })?)
    .context("Agent dogfood report is not valid JSON")?;
    if report["schema_version"] != AGENT_DOGFOOD_REPORT_SCHEMA_VERSION
        || report["release"]["tag"] != "v0.5.0-rc.7"
        || report["gate"]["passed"] != Value::Bool(true)
        || report["gate"]["checks"].as_array().is_none_or(|checks| {
            checks.len() != 14
                || checks
                    .iter()
                    .any(|check| !check["passed"].as_bool().unwrap_or(false))
        })
    {
        bail!("Agent dogfood report does not contain the exact all-green GA input");
    }

    let root = workspace_root();
    let status = Command::new("node")
        .current_dir(&root)
        .arg("scripts/agent-dogfood.mjs")
        .arg("verify")
        .arg(root.join(AGENT_DOGFOOD_SPEC_PATH))
        .arg(root.join(AGENT_DOGFOOD_EVIDENCE_DIRECTORY))
        .arg(report_path)
        .status()
        .context("failed to launch the deterministic Agent dogfood verifier")?;
    if !status.success() {
        bail!("deterministic Agent dogfood verification rejected the GA input");
    }
    Ok(report_sha256)
}

fn release_post_publish_evidence(request: ReleasePostPublishEvidenceRequest) -> Result<()> {
    verify_project_metadata(&workspace_root())?;
    if !supported_release_tag(&request.tag)
        || !lowercase_git_sha(&request.source_sha)
        || !lowercase_git_sha(&request.source_tree)
        || !lowercase_git_sha(&request.tag_object_sha)
        || !matches!(
            request.tag_signature_verification.as_str(),
            "valid" | "unknown_key" | "unverified_email"
        )
    {
        bail!(
            "post-publish evidence requires a signed canonical v{VERSION} or v{VERSION}-rc.N tag"
        );
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
        &request.source_tree,
        &full_ci,
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
    source_tree: &str,
    full_ci: &FullCiRunEvidence,
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
    let full_ci_jobs_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&full_ci.jobs)?));
    let full_ci_run_id = full_ci.run_id.to_string();
    let expected_baseline_digest = v0_5_stable_release_baseline_digest(source_sha);
    if stable.schema_version != STABLE_RELEASE_GATE_SCHEMA_VERSION
        || stable.release_version != VERSION
        || stable.upgrade_source_version != STABLE_UPGRADE_SOURCE_VERSION
        || stable.tag != tag
        || stable.decision != StableReleaseDecision::Allow
        || stable.release_verification_sha256 != release_sha
        || stable.compiler_pack_verification_sha256 != compiler_sha
        || stable.benchmark_report_sha256 != benchmark_sha
        || stable
            .checks
            .iter()
            .map(|check| check.id.as_str())
            .ne(STABLE_RELEASE_GATE_CHECK_IDS.iter().copied())
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
        || stable
            .workflow_results
            .get("source_tree")
            .map(String::as_str)
            != Some(source_tree)
        || stable
            .workflow_results
            .get("main_head_sha")
            .map(String::as_str)
            != Some(source_sha)
        || stable
            .workflow_results
            .get("maintenance_head_sha")
            .map(String::as_str)
            != Some(source_sha)
        || stable
            .workflow_results
            .get("baseline_digest")
            .map(String::as_str)
            != Some(expected_baseline_digest.as_str())
        || stable
            .workflow_results
            .get("agent_dogfood_report_sha256")
            .map(String::as_str)
            != Some(AGENT_DOGFOOD_REPORT_SHA256)
        || stable
            .workflow_results
            .get("full_ci_run_id")
            .map(String::as_str)
            != Some(full_ci_run_id.as_str())
        || stable
            .workflow_results
            .get("full_ci_url")
            .map(String::as_str)
            != Some(full_ci.url.as_str())
        || stable
            .workflow_results
            .get("full_ci_head_sha")
            .map(String::as_str)
            != Some(full_ci.head_sha.as_str())
        || stable
            .workflow_results
            .get("full_ci_head_branch")
            .map(String::as_str)
            != Some(full_ci.head_branch.as_str())
        || stable
            .workflow_results
            .get("full_ci_jobs_sha256")
            .map(String::as_str)
            != Some(full_ci_jobs_sha256.as_str())
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
    input: StableReleaseGateInput<'_>,
) -> StableReleaseGateReport {
    let StableReleaseGateInput {
        release_verification_sha256,
        benchmark_report_sha256,
        compiler_pack_verification_sha256,
        agent_dogfood_report_sha256,
        compiler_pack_verified,
        full_ci,
        mut workflow_results,
    } = input;
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
    let source_sha = workflow_results
        .get("source_sha")
        .cloned()
        .unwrap_or_default();
    let source_tree = workflow_results
        .get("source_tree")
        .cloned()
        .unwrap_or_default();
    let main_head_sha = workflow_results
        .get("main_head_sha")
        .cloned()
        .unwrap_or_default();
    let maintenance_head_sha = workflow_results
        .get("maintenance_head_sha")
        .cloned()
        .unwrap_or_default();
    let baseline_digest = v0_5_stable_release_baseline_digest(&source_sha);
    workflow_results.insert("baseline_digest".to_owned(), baseline_digest.clone());
    let full_ci_matches_source = lowercase_git_sha(&source_sha)
        && full_ci.run_id != 0
        && full_ci.url == canonical_actions_run_url(full_ci.run_id)
        && full_ci.head_sha == source_sha
        && full_ci.head_branch == "main"
        && full_ci
            .jobs
            .iter()
            .map(|job| job.name.as_str())
            .eq(FULL_CI_JOB_NAMES.iter().copied())
        && full_ci.jobs.iter().all(|job| job.conclusion == "success");
    let stable_baseline_matches_source = release.tag == format!("v{STABLE_RELEASE_VERSION}")
        && source_sha == main_head_sha
        && source_sha == maintenance_head_sha
        && lowercase_git_sha(&source_tree)
        && lowercase_sha256(&baseline_digest);
    let release_source_matches_tag = supported_release_tag(&release.tag)
        && full_ci_matches_source
        && (release.tag != format!("v{STABLE_RELEASE_VERSION}") || stable_baseline_matches_source);
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
            id: "agent-dogfood-ga".to_owned(),
            passed: agent_dogfood_report_sha256 == AGENT_DOGFOOD_REPORT_SHA256,
            evidence: format!(
                "the exact {AGENT_DOGFOOD_REPORT_SCHEMA_VERSION} report passed all fourteen precommitted accuracy, safety, reconnect, setup, and efficiency gates at sha256:{agent_dogfood_report_sha256}"
            ),
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
                "the immutable v0.4.0 and v0.5.0 sources remain enforced; canonical v{STABLE_RELEASE_VERSION}-rc.N tags bind their exact source SHA; stable v{STABLE_RELEASE_VERSION} binds main, {STABLE_RELEASE_MAINTENANCE_BRANCH}, tag, source tree, and full CI at baseline status {STABLE_RELEASE_BASELINE_STATUS}"
            ),
        },
        StableReleaseGateCheck {
            id: "ga-baseline-full-ci".to_owned(),
            passed: full_ci_matches_source
                && (release.tag != format!("v{STABLE_RELEASE_VERSION}")
                    || stable_baseline_matches_source),
            evidence: format!(
                "full CI run {} has the exact eight all-green jobs for main SHA {}; stable baseline digest is sha256:{baseline_digest}",
                full_ci.run_id, full_ci.head_sha
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
        ("source_tree", "DEPGRAPH_RELEASE_SOURCE_TREE"),
        ("main_head_sha", "DEPGRAPH_RELEASE_MAIN_HEAD_SHA"),
        (
            "maintenance_head_sha",
            "DEPGRAPH_RELEASE_MAINTENANCE_HEAD_SHA",
        ),
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
        "flate2",
        "typescript",
        "golang.org/x/tools",
        "ra_ap_hir",
        "ra_ap_ide_db",
        "ra_ap_syntax",
        "ra_ap_vfs",
        "rmcp",
        "rmcp-macros",
        "salsa",
        "tar",
        "zip",
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
    use sha2::{Digest as _, Sha256};

    use super::project_metadata::{
        GithubActionsPolicy, NPM_POST_PUBLISH_RETRY_BLOCK, RECOVERY_PINNED_NODE_SETUP_STEP,
        RECOVERY_VERIFIER_RUN, verify_codeowners, verify_github_actions_security,
        verify_local_markdown_links, verify_mcp_tasks_architecture_decision,
        verify_project_metadata, verify_public_community_surface,
        verify_security_disclosure_dry_run, verify_workflow_policy_text,
    };
    use super::release_verify_packaged::{
        remove_transient_build_run_ids, verify_packaged_cross_language,
    };
    use super::sbom::{
        cargo_metadata, cargo_runtime_packages, normalized_spdx_license, package_url,
        verify_mcp_dependencies, verify_rust_analyzer_dependencies, web_runtime_packages,
    };
    use super::{
        AGENT_DOGFOOD_REPORT_PATH, AGENT_DOGFOOD_REPORT_SHA256, ARCHIVE_MTIME,
        BENCHMARK_REPORT_SCHEMA_VERSION, BOUNDED_QUERY_PACKAGE_SMOKE_SCHEMA_VERSION,
        BoundedQueryPackageSmokeReport, CROSS_LANGUAGE_PACKAGE_SMOKE_SCHEMA_VERSION, Cli,
        CrossLanguagePackageSmokeReport, DependencyPackage, FULL_CI_JOB_NAMES, FullCiJobEvidence,
        FullCiRunEvidence, MCP_OPERATION_CONTRACT_VERSION, MCP_PROTOCOL_REVISION, MCP_SDK_VERSION,
        MCP_TOOL_CONTRACT_VERSION, PROJECT_LICENSE_EXPRESSION, RELEASE_CARGO_BUILD_TARGETS,
        RELEASE_POST_PUBLISH_EVIDENCE_SCHEMA_VERSION, RELEASE_TARGETS,
        RUNTIME_COLLECTOR_CONTRACT_VERSION, RUST_SYSROOT_COMPONENT_SHA256,
        ReleasePostPublishEvidence, ReleasePostPublishEvidenceRequest, ReleaseVerificationReport,
        STABLE_BENCHMARK_METRICS, STABLE_RELEASE_GATE_CHECK_IDS,
        STABLE_RELEASE_GATE_SCHEMA_VERSION, STABLE_RELEASE_VERSION,
        STABLE_UPGRADE_SOURCE_FIXTURE_PATH, STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        STABLE_UPGRADE_SOURCE_STORE_SCHEMA_VERSION, STABLE_UPGRADE_SOURCE_VERSION,
        StableReleaseDecision, StableReleaseGateInput, TYPESCRIPT_VERSION,
        TargetVerificationReport, Task, V0_2_RC1_STORE_SCHEMA_VERSION,
        V0_4_RC1_STORE_SCHEMA_VERSION, V0_4_STABLE_RELEASE_BASELINE_DIGEST,
        V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH, V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256, VERSION,
        WEB_SEMANTIC_CAPABILITIES, WEB_SEMANTIC_RUNTIME_ARTIFACTS, WEB_SEMANTIC_RUNTIME_COMPONENTS,
        WebSemanticAttestation, WorkerBackend, archive_entries, canonical_actions_run_url,
        compiler_pack_identity_binding, create_tar_archive, create_zip_archive,
        evaluate_stable_release_gate, executable_name_for_target, expected_release_asset_names,
        extract_archive, github_settings_verify, has_windows_executable_extension,
        parse_worker_handshake, public_readiness_verify, release_compatibility,
        release_post_publish_evidence, rust_backend_from_handshake, rustc_source_identity,
        supported_release_tag, target_native_smoke_expectation,
        v0_4_stable_release_baseline_digest, validate_bounded_query_package_smoke,
        validate_cross_language_package_smoke, validate_full_ci_run,
        verify_agent_dogfood_release_gate, verify_checksum_sidecar,
        verify_cross_language_package_smoke, verify_pinned_rust_sysroot_digest,
        verify_release_tag_values, verify_rust_backend, verify_stable_release_source_guard,
        verify_web_semantic_attestation, web_semantic_from_handshake,
        without_windows_verbatim_prefix, workspace_root,
    };

    fn post_publish_evidence_fixture(
        tag: &str,
    ) -> Result<(tempfile::TempDir, ReleasePostPublishEvidenceRequest)> {
        let temp = tempfile::tempdir()?;
        let workflow = temp.path().join("workflow");
        let public = temp.path().join("public");
        fs::create_dir_all(&workflow)?;
        fs::create_dir_all(&public)?;
        let source_sha = "a".repeat(40);
        let source_tree = "b".repeat(40);
        let tag_object_sha = "c".repeat(40);
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
        let full_ci_jobs = FULL_CI_JOB_NAMES
            .iter()
            .map(|name| FullCiJobEvidence {
                name: (*name).to_owned(),
                conclusion: "success".to_owned(),
            })
            .collect::<Vec<_>>();
        let full_ci_jobs_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&full_ci_jobs)?));
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
                    "source_tree": source_tree,
                    "main_head_sha": source_sha,
                    "maintenance_head_sha": source_sha,
                    "baseline_digest": super::v0_5_stable_release_baseline_digest(&source_sha),
                    "agent_dogfood_report_sha256": AGENT_DOGFOOD_REPORT_SHA256,
                    "full_ci_run_id": "123",
                    "full_ci_url": "https://github.com/TamaT-LLC/depgraph-cli/actions/runs/123",
                    "full_ci_head_sha": source_sha,
                    "full_ci_head_branch": "main",
                    "full_ci_jobs_sha256": full_ci_jobs_sha256,
                    "quality": "success",
                    "compiler-precise-hostile": "success",
                    "benchmark": "success",
                    "package": "success",
                    "verify-assets": "success",
                    "compiler-pack": "success",
                    "verify-compiler-packs": "success"
                },
                "checks": STABLE_RELEASE_GATE_CHECK_IDS.iter().map(|id| json!({
                    "id": id,
                    "passed": true,
                    "evidence": "fixture",
                })).collect::<Vec<_>>(),
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
    fn japanese_readme_shared_contract_drift_is_rejected() -> Result<()> {
        let readme = super::read_lf_normalized_text(&workspace_root().join("README.md"))?;
        let english_readme =
            super::read_lf_normalized_text(&workspace_root().join("README.en.md"))?;
        super::project_metadata::verify_japanese_readme_contract(&readme, &english_readme)?;

        let store_schema = format!(
            "tag後の現行`main`はStore schema `{0}`を使用し、schema {0}へ移行したStoreを`v0.5.4` binaryで開くことはできない。",
            depgraph_store::STORE_SCHEMA_VERSION
        );
        let drifted_schema = readme.replacen(
            &store_schema,
            "tag後の現行`main`はStore schema `999`を使用し、schema 999へ移行したStoreを`v0.5.4` binaryで開くことはできない。",
            1,
        );
        assert_ne!(drifted_schema, readme);
        assert!(
            super::project_metadata::verify_japanese_readme_contract(
                &drifted_schema,
                &english_readme
            )
            .is_err()
        );

        for example in super::project_metadata::readme_cli_examples(&readme) {
            let drifted_example = format!("{example} --invalid-readme-contract");
            let drifted_readme = readme.replacen(example, &drifted_example, 1);
            assert_ne!(drifted_readme, readme);
            assert!(
                super::project_metadata::verify_japanese_readme_contract(
                    &drifted_readme,
                    &english_readme
                )
                .is_err(),
                "Japanese README CLI drift was accepted: {example}"
            );
        }

        let drifted_exit_code = readme.replacen(
            "| 0 | ポリシー違反なしで処理が完了した |",
            "| 0 | 常に失敗する |",
            1,
        );
        assert_ne!(drifted_exit_code, readme);
        assert!(
            super::project_metadata::verify_japanese_readme_contract(
                &drifted_exit_code,
                &english_readme
            )
            .is_err()
        );

        let drifted_target = readme.replacen("x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu", 1);
        assert_ne!(drifted_target, readme);
        assert!(
            super::project_metadata::verify_japanese_readme_contract(
                &drifted_target,
                &english_readme
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn post_publish_evidence_binds_exact_public_assets_and_full_ci() -> Result<()> {
        let tag = format!("v{STABLE_RELEASE_VERSION}-rc.1");
        let (_temp, request) = post_publish_evidence_fixture(&tag)?;
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
    fn post_publish_evidence_accepts_the_exact_stable_tag() -> Result<()> {
        let tag = format!("v{STABLE_RELEASE_VERSION}");
        let (_temp, request) = post_publish_evidence_fixture(&tag)?;
        release_post_publish_evidence(request)
    }

    #[test]
    fn full_ci_job_identity_matches_captured_github_api_response() -> Result<()> {
        let fixture = workspace_root().join(V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH);
        assert_eq!(
            super::sha256_file_streaming(&fixture)?,
            V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256
        );
        let source_sha = "7b0cd4cb31067874a71854c212be037b00519889";
        let run = validate_full_ci_run(&fixture, source_sha)?;
        assert_eq!(run.run_id, 31_867_648_482);
        assert_eq!(run.head_sha, source_sha);
        assert_eq!(run.jobs.len(), 8);
        assert!(run.jobs.iter().any(|job| {
            job.name
                == "integration (ubuntu-24.04, x86_64-unknown-linux-gnu, -C linker-features=-lld)"
                && job.conclusion == "success"
        }));
        Ok(())
    }

    #[test]
    fn full_ci_job_identity_rejects_the_stale_linux_display_name() -> Result<()> {
        let fixture = workspace_root().join(V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH);
        let mut input: Value = serde_json::from_slice(&fs::read(fixture)?)?;
        let linux = input["jobs"]
            .as_array_mut()
            .expect("captured Full CI jobs")
            .iter_mut()
            .find(|job| {
                job["name"]
                    == "integration (ubuntu-24.04, x86_64-unknown-linux-gnu, -C linker-features=-lld)"
            })
            .expect("captured Linux integration job");
        linux["name"] = json!("integration (ubuntu-24.04, x86_64-unknown-linux-gnu)");

        let temp = tempfile::tempdir()?;
        let stale = temp.path().join("stale-full-ci.json");
        fs::write(&stale, serde_json::to_vec(&input)?)?;
        let error = validate_full_ci_run(&stale, "7b0cd4cb31067874a71854c212be037b00519889")
            .expect_err("stale implicit matrix job identity must fail closed");
        assert_eq!(
            error.to_string(),
            "full CI evidence is not the exact all-green candidate run"
        );
        Ok(())
    }

    #[test]
    fn post_publish_evidence_rejects_public_tamper_skipped_or_rebound_full_ci() -> Result<()> {
        let prerelease_tag = format!("v{STABLE_RELEASE_VERSION}-rc.1");
        let (_temp, request) = post_publish_evidence_fixture(&prerelease_tag)?;
        fs::write(
            request.public_assets.join("benchmark-report.json"),
            b"tampered\n",
        )?;
        assert!(release_post_publish_evidence(request).is_err());

        let (_temp, request) = post_publish_evidence_fixture(&prerelease_tag)?;
        let mut full_ci: Value = serde_json::from_slice(&fs::read(&request.ci_run)?)?;
        full_ci["jobs"].as_array_mut().expect("fixture jobs").pop();
        fs::write(&request.ci_run, serde_json::to_vec(&full_ci)?)?;
        assert!(release_post_publish_evidence(request).is_err());

        let stable_tag = format!("v{STABLE_RELEASE_VERSION}");
        let (_temp, request) = post_publish_evidence_fixture(&stable_tag)?;
        let stable_name = "stable-release-gate.json";
        let mut stable: Value =
            serde_json::from_slice(&fs::read(request.workflow_assets.join(stable_name))?)?;
        stable["workflow_results"]["full_ci_run_id"] = json!("124");
        let stable = serde_json::to_vec(&stable)?;
        fs::write(request.workflow_assets.join(stable_name), &stable)?;
        fs::write(request.public_assets.join(stable_name), stable)?;
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
    fn codeowners_verification_accepts_crlf_and_rejects_owner_drift() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let codeowners = temp.path().join("CODEOWNERS");
        fs::write(
            &codeowners,
            b"# Require an owner review for every change in this repository.\r\n* @TakehiroT @Fuelda\r\n",
        )?;
        verify_codeowners(&codeowners)?;

        fs::write(
            &codeowners,
            b"# Require an owner review for every change in this repository.\r\n* @unexpected-owner @Fuelda\r\n",
        )?;
        assert!(verify_codeowners(&codeowners).is_err());
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

        for workflow_name in [
            "ci.yml",
            "npm-release.yml",
            "release-post-publish-recovery.yml",
            "release.yml",
            "stable-release-source-guard.yml",
        ] {
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
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
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

        let missing_go_cache_path = ci.replacen(
            "          cache-dependency-path: workers/go/go.sum\n",
            "",
            1,
        );
        assert!(
            verify_workflow_policy_text(
                "ci.yml",
                &missing_go_cache_path,
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
            "- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
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
        let relocated_publish_permissions = format!(
            "{}\n  evidence-proxy:\n    permissions:\n      actions: read\n      contents: write\n    runs-on: ubuntu-24.04\n    steps: []\n",
            release.replacen(
                "    permissions:\n      actions: read\n      contents: write",
                "    permissions:\n      contents: read",
                1,
            )
        );
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &relocated_publish_permissions,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
        let extra_publish_read_scope = release.replacen(
            "      contents: write",
            "      contents: write\n      issues: read",
            1,
        );
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &extra_publish_read_scope,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
        let missing_actions_read = release.replacen("      actions: read\n", "", 1);
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &missing_actions_read,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
        let writable_actions = release.replacen("      actions: read", "      actions: write", 1);
        assert!(
            verify_workflow_policy_text(
                "release.yml",
                &writable_actions,
                &pins,
                &mut BTreeSet::new(),
            )
            .is_err()
        );
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
        let package_node_then_pnpm = "      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0\n        with:\n          node-version: 24.18.0\n      - uses: pnpm/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86 # v6.0.10\n        with:\n          version: 10.33.0\n          standalone: false\n";
        let package_pnpm_then_node = "      - uses: pnpm/action-setup@0977fd99725f1db4007ccb2928dbb4e90d06cc86 # v6.0.10\n        with:\n          version: 10.33.0\n          standalone: false\n      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0\n        with:\n          node-version: 24.18.0\n";
        for package_setup_drift in [
            release.replacen(package_node_then_pnpm, package_pnpm_then_node, 1),
            release.replacen(
                "          standalone: false",
                "          standalone: true",
                1,
            ),
            release.replacen(
                "          standalone: false",
                "          standalone: false\n          standalone: false",
                1,
            ),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "release.yml",
                    &package_setup_drift,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }
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

        let npm_release = fs::read_to_string(root.join(".github/workflows/npm-release.yml"))?;
        let relocated_npm_retry = npm_release
            .replacen(NPM_POST_PUBLISH_RETRY_BLOCK, "", 1)
            .replacen(
                "          done < <(jq -r '.packages[] | [.name, .version, .tarball, .sha256, .integrity] | @tsv' \"$inventory\")\n",
                &format!(
                    "          done < <(jq -r '.packages[] | [.name, .version, .tarball, .sha256, .integrity] | @tsv' \"$inventory\")\n{NPM_POST_PUBLISH_RETRY_BLOCK}"
                ),
                1,
            );
        for drifted_npm_release in [
            npm_release.replacen("      actions: read\n", "", 1),
            npm_release.replacen("      id-token: write", "      contents: write", 1),
            npm_release.replacen("    environment: npm", "    environment: unreviewed", 1),
            npm_release.replacen(
                "          ref: ${{ github.sha }}",
                "          ref: main",
                1,
            ),
            npm_release.replacen(
                "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                1,
            ),
            npm_release.replacen(" --provenance", "", 1),
            npm_release.replacen("    timeout-minutes: 210", "    timeout-minutes: 180", 1),
            npm_release.replacen(
                "            for attempt in {1..60}; do",
                "            for attempt in 1 2 3 4 5; do",
                1,
            ),
            npm_release.replacen(
                "              if npm view \"${package}@${version}\" dist.integrity --json >\"$view_output\" 2>\"$view_error\"; then",
                "              actual_integrity=\"$(npm view \"${package}@${version}\" dist.integrity --json 2>/dev/null | jq -r '.')\"\n              if test -n \"$actual_integrity\"; then",
                1,
            ),
            npm_release.replacen("                sleep 30", "                sleep 1", 1),
            relocated_npm_retry,
            format!("{npm_release}\n# ${{{{ secrets.NPM_TOKEN }}}}\n"),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "npm-release.yml",
                    &drifted_npm_release,
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

        let recovery =
            fs::read_to_string(root.join(".github/workflows/release-post-publish-recovery.yml"))?;
        for drifted_recovery in [
            recovery.replacen("      contents: read", "      contents: write", 1),
            recovery.replacen(
                RECOVERY_PINNED_NODE_SETUP_STEP,
                "      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0\n      - name: Detached Node version text\n        run: echo 'node-version: 24.18.0'\n",
                1,
            ),
            recovery
                .replacen(RECOVERY_PINNED_NODE_SETUP_STEP, "", 1)
                .replacen(
                    RECOVERY_VERIFIER_RUN,
                    &format!(
                        "{RECOVERY_VERIFIER_RUN}\n{RECOVERY_PINNED_NODE_SETUP_STEP}"
                    ),
                    1,
                ),
            recovery
                .replacen(RECOVERY_PINNED_NODE_SETUP_STEP, "", 1)
                .replacen(
                    "    steps:\n",
                    &format!(
                        "    decoy:\n{RECOVERY_PINNED_NODE_SETUP_STEP}    steps:\n"
                    ),
                    1,
                ),
            recovery.replacen(
                "  workflow_dispatch:\n",
                "  workflow_dispatch:\n    inputs:\n      tag:\n        required: true\n",
                1,
            ),
            recovery.replacen(
                "run: scripts/release-post-publish-recovery.sh",
                "run: gh release upload v0.5.0 replacement.json",
                1,
            ),
        ] {
            assert!(
                verify_workflow_policy_text(
                    "release-post-publish-recovery.yml",
                    &drifted_recovery,
                    &pins,
                    &mut BTreeSet::new(),
                )
                .is_err()
            );
        }

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

    fn public_readiness_fixture() -> (
        depgraph_core::PublicReadinessBundle,
        depgraph_core::PublicReadinessExpectedState,
    ) {
        const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
        const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        let mut manifest = depgraph_core::PublicReadinessEvidenceManifest {
            schema_version: depgraph_core::PUBLIC_READINESS_EVIDENCE_SCHEMA_VERSION.into(),
            repository: depgraph_core::PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
            generated_at: "2026-07-26T00:02:00Z".into(),
            evidence: Vec::new(),
        };
        let input_digest = depgraph_core::public_readiness_evidence_input_digest(&manifest);
        manifest.evidence = depgraph_core::PUBLIC_READINESS_GATE_IDS
            .iter()
            .enumerate()
            .map(|(index, gate_id)| {
                let mut evidence = depgraph_core::PublicReadinessEvidence {
                    gate_id: (*gate_id).into(),
                    evidence_digest: String::new(),
                    input_digest: input_digest.clone(),
                    started_at: "2026-07-26T00:00:00Z".into(),
                    ended_at: format!("2026-07-26T00:01:{index:02}Z"),
                    producer_role: "repository-administrator".into(),
                    producer_identity: "team:readiness-producers".into(),
                    approver_role: "independent-code-reviewer".into(),
                    approver_identity: "team:readiness-gate-reviewers".into(),
                    tool: depgraph_core::PublicReadinessToolIdentity {
                        name: "readiness-auditor".into(),
                        version: "1.0.0".into(),
                        acquisition_digest: HASH_B.into(),
                        configuration_digest: HASH_C.into(),
                    },
                    findings: depgraph_core::PublicReadinessFindingSummary {
                        resolved: 0,
                        unresolved: 0,
                    },
                };
                evidence.evidence_digest =
                    depgraph_core::public_readiness_evidence_digest(&evidence).unwrap();
                evidence
            })
            .collect();
        let evidence_manifest_digest =
            depgraph_core::canonical_public_readiness_digest(&manifest).unwrap();
        let gates = manifest
            .evidence
            .iter()
            .map(|evidence| depgraph_core::PublicReadinessGate {
                id: evidence.gate_id.clone(),
                decision: depgraph_core::PublicReadinessDecision::Allow,
                evidence_digest: evidence.evidence_digest.clone(),
                producer_role: evidence.producer_role.clone(),
                producer_identity: evidence.producer_identity.clone(),
                approver_role: evidence.approver_role.clone(),
                approver_identity: evidence.approver_identity.clone(),
            })
            .collect();
        let mut record = depgraph_core::PublicReadinessRecord {
            schema_version: depgraph_core::PUBLIC_READINESS_SCHEMA_VERSION.into(),
            repository: depgraph_core::PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
            evidence_manifest_digest,
            gates,
            decision: depgraph_core::PublicReadinessDecision::Allow,
            decided_at: "2026-07-26T00:04:00Z".into(),
            accountable_role: "tamat-llc-organization-owner".into(),
            approvals: depgraph_core::PUBLIC_READINESS_FINAL_APPROVAL_ROLES
                .iter()
                .map(|role| depgraph_core::PublicReadinessApproval {
                    role: (*role).into(),
                    identity: format!("team:{role}s"),
                    approved_at: "2026-07-26T00:03:00Z".into(),
                    statement_digest: String::new(),
                })
                .collect(),
        };
        let statement_digests = record
            .approvals
            .iter()
            .map(|approval| {
                depgraph_core::public_readiness_approval_statement_digest(
                    &record,
                    &approval.role,
                    &approval.identity,
                )
            })
            .collect::<Vec<_>>();
        for (approval, statement_digest) in record.approvals.iter_mut().zip(statement_digests) {
            approval.statement_digest = statement_digest;
        }
        let expected = depgraph_core::PublicReadinessExpectedState {
            repository: depgraph_core::PUBLIC_READINESS_REPOSITORY.into(),
            candidate_commit: COMMIT.into(),
            audited_refs_digest: HASH_A.into(),
            github_settings_digest: HASH_B.into(),
            governance_tree_digest: HASH_C.into(),
            release_gate_digest: HASH_D.into(),
        };
        (
            depgraph_core::PublicReadinessBundle {
                record,
                evidence_manifest: manifest,
            },
            expected,
        )
    }

    #[test]
    fn public_readiness_verify_command_binds_expected_state_and_writes_reject() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bundle_path = temp.path().join("bundle.json");
        let output_path = temp.path().join("evaluation.json");
        let (bundle, expected) = public_readiness_fixture();
        fs::write(&bundle_path, serde_json::to_vec(&bundle)?)?;

        let cli = <Cli as clap::Parser>::try_parse_from([
            "cargo-xtask",
            "public-readiness-verify",
            bundle_path.to_str().unwrap(),
            "--candidate-commit",
            &expected.candidate_commit,
            "--audited-refs-digest",
            &expected.audited_refs_digest,
            "--github-settings-digest",
            &expected.github_settings_digest,
            "--governance-tree-digest",
            &expected.governance_tree_digest,
            "--release-gate-digest",
            &expected.release_gate_digest,
            "--output",
            output_path.to_str().unwrap(),
        ])?;
        assert!(matches!(
            cli.command,
            Task::PublicReadinessVerify { bundle, output, .. }
                if bundle == bundle_path && output == output_path
        ));

        public_readiness_verify(&bundle_path, expected.clone(), &output_path)?;
        let allow: depgraph_core::PublicReadinessEvaluation =
            serde_json::from_slice(&fs::read(&output_path)?)?;
        assert_eq!(
            allow.decision,
            depgraph_core::PublicReadinessDecision::Allow
        );
        assert!(allow.reasons.is_empty());

        let mut stale = expected;
        stale.github_settings_digest =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into();
        let error = public_readiness_verify(&bundle_path, stale, &output_path).unwrap_err();
        assert!(error.to_string().contains("verification rejected"));
        let reject: depgraph_core::PublicReadinessEvaluation =
            serde_json::from_slice(&fs::read(&output_path)?)?;
        assert_eq!(
            reject.decision,
            depgraph_core::PublicReadinessDecision::Reject
        );
        assert!(
            reject
                .reasons
                .contains(&depgraph_core::PublicReadinessRejectionReason::CandidateStateStale)
        );
        Ok(())
    }

    #[test]
    fn agent_dogfood_release_gate_is_digest_pinned_and_recomputed() -> Result<()> {
        let canonical = workspace_root().join(AGENT_DOGFOOD_REPORT_PATH);
        assert_eq!(
            verify_agent_dogfood_release_gate(&canonical)?,
            AGENT_DOGFOOD_REPORT_SHA256
        );

        let temp = tempfile::tempdir()?;
        let tampered = temp.path().join("report.json");
        let mut bytes = fs::read(canonical)?;
        bytes.push(b'\n');
        fs::write(&tampered, bytes)?;
        let error = verify_agent_dogfood_release_gate(&tampered).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));
        Ok(())
    }

    #[test]
    fn stable_release_gate_allows_pinned_ga_and_exact_rc_evidence_and_rejects_drift() {
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
        let full_ci = FullCiRunEvidence {
            run_id: 42,
            url: canonical_actions_run_url(42),
            head_sha: "1".repeat(40),
            head_branch: "main".to_owned(),
            jobs: FULL_CI_JOB_NAMES
                .iter()
                .map(|name| FullCiJobEvidence {
                    name: (*name).to_owned(),
                    conclusion: "success".to_owned(),
                })
                .collect(),
        };
        let gate_input = |workflow_results| StableReleaseGateInput {
            release_verification_sha256: "a".repeat(64),
            benchmark_report_sha256: "b".repeat(64),
            compiler_pack_verification_sha256: "c".repeat(64),
            agent_dogfood_report_sha256: AGENT_DOGFOOD_REPORT_SHA256.to_owned(),
            compiler_pack_verified: true,
            full_ci: &full_ci,
            workflow_results,
        };

        assert_eq!(
            evaluate_stable_release_gate(
                &release,
                &benchmark,
                gate_input(workflow_results.clone()),
            )
            .decision,
            StableReleaseDecision::Reject
        );

        let mut pinned_stable_workflow = workflow_results.clone();
        pinned_stable_workflow.insert("source_tree".to_owned(), "2".repeat(40));
        pinned_stable_workflow.insert("main_head_sha".to_owned(), "1".repeat(40));
        pinned_stable_workflow.insert("maintenance_head_sha".to_owned(), "1".repeat(40));
        assert_eq!(
            evaluate_stable_release_gate(
                &release,
                &benchmark,
                gate_input(pinned_stable_workflow.clone()),
            )
            .decision,
            StableReleaseDecision::Allow
        );
        pinned_stable_workflow.insert("maintenance_head_sha".to_owned(), "3".repeat(40));
        assert_eq!(
            evaluate_stable_release_gate(&release, &benchmark, gate_input(pinned_stable_workflow),)
                .decision,
            StableReleaseDecision::Reject
        );

        release.tag = format!("v{STABLE_RELEASE_VERSION}-rc.2");
        workflow_results.insert("ref_name".to_owned(), release.tag.clone());
        workflow_results.insert("source_sha".to_owned(), "1".repeat(40));
        let evaluate = |release: &ReleaseVerificationReport, benchmark: &Value| {
            evaluate_stable_release_gate(release, benchmark, gate_input(workflow_results.clone()))
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
                gate_input(malformed_prerelease_workflow),
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
            evaluate_stable_release_gate(&release, &benchmark, gate_input(failed_workflow),)
                .decision,
            StableReleaseDecision::Reject
        );

        let mut failed_hostile = workflow_results.clone();
        failed_hostile.insert("compiler-precise-hostile".to_owned(), "failure".to_owned());
        assert_eq!(
            evaluate_stable_release_gate(&release, &benchmark, gate_input(failed_hostile),)
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
        assert!(!supported_release_tag("v0.5.0"));
        assert!(!supported_release_tag("v0.5.0-rc.1"));
        assert!(supported_release_tag(&format!("v{STABLE_RELEASE_VERSION}")));
        assert!(supported_release_tag(&format!(
            "v{STABLE_RELEASE_VERSION}-rc.1"
        )));
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
