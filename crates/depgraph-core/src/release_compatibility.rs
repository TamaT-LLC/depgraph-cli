use depgraph_store::{CACHE_CONTRACT_VERSION, SNAPSHOT_DIFF_SCHEMA_VERSION, STORE_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};

use crate::{
    ASTRO_BUILD_CAPABILITY, ASTRO_BUILD_OBSERVATION_SCHEMA, ASTRO_BUILD_OBSERVER,
    ASTRO_BUILD_OBSERVER_VERSION, BOUNDED_QUERY_CONTRACT_VERSION, BOUNDED_QUERY_LIMIT_VERSION,
    BOUNDED_QUERY_PLAN_SCHEMA_VERSION, BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION,
    BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH, BOUNDED_QUERY_RELEASE_SMOKE_QUERY,
    BOUNDED_QUERY_RESULT_SCHEMA_VERSION, BOUNDED_QUERY_STATISTICS_VERSION,
    BOUNDED_QUERY_TYPE_CONTRACT_VERSION, COMPILER_PACK_CHANNEL_MANIFEST,
    COMPILER_PACK_CHANNEL_MANIFEST_SHA256, COMPILER_PACK_DISTRIBUTION,
    COMPILER_PACK_FALLBACK_POLICY, COMPILER_PACK_MANIFEST_SCHEMA_VERSION,
    COMPILER_PACK_RELEASE_CONTRACT_VERSION, COMPILER_PACK_RUST_RELEASE, COMPILER_PACK_RUSTC_COMMIT,
    COMPILER_PACK_SUPPORTED_TARGETS, COMPILER_PACK_TOOLCHAIN_CHANNEL,
    COMPILER_PACK_WRAPPER_PROTOCOL_VERSION, COMPILER_PRECISE_CONTRACT_VERSION,
    COMPILER_PRECISE_MIR_SCHEMA_VERSION, CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION,
    CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE, CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH,
    DAEMON_STATUS_SCHEMA_VERSION, DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION,
    DEFAULT_PROFILE_SELECTION_LIMIT_VERSION, DEFAULT_PROFILE_SELECTION_SCHEMA,
    DEFAULT_PROFILE_SELECTION_SCHEMA_PATH, EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA,
    EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA_PATH, FRAMEWORK_BUILD_CONVERTER_ARTIFACT,
    FRAMEWORK_BUILD_GATE_CONTRACT_VERSION, FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION,
    GO_PROFILE_PLANNING_VERSION, GRAPHML_SCHEMA_VERSION, INCREMENTAL_PLAN_SCHEMA_VERSION,
    NEXT_BUILD_CAPABILITY, NEXT_BUILD_OBSERVATION_SCHEMA, NEXT_BUILD_OBSERVER,
    NEXT_BUILD_OBSERVER_VERSION, POLICY_RESULT_SCHEMA_VERSION, POLICY_SCHEMA_VERSION,
    PROFILE_SELECTION_INVENTORY_VERSION, RUNTIME_COLLECTOR_CONTRACT_VERSION, RUNTIME_TRACE_SCHEMA,
    RUNTIME_TRACE_SCHEMA_VERSION, RUST_PROFILE_PLANNING_VERSION, RUST_SYSROOT_COMPONENT_NAME,
    RUST_SYSROOT_COMPONENT_ROOT, RUST_SYSROOT_COMPONENT_VERSION,
    RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION, RUST_SYSROOT_LICENSE_EXPRESSION,
    RUST_SYSROOT_SBOM_PACKAGE_NAME, RUST_SYSROOT_SOURCE_LAYOUT, RUST_SYSROOT_TOOLCHAIN_COMMIT,
    RUST_SYSROOT_TOOLCHAIN_VERSION, TANSTACK_ROUTER_BUILD_CAPABILITY,
    TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA, TANSTACK_ROUTER_BUILD_OBSERVER,
    TANSTACK_ROUTER_BUILD_OBSERVER_VERSION, TANSTACK_START_BUILD_CAPABILITY,
    TANSTACK_START_BUILD_OBSERVATION_SCHEMA, TANSTACK_START_BUILD_OBSERVER,
    TANSTACK_START_BUILD_OBSERVER_VERSION, profile_selection_web,
};
// Cross-language surface constants pinned by
// `cross_language_release_compatibility_contract`.
use crate::{
    FFI_CAPABILITY, FFI_LINK_CAPABILITY, FFI_LINK_OBSERVATION_SCHEMA,
    FFI_LINK_OBSERVATION_SCHEMA_PATH, GRAPHQL_CAPABILITY, GRAPHQL_REPOSITORY_MAPPING_CAPABILITY,
    HTTP_OPERATION_CORRELATION_VERSION, OPENAPI_CAPABILITY,
    OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION, PROTOBUF_CAPABILITY,
    PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrameworkBuildCapabilityHealth {
    pub framework: String,
    pub observer: String,
    pub observer_version: String,
    pub observation_schema: String,
    pub capability: String,
    pub observer_runtime_artifact: String,
    pub converter_runtime_artifact: String,
}

pub fn framework_build_capability_contract() -> Vec<FrameworkBuildCapabilityHealth> {
    [
        (
            "astro",
            ASTRO_BUILD_OBSERVER,
            ASTRO_BUILD_OBSERVER_VERSION,
            ASTRO_BUILD_OBSERVATION_SCHEMA,
            ASTRO_BUILD_CAPABILITY,
            "libexec/astro-build-integration.mjs",
        ),
        (
            "next",
            NEXT_BUILD_OBSERVER,
            NEXT_BUILD_OBSERVER_VERSION,
            NEXT_BUILD_OBSERVATION_SCHEMA,
            NEXT_BUILD_CAPABILITY,
            "libexec/next-build-adapter.mjs",
        ),
        (
            "tanstack-router",
            TANSTACK_ROUTER_BUILD_OBSERVER,
            TANSTACK_ROUTER_BUILD_OBSERVER_VERSION,
            TANSTACK_ROUTER_BUILD_OBSERVATION_SCHEMA,
            TANSTACK_ROUTER_BUILD_CAPABILITY,
            "libexec/tanstack-router-build-observer.mjs",
        ),
        (
            "tanstack-start",
            TANSTACK_START_BUILD_OBSERVER,
            TANSTACK_START_BUILD_OBSERVER_VERSION,
            TANSTACK_START_BUILD_OBSERVATION_SCHEMA,
            TANSTACK_START_BUILD_CAPABILITY,
            "libexec/tanstack-start-build-observer.mjs",
        ),
    ]
    .into_iter()
    .map(
        |(
            framework,
            observer,
            observer_version,
            observation_schema,
            capability,
            observer_runtime_artifact,
        )| FrameworkBuildCapabilityHealth {
            framework: framework.to_owned(),
            observer: observer.to_owned(),
            observer_version: observer_version.to_owned(),
            observation_schema: observation_schema.to_owned(),
            capability: capability.to_owned(),
            observer_runtime_artifact: observer_runtime_artifact.to_owned(),
            converter_runtime_artifact: FRAMEWORK_BUILD_CONVERTER_ARTIFACT.to_owned(),
        },
    )
    .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RustSysrootCompatibilityHealth {
    pub contract_version: String,
    pub toolchain_version: String,
    pub toolchain_commit: String,
    pub component_name: String,
    pub component_version: String,
    pub component_root: String,
    pub source_layout: String,
    pub license_expression: String,
    pub sbom_package_name: String,
}

pub fn rust_sysroot_compatibility_contract() -> RustSysrootCompatibilityHealth {
    RustSysrootCompatibilityHealth {
        contract_version: RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION.to_owned(),
        toolchain_version: RUST_SYSROOT_TOOLCHAIN_VERSION.to_owned(),
        toolchain_commit: RUST_SYSROOT_TOOLCHAIN_COMMIT.to_owned(),
        component_name: RUST_SYSROOT_COMPONENT_NAME.to_owned(),
        component_version: RUST_SYSROOT_COMPONENT_VERSION.to_owned(),
        component_root: RUST_SYSROOT_COMPONENT_ROOT.to_owned(),
        source_layout: RUST_SYSROOT_SOURCE_LAYOUT.to_owned(),
        license_expression: RUST_SYSROOT_LICENSE_EXPRESSION.to_owned(),
        sbom_package_name: RUST_SYSROOT_SBOM_PACKAGE_NAME.to_owned(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseCompatibilityHealth {
    pub worker_protocol_version: String,
    pub store_schema_version: i64,
    pub operation_journal_schema_version: i64,
    pub mcp_tool_contract_version: String,
    pub mcp_operation_contract_version: String,
    pub minimum_migratable_store_schema_version: i64,
    pub previous_release_version: String,
    pub previous_release_store_schema_version: i64,
    pub stable_release_gate_contract_version: String,
    pub stable_release_version: String,
    pub stable_upgrade_source_version: String,
    pub stable_upgrade_source_store_schema_version: i64,
    pub stable_upgrade_source_fixture_path: String,
    pub stable_upgrade_source_fixture_sha256: String,
    pub cache_contract_version: u32,
    pub snapshot_diff_schema_version: String,
    pub incremental_plan_schema_version: String,
    pub daemon_status_schema_version: String,
    pub policy_schema_version: String,
    pub policy_result_schema_version: String,
    pub framework_build_graph_contract_version: String,
    pub framework_build_gate_contract_version: String,
    pub framework_build_capabilities: Vec<FrameworkBuildCapabilityHealth>,
    pub rust_sysroot: RustSysrootCompatibilityHealth,
    pub runtime_trace_schema_version: String,
    pub runtime_collector_contract_version: String,
    pub graphml_schema_version: String,
    pub packaged_smoke_contract: String,
    pub bounded_query: BoundedQueryReleaseCompatibilityHealth,
    pub profile_selection: ProfileSelectionReleaseCompatibilityHealth,
    pub cross_language: CrossLanguageReleaseCompatibilityHealth,
    pub compiler_precise: CompilerPreciseReleaseCompatibilityHealth,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompilerPreciseReleaseCompatibilityHealth {
    pub release_contract_version: String,
    pub distribution: String,
    pub supported_targets: Vec<String>,
    pub compiler_contract_version: String,
    pub manifest_schema_version: String,
    pub toolchain_channel: String,
    pub rust_release: String,
    pub rustc_commit: String,
    pub channel_manifest: String,
    pub channel_manifest_sha256: String,
    pub wrapper_protocol_version: String,
    pub mir_schema_version: String,
    pub query_capabilities: Vec<String>,
    pub fallback_policy: String,
}

pub fn compiler_precise_release_compatibility_contract() -> CompilerPreciseReleaseCompatibilityHealth
{
    CompilerPreciseReleaseCompatibilityHealth {
        release_contract_version: COMPILER_PACK_RELEASE_CONTRACT_VERSION.to_owned(),
        distribution: COMPILER_PACK_DISTRIBUTION.to_owned(),
        supported_targets: COMPILER_PACK_SUPPORTED_TARGETS
            .iter()
            .map(|target| (*target).to_owned())
            .collect(),
        compiler_contract_version: COMPILER_PRECISE_CONTRACT_VERSION.to_owned(),
        manifest_schema_version: COMPILER_PACK_MANIFEST_SCHEMA_VERSION.to_owned(),
        toolchain_channel: COMPILER_PACK_TOOLCHAIN_CHANNEL.to_owned(),
        rust_release: COMPILER_PACK_RUST_RELEASE.to_owned(),
        rustc_commit: COMPILER_PACK_RUSTC_COMMIT.to_owned(),
        channel_manifest: COMPILER_PACK_CHANNEL_MANIFEST.to_owned(),
        channel_manifest_sha256: COMPILER_PACK_CHANNEL_MANIFEST_SHA256.to_owned(),
        wrapper_protocol_version: COMPILER_PACK_WRAPPER_PROTOCOL_VERSION.to_owned(),
        mir_schema_version: COMPILER_PRECISE_MIR_SCHEMA_VERSION.to_owned(),
        query_capabilities: vec![
            "monomorphized_call_graph".to_owned(),
            "typed_mir".to_owned(),
        ],
        fallback_policy: COMPILER_PACK_FALLBACK_POLICY.to_owned(),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundedQueryReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub language_contract_version: String,
    pub type_contract_version: String,
    pub statistics_version: String,
    pub plan_schema_version: String,
    pub limit_version: String,
    pub result_schema_version: String,
    pub fixture_path: String,
    pub fixture_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelectionReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub selection_contract_version: String,
    pub limit_version: String,
    pub inventory_version: String,
    pub rust_planning_version: String,
    pub go_planning_version: String,
    pub web_planning_version: String,
    pub automatic_schema_path: String,
    pub automatic_schema_sha256: String,
    pub explicit_schema_path: String,
    pub explicit_schema_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageCapabilityHealth {
    pub surface: String,
    pub capability: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageSchemaHealth {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossLanguageReleaseCompatibilityHealth {
    pub release_smoke_contract_version: String,
    pub contract_version: String,
    pub completeness_version: String,
    pub fixture_path: String,
    pub fixture_sha256: String,
    pub capabilities: Vec<CrossLanguageCapabilityHealth>,
    pub schemas: Vec<CrossLanguageSchemaHealth>,
}

pub fn cross_language_release_compatibility_contract() -> CrossLanguageReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    let digest = |contents: &str| {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(contents.as_bytes()))
        )
    };
    CrossLanguageReleaseCompatibilityHealth {
        release_smoke_contract_version: CROSS_LANGUAGE_RELEASE_SMOKE_CONTRACT_VERSION.to_owned(),
        contract_version: depgraph_protocol::CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: depgraph_protocol::CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        fixture_path: CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE_PATH.to_owned(),
        fixture_sha256: digest(CROSS_LANGUAGE_RELEASE_SMOKE_FIXTURE),
        capabilities: vec![
            CrossLanguageCapabilityHealth {
                surface: "common".to_owned(),
                capability: depgraph_protocol::CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "ffi-link".to_owned(),
                capability: FFI_LINK_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "ffi-static".to_owned(),
                capability: FFI_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "graphql-mapping".to_owned(),
                capability: GRAPHQL_REPOSITORY_MAPPING_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "graphql-source".to_owned(),
                capability: GRAPHQL_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "http-runtime".to_owned(),
                capability: HTTP_OPERATION_CORRELATION_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "openapi-generated".to_owned(),
                capability: OPENAPI_GENERATED_MAPPING_SCHEMA_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "openapi-source".to_owned(),
                capability: OPENAPI_CAPABILITY.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "protobuf-generated".to_owned(),
                capability: PROTOBUF_GENERATED_MAPPING_SCHEMA_VERSION.to_owned(),
            },
            CrossLanguageCapabilityHealth {
                surface: "protobuf-source".to_owned(),
                capability: PROTOBUF_CAPABILITY.to_owned(),
            },
        ],
        schemas: vec![
            CrossLanguageSchemaHealth {
                path: depgraph_protocol::CROSS_LANGUAGE_SCHEMA_PATH.to_owned(),
                sha256: digest(depgraph_protocol::CROSS_LANGUAGE_SCHEMA),
            },
            CrossLanguageSchemaHealth {
                path: FFI_LINK_OBSERVATION_SCHEMA_PATH.to_owned(),
                sha256: digest(FFI_LINK_OBSERVATION_SCHEMA),
            },
            CrossLanguageSchemaHealth {
                path: "schemas/depgraph-runtime-trace-v1.schema.json".to_owned(),
                sha256: digest(RUNTIME_TRACE_SCHEMA),
            },
        ],
    }
}

pub fn profile_selection_release_compatibility_contract()
-> ProfileSelectionReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    ProfileSelectionReleaseCompatibilityHealth {
        release_smoke_contract_version: "profile-selection-release-smoke-v1".to_owned(),
        selection_contract_version: DEFAULT_PROFILE_SELECTION_CONTRACT_VERSION.to_owned(),
        limit_version: DEFAULT_PROFILE_SELECTION_LIMIT_VERSION.to_owned(),
        inventory_version: PROFILE_SELECTION_INVENTORY_VERSION.to_owned(),
        rust_planning_version: RUST_PROFILE_PLANNING_VERSION.to_owned(),
        go_planning_version: GO_PROFILE_PLANNING_VERSION.to_owned(),
        web_planning_version: profile_selection_web::WEB_PROFILE_PLANNING_VERSION.to_owned(),
        automatic_schema_path: DEFAULT_PROFILE_SELECTION_SCHEMA_PATH.to_owned(),
        automatic_schema_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(DEFAULT_PROFILE_SELECTION_SCHEMA.as_bytes()))
        ),
        explicit_schema_path: EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA_PATH.to_owned(),
        explicit_schema_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                EXPLICIT_PROFILE_SELECTION_FILE_SCHEMA.as_bytes()
            ))
        ),
    }
}

pub fn bounded_query_release_compatibility_contract() -> BoundedQueryReleaseCompatibilityHealth {
    use sha2::{Digest as _, Sha256};

    BoundedQueryReleaseCompatibilityHealth {
        release_smoke_contract_version: BOUNDED_QUERY_RELEASE_SMOKE_CONTRACT_VERSION.to_owned(),
        language_contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
        type_contract_version: BOUNDED_QUERY_TYPE_CONTRACT_VERSION.to_owned(),
        statistics_version: BOUNDED_QUERY_STATISTICS_VERSION.to_owned(),
        plan_schema_version: BOUNDED_QUERY_PLAN_SCHEMA_VERSION.to_owned(),
        limit_version: BOUNDED_QUERY_LIMIT_VERSION.to_owned(),
        result_schema_version: BOUNDED_QUERY_RESULT_SCHEMA_VERSION.to_owned(),
        fixture_path: BOUNDED_QUERY_RELEASE_SMOKE_FIXTURE_PATH.to_owned(),
        fixture_sha256: format!(
            "sha256:{}",
            hex::encode(Sha256::digest(BOUNDED_QUERY_RELEASE_SMOKE_QUERY.as_bytes()))
        ),
    }
}

pub fn release_compatibility_contract() -> ReleaseCompatibilityHealth {
    ReleaseCompatibilityHealth {
        worker_protocol_version: depgraph_protocol::PROTOCOL_VERSION.to_owned(),
        store_schema_version: STORE_SCHEMA_VERSION,
        operation_journal_schema_version: 6,
        mcp_tool_contract_version: "depgraph-mcp-tools-v1".to_owned(),
        mcp_operation_contract_version: "depgraph-operation-v2".to_owned(),
        minimum_migratable_store_schema_version: 1,
        previous_release_version: "0.5.4".to_owned(),
        previous_release_store_schema_version: 17,
        stable_release_gate_contract_version: "stable-release-gate-v2".to_owned(),
        stable_release_version: "0.7.3".to_owned(),
        stable_upgrade_source_version: "0.4.0-rc.6".to_owned(),
        stable_upgrade_source_store_schema_version: 13,
        stable_upgrade_source_fixture_path: "xtask/fixtures/v0.4.0-rc.6-store-v13.sql".to_owned(),
        stable_upgrade_source_fixture_sha256:
            "sha256:43fe0dda73d03be9b8fff2ed9ff8ce888ad96e41e78335a1117646475c937150".to_owned(),
        cache_contract_version: CACHE_CONTRACT_VERSION,
        snapshot_diff_schema_version: SNAPSHOT_DIFF_SCHEMA_VERSION.to_owned(),
        incremental_plan_schema_version: INCREMENTAL_PLAN_SCHEMA_VERSION.to_owned(),
        daemon_status_schema_version: DAEMON_STATUS_SCHEMA_VERSION.to_owned(),
        policy_schema_version: POLICY_SCHEMA_VERSION.to_owned(),
        policy_result_schema_version: POLICY_RESULT_SCHEMA_VERSION.to_owned(),
        framework_build_graph_contract_version: FRAMEWORK_BUILD_GRAPH_CONTRACT_VERSION.to_owned(),
        framework_build_gate_contract_version: FRAMEWORK_BUILD_GATE_CONTRACT_VERSION.to_owned(),
        framework_build_capabilities: framework_build_capability_contract(),
        rust_sysroot: rust_sysroot_compatibility_contract(),
        runtime_trace_schema_version: RUNTIME_TRACE_SCHEMA_VERSION.to_owned(),
        runtime_collector_contract_version: RUNTIME_COLLECTOR_CONTRACT_VERSION.to_owned(),
        graphml_schema_version: GRAPHML_SCHEMA_VERSION.to_owned(),
        packaged_smoke_contract: "stable-v0.5.0-packaged-smoke-v1".to_owned(),
        bounded_query: bounded_query_release_compatibility_contract(),
        profile_selection: profile_selection_release_compatibility_contract(),
        cross_language: cross_language_release_compatibility_contract(),
        compiler_precise: compiler_precise_release_compatibility_contract(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FRAMEWORK_BUILD_CONVERTER_ARTIFACT, FRAMEWORK_BUILD_GATE_CONTRACT_VERSION,
        framework_build_capability_contract, release_compatibility_contract,
    };

    #[test]
    fn framework_build_release_gate_pins_every_dynamic_capability() {
        let capabilities = framework_build_capability_contract();
        assert_eq!(
            capabilities
                .iter()
                .map(|capability| capability.framework.as_str())
                .collect::<Vec<_>>(),
            ["astro", "next", "tanstack-router", "tanstack-start"]
        );
        assert!(capabilities.iter().all(|capability| {
            capability.converter_runtime_artifact == FRAMEWORK_BUILD_CONVERTER_ARTIFACT
                && capability.observer_runtime_artifact.starts_with("libexec/")
                && capability.observer_version.contains('.')
                && (capability.observation_schema.ends_with("-v1")
                    || capability.observation_schema.ends_with("-v2"))
        }));
        assert_eq!(
            release_compatibility_contract().framework_build_gate_contract_version,
            FRAMEWORK_BUILD_GATE_CONTRACT_VERSION
        );
    }
}
