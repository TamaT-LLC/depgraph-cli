use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::Path,
    process::Command,
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{
    BOUNDED_QUERY_SBOM_PACKAGE_NAME, CROSS_LANGUAGE_SBOM_PACKAGE_NAME, DependencyPackage,
    FirstPartyArtifactInventory, MCP_APACHE_NOTICE, MCP_MACROS_VERSION, MCP_SDK_NAME,
    MCP_SDK_VERSION, PROJECT_LICENSE_EXPRESSION, RUNTIME_COLLECTOR_ARTIFACT,
    RUNTIME_COLLECTOR_CONTRACT_VERSION, RUST_ANALYZER_CRATE_VERSION,
    RUST_ANALYZER_DIRECT_DEPENDENCIES, RUST_ANALYZER_REVISION, RUST_SYSROOT_COMPONENT_ROOT,
    RUST_SYSROOT_COMPONENT_VERSION, RUST_SYSROOT_DATA_TREE_CONTRACT_VERSION,
    RUST_SYSROOT_LICENSE_EXPRESSION, RUST_SYSROOT_SOURCE_LAYOUT, RUST_SYSROOT_TOOLCHAIN_COMMIT,
    RUST_SYSROOT_TOOLCHAIN_VERSION, ReleaseManifest, RuntimeCollectorInventory,
    SALSA_DIRECT_DEPENDENCIES, SALSA_VERSION, SBOM_SCOPE, VERSION, sha256_file,
};

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
const RUST_SYSROOT_SBOM_PACKAGE_NAME: &str = depgraph_core::RUST_SYSROOT_SBOM_PACKAGE_NAME;
const FORBIDDEN_RUST_ANALYZER_DEPENDENCIES: &[&str] = &[
    "ra_ap_flycheck",
    "ra_ap_load_cargo",
    "ra_ap_load-cargo",
    "ra_ap_proc_macro_srv",
    "ra_ap_project_model",
];

pub(crate) fn third_party_licenses(target: &str) -> Result<String> {
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

pub(crate) fn rust_sysroot_license_notice() -> String {
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

pub(crate) fn sbom(target: &str, rust_sysroot_sha256: &str) -> Result<Value> {
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

pub(crate) fn verify_runtime_collector_sbom(
    sbom: &Value,
    expected_sha256: &str,
    context: &str,
) -> Result<()> {
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

pub(crate) fn verify_rust_sysroot_sbom(
    sbom: &Value,
    expected_sha256: &str,
    context: &str,
) -> Result<()> {
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

pub(crate) fn verify_bounded_query_sbom(sbom: &Value, context: &str) -> Result<()> {
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

pub(crate) fn verify_cross_language_sbom(
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

pub(crate) fn verify_framework_build_sbom(
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

pub(crate) fn manifest_framework_build_artifact_checksums(
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

pub(crate) fn normalized_spdx_license(reported: &str) -> Option<String> {
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

pub(crate) fn package_url(package: &DependencyPackage) -> String {
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

pub(crate) fn dependency_inventory(target: &str) -> Result<Vec<DependencyPackage>> {
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

pub(crate) fn cargo_metadata(arguments: &[&str]) -> Result<Value> {
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

pub(crate) fn verify_rust_analyzer_dependencies(metadata: &Value) -> Result<()> {
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

pub(crate) fn verify_mcp_dependencies(metadata: &Value) -> Result<()> {
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

pub(crate) fn cargo_runtime_packages(metadata: &Value) -> Result<Vec<DependencyPackage>> {
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

pub(crate) fn web_runtime_packages(inventory: &Value) -> Result<Vec<DependencyPackage>> {
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

pub(crate) fn framework_build_artifact_checksums(
    inventory: &Value,
) -> Result<BTreeMap<String, String>> {
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

pub(crate) fn web_legal_documents() -> Result<Vec<(String, String)>> {
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

pub(crate) fn legal_document_section(label: &str, content: &str) -> String {
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
