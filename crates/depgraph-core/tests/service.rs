use std::{collections::BTreeSet, error::Error, path::Path};

use anyhow::Result;
use depgraph_core::service::{
    DEPGRAPH_SERVICE_LIMITS_VERSION, DepgraphCapability, DepgraphCapabilitySet,
    DepgraphMutatingContext, DepgraphMutatingUseCase, DepgraphMutatingUseCaseKind, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceConfigurationError, DepgraphServiceError,
    DepgraphServiceErrorCategory, DepgraphServiceLimit, DepgraphServiceLimits,
};
use depgraph_store::Store;
use serde_json::json;

fn read_only_service(
    root: &Path,
    store_path: &Path,
) -> Result<DepgraphService, DepgraphServiceError> {
    let config = DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

#[test]
fn configuration_canonicalizes_and_owns_its_immutable_values() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&store_directory)?;

    let mut declared_store = store_directory.join("graph.db");
    let mut declared_capabilities = vec![DepgraphCapability::Read];
    let config = DepgraphServiceConfig::new(
        root.join("."),
        declared_store.clone(),
        DepgraphCapabilitySet::try_new(declared_capabilities.clone())?,
        DepgraphServiceLimits::default(),
    )?;
    let service = DepgraphService::new(config);

    declared_store.set_file_name("different.db");
    declared_capabilities.push(DepgraphCapability::StoreWrite);

    assert_eq!(service.config().canonical_root(), root.canonicalize()?);
    assert_eq!(
        service.config().store_path(),
        store_directory.canonicalize()?.join("graph.db")
    );
    assert_eq!(
        service.config().capabilities().iter().collect::<Vec<_>>(),
        vec![DepgraphCapability::Read]
    );
    assert_eq!(
        service.config().limits().version(),
        DEPGRAPH_SERVICE_LIMITS_VERSION
    );
    assert!(
        !service
            .config()
            .capabilities()
            .contains(DepgraphCapability::StoreWrite)
    );
    Ok(())
}

#[test]
fn configuration_rejects_unsafe_paths_and_invalid_capability_sets() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&store_directory)?;

    let missing_root = DepgraphServiceConfig::new(
        temporary.path().join("missing"),
        store_directory.join("graph.db"),
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        missing_root,
        DepgraphServiceError::InvalidConfiguration {
            reason: DepgraphServiceConfigurationError::RootUnavailable { .. }
        }
    ));

    let relative_store = DepgraphServiceConfig::new(
        &root,
        Path::new("relative.db"),
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(
        relative_store,
        DepgraphServiceError::InvalidConfiguration {
            reason: DepgraphServiceConfigurationError::StorePathNotAbsolute
        }
    ));

    for (declared, capability, dependency) in [
        (BTreeSet::new(), DepgraphCapability::Read, None),
        (
            BTreeSet::from([DepgraphCapability::Read, DepgraphCapability::DaemonControl]),
            DepgraphCapability::DaemonControl,
            Some(DepgraphCapability::StoreWrite),
        ),
        (
            BTreeSet::from([DepgraphCapability::Read, DepgraphCapability::ProjectExec]),
            DepgraphCapability::ProjectExec,
            Some(DepgraphCapability::StoreWrite),
        ),
    ] {
        let error = DepgraphCapabilitySet::try_new(declared).unwrap_err();
        match dependency {
            None => assert!(matches!(
                error,
                DepgraphServiceError::InvalidConfiguration {
                    reason: DepgraphServiceConfigurationError::MissingCapability {
                        capability: actual
                    }
                } if actual == capability
            )),
            Some(requires) => assert!(matches!(
                error,
                DepgraphServiceError::InvalidConfiguration {
                    reason: DepgraphServiceConfigurationError::MissingCapabilityDependency {
                        capability: actual,
                        requires: actual_requirement,
                    }
                } if actual == capability && actual_requirement == requires
            )),
        }
    }
    Ok(())
}

#[test]
fn versioned_limits_fail_closed() {
    let unsupported =
        DepgraphServiceLimits::try_new("depgraph-service-limits-v2", 1, 1, 1, 1).unwrap_err();
    assert!(matches!(
        unsupported,
        DepgraphServiceError::InvalidConfiguration {
            reason: DepgraphServiceConfigurationError::UnsupportedLimitsVersion { .. }
        }
    ));

    let zero =
        DepgraphServiceLimits::try_new(DEPGRAPH_SERVICE_LIMITS_VERSION, 0, 1, 1, 1).unwrap_err();
    assert!(matches!(
        zero,
        DepgraphServiceError::InvalidConfiguration {
            reason: DepgraphServiceConfigurationError::ZeroLimit {
                limit: DepgraphServiceLimit::InlineInputBytes
            }
        }
    ));

    let invalid_page_bounds =
        DepgraphServiceLimits::try_new(DEPGRAPH_SERVICE_LIMITS_VERSION, 1, 1, 2, 1).unwrap_err();
    assert!(matches!(
        invalid_page_bounds,
        DepgraphServiceError::InvalidConfiguration {
            reason: DepgraphServiceConfigurationError::InvalidPageLimits
        }
    ));
}

#[test]
fn each_read_request_uses_a_read_only_store_without_cache_mutation() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&store_directory)?;

    let key = format!("impact-query:sha256:{:064x}", 1);
    let payload = r#"{"complete":true,"impacts":[]}"#;
    let mut writer = Store::open(&store_path)?;
    let scan_id = "service-cache-seed";
    let coverage = json!({
        "profiles": 0,
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
        "reasons": []
    });
    writer.start_scan_with_revision(scan_id, &root, false, Some("fixture"))?;
    for event in [
        json!({"event":"scan_started","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
        json!({"event":"scan_completed","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":2,"coverage":coverage}),
    ] {
        writer.ingest_event(&event)?;
    }
    writer.finish_scan(scan_id, "completed", None, true)?;
    let snapshot_id = writer
        .current_snapshot_id()?
        .expect("the fixture scan must promote a snapshot");
    assert!(writer.store_impact_query_cache(&key, &snapshot_id, payload)?);
    let cache_counts_before = writer.cache_entry_counts()?;
    assert_eq!(writer.impact_query_cache_entry_count()?, 1);
    drop(writer);

    let service = read_only_service(&root, &store_path)?;
    let factory = service.read_store_factory();
    let mut first_request = factory.open()?;
    assert_eq!(
        first_request
            .store()
            .lookup_impact_query_cache(&key, &snapshot_id)?,
        Some(payload.to_owned()),
        "a validated cache hit must remain usable when its best-effort touch is read-only"
    );
    assert!(
        first_request
            .store()
            .start_scan("must-not-write", service.config().canonical_root(), false)
            .is_err()
    );
    drop(first_request);

    let mut second_request = factory.open()?;
    assert_eq!(
        second_request.store().cache_entry_counts()?,
        cache_counts_before
    );
    assert_eq!(second_request.store().impact_query_cache_entry_count()?, 1);
    assert!(second_request.store().scan("must-not-write")?.is_none());
    Ok(())
}

struct StartScanUseCase;

impl DepgraphMutatingUseCase for StartScanUseCase {
    type Output = (DepgraphMutatingUseCaseKind, bool);

    const KIND: DepgraphMutatingUseCaseKind = DepgraphMutatingUseCaseKind::Store;

    fn execute(
        self,
        context: &mut DepgraphMutatingContext<'_>,
    ) -> Result<Self::Output, DepgraphServiceError> {
        let kind = context.kind();
        let root = context.canonical_root().to_path_buf();
        let store = context
            .store()
            .expect("store-mutating contexts always contain a writable store");
        store
            .start_scan("mutating-boundary", &root, false)
            .map_err(DepgraphServiceError::store_operation)?;
        Ok((kind, true))
    }
}

#[test]
fn mutating_use_cases_are_authorized_before_a_writable_store_opens() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&store_directory)?;

    let read_only = read_only_service(&root, &store_path)?;
    let denied = read_only.execute_mutating(StartScanUseCase).unwrap_err();
    assert!(matches!(
        denied,
        DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::StoreWrite
        }
    ));
    assert!(
        !store_path.exists(),
        "authorization must precede store creation"
    );

    let capabilities =
        DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::StoreWrite])?;
    let config = DepgraphServiceConfig::new(
        &root,
        &store_path,
        capabilities,
        DepgraphServiceLimits::default(),
    )?;
    let service = DepgraphService::new(config);
    assert_eq!(
        service.execute_mutating(StartScanUseCase)?,
        (DepgraphMutatingUseCaseKind::Store, true)
    );

    let mut request = service.read_store_factory().open()?;
    assert!(request.store().scan("mutating-boundary")?.is_some());
    Ok(())
}

#[test]
fn service_errors_have_structural_categories_and_redacted_display() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("secret-cache").join("missing.db");
    std::fs::create_dir_all(&root)?;

    let service = read_only_service(&root, &store_path)?;
    let error = match service.read_store_factory().open() {
        Ok(_) => panic!("a missing store must not open read-only"),
        Err(error) => error,
    };
    assert_eq!(error.category(), DepgraphServiceErrorCategory::Store);
    assert!(matches!(
        error,
        DepgraphServiceError::ReadStoreUnavailable { .. }
    ));
    assert!(
        !error
            .to_string()
            .contains(&store_path.to_string_lossy().to_string())
    );
    assert!(Error::source(&error).is_some());

    let denied = DepgraphServiceError::CapabilityDenied {
        required: DepgraphCapability::RepositoryWrite,
    };
    assert_eq!(
        denied.category(),
        DepgraphServiceErrorCategory::Authorization
    );

    let invalid = DepgraphServiceLimits::try_new("invalid", 1, 1, 1, 1).unwrap_err();
    assert_eq!(
        invalid.category(),
        DepgraphServiceErrorCategory::Configuration
    );
    Ok(())
}
