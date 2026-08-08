use std::path::Path;

use anyhow::Result;
use depgraph_core::service::{
    DeferredScanServiceOutcome, DepgraphCapability, DepgraphCapabilitySet, DepgraphService,
    DepgraphServiceConfig, DepgraphServiceError, DepgraphServiceLimits, ScanRequest,
    SnapshotLocator, SnapshotNameCreateRequest,
};
use depgraph_core::{CancellationToken, ScanCacheMode, acquire_store_writer_lock};
use depgraph_store::Store;
use serde_json::json;

fn service(
    root: &Path,
    store_path: &Path,
    capabilities: impl IntoIterator<Item = DepgraphCapability>,
) -> DepgraphService {
    DepgraphService::new(
        DepgraphServiceConfig::new(
            root,
            store_path,
            DepgraphCapabilitySet::try_new(capabilities).unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap(),
    )
}

fn seed_completed_snapshot(store: &mut Store, root: &Path, scan_id: &str) -> Result<String> {
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
    store.start_scan_with_revision(scan_id, root, false, Some("revision"))?;
    for event in [
        json!({"event":"scan_started","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
        json!({"event":"scan_completed","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":2,"coverage":coverage}),
    ] {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store.current_snapshot_id()?.unwrap())
}

#[tokio::test]
async fn store_write_service_denies_scan_and_snapshot_naming_before_store_access() {
    let temporary = tempfile::tempdir().unwrap();
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("missing-store.sqlite");
    std::fs::create_dir(&repository).unwrap();
    let service = service(&repository, &store_path, [DepgraphCapability::Read]);

    let scan = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await;
    assert!(matches!(
        scan,
        Err(DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::StoreWrite
        })
    ));
    let naming = service.snapshot_name_create(
        &SnapshotNameCreateRequest::new("baseline", SnapshotLocator::Current),
        &CancellationToken::new(),
    );
    assert!(matches!(
        naming,
        Err(DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::StoreWrite
        })
    ));
    assert!(!store_path.exists());
}

#[test]
fn snapshot_name_create_is_completed_only_immutable_and_writer_locked() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    let snapshot_id = seed_completed_snapshot(&mut Store::open(&store_path)?, &repository, "one")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let named = service.snapshot_name_create(
        &SnapshotNameCreateRequest::new("baseline", SnapshotLocator::Current),
        &CancellationToken::new(),
    )?;
    assert_eq!(named.name(), "baseline");
    assert_eq!(named.snapshot().id(), snapshot_id);
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("BASELINE", SnapshotLocator::Current),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::Conflict)
    ));
    assert_eq!(
        Store::open_read_only(&store_path)?
            .snapshot_id_for_name("baseline")?
            .as_deref(),
        Some(snapshot_id.as_str())
    );

    let missing = SnapshotLocator::parse(format!("snapshot:sha256:{}", "f".repeat(64)))?;
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("missing", missing),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::NotFound)
    ));

    let _lock = acquire_store_writer_lock(&store_path)?;
    assert!(matches!(
        service.snapshot_name_create(
            &SnapshotNameCreateRequest::new("locked", SnapshotLocator::Current),
            &CancellationToken::new(),
        ),
        Err(DepgraphServiceError::StoreWriterConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn safe_scan_preserves_source_tree_and_cancel_does_not_replace_current_snapshot() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("README.md"), "source remains immutable\n")?;
    let before_source = std::fs::read(repository.join("README.md"))?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let completed = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await?;
    let snapshot_id = completed
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    assert_eq!(completed.outcome().status, "completed");
    assert!(!completed.outcome().coverage.project_code_executed);
    assert_eq!(std::fs::read(repository.join("README.md"))?, before_source);

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(matches!(
        service
            .scan_cancellable(&ScanRequest::new(false, ScanCacheMode::Disabled), cancelled,)
            .await,
        Err(DepgraphServiceError::Cancelled)
    ));
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(snapshot_id.as_str())
    );
    assert_eq!(std::fs::read(repository.join("README.md"))?, before_source);
    Ok(())
}

#[tokio::test]
async fn cached_safe_scan_completes_and_reports_cold_then_warm_cache_events() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("README.md"), "cache fixture\n")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let cold = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Enabled),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("cold cached scan timed out")?;
    assert!(
        cold.outcome()
            .cache_events
            .iter()
            .any(|event| event.outcome == "miss")
    );

    let warm = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        service.scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Enabled),
            CancellationToken::new(),
        ),
    )
    .await
    .expect("warm cached scan timed out")?;
    assert!(
        warm.outcome()
            .cache_events
            .iter()
            .any(|event| event.outcome == "hit")
    );
    Ok(())
}

#[tokio::test]
async fn completed_deferred_recovery_does_not_replace_a_newer_current_snapshot() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let repository = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir(&repository)?;
    std::fs::write(repository.join("one.rs"), "pub fn one() {}\n")?;
    let service = service(
        &repository,
        &store_path,
        [DepgraphCapability::Read, DepgraphCapability::StoreWrite],
    );

    let completion = match service
        .scan_deferred_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await?
    {
        DeferredScanServiceOutcome::Pending(completion) => completion,
        DeferredScanServiceOutcome::Finished(_) => anyhow::bail!("scan did not defer completion"),
    };
    let scan_id = completion.outcome().outcome().scan_id.clone();
    let completed_snapshot_id = completion
        .outcome()
        .completed_snapshot_id()
        .unwrap()
        .as_str()
        .to_owned();
    completion.promote()?;

    std::fs::write(repository.join("two.rs"), "pub fn two() {}\n")?;
    let newer = service
        .scan_cancellable(
            &ScanRequest::new(false, ScanCacheMode::Disabled),
            CancellationToken::new(),
        )
        .await?;
    let newer_snapshot_id = newer.completed_snapshot_id().unwrap().as_str().to_owned();
    assert_ne!(newer_snapshot_id, completed_snapshot_id);

    service.recover_deferred_scan_completion(&scan_id, &completed_snapshot_id)?;
    assert_eq!(
        Store::open_read_only(&store_path)?
            .current_snapshot_id()?
            .as_deref(),
        Some(newer_snapshot_id.as_str())
    );
    Ok(())
}
