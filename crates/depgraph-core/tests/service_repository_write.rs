use std::{fs::OpenOptions, path::Path};

use anyhow::Result;
use depgraph_core::{
    CancellationToken, Config, GraphQueryFilter, SnapshotLocator,
    service::{
        DEPGRAPH_SERVICE_LIMITS_VERSION, DeferredExportFileRecovery, DepgraphCapability,
        DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig,
        DepgraphServiceErrorCategory, DepgraphServiceLimits, ExportFileRequest, GraphExportFormat,
        GraphExportRequest, RepositoryInitRequest, RepositoryOverwritePolicy,
        RepositoryRelativePath,
    },
};
use depgraph_store::Store;
use serde_json::json;
use sha2::{Digest as _, Sha256};

fn repository_write_service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])?,
        DepgraphServiceLimits::default(),
    )?))
}

fn seed_completed_snapshot(store: &mut Store, root: &Path) -> Result<String> {
    let scan_id = "repository-export";
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
    store.start_scan_with_revision(scan_id, root, false, Some("revision-export"))?;
    for event in [
        json!({"event":"scan_started","protocol_version":"1.0","scan_id":scan_id,"adapter":"fixture","adapter_version":"1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
        json!({"event":"scan_completed","protocol_version":"1.0","scan_id":scan_id,"adapter":"fixture","adapter_version":"1.0","seq":2,"coverage":coverage}),
    ] {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed fixture snapshot is promoted"))
}

#[test]
fn repository_init_writes_default_config_only_at_the_fixed_root() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let result = service.repository_init(
        &RepositoryInitRequest::new(false),
        &CancellationToken::new(),
    )?;

    assert_eq!(result.output_path().as_str(), ".depgraph.toml");
    assert_eq!(
        std::fs::read_to_string(root.join(".depgraph.toml"))?,
        Config::render_default()?
    );
    assert!(root.join(".depgraph.toml").symlink_metadata()?.is_file());
    Ok(())
}

#[test]
fn repository_init_without_force_reports_conflict_and_preserves_existing_file() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let output = root.join(".depgraph.toml");
    std::fs::write(&output, b"existing-canary")?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let error = service
        .repository_init(
            &RepositoryInitRequest::new(false),
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Conflict);
    assert_eq!(std::fs::read(&output)?, b"existing-canary");
    Ok(())
}

#[cfg(unix)]
#[test]
fn repository_init_force_rejects_symlink_without_mutation() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let outside = temporary.path().join("outside.toml");
    std::fs::write(&outside, b"outside-canary")?;
    let output = root.join(".depgraph.toml");
    symlink(&outside, &output)?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let error = service
        .repository_init(&RepositoryInitRequest::new(true), &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert!(output.symlink_metadata()?.file_type().is_symlink());
    assert_eq!(std::fs::read(&outside)?, b"outside-canary");
    Ok(())
}

#[cfg(windows)]
#[test]
fn repository_init_force_rejects_file_reparse_point_without_mutation() -> Result<()> {
    use std::os::windows::fs::{MetadataExt as _, symlink_file};

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let outside = temporary.path().join("outside.toml");
    std::fs::write(&outside, b"outside-canary")?;
    let output = root.join(".depgraph.toml");
    if let Err(source) = symlink_file(&outside, &output) {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(source.into());
    }
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let error = service
        .repository_init(&RepositoryInitRequest::new(true), &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert_ne!(output.symlink_metadata()?.file_attributes() & 0x400, 0);
    assert_eq!(std::fs::read(&outside)?, b"outside-canary");
    Ok(())
}

#[cfg(unix)]
#[test]
fn repository_init_without_force_rejects_symlink_as_integrity_failure() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let outside = temporary.path().join("outside.toml");
    std::fs::write(&outside, b"outside-canary")?;
    let output = root.join(".depgraph.toml");
    symlink(&outside, &output)?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let error = service
        .repository_init(
            &RepositoryInitRequest::new(false),
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert!(output.symlink_metadata()?.file_type().is_symlink());
    assert_eq!(std::fs::read(&outside)?, b"outside-canary");
    Ok(())
}

#[test]
fn repository_init_force_rejects_non_regular_target_without_mutation() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let output = root.join(".depgraph.toml");
    std::fs::create_dir(&output)?;
    std::fs::write(output.join("canary"), b"keep")?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;

    let error = service
        .repository_init(&RepositoryInitRequest::new(true), &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert!(output.symlink_metadata()?.is_dir());
    assert_eq!(std::fs::read(output.join("canary"))?, b"keep");
    Ok(())
}

#[cfg(unix)]
#[test]
fn repository_init_force_keeps_existing_file_when_staging_cannot_start() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir(&root)?;
    let output = root.join(".depgraph.toml");
    std::fs::write(&output, b"existing-canary")?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555))?;

    let result =
        service.repository_init(&RepositoryInitRequest::new(true), &CancellationToken::new());

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
    let error = result.unwrap_err();
    assert_eq!(error.category(), DepgraphServiceErrorCategory::Internal);
    assert_eq!(std::fs::read(&output)?, b"existing-canary");
    assert_eq!(std::fs::read_dir(&root)?.count(), 1);
    Ok(())
}

#[test]
fn export_file_writes_complete_content_and_reports_exact_digest_and_bytes() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let graph = GraphExportRequest::try_new(
        SnapshotLocator::parse(&snapshot_id)?,
        GraphExportFormat::Json,
        None,
        GraphQueryFilter::default(),
        100,
        100,
    )?;
    let request = ExportFileRequest::new(
        graph,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    std::fs::create_dir(root.join("artifacts"))?;

    let result = service.export_file(&request, &CancellationToken::new())?;

    let content = std::fs::read(root.join("artifacts/graph.json"))?;
    assert_eq!(result.output_path().as_str(), "artifacts/graph.json");
    assert_eq!(result.format(), GraphExportFormat::Json);
    assert_eq!(result.output_bytes(), content.len() as u64);
    assert_eq!(
        result.content_sha256(),
        hex::encode(Sha256::digest(&content))
    );
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn export_file_rejects_graph_store_journal_and_sidecar_paths() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = root.join(".depgraph/graph.db");
    std::fs::create_dir_all(root.join(".depgraph"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let original_store = std::fs::read(&store_path)?;
    let service = repository_write_service(&root, &store_path)?;

    for protected_path in [
        ".depgraph/graph.db",
        ".depgraph/graph.db-wal",
        ".depgraph/graph.db-shm",
        ".depgraph/graph.db-journal",
        ".depgraph/graph.db.operations.sqlite",
        ".depgraph/graph.db.operations.sqlite-wal",
        ".depgraph/graph.db.operations.sqlite-shm",
        ".depgraph/graph.db.operations.sqlite-journal",
        ".depgraph/graph.db.operations.sqlite.runner-purge-lock",
    ] {
        let request = ExportFileRequest::new(
            GraphExportRequest::try_new(
                SnapshotLocator::parse(&snapshot_id)?,
                GraphExportFormat::Json,
                None,
                GraphQueryFilter::default(),
                100,
                100,
            )?,
            RepositoryRelativePath::parse(protected_path)?,
            RepositoryOverwritePolicy::Overwrite,
        );

        let error = service
            .export_file(&request, &CancellationToken::new())
            .unwrap_err();
        assert_eq!(
            error.category(),
            DepgraphServiceErrorCategory::Integrity,
            "protected path {protected_path} must fail closed"
        );
    }

    let case_alias = ".DEPGRAPH/GRAPH.DB";
    if root.join(".DEPGRAPH").try_exists()? {
        let request = ExportFileRequest::new(
            GraphExportRequest::try_new(
                SnapshotLocator::parse(&snapshot_id)?,
                GraphExportFormat::Json,
                None,
                GraphQueryFilter::default(),
                100,
                100,
            )?,
            RepositoryRelativePath::parse(case_alias)?,
            RepositoryOverwritePolicy::Overwrite,
        );

        let error = service
            .export_file(&request, &CancellationToken::new())
            .unwrap_err();
        assert_eq!(
            error.category(),
            DepgraphServiceErrorCategory::Integrity,
            "filesystem case alias {case_alias} must fail closed"
        );
    }

    assert_eq!(std::fs::read(&store_path)?, original_store);
    assert_eq!(
        Store::open(&store_path)?.current_snapshot_id()?,
        Some(snapshot_id)
    );
    Ok(())
}

#[test]
fn create_repository_output_rejects_protected_absent_sidecars() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = root.join(".depgraph/graph.db");
    std::fs::create_dir_all(root.join(".depgraph"))?;
    let service = repository_write_service(&root, &store_path)?;

    for protected_path in [
        ".depgraph/graph.db-wal",
        ".depgraph/graph.db-shm",
        ".depgraph/graph.db-journal",
        ".depgraph/graph.db.operations.sqlite",
        ".depgraph/graph.db.operations.sqlite-wal",
        ".depgraph/graph.db.operations.sqlite-shm",
        ".depgraph/graph.db.operations.sqlite-journal",
        ".depgraph/graph.db.operations.sqlite.runner-purge-lock",
    ] {
        let error = service
            .create_repository_output(protected_path)
            .unwrap_err();
        assert_eq!(
            error.category(),
            DepgraphServiceErrorCategory::Integrity,
            "public output helper must protect {protected_path}"
        );
        assert!(!root.join(protected_path).exists());
    }

    Ok(())
}

#[test]
fn create_repository_output_rejects_unicode_alias_of_absent_protected_sidecar() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let protected_directory = root.join(".depgraph");
    let store_path = protected_directory.join("Gráph.db");
    std::fs::create_dir_all(&protected_directory)?;
    std::fs::write(&store_path, b"store-canary")?;

    let aliased_store = protected_directory.join("GRÁPH.DB");
    if !aliased_store.try_exists()? {
        return Ok(());
    }

    let service = repository_write_service(&root, &store_path)?;
    for aliased_path in [
        ".depgraph/GRÁPH.DB-wal",
        ".depgraph/GRÁPH.DB.operations.sqlite.runner-purge-lock",
    ] {
        let error = service.create_repository_output(aliased_path).unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
        assert!(!root.join(aliased_path).exists());
    }
    assert_eq!(std::fs::read(&store_path)?, b"store-canary");
    Ok(())
}

#[test]
fn export_file_precondition_rejects_an_oversized_existing_destination() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let output = root.join("artifacts/graph.json");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&output)?;
    file.set_len(65)?;
    drop(file);
    let limits =
        DepgraphServiceLimits::try_new(DEPGRAPH_SERVICE_LIMITS_VERSION, 1_024, 64, 10, 100)?;
    let service = DepgraphService::new(DepgraphServiceConfig::new(
        &root,
        temporary.path().join("graph.db"),
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])?,
        limits,
    )?);

    let error = service
        .repository_output_precondition(
            &RepositoryRelativePath::parse("artifacts/graph.json")?,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Resource);
    assert_eq!(std::fs::metadata(output)?.len(), 65);
    Ok(())
}

#[test]
fn export_file_no_replace_preserves_an_existing_regular_destination() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let output = root.join("artifacts/graph.json");
    std::fs::write(&output, b"existing-canary")?;
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );

    let error = service
        .export_file(&request, &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Conflict);
    assert_eq!(std::fs::read(&output)?, b"existing-canary");
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn direct_export_file_honors_the_supplied_destination_precondition() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json")?;
    let output = root.join(output_path.as_str());
    std::fs::write(&output, b"initial-canary")?;
    let service = repository_write_service(&root, &store_path)?;
    let precondition =
        service.repository_output_precondition(&output_path, &CancellationToken::new())?;
    std::fs::write(&output, b"changed-canary")?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path,
        RepositoryOverwritePolicy::Overwrite,
    )
    .with_destination_precondition(precondition);

    let error = service
        .export_file(&request, &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert_eq!(std::fs::read(&output)?, b"changed-canary");
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn export_rendered_file_rejects_empty_content_before_publication() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let service = repository_write_service(&root, &temporary.path().join("graph.db"))?;
    let output_path = RepositoryRelativePath::parse("artifacts/empty.json")?;

    let error = service
        .export_rendered_file(
            &output_path,
            RepositoryOverwritePolicy::NoReplace,
            GraphExportFormat::Json,
            &[],
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Input);
    assert!(!root.join(output_path.as_str()).exists());
    assert!(std::fs::read_dir(root.join("artifacts"))?.next().is_none());
    Ok(())
}

#[test]
fn export_file_overwrite_atomically_replaces_an_existing_regular_destination() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let output = root.join("artifacts/graph.json");
    std::fs::write(&output, b"existing-canary")?;
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::Overwrite,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o640))?;
    }

    let result = service.export_file(&request, &CancellationToken::new())?;

    let content = std::fs::read(&output)?;
    assert_ne!(content, b"existing-canary");
    assert_eq!(content.len() as u64, result.output_bytes());
    assert_eq!(
        hex::encode(Sha256::digest(&content)),
        result.content_sha256()
    );
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&output)?.permissions().mode() & 0o777,
            0o640
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn export_file_rejects_a_symlink_parent_without_outside_mutation() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let outside = temporary.path().join("outside");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&outside)?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    symlink(&outside, root.join("artifacts"))?;
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::Overwrite,
    );

    let error = service
        .export_file(&request, &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert!(std::fs::read_dir(&outside)?.next().is_none());
    assert!(
        root.join("artifacts")
            .symlink_metadata()?
            .file_type()
            .is_symlink()
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn export_file_rejects_a_directory_reparse_parent_without_outside_mutation() -> Result<()> {
    use std::os::windows::fs::{MetadataExt as _, symlink_dir};

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let outside = temporary.path().join("outside");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&outside)?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    if let Err(source) = symlink_dir(&outside, root.join("artifacts")) {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(source.into());
    }
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::Overwrite,
    );

    let error = service
        .export_file(&request, &CancellationToken::new())
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert!(std::fs::read_dir(&outside)?.next().is_none());
    assert_ne!(
        root.join("artifacts").symlink_metadata()?.file_attributes() & 0x400,
        0
    );
    Ok(())
}

#[test]
fn deferred_export_cancellation_removes_owned_staging_without_publication() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );

    let completion = service.export_file_deferred_for_operation(
        &request,
        "op_0123456789abcdef0123456789abcdef",
        &CancellationToken::new(),
    )?;

    assert!(!root.join("artifacts/graph.json").exists());
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    completion.cancel()?;
    assert!(!root.join("artifacts/graph.json").exists());
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 0);
    Ok(())
}

#[test]
fn deferred_export_cleanup_without_a_stage_does_not_rerender() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    std::fs::remove_file(&store_path)?;

    service.cancel_deferred_export_file_for_operation(
        &request,
        "op_0123456789abcdef0123456789abcdef",
        &CancellationToken::new(),
    )?;

    assert!(std::fs::read_dir(root.join("artifacts"))?.next().is_none());
    Ok(())
}

#[test]
fn deferred_export_cleanup_keeps_store_failures_retryable_when_stage_exists() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    std::fs::remove_file(&store_path)?;

    let error = service
        .cancel_deferred_export_file_for_operation(
            &request,
            operation_id,
            &CancellationToken::new(),
        )
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Store);
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    assert!(!root.join("artifacts/graph.json").exists());
    drop(completion);
    Ok(())
}

#[test]
fn deferred_export_cleanup_preserves_a_foreign_non_regular_stage() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    std::fs::remove_file(&stage)?;
    std::fs::create_dir(&stage)?;
    std::fs::write(stage.join("foreign-canary"), b"preserve-me")?;

    service.cancel_deferred_export_file_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;

    assert!(stage.is_dir());
    assert_eq!(std::fs::read(stage.join("foreign-canary"))?, b"preserve-me");
    assert!(!root.join("artifacts/graph.json").exists());
    drop(completion);
    Ok(())
}

#[test]
fn live_deferred_export_cancel_preserves_a_foreign_non_regular_stage() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let completion = service.export_file_deferred_for_operation(
        &request,
        "op_0123456789abcdef0123456789abcdef",
        &CancellationToken::new(),
    )?;
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    std::fs::remove_file(&stage)?;
    std::fs::create_dir(&stage)?;
    std::fs::write(stage.join("foreign-canary"), b"preserve-me")?;

    completion.cancel()?;

    assert!(stage.is_dir());
    assert_eq!(std::fs::read(stage.join("foreign-canary"))?, b"preserve-me");
    assert!(!root.join("artifacts/graph.json").exists());
    Ok(())
}

#[test]
fn deferred_export_retry_recognizes_the_exact_operation_owned_stage() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";

    let first = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let replay = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;

    assert_eq!(replay.result(), first.result());
    assert_eq!(replay.snapshot_id(), first.snapshot_id());
    assert!(!root.join("artifacts/graph.json").exists());
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    replay.cancel()?;
    Ok(())
}

#[test]
fn deferred_export_retry_rejects_and_preserves_a_foreign_owned_stage() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let first = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    std::fs::write(&stage, b"foreign-canary")?;

    let error = match service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    ) {
        Ok(_) => panic!("foreign deterministic staging must not be adopted"),
        Err(error) => error,
    };

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert_eq!(std::fs::read(&stage)?, b"foreign-canary");
    assert!(!root.join("artifacts/graph.json").exists());
    drop(first);
    Ok(())
}

#[test]
fn deferred_export_publishes_only_when_completion_is_promoted() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Dot,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.dot")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let completion = service.export_file_deferred_for_operation(
        &request,
        "op_0123456789abcdef0123456789abcdef",
        &CancellationToken::new(),
    )?;
    let expected = completion.result().clone();
    assert!(!root.join("artifacts/graph.dot").exists());

    completion.promote()?;

    let content = std::fs::read(root.join("artifacts/graph.dot"))?;
    assert_eq!(content.len() as u64, expected.output_bytes());
    assert_eq!(
        hex::encode(Sha256::digest(&content)),
        expected.content_sha256()
    );
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn deferred_export_recovery_recognizes_exact_already_published_content() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json")?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path.clone(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let expected = completion.result().clone();
    let destination_precondition = completion.destination_precondition().clone();
    completion.promote()?;

    service.recover_deferred_export_file_completion(&DeferredExportFileRecovery {
        operation_id,
        output_path: &output_path,
        overwrite: RepositoryOverwritePolicy::NoReplace,
        format: GraphExportFormat::Json,
        output_bytes: expected.output_bytes(),
        content_sha256: expected.content_sha256(),
        destination_precondition: Some(&destination_precondition),
    })?;

    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn deferred_export_recovery_preserves_foreign_stage_after_exact_publication() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json")?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path.clone(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let expected = completion.result().clone();
    let destination_precondition = completion.destination_precondition().clone();
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    let published = std::fs::read(&stage)?;
    std::fs::write(root.join(output_path.as_str()), &published)?;
    std::fs::remove_file(&stage)?;
    std::fs::create_dir(&stage)?;
    std::fs::write(stage.join("foreign-canary"), b"preserve-me")?;
    drop(completion);

    service.recover_deferred_export_file_completion(&DeferredExportFileRecovery {
        operation_id,
        output_path: &output_path,
        overwrite: RepositoryOverwritePolicy::NoReplace,
        format: GraphExportFormat::Json,
        output_bytes: expected.output_bytes(),
        content_sha256: expected.content_sha256(),
        destination_precondition: Some(&destination_precondition),
    })?;

    assert_eq!(std::fs::read(root.join(output_path.as_str()))?, published);
    assert!(stage.is_dir());
    assert_eq!(std::fs::read(stage.join("foreign-canary"))?, b"preserve-me");
    Ok(())
}

#[test]
fn deferred_export_recovery_finalizes_overwrite_when_original_destination_is_unchanged()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json")?;
    let output = root.join(output_path.as_str());
    std::fs::write(&output, b"original-destination")?;
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path.clone(),
        RepositoryOverwritePolicy::Overwrite,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let expected = completion.result().clone();
    let destination_precondition = completion.destination_precondition().clone();
    drop(completion);

    service.recover_deferred_export_file_completion(&DeferredExportFileRecovery {
        operation_id,
        output_path: &output_path,
        overwrite: RepositoryOverwritePolicy::Overwrite,
        format: GraphExportFormat::Json,
        output_bytes: expected.output_bytes(),
        content_sha256: expected.content_sha256(),
        destination_precondition: Some(&destination_precondition),
    })?;

    let content = std::fs::read(&output)?;
    assert_eq!(content.len() as u64, expected.output_bytes());
    assert_eq!(
        hex::encode(Sha256::digest(&content)),
        expected.content_sha256()
    );
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 1);
    Ok(())
}

#[test]
fn deferred_export_recovery_rejects_an_externally_changed_overwrite_destination() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let output_path = RepositoryRelativePath::parse("artifacts/graph.json")?;
    let output = root.join(output_path.as_str());
    std::fs::write(&output, b"original-destination")?;
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path.clone(),
        RepositoryOverwritePolicy::Overwrite,
    );
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let expected = completion.result().clone();
    let destination_precondition = completion.destination_precondition().clone();
    drop(completion);
    std::fs::write(&output, b"external-change")?;

    let error = service
        .recover_deferred_export_file_completion(&DeferredExportFileRecovery {
            operation_id,
            output_path: &output_path,
            overwrite: RepositoryOverwritePolicy::Overwrite,
            format: GraphExportFormat::Json,
            output_bytes: expected.output_bytes(),
            content_sha256: expected.content_sha256(),
            destination_precondition: Some(&destination_precondition),
        })
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    assert_eq!(std::fs::read(&output)?, b"external-change");
    assert_eq!(std::fs::read_dir(root.join("artifacts"))?.count(), 2);
    Ok(())
}

#[test]
fn deferred_export_recovery_rejects_empty_staging_before_publication() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let output_path = RepositoryRelativePath::parse("artifacts/empty.json")?;
    let operation_id = "op_0123456789abcdef0123456789abcdef";
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        output_path.clone(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let completion = service.export_file_deferred_for_operation(
        &request,
        operation_id,
        &CancellationToken::new(),
    )?;
    let destination_precondition = completion.destination_precondition().clone();
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    std::fs::write(&stage, b"")?;
    drop(completion);
    let empty_digest = hex::encode(Sha256::digest(b""));

    let error = service
        .recover_deferred_export_file_completion(&DeferredExportFileRecovery {
            operation_id,
            output_path: &output_path,
            overwrite: RepositoryOverwritePolicy::NoReplace,
            format: GraphExportFormat::Json,
            output_bytes: 0,
            content_sha256: &empty_digest,
            destination_precondition: Some(&destination_precondition),
        })
        .unwrap_err();

    assert_eq!(error.category(), DepgraphServiceErrorCategory::Input);
    assert!(!root.join(output_path.as_str()).exists());
    assert_eq!(std::fs::metadata(stage)?.len(), 0);
    Ok(())
}

#[test]
fn deferred_export_lifecycle_rejects_every_protected_destination_before_shortcuts() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = root.join(".depgraph/graph.db");
    std::fs::create_dir_all(root.join(".depgraph"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let protected_paths = [
        ".depgraph/graph.db",
        ".depgraph/graph.db-wal",
        ".depgraph/graph.db.operations.sqlite",
        ".depgraph/graph.db.operations.sqlite.runner-purge-lock",
        ".depgraph/GRAPH.DB-wal",
    ];
    for protected_path in protected_paths {
        let absolute = root.join(protected_path);
        if !absolute.exists() {
            std::fs::write(&absolute, format!("protected-canary:{protected_path}"))?;
        }
        let before = std::fs::read(&absolute)?;
        let digest = hex::encode(Sha256::digest(&before));
        let output_path = RepositoryRelativePath::parse(protected_path)?;
        let recovery =
            service.recover_deferred_export_file_completion(&DeferredExportFileRecovery {
                operation_id: "op_0123456789abcdef0123456789abcdef",
                output_path: &output_path,
                overwrite: RepositoryOverwritePolicy::NoReplace,
                format: GraphExportFormat::Json,
                output_bytes: before.len() as u64,
                content_sha256: &digest,
                destination_precondition: None,
            });
        let request = ExportFileRequest::new(
            GraphExportRequest::try_new(
                SnapshotLocator::parse(&snapshot_id)?,
                GraphExportFormat::Json,
                None,
                GraphQueryFilter::default(),
                100,
                100,
            )?,
            output_path,
            RepositoryOverwritePolicy::NoReplace,
        );
        let cancellation = service.cancel_deferred_export_file_for_operation(
            &request,
            "op_0123456789abcdef0123456789abcdef",
            &CancellationToken::new(),
        );

        assert_eq!(
            recovery.unwrap_err().category(),
            DepgraphServiceErrorCategory::Integrity,
            "recovery accepted {protected_path}"
        );
        assert_eq!(
            cancellation.unwrap_err().category(),
            DepgraphServiceErrorCategory::Integrity,
            "cancellation accepted {protected_path}"
        );
        assert_eq!(std::fs::read(absolute)?, before);
    }
    Ok(())
}

#[test]
fn public_repository_outputs_reserve_deterministic_export_stage_names() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(root.join("artifacts"))?;
    let mut store = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut store, &root)?;
    drop(store);
    let service = repository_write_service(&root, &store_path)?;
    let request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        RepositoryRelativePath::parse("artifacts/graph.json")?,
        RepositoryOverwritePolicy::NoReplace,
    );
    let completion = service.export_file_deferred_for_operation(
        &request,
        "op_0123456789abcdef0123456789abcdef",
        &CancellationToken::new(),
    )?;
    let stage = std::fs::read_dir(root.join("artifacts"))?
        .next()
        .expect("deterministic stage exists")?
        .path();
    let stage_name = stage
        .file_name()
        .and_then(|name| name.to_str())
        .expect("stage name is portable");
    let stage_path = RepositoryRelativePath::parse(format!("artifacts/{stage_name}"))?;
    completion.cancel()?;

    let create_category = match service.create_repository_output(stage_path.as_str()) {
        Ok(output) => {
            drop(output);
            std::fs::remove_file(root.join(stage_path.as_str()))?;
            None
        }
        Err(error) => Some(error.category()),
    };
    let rendered_category = match service.export_rendered_file(
        &stage_path,
        RepositoryOverwritePolicy::NoReplace,
        GraphExportFormat::Json,
        b"{}",
        &CancellationToken::new(),
    ) {
        Ok(_) => {
            std::fs::remove_file(root.join(stage_path.as_str()))?;
            None
        }
        Err(error) => Some(error.category()),
    };
    let direct_request = ExportFileRequest::new(
        GraphExportRequest::try_new(
            SnapshotLocator::parse(&snapshot_id)?,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            100,
            100,
        )?,
        stage_path.clone(),
        RepositoryOverwritePolicy::NoReplace,
    );
    let direct_category = match service.export_file(&direct_request, &CancellationToken::new()) {
        Ok(_) => {
            std::fs::remove_file(root.join(stage_path.as_str()))?;
            None
        }
        Err(error) => Some(error.category()),
    };

    for category in [create_category, rendered_category, direct_category] {
        assert_eq!(category, Some(DepgraphServiceErrorCategory::Integrity));
    }
    assert!(!root.join(stage_path.as_str()).exists());

    let digest = stage_name
        .strip_prefix(".depgraph-export-")
        .expect("deterministic stage prefix");
    for alias in [
        format!("artifacts/.DEPGRAPH-EXPORT-{digest}"),
        format!("artifacts/.depgraph-export-{}", digest.to_uppercase()),
    ] {
        let alias_path = RepositoryRelativePath::parse(alias)?;
        let category = match service.create_repository_output(alias_path.as_str()) {
            Ok(output) => {
                drop(output);
                std::fs::remove_file(root.join(alias_path.as_str()))?;
                None
            }
            Err(error) => Some(error.category()),
        };
        assert_eq!(
            category,
            Some(DepgraphServiceErrorCategory::Integrity),
            "public output accepted deterministic stage alias {}",
            alias_path.as_str()
        );
    }
    Ok(())
}
