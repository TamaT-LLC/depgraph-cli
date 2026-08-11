use std::{
    collections::BTreeSet,
    error::Error,
    io::{Read as _, Write as _},
    path::Path,
};

use anyhow::Result;
use depgraph_core::service::{
    CurrentSnapshotAvailability, DEPGRAPH_SERVICE_LIMITS_VERSION, DepgraphCapability,
    DepgraphCapabilitySet, DepgraphMutatingContext, DepgraphMutatingUseCase,
    DepgraphMutatingUseCaseKind, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceConfigurationError, DepgraphServiceError, DepgraphServiceErrorCategory,
    DepgraphServiceLimit, DepgraphServiceLimits, MAX_REPOSITORY_PATH_BYTES,
    MAX_REPOSITORY_PATH_COMPONENT_BYTES, MAX_REPOSITORY_PATH_COMPONENTS, NodeMatchMode,
    RepositoryFileError, RepositoryPathError, RepositoryPathSelector, RepositoryRelativePath,
    SnapshotLocator,
};
use depgraph_core::{CancellationToken, DoctorRequest, ProfilePlanRequest};
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

fn repository_write_service(
    root: &Path,
    store_path: &Path,
) -> Result<DepgraphService, DepgraphServiceError> {
    let config = DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::RepositoryWrite,
        ])?,
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

fn daemon_control_service(
    root: &Path,
    store_path: &Path,
) -> Result<DepgraphService, DepgraphServiceError> {
    let config = DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::try_new([
            DepgraphCapability::Read,
            DepgraphCapability::StoreWrite,
            DepgraphCapability::DaemonControl,
        ])?,
        DepgraphServiceLimits::default(),
    )?;
    Ok(DepgraphService::new(config))
}

fn seed_completed_snapshot(
    store: &mut Store,
    root: &Path,
    scan_id: &str,
    revision: &str,
) -> Result<String> {
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
    store.start_scan_with_revision(scan_id, root, false, Some(revision))?;
    for event in [
        json!({"event":"scan_started","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":1,"root":root,"project_code_executed":false,"safe_mode":true}),
        json!({"event":"scan_completed","protocol_version":"1.0","scan_id":scan_id,"adapter":"rust","adapter_version":"0.1.0","seq":2,"coverage":coverage}),
    ] {
        store.ingest_event(&event)?;
    }
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("a promoted completed scan has a current snapshot"))
}

fn seed_search_snapshot(store: &mut Store, root: &Path) -> Result<String> {
    let coverage = json!({
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
        "reasons": []
    });
    store.start_scan_with_revision("search", root, false, Some("revision-search"))?;
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "search",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "rust:safe",
        "language": "rust",
        "features": [],
        "environment": {},
        "properties": {}
    });
    store.ingest_event(&profile)?;
    for (seq, node) in [
        json!({
            "id": "node:zeta",
            "kind": "module",
            "locator": "repo://src/zeta.rs",
            "display_name": "crate::zeta",
            "properties": {"path": root.join("secret-zeta.rs"), "secret": "must-not-leak"}
        }),
        json!({
            "id": "node:alpha",
            "kind": "module",
            "locator": "repo://src/alpha.rs",
            "display_name": "crate::alpha",
            "properties": {"path": root.join("secret-alpha.rs"), "secret": "must-not-leak"}
        }),
        json!({
            "id": "node:beta",
            "kind": "function",
            "locator": "repo://src/beta.rs#fixture",
            "display_name": "crate::beta::fixture",
            "properties": {"path": root.join("secret-beta.rs"), "secret": "must-not-leak"}
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let mut event = common("node_upsert", seq as u64 + 3);
        event["node"] = node;
        store.ingest_event(&event)?;
    }
    let mut profile_completed = common("profile_completed", 6);
    profile_completed["profile_id"] = json!("rust:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", 7);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan("search", "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("search fixture snapshot is current"))
}

#[test]
fn context_uses_logical_identity_and_succeeds_without_a_snapshot() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    Store::open(&store_path)?;

    let service = read_only_service(&root, &store_path)?;
    let empty = service.get_context()?;
    assert_eq!(empty.repository_id(), "repository");
    assert!(
        !empty
            .repository_id()
            .contains(root.to_string_lossy().as_ref())
    );
    assert_eq!(empty.enabled_capabilities(), &[DepgraphCapability::Read]);
    assert_eq!(
        empty.current_snapshot().availability(),
        CurrentSnapshotAvailability::Unavailable
    );
    assert!(empty.current_snapshot().details().is_none());

    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_search_snapshot(&mut writer, &root)?;
    let populated = service.get_context()?;
    let current = populated
        .current_snapshot()
        .details()
        .expect("current completed snapshot details");
    assert_eq!(current.id(), snapshot_id);
    assert_eq!(current.coverage().profiles, 1);
    assert_eq!(current.coverage().files_analyzed, 0);
    Ok(())
}

#[test]
fn find_nodes_is_bounded_projected_and_stably_sorted_for_every_match_mode() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_search_snapshot(&mut writer, &root)?;
    let service = read_only_service(&root, &store_path)?;
    let snapshot = SnapshotLocator::parse(&snapshot_id)?;

    let exact = service.find_nodes(&snapshot, "module", NodeMatchMode::Exact)?;
    assert_eq!(
        exact
            .nodes()
            .iter()
            .map(|node| node.id())
            .collect::<Vec<_>>(),
        ["node:alpha", "node:zeta"]
    );
    let prefix = service.find_nodes(&snapshot, "crate::", NodeMatchMode::Prefix)?;
    assert_eq!(prefix.nodes().len(), 3);
    let contains = service.find_nodes(&snapshot, "fixture", NodeMatchMode::Contains)?;
    assert_eq!(contains.nodes().len(), 1);
    let public = serde_json::to_value(&contains.nodes()[0])?;
    let mut fields = public
        .as_object()
        .expect("node projection object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(fields, ["display_name", "id", "kind", "locator"]);
    assert!(!public.to_string().contains("must-not-leak"));
    assert!(!public.to_string().contains(root.to_string_lossy().as_ref()));

    assert!(
        service
            .find_nodes(&snapshot, &"あ".repeat(85), NodeMatchMode::Contains)
            .is_ok()
    );
    assert!(matches!(
        service.find_nodes(&snapshot, &"あ".repeat(86), NodeMatchMode::Contains),
        Err(DepgraphServiceError::InvalidInput)
    ));
    Ok(())
}

#[test]
fn completed_snapshot_list_and_show_are_stable_closed_service_views() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_search_snapshot(&mut writer, &root)?;
    writer.create_snapshot_name("zeta", &snapshot_id)?;
    writer.create_snapshot_name("alpha", &snapshot_id)?;
    let service = read_only_service(&root, &store_path)?;

    let listed = service.list_completed_snapshots()?;
    assert_eq!(
        listed.iter().map(|item| item.name()).collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert!(
        listed
            .iter()
            .all(|item| item.snapshot().id() == snapshot_id)
    );
    let shown = service.show_completed_snapshot(&SnapshotLocator::parse("ALPHA")?)?;
    assert_eq!(shown.id(), snapshot_id);
    assert_eq!(shown.names(), ["alpha", "zeta"]);
    let public = serde_json::to_string(&shown)?;
    assert!(!public.contains(root.to_string_lossy().as_ref()));
    assert!(!public.contains("properties"));
    Ok(())
}

#[test]
fn completed_snapshot_list_preserves_cli_behavior_above_mcp_page_limit() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    std::fs::create_dir_all(&root)?;
    let mut writer = Store::open(&store_path)?;
    let snapshot_id = seed_completed_snapshot(&mut writer, &root, "many-names", "revision")?;
    for index in 0..=1_000 {
        writer.create_snapshot_name(&format!("name-{index:04}"), &snapshot_id)?;
    }
    drop(writer);

    let listed = read_only_service(&root, &store_path)?.list_completed_snapshots()?;
    assert_eq!(listed.len(), 1_001);
    assert_eq!(listed.first().unwrap().name(), "name-0000");
    assert_eq!(listed.last().unwrap().name(), "name-1000");
    Ok(())
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
fn repository_paths_and_graph_path_selectors_are_lexically_normalized() -> Result<()> {
    let path = RepositoryRelativePath::parse("src/domain/model.rs")?;
    assert_eq!(path.as_str(), "src/domain/model.rs");

    let selector = RepositoryPathSelector::parse("path:src/domain/model.rs")?;
    assert_eq!(selector.path(), "src/domain/model.rs");
    assert_eq!(selector.to_string(), "path:src/domain/model.rs");

    for input in [
        "console",
        "com10.log",
        "lpt0",
        "auxiliary.txt",
        ".git/config",
    ] {
        RepositoryRelativePath::parse(input)
            .unwrap_or_else(|error| panic!("portable path {input:?} was rejected: {error:?}"));
    }

    for (input, expected) in [
        ("", RepositoryPathError::Empty),
        ("/etc/passwd", RepositoryPathError::Absolute),
        ("./src/lib.rs", RepositoryPathError::DotComponent),
        ("src/../secret", RepositoryPathError::ParentComponent),
        ("src//lib.rs", RepositoryPathError::EmptyComponent),
        ("src/lib.rs/", RepositoryPathError::EmptyComponent),
        ("src\0secret", RepositoryPathError::Nul),
        ("C:/Windows/win.ini", RepositoryPathError::PlatformPrefix),
        ("C:Windows/win.ini", RepositoryPathError::PlatformPrefix),
        ("C:\\Windows\\win.ini", RepositoryPathError::PlatformPrefix),
        ("public.txt:private", RepositoryPathError::PlatformStream),
        (
            "nested/public.txt:private",
            RepositoryPathError::PlatformStream,
        ),
        ("nested/.. ", RepositoryPathError::PlatformAlias),
        ("nested/file.", RepositoryPathError::PlatformAlias),
        ("CON", RepositoryPathError::PlatformDevice),
        ("nested/nul.txt", RepositoryPathError::PlatformDevice),
        ("nested/Com1.log", RepositoryPathError::PlatformDevice),
        ("nested/LPT9", RepositoryPathError::PlatformDevice),
        ("nested/COM¹.txt", RepositoryPathError::PlatformDevice),
        (
            "\\\\server\\share\\file",
            RepositoryPathError::PlatformPrefix,
        ),
        ("\\\\?\\C:\\file", RepositoryPathError::PlatformPrefix),
        (
            "src\\platform-specific.rs",
            RepositoryPathError::PlatformSeparator,
        ),
    ] {
        let error = RepositoryRelativePath::parse(input).unwrap_err();
        assert!(
            matches!(
                error,
                DepgraphServiceError::InvalidRepositoryPath { reason } if reason == expected
            ),
            "unexpected result for {input:?}: {error:?}"
        );
    }

    let long_component = "x".repeat(MAX_REPOSITORY_PATH_COMPONENT_BYTES + 1);
    assert!(matches!(
        RepositoryRelativePath::parse(&long_component),
        Err(DepgraphServiceError::InvalidRepositoryPath {
            reason: RepositoryPathError::ComponentTooLong
        })
    ));
    let too_many_components = std::iter::repeat_n("a", MAX_REPOSITORY_PATH_COMPONENTS + 1)
        .collect::<Vec<_>>()
        .join("/");
    assert!(matches!(
        RepositoryRelativePath::parse(&too_many_components),
        Err(DepgraphServiceError::InvalidRepositoryPath {
            reason: RepositoryPathError::TooManyComponents
        })
    ));
    let too_long = std::iter::repeat_n("x".repeat(240), 18)
        .collect::<Vec<_>>()
        .join("/");
    assert!(too_long.len() > MAX_REPOSITORY_PATH_BYTES);
    assert!(matches!(
        RepositoryRelativePath::parse(&too_long),
        Err(DepgraphServiceError::InvalidRepositoryPath {
            reason: RepositoryPathError::TooLong
        })
    ));
    Ok(())
}

#[test]
fn confined_input_and_output_handles_use_only_repository_relative_paths() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(root.join("nested"))?;
    std::fs::create_dir_all(&store_directory)?;
    std::fs::write(root.join("nested/input.txt"), b"confined")?;
    let service = repository_write_service(&root, &store_path)?;

    let mut input = service.open_repository_input("nested/input.txt")?;
    let mut contents = String::new();
    input.read_to_string(&mut contents)?;
    assert_eq!(contents, "confined");
    assert_eq!(input.relative_path().as_str(), "nested/input.txt");

    let mut output = service.create_repository_output("nested/output.txt")?;
    output.write_all(b"created through confined handle")?;
    output.flush()?;
    drop(output);
    assert_eq!(
        std::fs::read(root.join("nested/output.txt"))?,
        b"created through confined handle"
    );

    let conflict = service
        .create_repository_output("nested/output.txt")
        .unwrap_err();
    assert!(matches!(
        conflict,
        DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::AlreadyExists
        }
    ));

    let read_only = read_only_service(&root, &store_path)?;
    let denied = read_only
        .create_repository_output("nested/denied.txt")
        .unwrap_err();
    assert!(matches!(
        denied,
        DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::RepositoryWrite
        }
    ));
    assert!(!root.join("nested/denied.txt").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn posix_no_follow_handles_reject_symlinks_and_root_identity_changes() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let outside = temporary.path().join("outside");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(root.join("nested"))?;
    std::fs::create_dir_all(&outside)?;
    std::fs::create_dir_all(&store_directory)?;
    std::fs::write(outside.join("canary.txt"), b"outside")?;
    symlink(outside.join("canary.txt"), root.join("linked-file"))?;
    symlink(&outside, root.join("linked-directory"))?;
    symlink(outside.join("canary.txt"), root.join("linked-output"))?;

    let service = repository_write_service(&root, &store_path)?;
    for relative in ["linked-file", "linked-directory/canary.txt"] {
        let error = service.open_repository_input(relative).unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    }
    let output_error = service
        .create_repository_output("linked-output")
        .unwrap_err();
    assert_eq!(
        output_error.category(),
        DepgraphServiceErrorCategory::Integrity
    );
    assert_eq!(std::fs::read(outside.join("canary.txt"))?, b"outside");

    let original_root = temporary.path().join("original-repository");
    std::fs::rename(&root, &original_root)?;
    std::fs::create_dir_all(root.join("nested"))?;
    std::fs::write(root.join("nested/input.txt"), b"replacement")?;
    let identity_error = service
        .open_repository_input("nested/input.txt")
        .unwrap_err();
    assert!(matches!(
        identity_error,
        DepgraphServiceError::RepositoryFile {
            reason: RepositoryFileError::BoundaryViolation
        }
    ));
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_no_follow_handles_reject_file_and_directory_reparse_points() -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let outside = temporary.path().join("outside");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&outside)?;
    std::fs::create_dir_all(&store_directory)?;
    std::fs::write(outside.join("canary.txt"), b"outside")?;
    if let Err(source) = symlink_file(outside.join("canary.txt"), root.join("linked-file")) {
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            return Ok(());
        }
        return Err(source.into());
    }
    symlink_dir(&outside, root.join("linked-directory"))?;

    let service = repository_write_service(&root, &store_path)?;
    for relative in ["linked-file", "linked-directory/canary.txt"] {
        let error = service.open_repository_input(relative).unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    }
    Ok(())
}

#[test]
fn snapshot_requests_pin_completed_stable_ids_and_keep_path_selectors_separate() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_directory = temporary.path().join("cache");
    let store_path = store_directory.join("graph.db");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&store_directory)?;

    let mut writer = Store::open(&store_path)?;
    let first_snapshot = seed_completed_snapshot(&mut writer, &root, "first", "revision-1")?;
    writer.create_snapshot_name("baseline", &first_snapshot)?;

    let service = read_only_service(&root, &store_path)?;
    let mut current_request = service.start_snapshot_request("current")?;
    let named_request = service.start_snapshot_request("baseline")?;
    let stable_request = service.start_snapshot_request(&first_snapshot)?;
    assert_eq!(current_request.snapshot_id().as_str(), first_snapshot);
    assert_eq!(named_request.snapshot_id().as_str(), first_snapshot);
    assert_eq!(stable_request.snapshot_id().as_str(), first_snapshot);

    let second_snapshot = seed_completed_snapshot(&mut writer, &root, "second", "revision-2")?;
    assert_ne!(second_snapshot, first_snapshot);
    assert_eq!(
        writer.current_snapshot_id()?.as_deref(),
        Some(second_snapshot.as_str())
    );
    assert_eq!(
        current_request.store().current_snapshot_id()?.as_deref(),
        Some(second_snapshot.as_str()),
        "the request connection may observe a later current pointer"
    );
    assert_eq!(
        current_request.snapshot_id().as_str(),
        first_snapshot,
        "the resolved request identity must remain immutable"
    );

    let path_selector = service.normalize_path_selector("path:src/not-on-disk.rs")?;
    assert_eq!(path_selector.path(), "src/not-on-disk.rs");
    assert!(matches!(
        service.start_snapshot_request(path_selector.to_string()),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        SnapshotLocator::parse("snapshot:sha256:not-a-digest"),
        Err(DepgraphServiceError::InvalidInput)
    ));
    assert!(matches!(
        service.start_snapshot_request(format!("snapshot:sha256:{}", "0".repeat(64))),
        Err(DepgraphServiceError::NotFound)
    ));
    Ok(())
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

fn write_profile_plan_repository(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='service-lifecycle-fixture'\nversion='0.1.0'\n",
    )?;
    std::fs::write(root.join("src/lib.rs"), "pub fn fixture() {}\n")?;
    std::fs::write(
        root.join("build.rs"),
        "fn main() { std::fs::write(\"project-code-ran\", \"bad\").unwrap(); }\n",
    )?;
    Ok(())
}

#[test]
fn lifecycle_profile_plan_is_bounded_static_and_inline_file_equivalent() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("missing-store.sqlite");
    std::fs::create_dir_all(&root)?;
    write_profile_plan_repository(&root)?;
    let service = read_only_service(&root, &store_path)?;

    let automatic = service
        .profile_plan_cancellable(&ProfilePlanRequest::default(), &CancellationToken::new())?;
    assert!(!store_path.exists());
    assert!(!root.join("project-code-ran").exists());

    let document = serde_json::to_string(&json!({
        "contract_version": "default-profile-selection-v1",
        "profiles": [automatic.plan.profiles[0].axes]
    }))?;
    std::fs::create_dir_all(root.join(".depgraph"))?;
    std::fs::write(root.join(".depgraph/profiles.json"), &document)?;
    let inline = service.profile_plan_cancellable(
        &ProfilePlanRequest {
            profiles_document: Some(document),
            ..ProfilePlanRequest::default()
        },
        &CancellationToken::new(),
    )?;
    let file = service.profile_plan_cancellable(
        &ProfilePlanRequest {
            profiles_file: Some(RepositoryRelativePath::parse(".depgraph/profiles.json")?),
            ..ProfilePlanRequest::default()
        },
        &CancellationToken::new(),
    )?;
    assert_eq!(serde_json::to_value(inline)?, serde_json::to_value(file)?);
    assert!(!store_path.exists());
    assert!(!root.join("project-code-ran").exists());

    let limits = DepgraphServiceLimits::try_new(
        DEPGRAPH_SERVICE_LIMITS_VERSION,
        8,
        1024 * 1024,
        100,
        1_000,
    )?;
    let bounded = DepgraphService::new(DepgraphServiceConfig::new(
        &root,
        &store_path,
        DepgraphCapabilitySet::read_only(),
        limits,
    )?);
    assert!(matches!(
        bounded.profile_plan_cancellable(
            &ProfilePlanRequest {
                profiles_document: Some("123456789".to_owned()),
                ..ProfilePlanRequest::default()
            },
            &CancellationToken::new()
        ),
        Err(DepgraphServiceError::ResourceExhausted)
    ));
    assert!(RepositoryRelativePath::parse("../profiles.json").is_err());
    assert!(RepositoryRelativePath::parse("/outside/profiles.json").is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn lifecycle_profile_plan_rejects_file_and_parent_symlinks() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let outside = temporary.path().join("outside");
    let store_path = temporary.path().join("missing-store.sqlite");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&outside)?;
    write_profile_plan_repository(&root)?;
    std::fs::write(outside.join("profiles.json"), b"{}")?;
    symlink(
        outside.join("profiles.json"),
        root.join("profiles-link.json"),
    )?;
    symlink(&outside, root.join("linked-parent"))?;
    let service = read_only_service(&root, &store_path)?;

    for path in ["profiles-link.json", "linked-parent/profiles.json"] {
        let error = service
            .profile_plan_cancellable(
                &ProfilePlanRequest {
                    profiles_file: Some(RepositoryRelativePath::parse(path)?),
                    ..ProfilePlanRequest::default()
                },
                &CancellationToken::new(),
            )
            .unwrap_err();
        assert_eq!(error.category(), DepgraphServiceErrorCategory::Integrity);
    }
    assert!(!store_path.exists());
    Ok(())
}

#[test]
fn lifecycle_daemon_status_reads_only_the_bounded_status_file() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("never-opened.sqlite");
    std::fs::create_dir_all(&root)?;
    let service = read_only_service(&root, &store_path)?;
    let status_path = temporary
        .path()
        .join("never-opened.sqlite.daemon-status.json");
    let status = json!({
        "schema_version": "daemon-status-v1",
        "root": root,
        "phase": "idle",
        "started_at": "2026-08-06T00:00:00Z",
        "stopped_at": null,
        "debounce_milliseconds": 100,
        "pending_change_count": 0,
        "active_attempt_id": null,
        "last_completed_attempt": null,
        "last_failed_attempt": null,
        "last_cancelled_attempt": null,
        "last_watcher_error": null,
        "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
    });
    let original = serde_json::to_vec(&status)?;
    std::fs::write(&status_path, &original)?;

    let actual = service.daemon_status_cancellable(&CancellationToken::new())?;
    assert_eq!(serde_json::to_value(actual)?, status);
    assert_eq!(std::fs::read(&status_path)?, original);
    assert!(!store_path.exists());
    Ok(())
}

#[tokio::test]
async fn lifecycle_daemon_stop_is_idempotent_only_after_stopped_cleanup_and_lock_release()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("never-opened.sqlite");
    std::fs::create_dir_all(&root)?;
    let service = daemon_control_service(&root, &store_path)?;
    let status_path = temporary
        .path()
        .join("never-opened.sqlite.daemon-status.json");
    let stop_path = temporary.path().join("never-opened.sqlite.daemon-stop");
    std::fs::write(
        &status_path,
        serde_json::to_vec(&json!({
            "schema_version": "daemon-status-v1",
            "root": root.canonicalize()?,
            "phase": "stopped",
            "started_at": "2026-08-06T00:00:00Z",
            "stopped_at": "2026-08-06T00:00:01Z",
            "debounce_milliseconds": 100,
            "pending_change_count": 0,
            "active_attempt_id": null,
            "last_completed_attempt": null,
            "last_failed_attempt": null,
            "last_cancelled_attempt": null,
            "last_watcher_error": null,
            "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
        }))?,
    )?;
    std::fs::write(
        &stop_path,
        serde_json::to_vec(&json!({
            "schema_version": "depgraph-daemon-stop-request-v1",
            "root": root.canonicalize()?,
            "started_at": "2026-08-06T00:00:00Z"
        }))?,
    )?;

    let status = service
        .daemon_stop_cancellable(&CancellationToken::new())
        .await?;

    assert_eq!(status.phase, depgraph_core::DaemonPhase::Stopped);
    assert!(!stop_path.exists());
    assert!(!store_path.exists());
    Ok(())
}

#[tokio::test]
async fn lifecycle_daemon_start_recovers_an_active_status_left_by_a_crashed_owner() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir_all(&root)?;
    let service = daemon_control_service(&root, &store_path)?;
    std::fs::write(
        temporary.path().join("graph.sqlite.daemon-status.json"),
        serde_json::to_vec(&json!({
            "schema_version": "daemon-status-v1",
            "root": root.canonicalize()?,
            "phase": "idle",
            "started_at": "2026-08-11T00:00:00Z",
            "stopped_at": null,
            "debounce_milliseconds": 100,
            "pending_change_count": 0,
            "active_attempt_id": null,
            "last_completed_attempt": null,
            "last_failed_attempt": null,
            "last_cancelled_attempt": null,
            "last_watcher_error": null,
            "recovered_attempts": {"scan_attempt_ids": [], "build_attempt_ids": []}
        }))?,
    )?;

    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let stopped = service
        .daemon_start_foreground_with_running_cancellable(false, &cancellation, move || {
            stop.cancel();
        })
        .await?;

    assert_eq!(stopped.phase, depgraph_core::DaemonPhase::Stopped);
    assert!(!service.daemon_running_cancellable(&CancellationToken::new())?);
    Ok(())
}

#[tokio::test]
async fn lifecycle_daemon_start_releases_locks_after_post_acquisition_control_error() -> Result<()>
{
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    let stop_path = temporary.path().join("graph.sqlite.daemon-stop");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir(&stop_path)?;
    let service = daemon_control_service(&root, &store_path)?;

    let malformed_stop_error = service
        .daemon_start_foreground_cancellable(false, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(malformed_stop_error, DepgraphServiceError::Integrity),
        "unexpected malformed stop-path error: {malformed_stop_error:?}"
    );

    std::fs::remove_dir(&stop_path)?;
    let cancellation = CancellationToken::new();
    let stop = cancellation.clone();
    let stopped = service
        .daemon_start_foreground_with_running_cancellable(false, &cancellation, move || {
            stop.cancel();
        })
        .await?;
    assert_eq!(stopped.phase, depgraph_core::DaemonPhase::Stopped);
    Ok(())
}

#[tokio::test]
async fn lifecycle_daemon_control_rejects_store_write_only_without_mutation() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("missing.sqlite");
    std::fs::create_dir_all(&root)?;
    let config = DepgraphServiceConfig::new(
        &root,
        &store_path,
        DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::StoreWrite])?,
        DepgraphServiceLimits::default(),
    )?;
    let service = DepgraphService::new(config);

    assert!(matches!(
        service
            .daemon_stop_cancellable(&CancellationToken::new())
            .await,
        Err(DepgraphServiceError::CapabilityDenied {
            required: DepgraphCapability::DaemonControl
        })
    ));
    assert!(!store_path.exists());
    Ok(())
}

#[test]
fn lifecycle_methods_honor_preexisting_cancellation_before_io() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("missing.sqlite");
    std::fs::create_dir_all(&root)?;
    write_profile_plan_repository(&root)?;
    let service = read_only_service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert!(matches!(
        service.profile_plan_cancellable(&ProfilePlanRequest::default(), &cancellation),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(matches!(
        service.daemon_status_cancellable(&cancellation),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(matches!(
        service.doctor_cancellable(&DoctorRequest::default(), &cancellation),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(!store_path.exists());
    Ok(())
}

#[test]
fn lifecycle_doctor_projects_only_allowlisted_redacted_agent_data() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("graph.sqlite");
    std::fs::create_dir_all(&root)?;
    let mut store = Store::open(&store_path)?;
    store.start_scan("redaction", &root, false)?;
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": "redaction",
            "adapter": "rust",
            "adapter_version": "0.1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;
    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "rust:safe",
        "language": "rust",
        "features": [],
        "environment": {"API_TOKEN": "profile-secret"},
        "properties": {"compiler_command": "/usr/bin/rustc --crate-name secret"}
    });
    store.ingest_event(&profile)?;
    let mut diagnostic = common("diagnostic", 3);
    diagnostic["diagnostic"] = json!({
        "id": "diagnostic:redaction",
        "severity": "warning",
        "code": "fixture.warning",
        "message": "diagnostic-secret /private/tool",
        "path": "src/lib.rs",
        "properties": {"credential": "diagnostic-property-secret"}
    });
    store.ingest_event(&diagnostic)?;
    let coverage = json!({
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
        "reasons": []
    });
    let mut profile_completed = common("profile_completed", 4);
    profile_completed["profile_id"] = json!("rust:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    let mut completed = common("scan_completed", 5);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.save_adapter_log(
        "redaction",
        "rust",
        "worker-log-secret /usr/bin/rustc",
        false,
    )?;
    store.finish_scan("redaction", "completed", None, true)?;
    drop(store);

    let service = read_only_service(&root, &store_path)?;
    let response = service.doctor_cancellable(
        &DoctorRequest {
            details: true,
            use_service_root: true,
            compiler_pack_requirement: None,
        },
        &CancellationToken::new(),
    )?;
    let value = serde_json::to_value(response)?;
    let encoded = serde_json::to_string(&value)?;
    for forbidden in [
        "profile-secret",
        "diagnostic-secret",
        "diagnostic-property-secret",
        "worker-log-secret",
        "/usr/bin/rustc",
        &root.to_string_lossy(),
    ] {
        assert!(!encoded.contains(forbidden), "leaked {forbidden:?}");
    }
    assert!(value.get("diagnostic_root").is_none());
    for worker in value["workers"].as_array().unwrap() {
        assert!(worker.get("command").is_none());
        assert!(worker.get("error").is_none());
        assert!(worker.get("root_launch_error").is_none());
    }
    let latest = &value["latest_attempt"];
    assert!(latest.get("adapter_logs").is_none());
    assert!(latest["profiles"][0].get("environment").is_none());
    assert!(latest["profiles"][0].get("properties").is_none());
    assert!(latest["diagnostics"][0].get("message").is_none());
    assert!(latest["diagnostics"][0].get("properties").is_none());
    Ok(())
}
