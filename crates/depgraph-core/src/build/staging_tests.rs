use super::*;
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, fs::symlink};

fn write_fixture(root: &Path, relative: &str, contents: &str) -> Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().context("fixture path has no parent")?)?;
    fs::write(path, contents)?;
    Ok(())
}

fn link_fixture(root: &Path, relative: &str, target: impl AsRef<Path>) -> Result<()> {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().context("fixture link has no parent")?)?;
    symlink(target, path)?;
    Ok(())
}

fn assert_absent(path: &Path) {
    assert!(
        fs::symlink_metadata(path).is_err(),
        "excluded entry must not exist, even as a dangling link: {}",
        path.display()
    );
}

fn assert_rebased_link(root: &Path, relative: &str, target: &str) -> Result<()> {
    let link = root.join(relative);
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    assert!(fs::read_link(&link)?.is_relative());
    assert_eq!(link.canonicalize()?, root.join(target).canonicalize()?);
    assert!(link.canonicalize()?.starts_with(root.canonicalize()?));
    Ok(())
}

fn run_node(root: &Path, script: &str) -> Result<String> {
    let node = resolve_safe_executable("node", root)
        .context("Node.js is required for the pnpm staging regression")?;
    let output = std::process::Command::new(node)
        .arg(script)
        .current_dir(root)
        .env_remove("NODE_OPTIONS")
        .env_remove("NODE_PATH")
        .output()?;
    assert!(
        output.status.success(),
        "Node.js failed in {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn write_pnpm_fixture(root: &Path) -> Result<()> {
    for (version, exports) in [
        ("1.1.0", "exports.version = '1.1.0';\n"),
        (
            "1.2.0",
            "exports.version = '1.2.0'; exports.createSlot = () => 'nested-slot-1.2.0';\n",
        ),
    ] {
        let package = format!(
            "node_modules/.pnpm/@radix-ui+react-slot@{version}/node_modules/@radix-ui/react-slot"
        );
        write_fixture(root, &format!("{package}/index.js"), exports)?;
        write_fixture(
            root,
            &format!("{package}/package.json"),
            &format!(
                r#"{{"name":"@radix-ui/react-slot","version":"{version}","main":"index.js"}}"#
            ),
        )?;
    }
    let consumer =
        "node_modules/.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-dialog";
    write_fixture(
        root,
        &format!("{consumer}/package.json"),
        r#"{"name":"@radix-ui/react-dialog","version":"1.1.1","main":"index.js"}"#,
    )?;
    write_fixture(
        root,
        &format!("{consumer}/index.js"),
        "const { createSlot } = require('@radix-ui/react-slot');\nmodule.exports = { slot: createSlot(), resolved: require.resolve('@radix-ui/react-slot') };\n",
    )?;
    write_fixture(
        root,
        &format!("{consumer}/cli.js"),
        "#!/usr/bin/env node\nconsole.log(require('./index.js').slot);\n",
    )?;
    fs::set_permissions(
        root.join(format!("{consumer}/cli.js")),
        fs::Permissions::from_mode(0o755),
    )?;
    link_fixture(
        root,
        "node_modules/@radix-ui/react-slot",
        "../.pnpm/@radix-ui+react-slot@1.1.0/node_modules/@radix-ui/react-slot",
    )?;
    link_fixture(
        root,
        "node_modules/@radix-ui/react-dialog",
        "../.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-dialog",
    )?;
    link_fixture(
        root,
        "node_modules/.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-slot",
        "../../../@radix-ui+react-slot@1.2.0/node_modules/@radix-ui/react-slot",
    )?;
    link_fixture(
        root,
        "node_modules/.bin/dialog-fixture",
        "../.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-dialog/cli.js",
    )?;
    write_fixture(
        root,
        "verify.cjs",
        r#"const assert = require('node:assert/strict');
const direct = require('@radix-ui/react-slot');
assert.equal(direct.version, '1.1.0');
assert.equal(direct.createSlot, undefined);
const nested = require('@radix-ui/react-dialog');
assert.equal(nested.slot, 'nested-slot-1.2.0');
assert.match(nested.resolved.replaceAll('\\', '/'), /\/\.pnpm\/@radix-ui\+react-slot@1\.2\.0\//);
console.log(nested.slot);
"#,
    )?;
    Ok(())
}

#[test]
fn staged_pnpm_node_resolution_preserves_nested_package_versions_and_bin_links() -> Result<()> {
    // Exercise both root-level installs and workspace-member node_modules.
    for relative_app in ["", "apps/web"] {
        let root = tempfile::tempdir()?;
        let app = root.path().join(relative_app);
        write_pnpm_fixture(&app)?;
        assert_eq!(run_node(&app, "verify.cjs")?, "nested-slot-1.2.0\n");
        assert_eq!(
            run_node(&app, "node_modules/.bin/dialog-fixture")?,
            "nested-slot-1.2.0\n"
        );

        let destination = tempfile::tempdir()?;
        stage_workspace(root.path(), destination.path())?;
        let staged = destination.path().join(relative_app);
        // This fails with createSlot-is-not-a-function under the old dereferencing stager.
        assert_eq!(run_node(&staged, "verify.cjs")?, "nested-slot-1.2.0\n");
        assert_eq!(
            run_node(&staged, "node_modules/.bin/dialog-fixture")?,
            "nested-slot-1.2.0\n"
        );
        for (link, target) in [
            (
                "node_modules/@radix-ui/react-slot",
                "node_modules/.pnpm/@radix-ui+react-slot@1.1.0/node_modules/@radix-ui/react-slot",
            ),
            (
                "node_modules/@radix-ui/react-dialog",
                "node_modules/.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-dialog",
            ),
            (
                "node_modules/.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-slot",
                "node_modules/.pnpm/@radix-ui+react-slot@1.2.0/node_modules/@radix-ui/react-slot",
            ),
            (
                "node_modules/.bin/dialog-fixture",
                "node_modules/.pnpm/@radix-ui+react-dialog@1.1.1/node_modules/@radix-ui/react-dialog/cli.js",
            ),
        ] {
            assert_rebased_link(&staged, link, target)?;
        }
        assert_eq!(
            fs::metadata(staged.join("node_modules/.bin/dialog-fixture"))?
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
    Ok(())
}

#[test]
fn absolute_dependency_links_are_rebased_without_original_checkout_write_through() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(root.path(), "packages/pkg/index.js", "original\n")?;
    link_fixture(
        root.path(),
        "node_modules/pkg",
        root.path().join("packages/pkg"),
    )?;
    link_fixture(
        root.path(),
        "node_modules/.bin/pkg",
        root.path().join("packages/pkg/index.js"),
    )?;
    // Lexically earlier aliases must not require their destination links to exist yet.
    link_fixture(root.path(), "node_modules/aaa", "pkg")?;
    let before = source_mutation_fingerprint(root.path())?;
    let destination = tempfile::tempdir()?;
    stage_workspace(root.path(), destination.path())?;
    for (link, target) in [
        ("node_modules/pkg", "packages/pkg"),
        ("node_modules/aaa", "packages/pkg"),
        ("node_modules/.bin/pkg", "packages/pkg/index.js"),
    ] {
        assert_rebased_link(destination.path(), link, target)?;
    }
    assert_eq!(source_mutation_fingerprint(root.path())?, before);
    fs::write(
        destination.path().join("node_modules/aaa/index.js"),
        "changed\n",
    )?;
    assert_eq!(
        fs::read_to_string(destination.path().join("node_modules/.bin/pkg"))?,
        "changed\n"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("packages/pkg/index.js"))?,
        "original\n"
    );
    assert_eq!(source_mutation_fingerprint(root.path())?, before);
    Ok(())
}

#[test]
fn links_outside_node_modules_keep_materialized_file_and_directory_behavior() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(root.path(), "packages/pkg/index.js", "fixture\n")?;
    link_fixture(root.path(), "directory-alias", "packages/pkg")?;
    link_fixture(root.path(), "file-alias", "packages/pkg/index.js")?;
    let destination = tempfile::tempdir()?;
    stage_workspace(root.path(), destination.path())?;
    assert!(fs::symlink_metadata(destination.path().join("directory-alias"))?.is_dir());
    assert!(fs::symlink_metadata(destination.path().join("file-alias"))?.is_file());
    fs::write(destination.path().join("file-alias"), "changed\n")?;
    assert_eq!(
        fs::read_to_string(destination.path().join("directory-alias/index.js"))?,
        "fixture\n"
    );
    assert_eq!(
        fs::read_to_string(root.path().join("packages/pkg/index.js"))?,
        "fixture\n"
    );
    Ok(())
}

#[test]
fn dependency_links_to_ignored_or_control_targets_are_omitted() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(
        root.path(),
        ".depgraph.toml",
        "schema_version = 1\n[build]\nignored_paths = ['private', 'node_modules/ignored-link']\n",
    )?;
    for (name, target) in [
        ("git", ".git/objects"),
        ("nested-git", "packages/pkg/.git"),
        ("depgraph", ".depgraph/cache"),
        ("next", ".next/server"),
        ("target", "target/debug"),
        ("private", "private/data"),
    ] {
        write_fixture(root.path(), &format!("{target}/excluded.txt"), "excluded\n")?;
        link_fixture(
            root.path(),
            &format!("node_modules/{name}"),
            format!("../{target}"),
        )?;
        link_fixture(
            root.path(),
            &format!("node_modules/{name}-file"),
            format!("../{target}/excluded.txt"),
        )?;
    }
    link_fixture(root.path(), "node_modules/ignored-link", "missing-target")?;
    let destination = tempfile::tempdir()?;
    stage_workspace(root.path(), destination.path())?;
    for name in ["git", "nested-git", "depgraph", "next", "target", "private"] {
        assert_absent(&destination.path().join(format!("node_modules/{name}")));
        assert_absent(&destination.path().join(format!("node_modules/{name}-file")));
    }
    assert_absent(&destination.path().join("node_modules/ignored-link"));
    assert_absent(&destination.path().join("private"));
    fingerprint_build_source(root.path())?;
    Ok(())
}

fn assert_stage_and_fingerprint_reject(root: &Path, path: &str) -> Result<()> {
    let destination = tempfile::tempdir()?;
    for error in [
        stage_workspace(root, destination.path()).expect_err("unsafe link must fail closed"),
        fingerprint_build_source(root).expect_err("unsafe source must not enter build cache"),
    ] {
        let error = error.to_string();
        assert!(error.contains("security policy violation"), "{error}");
        assert!(error.contains(path), "{error}");
    }
    Ok(())
}

#[test]
fn dependency_links_reject_external_absolute_and_relative_targets() -> Result<()> {
    let enclosing = tempfile::tempdir()?;
    let root = enclosing.path().join("workspace");
    write_fixture(enclosing.path(), "outside/value.js", "outside\n")?;
    for target in [
        enclosing.path().join("outside"),
        enclosing.path().join("outside/value.js"),
        PathBuf::from("../../outside"),
        PathBuf::from("../../outside/value.js"),
    ] {
        link_fixture(&root, "node_modules/escape", target)?;
        assert_stage_and_fingerprint_reject(&root, "node_modules/escape")?;
        fs::remove_file(root.join("node_modules/escape"))?;
    }
    Ok(())
}

#[test]
fn dependency_links_reject_dangling_self_referential_and_mutually_cyclic_targets() -> Result<()> {
    for target in ["missing", "cycle"] {
        let root = tempfile::tempdir()?;
        link_fixture(root.path(), "node_modules/cycle", target)?;
        assert_stage_and_fingerprint_reject(root.path(), "node_modules/cycle")?;
    }
    let root = tempfile::tempdir()?;
    link_fixture(root.path(), "node_modules/first", "second")?;
    link_fixture(root.path(), "node_modules/second", "first")?;
    assert_stage_and_fingerprint_reject(root.path(), "node_modules/")?;
    Ok(())
}

#[test]
fn dependency_directory_links_to_ancestors_are_skipped() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(root.path(), "node_modules/pkg/index.js", "fixture\n")?;
    for (link, target) in [
        ("node_modules/root", ".."),
        ("node_modules/self", "."),
        ("node_modules/pkg/ancestor", ".."),
        ("node_modules/pkg/self", "."),
    ] {
        link_fixture(root.path(), link, target)?;
    }
    let destination = tempfile::tempdir()?;
    stage_workspace(root.path(), destination.path())?;
    for link in [
        "node_modules/root",
        "node_modules/self",
        "node_modules/pkg/ancestor",
        "node_modules/pkg/self",
    ] {
        assert_absent(&destination.path().join(link));
    }
    assert!(
        destination
            .path()
            .join("node_modules/pkg/index.js")
            .is_file()
    );
    fingerprint_build_source(root.path())?;
    Ok(())
}

#[test]
fn dependency_links_to_special_files_fail_closed() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fifo = std::ffi::CString::new(root.path().join("fifo").as_os_str().as_bytes())?;
    // SAFETY: fifo is a valid NUL-terminated path whose storage outlives this call.
    let created = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
    if created != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    link_fixture(root.path(), "node_modules/special", "../fifo")?;
    let canonical_root = root.path().canonicalize()?;
    let policy = load_stage_policy(root.path())?;
    let mut collected = Vec::new();
    let mut seen_logical = BTreeSet::new();
    let mut walk_stack = BTreeSet::new();
    let mut walk = StageWalk {
        source: root.path(),
        canonical_root: &canonical_root,
        policy: &policy,
        collected: &mut collected,
        seen_logical: &mut seen_logical,
        walk_stack: &mut walk_stack,
    };
    let error = stage_symlink_entry(
        &mut walk,
        Path::new("node_modules/special"),
        &root.path().join("node_modules/special"),
    )
    .expect_err("a dependency link must not preserve a special-file target")
    .to_string();
    assert!(error.contains("security policy violation"), "{error}");
    assert!(error.contains("node_modules/special"), "{error}");
    assert!(collected.is_empty());
    assert!(stage_workspace(root.path(), tempfile::tempdir()?.path()).is_err());
    assert!(fingerprint_build_source(root.path()).is_err());
    Ok(())
}

fn cache_input(root: &Path) -> Result<BuildCacheInput> {
    let (source_root_digest, manifest_lock_config_digest, staging_metadata_digest) =
        fingerprint_build_source(root)?;
    Ok(BuildCacheInput {
        base_snapshot_id: "fixture-snapshot".to_owned(),
        adapter: "fixture-adapter".to_owned(),
        adapter_version: "1".to_owned(),
        adapter_artifact_digest: "fixture-artifact".to_owned(),
        command_plan_digest: "fixture-command".to_owned(),
        environment_key_set_digest: "fixture-environment".to_owned(),
        manifest_lock_config_digest,
        profile_id: "fixture-profile".to_owned(),
        protocol_version: BUILD_SUPERVISOR_VERSION.to_owned(),
        source_root_digest,
        staging_metadata_digest,
        target: None,
        toolchain_executable_digest: "fixture-executable".to_owned(),
        toolchain_version: "fixture-version".to_owned(),
    })
}

#[test]
fn retargeting_dependency_links_to_identical_content_invalidates_source_cache_and_audits()
-> Result<()> {
    let root = tempfile::tempdir()?;
    for target in ["packages/first/index.js", "packages/second/index.js"] {
        write_fixture(root.path(), target, "module.exports = 1;\n")?;
    }
    link_fixture(root.path(), "node_modules/pkg", "../packages/first")?;
    let original = cache_input(root.path())?;
    let original_mutation = source_mutation_fingerprint(root.path())?;
    let original_workspace = digest_workspace(root.path())?;
    validate_build_cache_source(&original, root.path())?;
    let first_stage = tempfile::tempdir()?;
    stage_workspace(root.path(), first_stage.path())?;
    let original_staged = digest_workspace(first_stage.path())?;

    fs::remove_file(root.path().join("node_modules/pkg"))?;
    link_fixture(root.path(), "node_modules/pkg", "../packages/second")?;
    let changed = cache_input(root.path())?;
    assert_ne!(original.source_root_digest, changed.source_root_digest);
    assert_ne!(
        original.staging_metadata_digest,
        changed.staging_metadata_digest
    );
    assert_eq!(
        original.manifest_lock_config_digest,
        changed.manifest_lock_config_digest
    );
    assert_ne!(
        crate::cache::build_cache_key(&original).key,
        crate::cache::build_cache_key(&changed).key
    );
    assert_ne!(original_mutation, source_mutation_fingerprint(root.path())?);
    assert_ne!(original_workspace, digest_workspace(root.path())?);
    assert!(validate_build_cache_source(&original, root.path()).is_err());
    let second_stage = tempfile::tempdir()?;
    stage_workspace(root.path(), second_stage.path())?;
    assert_ne!(original_staged, digest_workspace(second_stage.path())?);
    Ok(())
}

#[test]
fn mutation_fingerprint_detects_changed_link_text_with_same_canonical_target() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(root.path(), "packages/pkg/index.js", "fixture\n")?;
    link_fixture(root.path(), "node_modules/pkg", "../packages/pkg")?;
    let original = fingerprint_build_source(root.path())?;
    let original_mutation = source_mutation_fingerprint(root.path())?;
    fs::remove_file(root.path().join("node_modules/pkg"))?;
    link_fixture(root.path(), "node_modules/pkg", "../packages/./pkg")?;
    let changed = fingerprint_build_source(root.path())?;
    assert_eq!(original.0, changed.0);
    assert_ne!(original.2, changed.2);
    assert_ne!(original_mutation, source_mutation_fingerprint(root.path())?);
    Ok(())
}

#[test]
fn preserved_dependency_links_count_toward_entry_bounds() -> Result<()> {
    let mut collected = Vec::with_capacity(MAX_STAGED_FILES);
    for _ in 0..MAX_STAGED_FILES - 1 {
        collected.push((PathBuf::new(), StagedPathKind::Directory));
    }
    push_staged_path(
        &mut collected,
        PathBuf::from("node_modules/last"),
        StagedPathKind::Symlink {
            target: PathBuf::from("../packages/pkg"),
            original_target: PathBuf::from("../packages/pkg"),
            original_absolute: false,
            directory: true,
        },
    )?;
    let error = push_staged_path(
        &mut collected,
        PathBuf::from("node_modules/overflow"),
        StagedPathKind::Symlink {
            target: PathBuf::from("../packages/pkg"),
            original_target: PathBuf::from("../packages/pkg"),
            original_absolute: false,
            directory: true,
        },
    )
    .expect_err("preserved links must count toward the staged entry limit")
    .to_string();
    assert!(error.contains("exceeds file or byte limit"), "{error}");
    assert_eq!(collected.len(), MAX_STAGED_FILES);
    Ok(())
}

#[test]
fn dependency_target_bytes_remain_bounded_before_copying_or_hashing() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("packages/pkg"))?;
    // A sparse file exercises the bound without allocating or reading gigabytes.
    fs::File::create(root.path().join("packages/pkg/oversized"))?.set_len(MAX_STAGED_BYTES + 1)?;
    link_fixture(root.path(), "node_modules/pkg", "../packages/pkg")?;
    let destination = tempfile::tempdir()?;
    for error in [
        stage_workspace(root.path(), destination.path())
            .expect_err("oversized target must not copy"),
        fingerprint_build_source(root.path()).expect_err("oversized target must not hash"),
    ] {
        let error = error.to_string();
        assert!(error.contains("exceeds file or byte limit"), "{error}");
    }
    assert_absent(&destination.path().join("packages/pkg/oversized"));
    assert_absent(&destination.path().join("node_modules/pkg"));
    Ok(())
}

#[test]
fn absolute_dependency_link_fingerprints_are_checkout_location_independent() -> Result<()> {
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    for root in [first.path(), second.path()] {
        write_fixture(root, "packages/pkg/index.js", "fixture\n")?;
        link_fixture(root, "node_modules/pkg", root.join("packages/pkg"))?;
    }
    assert_eq!(
        fingerprint_build_source(first.path())?,
        fingerprint_build_source(second.path())?
    );
    assert_eq!(
        source_mutation_fingerprint(first.path())?,
        source_mutation_fingerprint(second.path())?
    );
    let first_stage = tempfile::tempdir()?;
    let second_stage = tempfile::tempdir()?;
    stage_workspace(first.path(), first_stage.path())?;
    stage_workspace(second.path(), second_stage.path())?;
    assert_eq!(
        digest_workspace(first_stage.path())?,
        digest_workspace(second_stage.path())?
    );
    Ok(())
}

#[test]
fn changing_dependency_link_between_absolute_and_relative_is_audited() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_fixture(root.path(), "packages/pkg/index.js", "fixture\n")?;
    link_fixture(
        root.path(),
        "node_modules/pkg",
        root.path().join("packages/pkg"),
    )?;
    let original = fingerprint_build_source(root.path())?;
    fs::remove_file(root.path().join("node_modules/pkg"))?;
    link_fixture(root.path(), "node_modules/pkg", "../packages/pkg")?;
    let changed = fingerprint_build_source(root.path())?;
    assert_eq!(original.0, changed.0);
    assert_ne!(original.2, changed.2);
    Ok(())
}

#[test]
fn symlinked_source_roots_preserve_rebasing_identity_and_ancestor_cycle_skips() -> Result<()> {
    let enclosing = tempfile::tempdir()?;
    let original = enclosing.path().join("original");
    let actual = enclosing.path().join("actual");
    let alias = enclosing.path().join("alias");
    fs::create_dir_all(&actual)?;
    symlink(&actual, &alias)?;
    for root in [&original, &alias] {
        write_fixture(root, "packages/pkg/index.js", "fixture\n")?;
        link_fixture(root, "node_modules/pkg", root.join("packages/pkg"))?;
        link_fixture(root, "node_modules/self", ".")?;
    }
    assert_eq!(
        fingerprint_build_source(&original)?,
        fingerprint_build_source(&alias)?
    );
    let destination = tempfile::tempdir()?;
    stage_workspace(&alias, destination.path())?;
    assert_rebased_link(destination.path(), "node_modules/pkg", "packages/pkg")?;
    assert_absent(&destination.path().join("node_modules/self"));
    Ok(())
}
