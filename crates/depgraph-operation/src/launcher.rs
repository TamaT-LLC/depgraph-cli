use std::{
    fs::File,
    io::{Read as _, Seek as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use depgraph_core::DepgraphCapability;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::RunnerStartupConfig;

pub const OPERATION_RUNNER_STARTUP_CONTRACT: &str = "depgraph-operation-runner-v1";
const RUNNER_BASENAME: &str = "depgraph-operation-runner";
const MAX_VERIFIED_RELEASE_RUNNER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VERIFIED_DEVELOPMENT_RUNNER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RELEASE_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerResolutionPolicy {
    ReleaseManifest,
    DevelopmentSibling,
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerLaunchError {
    #[error("operation runner executable resolution failed")]
    Resolution,
    #[error("operation runner release verification failed")]
    ReleaseVerification,
    #[error("operation runner launch failed")]
    Launch(#[source] std::io::Error),
}

#[derive(Clone)]
struct VerifiedRunnerExecutable {
    path: PathBuf,
    expected_sha256: Option<String>,
}

impl std::fmt::Debug for VerifiedRunnerExecutable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("VerifiedRunnerExecutable")
            .field(&"verified")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct OperationRunnerLauncher {
    executable: VerifiedRunnerExecutable,
    policy: RunnerResolutionPolicy,
}

impl OperationRunnerLauncher {
    pub fn resolve() -> Result<Self, RunnerLaunchError> {
        let current = std::env::current_exe().map_err(RunnerLaunchError::Launch)?;
        resolve_for_executable(&current)
    }

    #[must_use]
    pub const fn resolution_policy(&self) -> RunnerResolutionPolicy {
        self.policy
    }

    pub fn launch(
        &self,
        startup: &RunnerStartupConfig,
    ) -> Result<LaunchedOperationRunner, RunnerLaunchError> {
        self.executable.revalidate(self.policy)?;
        let mut command = Command::new(&self.executable.path);
        command
            .arg("--startup-contract")
            .arg(OPERATION_RUNNER_STARTUP_CONTRACT)
            .arg("--root")
            .arg(startup.service_config().canonical_root())
            .arg("--store")
            .arg(startup.service_config().store_path())
            .current_dir(
                self.executable
                    .path
                    .parent()
                    .ok_or(RunnerLaunchError::Resolution)?,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear();
        for capability in startup.service_config().capabilities().iter() {
            command
                .arg("--capability")
                .arg(capability_argument(capability));
        }
        configure_detached_process(&mut command);
        let mut child = command.spawn().map_err(RunnerLaunchError::Launch)?;
        let process_id = child.id();
        // Reap while the launcher remains alive. If it exits first, dropping the
        // wait thread does not signal or otherwise own the detached runner.
        let _ = std::thread::Builder::new()
            .name("depgraph-operation-runner-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
        Ok(LaunchedOperationRunner { process_id })
    }
}

impl VerifiedRunnerExecutable {
    fn revalidate(&self, policy: RunnerResolutionPolicy) -> Result<(), RunnerLaunchError> {
        let failure = || match policy {
            RunnerResolutionPolicy::ReleaseManifest => RunnerLaunchError::ReleaseVerification,
            RunnerResolutionPolicy::DevelopmentSibling => RunnerLaunchError::Resolution,
        };
        let observed = verify_runner_file(&self.path, self.expected_sha256.as_deref())
            .map_err(|_| failure())?;
        if observed.path != self.path {
            return Err(failure());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchedOperationRunner {
    process_id: u32,
}

impl LaunchedOperationRunner {
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }
}

fn resolve_for_executable(
    current_executable: &Path,
) -> Result<OperationRunnerLauncher, RunnerLaunchError> {
    let current_executable = current_executable
        .canonicalize()
        .map_err(|_| RunnerLaunchError::Resolution)?;
    let executable_dir = current_executable
        .parent()
        .ok_or(RunnerLaunchError::Resolution)?;
    if let Some(manifest) = release_manifest_path(executable_dir) {
        let executable = verified_release_runner(&manifest)?;
        return Ok(OperationRunnerLauncher {
            executable,
            policy: RunnerResolutionPolicy::ReleaseManifest,
        });
    }
    if looks_like_packaged_layout(executable_dir) {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    let executable = development_runner(executable_dir)?;
    Ok(OperationRunnerLauncher {
        executable,
        policy: RunnerResolutionPolicy::DevelopmentSibling,
    })
}

fn release_manifest_path(executable_dir: &Path) -> Option<PathBuf> {
    [
        executable_dir.join("release-manifest.json"),
        executable_dir.join("../release-manifest.json"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn looks_like_packaged_layout(executable_dir: &Path) -> bool {
    executable_dir.file_name().is_some_and(|name| name == "bin")
        && executable_dir.join("../libexec").is_dir()
}

#[derive(Deserialize)]
struct ReleaseManifestProjection {
    release_version: String,
    operation_runner: ReleaseRunnerArtifact,
}

#[derive(Deserialize)]
struct ReleaseRunnerArtifact {
    version: String,
    path: String,
    sha256: String,
}

fn verified_release_runner(
    manifest_path: &Path,
) -> Result<VerifiedRunnerExecutable, RunnerLaunchError> {
    let metadata = std::fs::symlink_metadata(manifest_path)
        .map_err(|_| RunnerLaunchError::ReleaseVerification)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RELEASE_MANIFEST_BYTES
    {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    let release_root = manifest_path
        .parent()
        .ok_or(RunnerLaunchError::ReleaseVerification)?;
    let root_metadata = std::fs::symlink_metadata(release_root)
        .map_err(|_| RunnerLaunchError::ReleaseVerification)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    let release_root = release_root
        .canonicalize()
        .map_err(|_| RunnerLaunchError::ReleaseVerification)?;
    let manifest: ReleaseManifestProjection = serde_json::from_slice(
        &std::fs::read(manifest_path).map_err(|_| RunnerLaunchError::ReleaseVerification)?,
    )
    .map_err(|_| RunnerLaunchError::ReleaseVerification)?;
    let expected_path = format!("libexec/{}", executable_name(RUNNER_BASENAME));
    if manifest.release_version != env!("CARGO_PKG_VERSION")
        || manifest.operation_runner.version != env!("CARGO_PKG_VERSION")
        || manifest.operation_runner.path != expected_path
        || manifest.operation_runner.sha256.len() != 64
        || !manifest
            .operation_runner
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    reject_symlink_components(&release_root, &manifest.operation_runner.path)?;
    let candidate = release_root.join(&manifest.operation_runner.path);
    verify_runner_file(&candidate, Some(&manifest.operation_runner.sha256))
        .map_err(|_| RunnerLaunchError::ReleaseVerification)
}

fn development_runner(
    executable_dir: &Path,
) -> Result<VerifiedRunnerExecutable, RunnerLaunchError> {
    let file_name = executable_name(RUNNER_BASENAME);
    let mut candidates = vec![executable_dir.join(&file_name)];
    if executable_dir
        .file_name()
        .is_some_and(|name| name == "deps")
        && let Some(parent) = executable_dir.parent()
    {
        candidates.push(parent.join(&file_name));
    }
    candidates
        .into_iter()
        .find_map(|candidate| verify_runner_file(&candidate, None).ok())
        .ok_or(RunnerLaunchError::Resolution)
}

fn verify_runner_file(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<VerifiedRunnerExecutable, ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    let max_bytes = if expected_sha256.is_some() {
        MAX_VERIFIED_RELEASE_RUNNER_BYTES
    } else {
        MAX_VERIFIED_DEVELOPMENT_RUNNER_BYTES
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > max_bytes
        || !is_executable_file(path)
    {
        return Err(());
    }
    let canonical = path.canonicalize().map_err(|_| ())?;
    if let Some(expected) = expected_sha256 {
        let mut file = File::open(&canonical).map_err(|_| ())?;
        let observed_length = file.seek(std::io::SeekFrom::End(0)).map_err(|_| ())?;
        if observed_length != metadata.len() || observed_length > max_bytes {
            return Err(());
        }
        file.rewind().map_err(|_| ())?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).map_err(|_| ())?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        if format!("{:x}", digest.finalize()) != expected {
            return Err(());
        }
    }
    Ok(VerifiedRunnerExecutable {
        path: canonical,
        expected_sha256: expected_sha256.map(str::to_owned),
    })
}

fn reject_symlink_components(release_root: &Path, declared: &str) -> Result<(), RunnerLaunchError> {
    let declared = Path::new(declared);
    if declared.is_absolute()
        || declared
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    let mut cursor = release_root.to_path_buf();
    for component in declared.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(RunnerLaunchError::ReleaseVerification);
        };
        cursor.push(component);
        if std::fs::symlink_metadata(&cursor)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(RunnerLaunchError::ReleaseVerification);
        }
    }
    Ok(())
}

const fn capability_argument(capability: DepgraphCapability) -> &'static str {
    match capability {
        DepgraphCapability::Read => "read",
        DepgraphCapability::StoreWrite => "store-write",
        DepgraphCapability::RepositoryWrite => "repository-write",
        DepgraphCapability::DaemonControl => "daemon-control",
        DepgraphCapability::ProjectExec => "project-exec",
    }
}

#[cfg(unix)]
fn configure_detached_process(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(windows)]
fn configure_detached_process(command: &mut Command) {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };
    command.creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
}

#[cfg(not(any(unix, windows)))]
fn configure_detached_process(_command: &mut Command) {}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

#[cfg(not(any(unix, windows)))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(windows)]
fn executable_name(base: &str) -> String {
    format!("{base}.exe")
}

#[cfg(not(windows))]
fn executable_name(base: &str) -> String {
    base.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_test_executable(path: &Path) {
        std::fs::write(path, b"test runner fixture").unwrap();
        make_test_executable(path);
    }

    fn make_test_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).unwrap();
        }
    }

    fn sha256(path: &Path) -> String {
        format!("{:x}", Sha256::digest(std::fs::read(path).unwrap()))
    }

    #[test]
    fn release_and_development_runner_size_bounds_are_distinct_and_closed() {
        let root = tempfile::tempdir().unwrap();
        let runner = root.path().join(executable_name(RUNNER_BASENAME));
        let file = File::create(&runner).unwrap();
        file.set_len(MAX_VERIFIED_RELEASE_RUNNER_BYTES + 1).unwrap();
        make_test_executable(&runner);

        assert!(verify_runner_file(&runner, Some("unused-digest")).is_err());
        assert!(verify_runner_file(&runner, None).is_ok());

        file.set_len(MAX_VERIFIED_DEVELOPMENT_RUNNER_BYTES + 1)
            .unwrap();
        assert!(verify_runner_file(&runner, None).is_err());
    }

    #[test]
    fn release_resolution_requires_exact_manifest_path_version_and_digest() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let libexec = root.path().join("libexec");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&libexec).unwrap();
        let current = bin.join(executable_name("depgraph"));
        let runner = libexec.join(executable_name(RUNNER_BASENAME));
        write_test_executable(&current);
        write_test_executable(&runner);
        let manifest = serde_json::json!({
            "release_version": env!("CARGO_PKG_VERSION"),
            "operation_runner": {
                "version": env!("CARGO_PKG_VERSION"),
                "path": format!("libexec/{}", executable_name(RUNNER_BASENAME)),
                "sha256": sha256(&runner),
            }
        });
        std::fs::write(
            root.path().join("release-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let resolved = resolve_for_executable(&current).unwrap();
        assert_eq!(
            resolved.resolution_policy(),
            RunnerResolutionPolicy::ReleaseManifest
        );
        assert!(!format!("{resolved:?}").contains(root.path().to_string_lossy().as_ref()));

        std::fs::write(&runner, b"tampered runner").unwrap();
        assert!(matches!(
            resolved.executable.revalidate(resolved.policy),
            Err(RunnerLaunchError::ReleaseVerification)
        ));
        assert!(matches!(
            resolve_for_executable(&current),
            Err(RunnerLaunchError::ReleaseVerification)
        ));
    }

    #[test]
    fn development_resolution_accepts_only_the_fixed_build_sibling_locations() {
        let root = tempfile::tempdir().unwrap();
        let deps = root.path().join("deps");
        std::fs::create_dir(&deps).unwrap();
        let current = deps.join("operation-tests");
        let runner = root.path().join(executable_name(RUNNER_BASENAME));
        write_test_executable(&current);
        write_test_executable(&runner);

        let resolved = resolve_for_executable(&current).unwrap();
        assert_eq!(
            resolved.resolution_policy(),
            RunnerResolutionPolicy::DevelopmentSibling
        );

        std::fs::remove_file(&runner).unwrap();
        assert!(matches!(
            resolve_for_executable(&current),
            Err(RunnerLaunchError::Resolution)
        ));
    }
}
