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
const CORE_BASENAME: &str = "depgraph";
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
    #[error("operation runner environment policy failed")]
    EnvironmentPolicy,
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

#[derive(Clone, Debug)]
pub struct DaemonExecutableLauncher {
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
        if let Some(requirement) = startup.compiler_pack_requirement_path() {
            command.arg("--compiler-pack-requirement").arg(requirement);
        }
        copy_safe_daemon_environment(&mut command, startup.service_config().canonical_root())?;
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

impl DaemonExecutableLauncher {
    #[cfg(test)]
    pub(crate) fn for_test_executable(path: &Path) -> Result<Self, RunnerLaunchError> {
        let executable =
            verify_runner_file(path, None).map_err(|_| RunnerLaunchError::Resolution)?;
        Ok(Self {
            executable,
            policy: RunnerResolutionPolicy::DevelopmentSibling,
        })
    }

    pub fn resolve() -> Result<Self, RunnerLaunchError> {
        let current = std::env::current_exe().map_err(RunnerLaunchError::Launch)?;
        resolve_daemon_for_executable(&current)
    }

    pub fn launch(
        &self,
        startup: &RunnerStartupConfig,
        strict: bool,
    ) -> Result<LaunchedDaemonProcess, RunnerLaunchError> {
        self.executable.revalidate(self.policy)?;
        let mut command = Command::new(&self.executable.path);
        command
            .arg("--store")
            .arg(startup.service_config().store_path())
            .arg("daemon")
            .arg("start")
            .arg(startup.service_config().canonical_root())
            .arg("--json")
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
        if strict {
            command.arg("--strict");
        }
        copy_safe_daemon_environment(&mut command, startup.service_config().canonical_root())?;
        configure_detached_process(&mut command);
        let child = command.spawn().map_err(RunnerLaunchError::Launch)?;
        Ok(LaunchedDaemonProcess { child: Some(child) })
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

pub struct LaunchedDaemonProcess {
    child: Option<std::process::Child>,
}

impl std::fmt::Debug for LaunchedDaemonProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchedDaemonProcess")
            .field("state", &"owned")
            .finish()
    }
}

impl LaunchedDaemonProcess {
    /// Observe an early child exit without exposing its status or launch
    /// details. Once reaped, clear ownership so Drop cannot signal a reused
    /// process identifier.
    pub fn has_exited(&mut self) -> Result<bool, RunnerLaunchError> {
        let Some(child) = &mut self.child else {
            return Ok(true);
        };
        if child
            .try_wait()
            .map_err(RunnerLaunchError::Launch)?
            .is_some()
        {
            self.child = None;
            return Ok(true);
        }
        Ok(false)
    }

    /// Transfer ownership to a bounded reaper after running publication has
    /// made the daemon independently recoverable through status/control files.
    pub fn detach(mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("depgraph-daemon-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }

    /// Stop the entire launched process group and reap the direct child while
    /// it is still owned by the operation promotion.
    pub fn terminate_and_reap(mut self) -> Result<(), RunnerLaunchError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        terminate_process_tree(&mut child);
        child.wait().map_err(RunnerLaunchError::Launch)?;
        Ok(())
    }
}

impl Drop for LaunchedDaemonProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            terminate_process_tree(child);
            let _ = child.wait();
        }
    }
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

fn resolve_daemon_for_executable(
    current_executable: &Path,
) -> Result<DaemonExecutableLauncher, RunnerLaunchError> {
    let current_executable = current_executable
        .canonicalize()
        .map_err(|_| RunnerLaunchError::Resolution)?;
    let executable_dir = current_executable
        .parent()
        .ok_or(RunnerLaunchError::Resolution)?;
    if let Some(manifest) = release_manifest_path(executable_dir) {
        return Ok(DaemonExecutableLauncher {
            executable: verified_release_core(&manifest)?,
            policy: RunnerResolutionPolicy::ReleaseManifest,
        });
    }
    if looks_like_packaged_layout(executable_dir) {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    Ok(DaemonExecutableLauncher {
        executable: development_executable(executable_dir, CORE_BASENAME)?,
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
    core: ReleaseCoreArtifact,
    operation_runner: ReleaseRunnerArtifact,
}

#[derive(Deserialize)]
struct ReleaseCoreArtifact {
    path: String,
    sha256: String,
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

fn verified_release_core(
    manifest_path: &Path,
) -> Result<VerifiedRunnerExecutable, RunnerLaunchError> {
    let (release_root, manifest) = read_release_manifest(manifest_path)?;
    let expected_path = format!("bin/{}", executable_name(CORE_BASENAME));
    if manifest.release_version != env!("CARGO_PKG_VERSION")
        || manifest.core.path != expected_path
        || !valid_release_digest(&manifest.core.sha256)
    {
        return Err(RunnerLaunchError::ReleaseVerification);
    }
    reject_symlink_components(&release_root, &manifest.core.path)?;
    verify_runner_file(
        &release_root.join(&manifest.core.path),
        Some(&manifest.core.sha256),
    )
    .map_err(|_| RunnerLaunchError::ReleaseVerification)
}

fn read_release_manifest(
    manifest_path: &Path,
) -> Result<(PathBuf, ReleaseManifestProjection), RunnerLaunchError> {
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
    let manifest = serde_json::from_slice(
        &std::fs::read(manifest_path).map_err(|_| RunnerLaunchError::ReleaseVerification)?,
    )
    .map_err(|_| RunnerLaunchError::ReleaseVerification)?;
    Ok((release_root, manifest))
}

fn valid_release_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn development_runner(
    executable_dir: &Path,
) -> Result<VerifiedRunnerExecutable, RunnerLaunchError> {
    development_executable(executable_dir, RUNNER_BASENAME)
}

fn development_executable(
    executable_dir: &Path,
    basename: &str,
) -> Result<VerifiedRunnerExecutable, RunnerLaunchError> {
    let file_name = executable_name(basename);
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

#[cfg(unix)]
fn terminate_process_tree(child: &mut std::process::Child) {
    let process_group = i32::try_from(child.id()).ok().and_then(i32::checked_neg);
    if let Some(process_group) = process_group {
        // The child was launched as a fresh process group. SIGINT follows the
        // foreground CLI's normal graceful shutdown path.
        unsafe {
            libc::kill(process_group, libc::SIGINT);
        }
    }
    for _ in 0..100 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if let Some(process_group) = process_group {
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
    } else {
        let _ = child.kill();
    }
}

#[cfg(not(unix))]
fn terminate_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
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

fn copy_safe_daemon_environment(
    command: &mut Command,
    root: &Path,
) -> Result<(), RunnerLaunchError> {
    let current_directory = std::env::current_dir().map_err(RunnerLaunchError::Launch)?;
    copy_safe_daemon_environment_with(command, root, &current_directory, |key| {
        std::env::var_os(key)
    })
}

fn copy_safe_daemon_environment_with(
    command: &mut Command,
    root: &Path,
    current_directory: &Path,
    mut environment: impl FnMut(&str) -> Option<std::ffi::OsString>,
) -> Result<(), RunnerLaunchError> {
    let raw_path = environment("PATH").ok_or(RunnerLaunchError::EnvironmentPolicy)?;
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut safe_paths = Vec::new();
    for path in std::env::split_paths(&raw_path) {
        if !path.is_absolute() {
            continue;
        }
        let Ok(path) = path.canonicalize() else {
            continue;
        };
        if !path.is_dir() || path.starts_with(&canonical_root) || safe_paths.contains(&path) {
            continue;
        }
        safe_paths.push(path);
    }
    if safe_paths.is_empty() {
        return Err(RunnerLaunchError::EnvironmentPolicy);
    }
    let safe_path =
        std::env::join_paths(safe_paths).map_err(|_| RunnerLaunchError::EnvironmentPolicy)?;
    command.env("PATH", safe_path);

    for key in [
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SystemRoot",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOROOT",
        "GOPATH",
        "GOMODCACHE",
    ] {
        let Some(value) = environment(key) else {
            continue;
        };
        let path = PathBuf::from(&value);
        if path.is_absolute()
            && path
                .canonicalize()
                .is_ok_and(|canonical| !canonical.starts_with(&canonical_root))
        {
            command.env(key, value);
        }
    }
    for key in [
        "DEPGRAPH_RUST_WORKER",
        "DEPGRAPH_GO_WORKER",
        "DEPGRAPH_WEB_WORKER",
    ] {
        let Some(value) = environment(key) else {
            continue;
        };
        let path = PathBuf::from(value);
        let candidate = if path.is_absolute() {
            path
        } else {
            current_directory.join(path)
        };
        let canonical = candidate
            .canonicalize()
            .map_err(|_| RunnerLaunchError::EnvironmentPolicy)?;
        if !canonical.is_file() || canonical.starts_with(&canonical_root) {
            return Err(RunnerLaunchError::EnvironmentPolicy);
        }
        command.env(key, canonical);
    }
    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = environment(key) {
            command.env(key, value);
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
    use depgraph_core::{DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits};

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
            "core": {
                "path": format!("bin/{}", executable_name(CORE_BASENAME)),
                "sha256": sha256(&current),
            },
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

    #[cfg(unix)]
    #[test]
    fn issue_315_daemon_process_reports_early_exit_without_waiting() {
        let child = Command::new("/usr/bin/false").spawn().unwrap();
        let mut process = LaunchedDaemonProcess { child: Some(child) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if process.has_exited().unwrap() {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "exited daemon child was not observed"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn issue_315_daemon_environment_preserves_only_explicit_worker_overrides() {
        use std::collections::BTreeMap;
        use std::ffi::{OsStr, OsString};

        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path().join("repository");
        let safe_bin = temporary.path().join("safe-bin");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&safe_bin).unwrap();
        let rust_worker = temporary.path().join("rust-worker");
        let go_worker = temporary.path().join("go-worker");
        let web_worker = temporary.path().join("web-worker");
        for worker in [&rust_worker, &go_worker, &web_worker] {
            write_test_executable(worker);
        }
        let environment = BTreeMap::from([
            (OsString::from("PATH"), safe_bin.into_os_string()),
            (
                OsString::from("DEPGRAPH_RUST_WORKER"),
                OsString::from("rust-worker"),
            ),
            (
                OsString::from("DEPGRAPH_GO_WORKER"),
                go_worker.into_os_string(),
            ),
            (
                OsString::from("DEPGRAPH_WEB_WORKER"),
                web_worker.into_os_string(),
            ),
            (
                OsString::from("DEPGRAPH_SECRET"),
                OsString::from("must-not-cross-boundary"),
            ),
        ]);
        let mut command = Command::new("/usr/bin/true");
        command.env_clear();

        copy_safe_daemon_environment_with(&mut command, &repository, temporary.path(), |key| {
            environment.get(OsStr::new(key)).cloned()
        })
        .unwrap();

        let copied = command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.unwrap().to_owned()))
            .collect::<BTreeMap<_, _>>();
        for key in [
            "DEPGRAPH_RUST_WORKER",
            "DEPGRAPH_GO_WORKER",
            "DEPGRAPH_WEB_WORKER",
        ] {
            assert!(copied.contains_key(OsStr::new(key)));
        }
        assert_eq!(
            copied.get(OsStr::new("DEPGRAPH_RUST_WORKER")),
            Some(&rust_worker.canonicalize().unwrap().into_os_string())
        );
        assert!(!copied.contains_key(OsStr::new("DEPGRAPH_SECRET")));
    }

    #[cfg(unix)]
    #[test]
    fn issue_315_invalid_worker_override_fails_closed_at_daemon_boundary() {
        use std::collections::BTreeMap;
        use std::ffi::{OsStr, OsString};

        let temporary = tempfile::tempdir().unwrap();
        let repository = temporary.path().join("repository");
        let safe_bin = temporary.path().join("safe-bin");
        std::fs::create_dir_all(&repository).unwrap();
        std::fs::create_dir_all(&safe_bin).unwrap();
        write_test_executable(&repository.join("project-worker"));
        let environment = BTreeMap::from([
            (OsString::from("PATH"), safe_bin.into_os_string()),
            (
                OsString::from("DEPGRAPH_RUST_WORKER"),
                OsString::from("repository/project-worker"),
            ),
        ]);
        let mut command = Command::new("/usr/bin/true");
        command.env_clear();

        assert!(matches!(
            copy_safe_daemon_environment_with(&mut command, &repository, temporary.path(), |key| {
                environment.get(OsStr::new(key)).cloned()
            },),
            Err(RunnerLaunchError::EnvironmentPolicy)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn issue_315_daemon_launcher_spawns_exact_absolute_program_argv_and_allowlisted_environment() {
        let root = tempfile::tempdir().unwrap();
        let repository = root
            .path()
            .join("repository; touch depgraph-shell-parsed; #");
        std::fs::create_dir(&repository).unwrap();
        let store = root.path().join("graph store.sqlite");
        let config = DepgraphServiceConfig::new(
            repository,
            store,
            DepgraphCapabilitySet::try_new([
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::DaemonControl,
            ])
            .unwrap(),
            DepgraphServiceLimits::default(),
        )
        .unwrap();
        let startup = RunnerStartupConfig::new(config.clone()).unwrap();
        let capture = root.path().join("daemon-launch.txt");
        let fake = root
            .path()
            .join("daemon executable; touch executable-shell-parsed; #");
        let capture_literal = serde_json::to_string(capture.to_str().unwrap()).unwrap();
        let source = root.path().join("fake-daemon.c");
        std::fs::write(
            &source,
            format!(
                r#"#include <stdio.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {{
    FILE *output = fopen({capture_literal}, "w");
    if (output == NULL) return 2;
    fprintf(output, "argc=%d\n", argc);
    for (int index = 0; index < argc; index++) fprintf(output, "arg=%s\n", argv[index]);
    for (char **entry = environ; *entry != NULL; entry++) fprintf(output, "env=%s\n", *entry);
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return 3;
    fprintf(output, "cwd=%s\n", cwd);
    return fclose(output) == 0 ? 0 : 4;
}}
"#
            ),
        )
        .unwrap();
        let compiler = if cfg!(target_os = "macos") {
            "/usr/bin/clang"
        } else {
            "/usr/bin/cc"
        };
        let compiled = Command::new(compiler)
            .arg(&source)
            .arg("-o")
            .arg(&fake)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "native fake compiler failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let executable = verify_runner_file(&fake, None).unwrap();
        let exact_executable = executable.path.clone();
        assert!(exact_executable.is_absolute());
        let launcher = DaemonExecutableLauncher {
            executable,
            policy: RunnerResolutionPolicy::DevelopmentSibling,
        };

        let mut process = launcher.launch(&startup, true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let completed = loop {
            if process.has_exited().unwrap() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(
            completed,
            "fake daemon did not complete its invocation record"
        );
        process.terminate_and_reap().unwrap();
        assert!(
            capture.is_file(),
            "fake daemon did not record its invocation"
        );

        let observed = std::fs::read_to_string(&capture).unwrap();
        let expected = [
            "argc=8".to_owned(),
            format!("arg={}", exact_executable.display()),
            "arg=--store".to_owned(),
            format!("arg={}", config.store_path().display()),
            "arg=daemon".to_owned(),
            "arg=start".to_owned(),
            format!("arg={}", config.canonical_root().display()),
            "arg=--json".to_owned(),
            "arg=--strict".to_owned(),
            format!("cwd={}", exact_executable.parent().unwrap().display()),
        ]
        .join("\n")
            + "\n";
        let observed_arguments = observed
            .lines()
            .filter(|line| !line.starts_with("env="))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(observed_arguments, expected);
        let observed_environment = observed
            .lines()
            .filter_map(|line| line.strip_prefix("env="))
            .filter_map(|entry| entry.split_once('=').map(|(key, _)| key))
            .collect::<Vec<_>>();
        assert!(observed_environment.contains(&"PATH"));
        assert!(observed_environment.iter().all(|key| matches!(
            *key,
            "PATH"
                | "HOME"
                | "USERPROFILE"
                | "TMPDIR"
                | "TEMP"
                | "TMP"
                | "SystemRoot"
                | "CARGO_HOME"
                | "RUSTUP_HOME"
                | "GOROOT"
                | "GOPATH"
                | "GOMODCACHE"
                | "LANG"
                | "LC_ALL"
                | "DEPGRAPH_RUST_WORKER"
                | "DEPGRAPH_GO_WORKER"
                | "DEPGRAPH_WEB_WORKER"
        )));
        assert!(!root.path().join("depgraph-shell-parsed").exists());
        assert!(!root.path().join("executable-shell-parsed").exists());
    }
}
