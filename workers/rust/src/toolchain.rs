use crate::{
    CARGO_BASELINE_COMMIT, RUST_TOOLCHAIN_BASELINE, RUSTC_BASELINE_COMMIT,
    metadata::{neutral_environment, resolve_safe_tool, safe_external_directory, sanitized_path},
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;
pub(crate) const TOOLCHAIN_SELECTION_CONTRACT: &str = "installed-verified-rust-toolchain-v1";
pub(crate) const TOOLCHAIN_REMEDIATION: &str =
    "rustup toolchain install 1.93.1 --profile minimal --component rust-src";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolchainSelectionKind {
    HostDefault,
    InstalledVerifiedBaseline,
    Unavailable,
}

impl ToolchainSelectionKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::HostDefault => "host-default",
            Self::InstalledVerifiedBaseline => "installed-verified-baseline",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolchainProbeStatus {
    Compatible,
    Unsupported,
    Unavailable,
}

impl ToolchainProbeStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolVersion {
    command: String,
    release: String,
    commit_hash: Option<String>,
    host: String,
    sha256: Option<String>,
}

impl ToolVersion {
    fn as_value(&self) -> Value {
        json!({
            "command": self.command,
            "release": self.release,
            "commit_hash": self.commit_hash,
            "host": self.host,
            "sha256": self.sha256,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustToolchainCommands {
    rustc: PathBuf,
    cargo: PathBuf,
    rustc_sha256: String,
    cargo_sha256: String,
}

impl RustToolchainCommands {
    pub(crate) fn rustc(&self) -> &Path {
        &self.rustc
    }

    pub(crate) fn cargo(&self) -> &Path {
        &self.cargo
    }

    pub(crate) fn verify_integrity(&self) -> Result<()> {
        verify_tool_digest(&self.rustc, &self.rustc_sha256)
            .context("verified rustc changed after toolchain selection")?;
        verify_tool_digest(&self.cargo, &self.cargo_sha256)
            .context("verified cargo changed after toolchain selection")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustToolchainProbe {
    status: ToolchainProbeStatus,
    rustc: Option<ToolVersion>,
    cargo: Option<ToolVersion>,
    reason: Option<String>,
    commands: Option<RustToolchainCommands>,
}

impl RustToolchainProbe {
    pub(crate) fn status(&self) -> ToolchainProbeStatus {
        self.status
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub(crate) fn as_value(&self) -> Value {
        json!({
            "status": self.status.as_str(),
            "rustc": self.rustc.as_ref().map(ToolVersion::as_value),
            "cargo": self.cargo.as_ref().map(ToolVersion::as_value),
            "reason": self.reason,
        })
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: ToolchainProbeStatus::Unavailable,
            rustc: None,
            cargo: None,
            reason: Some(reason.into()),
            commands: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RustToolchainSelection {
    host: RustToolchainProbe,
    effective: RustToolchainProbe,
    kind: ToolchainSelectionKind,
}

impl RustToolchainSelection {
    pub(crate) fn host_status(&self) -> ToolchainProbeStatus {
        self.host.status()
    }

    pub(crate) fn status(&self) -> ToolchainProbeStatus {
        self.effective.status()
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        self.effective.reason()
    }

    pub(crate) fn selection(&self) -> &'static str {
        self.kind.as_str()
    }

    pub(crate) fn commands(&self) -> Option<&RustToolchainCommands> {
        self.effective.commands.as_ref()
    }

    pub(crate) fn host_as_value(&self) -> Value {
        self.host.as_value()
    }

    pub(crate) fn attestation_as_value(&self) -> Value {
        json!({
            "contract": TOOLCHAIN_SELECTION_CONTRACT,
            "selection": self.selection(),
            "status": self.status().as_str(),
            "rustc": self.effective.rustc.as_ref().map(ToolVersion::as_value),
            "cargo": self.effective.cargo.as_ref().map(ToolVersion::as_value),
        })
    }
}

pub(crate) fn probe_rust_toolchain(root: &Path) -> RustToolchainSelection {
    let host = probe_host_toolchain(root);
    if let Ok(installed) = probe_installed_baseline(root)
        && installed.status() == ToolchainProbeStatus::Compatible
    {
        return RustToolchainSelection {
            host,
            effective: installed,
            kind: ToolchainSelectionKind::InstalledVerifiedBaseline,
        };
    }
    let kind = if host.status() == ToolchainProbeStatus::Compatible {
        ToolchainSelectionKind::HostDefault
    } else {
        ToolchainSelectionKind::Unavailable
    };
    RustToolchainSelection {
        effective: host.clone(),
        host,
        kind,
    }
}

fn probe_host_toolchain(root: &Path) -> RustToolchainProbe {
    let rustc = match resolve_safe_tool("rustc", root) {
        Ok(path) => path,
        Err(_) => {
            return RustToolchainProbe::unavailable("rustc is unavailable on the sanitized PATH");
        }
    };
    let cargo = match resolve_safe_tool("cargo", root) {
        Ok(path) => path,
        Err(_) => {
            return RustToolchainProbe::unavailable("cargo is unavailable on the sanitized PATH");
        }
    };
    probe_resolved_toolchain(root, &rustc, &cargo, PROBE_TIMEOUT)
        .unwrap_or_else(|error| RustToolchainProbe::unavailable(error.to_string()))
}

fn probe_installed_baseline(root: &Path) -> Result<RustToolchainProbe> {
    let rustup =
        resolve_safe_tool("rustup", root).context("rustup is unavailable on the sanitized PATH")?;
    let rustup_home = safe_rustup_home(root).context("safe Rustup home is unavailable")?;
    let rustc = rustup_which(root, &rustup, &rustup_home, "rustc")?;
    let cargo = rustup_which(root, &rustup, &rustup_home, "cargo")?;
    let rustc_root = verified_toolchain_root(&rustc, &rustup_home)?;
    let cargo_root = verified_toolchain_root(&cargo, &rustup_home)?;
    if rustc_root != cargo_root {
        bail!("installed Rust baseline resolves rustc and cargo from different toolchains");
    }
    let probe = probe_resolved_toolchain(root, &rustc, &cargo, PROBE_TIMEOUT)?;
    if probe.status() != ToolchainProbeStatus::Compatible {
        bail!("installed Rust baseline does not match the verified compatibility pair");
    }
    let host = probe
        .rustc
        .as_ref()
        .context("installed Rust baseline omitted rustc identity")?
        .host
        .as_str();
    let expected_name = format!("{RUST_TOOLCHAIN_BASELINE}-{host}");
    if rustc_root.file_name() != Some(expected_name.as_ref()) {
        bail!("installed Rust baseline directory does not match its attested host");
    }
    Ok(probe)
}

fn safe_rustup_home(root: &Path) -> Option<PathBuf> {
    std::env::var_os("RUSTUP_HOME")
        .as_deref()
        .and_then(|value| safe_external_directory(root, value))
        .or_else(|| {
            ["HOME", "USERPROFILE"].into_iter().find_map(|key| {
                std::env::var_os(key)
                    .map(PathBuf::from)
                    .map(|home| home.join(".rustup"))
                    .filter(|path| path.is_dir())
                    .and_then(|path| safe_external_directory(root, path.as_os_str()))
            })
        })
}

fn rustup_which(root: &Path, rustup: &Path, rustup_home: &Path, tool: &str) -> Result<PathBuf> {
    let neutral = neutral_environment(root)?;
    let mut command = Command::new(rustup);
    command
        .args(["which", "--toolchain", RUST_TOOLCHAIN_BASELINE, tool])
        .current_dir(neutral.path());
    configure_probe_environment(&mut command, root, neutral.path())?;
    command.env("RUSTUP_HOME", rustup_home);
    let output = bounded_output(command, PROBE_TIMEOUT, PROBE_OUTPUT_LIMIT)
        .with_context(|| format!("resolve installed verified {tool}"))?;
    if !output.status.success() {
        bail!("verified Rust {RUST_TOOLCHAIN_BASELINE} is not installed");
    }
    let stdout =
        std::str::from_utf8(&output.stdout).context("rustup which returned non-UTF-8 output")?;
    let mut lines = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let path = PathBuf::from(lines.next().context("rustup which returned no path")?);
    if lines.next().is_some() || !path.is_absolute() {
        bail!("rustup which returned an invalid path");
    }
    let metadata = fs::symlink_metadata(&path).context("inspect rustup-selected tool")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("rustup-selected tool is not a non-symlink regular file");
    }
    let path = path
        .canonicalize()
        .context("canonicalize rustup-selected tool")?;
    verified_toolchain_root(&path, rustup_home)?;
    Ok(path)
}

fn verified_toolchain_root(tool: &Path, rustup_home: &Path) -> Result<PathBuf> {
    let toolchains = rustup_home
        .join("toolchains")
        .canonicalize()
        .context("canonicalize Rustup toolchains directory")?;
    let relative = tool
        .strip_prefix(&toolchains)
        .context("rustup-selected tool is outside the configured Rustup home")?;
    let mut components = relative.components();
    let toolchain = components
        .next()
        .context("rustup-selected tool has no toolchain directory")?;
    let bin = components
        .next()
        .context("rustup-selected tool has no bin directory")?;
    let executable = components
        .next()
        .context("rustup-selected tool has no executable")?;
    if components.next().is_some() || bin.as_os_str() != "bin" || executable.as_os_str().is_empty()
    {
        bail!("rustup-selected tool has an unexpected layout");
    }
    Ok(toolchains.join(toolchain.as_os_str()))
}

fn probe_resolved_toolchain(
    root: &Path,
    rustc_path: &Path,
    cargo_path: &Path,
    timeout: Duration,
) -> Result<RustToolchainProbe> {
    let neutral = neutral_environment(root)?;
    let rustc = run_version_probe("rustc", rustc_path, root, neutral.path(), timeout)?;
    let cargo = run_version_probe("cargo", cargo_path, root, neutral.path(), timeout)?;
    let commands = RustToolchainCommands {
        rustc: rustc_path
            .canonicalize()
            .context("canonicalize probed rustc")?,
        cargo: cargo_path
            .canonicalize()
            .context("canonicalize probed cargo")?,
        rustc_sha256: rustc.sha256.clone().context("rustc digest unavailable")?,
        cargo_sha256: cargo.sha256.clone().context("cargo digest unavailable")?,
    };
    commands.verify_integrity()?;
    let compatible = rustc.release == RUST_TOOLCHAIN_BASELINE
        && cargo.release == RUST_TOOLCHAIN_BASELINE
        && rustc.commit_hash.as_deref() == Some(RUSTC_BASELINE_COMMIT)
        && cargo.commit_hash.as_deref() == Some(CARGO_BASELINE_COMMIT)
        && rustc.host == cargo.host;
    let (status, reason) = if compatible {
        (ToolchainProbeStatus::Compatible, None)
    } else {
        (
            ToolchainProbeStatus::Unsupported,
            Some(format!(
                "observed rustc {} ({}) and cargo {} ({}) do not match the verified {} baseline pair",
                rustc.release,
                rustc.commit_hash.as_deref().unwrap_or("unknown"),
                cargo.release,
                cargo.commit_hash.as_deref().unwrap_or("unknown"),
                RUST_TOOLCHAIN_BASELINE,
            )),
        )
    };
    Ok(RustToolchainProbe {
        status,
        rustc: Some(rustc),
        cargo: Some(cargo),
        reason,
        commands: Some(commands),
    })
}

fn run_version_probe(
    name: &str,
    program: &Path,
    root: &Path,
    neutral: &Path,
    timeout: Duration,
) -> Result<ToolVersion> {
    let digest_before = digest_tool(program)?;
    let mut command = Command::new(program);
    command
        .arg("--version")
        .arg("--verbose")
        .current_dir(neutral);
    configure_probe_environment(&mut command, root, neutral)?;
    let output = bounded_output(command, timeout, PROBE_OUTPUT_LIMIT)
        .with_context(|| format!("{name} version probe failed"))?;
    if !output.status.success() {
        bail!("{name} version probe exited unsuccessfully");
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .with_context(|| format!("{name} version probe returned non-UTF-8 output"))?;
    let mut version = parse_verbose_version(name, stdout)?;
    let digest_after = digest_tool(program)?;
    if digest_after != digest_before {
        bail!("{name} changed during its version probe");
    }
    version.sha256 = Some(digest_after);
    Ok(version)
}

fn configure_probe_environment(command: &mut Command, root: &Path, neutral: &Path) -> Result<()> {
    command
        .env_clear()
        .env("PATH", sanitized_path(root)?)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "");

    for (key, directory) in [
        ("HOME", "home"),
        ("USERPROFILE", "home"),
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("CARGO_HOME", "cargo-home"),
        ("CARGO_TARGET_DIR", "cargo-target"),
    ] {
        let path = neutral.join(directory);
        fs::create_dir_all(&path)
            .with_context(|| format!("create neutral probe directory {directory}"))?;
        command.env(key, path);
    }

    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .as_deref()
        .and_then(|value| safe_external_directory(root, value))
        .or_else(|| {
            ["HOME", "USERPROFILE"].into_iter().find_map(|key| {
                std::env::var_os(key)
                    .map(PathBuf::from)
                    .map(|home| home.join(".rustup"))
                    .filter(|path| path.is_dir())
                    .and_then(|path| safe_external_directory(root, path.as_os_str()))
            })
        })
        .unwrap_or_else(|| neutral.join("rustup-home"));
    fs::create_dir_all(&rustup_home).context("create neutral Rustup home")?;
    command.env("RUSTUP_HOME", rustup_home);

    for key in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot")
        .as_deref()
        .and_then(|value| safe_external_directory(root, value))
    {
        command.env("SystemRoot", system_root);
    }
    Ok(())
}

fn parse_verbose_version(name: &str, output: &str) -> Result<ToolVersion> {
    let command = output
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .context("version probe output has no command line")?
        .to_owned();
    let field = |key: &str| {
        output.lines().find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            (candidate.trim() == key).then(|| value.trim().to_owned())
        })
    };
    let release = field("release").with_context(|| format!("{name} output has no release"))?;
    let host = field("host").with_context(|| format!("{name} output has no host"))?;
    Ok(ToolVersion {
        command,
        release,
        commit_hash: field("commit-hash").filter(|value| !value.is_empty()),
        host,
        sha256: None,
    })
}

fn digest_tool(path: &Path) -> Result<String> {
    use std::fmt::Write as _;

    let bytes = fs::read(path).context("read tool executable for attestation")?;
    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}").expect("writing a digest to String cannot fail");
    }
    Ok(digest)
}

fn verify_tool_digest(path: &Path, expected: &str) -> Result<()> {
    if digest_tool(path)? != expected {
        bail!("tool executable digest mismatch");
    }
    Ok(())
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    _stderr: Vec<u8>,
}

enum ProbeStream {
    Stdout(io::Result<Vec<u8>>),
    Stderr(io::Result<Vec<u8>>),
}

struct ProcessTreeGuard {
    #[cfg(unix)]
    process_group: i32,
    #[cfg(windows)]
    job: usize,
}

impl ProcessTreeGuard {
    fn attach(child: &Child) -> Result<Self> {
        #[cfg(unix)]
        {
            let process_group = i32::try_from(child.id()).context("probe process ID overflow")?;
            Ok(Self { process_group })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle as _;
            use windows_sys::Win32::{
                Foundation::CloseHandle,
                System::JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject,
                },
            };

            let process_handle = child.as_raw_handle();
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(std::io::Error::last_os_error()).context("create probe Job Object");
            }
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&raw const limits).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            };
            let assigned = configured != 0
                && unsafe { AssignProcessToJobObject(job, process_handle.cast()) } != 0;
            if !assigned {
                let error = std::io::Error::last_os_error();
                unsafe {
                    CloseHandle(job);
                }
                return Err(error).context("assign probe to Job Object");
            }
            Ok(Self { job: job as usize })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(Self {})
        }
    }

    fn terminate(&self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-self.process_group, libc::SIGKILL);
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job as _, 1);
        }
    }
}

impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        self.terminate();
        #[cfg(windows)]
        {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.job as _);
            }
        }
    }
}

fn bounded_output(mut command: Command, timeout: Duration, limit: usize) -> Result<BoundedOutput> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start version probe")?;
    let process_tree = ProcessTreeGuard::attach(&child).inspect_err(|_| {
        let _ = child.kill();
        let _ = child.wait();
    })?;
    let stdout = child
        .stdout
        .take()
        .context("capture version probe stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("capture version probe stderr")?;
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    thread::spawn(move || {
        let _ = stdout_sender.send(ProbeStream::Stdout(read_bounded(stdout, limit)));
    });
    thread::spawn(move || {
        let _ = sender.send(ProbeStream::Stderr(read_bounded(stderr, limit)));
    });
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child.try_wait().context("poll version probe")?;
        }
        loop {
            match receiver.try_recv() {
                Ok(ProbeStream::Stdout(result)) => {
                    stdout = Some(result.context("read version probe stdout")?);
                }
                Ok(ProbeStream::Stderr(result)) => {
                    stderr = Some(result.context("read version probe stderr")?);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if stdout.is_none() || stderr.is_none() {
                        process_tree.terminate();
                        let _ = child.kill();
                        let _ = child.wait();
                        bail!("version probe output reader stopped unexpectedly");
                    }
                    break;
                }
            }
        }
        if stdout.as_ref().is_some_and(|bytes| bytes.len() > limit)
            || stderr.as_ref().is_some_and(|bytes| bytes.len() > limit)
        {
            process_tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            bail!("version probe exceeded its output limit");
        }
        if let (Some(status), Some(stdout), Some(stderr)) =
            (status, stdout.as_ref(), stderr.as_ref())
        {
            process_tree.terminate();
            return Ok(BoundedOutput {
                status,
                stdout: stdout.clone(),
                _stderr: stderr.clone(),
            });
        }
        if Instant::now() >= deadline {
            process_tree.terminate();
            let _ = child.kill();
            let _ = child.wait();
            bail!("version probe exceeded its timeout");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_bounded(mut input: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input
        .by_ref()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::parse_verbose_version;
    #[cfg(unix)]
    use super::{
        PROBE_OUTPUT_LIMIT, PROBE_TIMEOUT, ToolchainProbeStatus, bounded_output,
        probe_resolved_toolchain,
    };
    #[cfg(unix)]
    use std::{process::Command, time::Duration};

    #[test]
    fn parses_verbose_rustc_and_cargo_output() {
        let rustc = parse_verbose_version(
            "rustc",
            "rustc 1.93.1 (01f6ddf75 2026-02-11)\nbinary: rustc\ncommit-hash: 01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf\nhost: aarch64-apple-darwin\nrelease: 1.93.1\n",
        )
        .unwrap();
        assert_eq!(rustc.release, "1.93.1");
        assert_eq!(rustc.host, "aarch64-apple-darwin");
        assert_eq!(
            rustc.commit_hash.as_deref(),
            Some("01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf")
        );
    }

    #[cfg(unix)]
    #[test]
    fn probes_only_external_tools_from_a_neutral_environment() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repository");
        let tools = temp.path().join("tools");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&tools).unwrap();
        let root = root.canonicalize().unwrap();
        let marker = root.join("project-tool-ran");
        let script = |name: &str, commit: &str| {
            let path = tools.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\n[ \"$PWD\" != {:?} ] || exit 10\n[ \"$RUSTUP_AUTO_INSTALL\" = 0 ] || exit 11\n[ \"$CARGO_NET_OFFLINE\" = true ] || exit 12\n[ -z \"$RUSTUP_TOOLCHAIN\" ] || exit 13\ncase \"$HOME$CARGO_HOME$TMPDIR$RUSTUP_HOME\" in *{:?}*) exit 14;; esac\nprintf '{} 1.93.1 (test)\\nrelease: 1.93.1\\ncommit-hash: {}\\nhost: test-host\\n'\n",
                    root,
                    root,
                    name,
                    commit,
                ),
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
            path
        };
        let rustc = script("rustc", crate::RUSTC_BASELINE_COMMIT);
        let cargo = script("cargo", crate::CARGO_BASELINE_COMMIT);
        let project_tool = root.join("rustc");
        std::fs::write(
            &project_tool,
            format!("#!/bin/sh\n: > {:?}\nexit 99\n", marker),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&project_tool).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&project_tool, permissions).unwrap();

        let probe = probe_resolved_toolchain(&root, &rustc, &cargo, PROBE_TIMEOUT).unwrap();
        assert_eq!(probe.status(), ToolchainProbeStatus::Compatible);
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn selected_toolchain_digest_rejects_post_probe_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repository");
        let tools = temp.path().join("tools");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&tools).unwrap();
        let root = root.canonicalize().unwrap();
        let script = |name: &str, commit: &str| {
            let path = tools.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '{} 1.93.1 (test)\\nrelease: 1.93.1\\ncommit-hash: {}\\nhost: test-host\\n'\n",
                    name, commit,
                ),
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
            path
        };
        let rustc = script("rustc", crate::RUSTC_BASELINE_COMMIT);
        let cargo = script("cargo", crate::CARGO_BASELINE_COMMIT);
        let probe = probe_resolved_toolchain(&root, &rustc, &cargo, PROBE_TIMEOUT).unwrap();
        assert_eq!(probe.status(), ToolchainProbeStatus::Compatible);

        std::fs::write(&rustc, "#!/bin/sh\nexit 99\n").unwrap();
        assert!(
            probe
                .commands
                .as_ref()
                .expect("verified commands")
                .verify_integrity()
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn mismatched_baseline_pair_remains_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repository");
        let tools = temp.path().join("tools");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&tools).unwrap();
        let root = root.canonicalize().unwrap();
        let script = |name: &str, commit: &str| {
            let path = tools.join(name);
            std::fs::write(
                &path,
                format!(
                    "#!/bin/sh\nprintf '{} 1.93.1 (test)\\nrelease: 1.93.1\\ncommit-hash: {}\\nhost: test-host\\n'\n",
                    name, commit,
                ),
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
            path
        };
        let rustc = script("rustc", crate::RUSTC_BASELINE_COMMIT);
        let cargo = script("cargo", "ffffffffffffffffffffffffffffffffffffffff");
        let probe = probe_resolved_toolchain(&root, &rustc, &cargo, PROBE_TIMEOUT).unwrap();

        assert_eq!(probe.status(), ToolchainProbeStatus::Unsupported);
        assert!(
            probe
                .reason()
                .is_some_and(|reason| reason.contains("do not match"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn enforces_timeout_and_output_limits() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let slow = temp.path().join("slow");
        std::fs::write(&slow, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        let mut permissions = std::fs::metadata(&slow).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&slow, permissions).unwrap();
        let command = Command::new(&slow);
        assert!(bounded_output(command, Duration::from_millis(20), 1024).is_err());

        let inherited_pipe = temp.path().join("inherited-pipe");
        std::fs::write(&inherited_pipe, "#!/bin/sh\nsleep 30 &\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&inherited_pipe).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&inherited_pipe, permissions).unwrap();
        let command = Command::new(&inherited_pipe);
        let started = std::time::Instant::now();
        assert!(bounded_output(command, Duration::from_millis(50), 1024).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        let noisy = temp.path().join("noisy");
        std::fs::write(
            &noisy,
            format!("#!/bin/sh\nprintf '%0{}d' 0\n", PROBE_OUTPUT_LIMIT + 1),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&noisy).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&noisy, permissions).unwrap();
        let command = Command::new(&noisy);
        assert!(bounded_output(command, Duration::from_secs(1), PROBE_OUTPUT_LIMIT).is_err());
    }

    #[test]
    fn rejects_incomplete_version_output() {
        assert!(parse_verbose_version("rustc", "rustc 1.93.1\nrelease: 1.93.1\n").is_err());
        assert!(
            parse_verbose_version("cargo", "cargo 1.93.1\nhost: test\nrelease: 1.93.1\n")
                .unwrap()
                .commit_hash
                .is_none()
        );
    }
}
