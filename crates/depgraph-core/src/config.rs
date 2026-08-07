use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use depgraph_protocol::MAX_EVENT_LINE_BYTES;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::PolicyConfig;

pub const CONFIG_FILE: &str = ".depgraph.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub scan: ScanConfig,
    pub daemon: DaemonConfig,
    pub strict: StrictConfig,
    pub profiles: ProfileConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub worker_timeout_seconds: u64,
    pub max_protocol_line_bytes: usize,
    pub max_protocol_bytes: usize,
    pub max_stderr_bytes: usize,
    pub follow_symlinks: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub debounce_milliseconds: u64,
    pub ignored_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StrictConfig {
    pub max_unresolved: u64,
    pub max_skipped: u64,
    pub max_unsupported_syntax: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileConfig {
    pub rust_features: Vec<String>,
    pub rust_targets: Vec<String>,
    pub rust_mode: String,
    pub go_tags: Vec<String>,
    pub go_call_graph: String,
    pub web_environments: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            scan: ScanConfig::default(),
            daemon: DaemonConfig::default(),
            strict: StrictConfig::default(),
            profiles: ProfileConfig::default(),
            policy: PolicyConfig::default(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            debounce_milliseconds: 200,
            ignored_paths: Vec::new(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            worker_timeout_seconds: 300,
            max_protocol_line_bytes: 1024 * 1024,
            max_protocol_bytes: 256 * 1024 * 1024,
            max_stderr_bytes: 10 * 1024 * 1024,
            follow_symlinks: false,
        }
    }
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            rust_features: Vec::new(),
            rust_targets: Vec::new(),
            rust_mode: "check".to_owned(),
            go_tags: Vec::new(),
            go_call_graph: "rta-cha".to_owned(),
            web_environments: vec!["server".to_owned(), "browser".to_owned()],
        }
    }
}

impl Config {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        let config: Self = toml::from_str(raw).context("failed to parse repository config")?;
        if config.schema_version != 1 {
            bail!(
                "unsupported config schema_version {}; expected 1",
                config.schema_version
            );
        }
        config.validate()?;
        Ok(config)
    }

    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(CONFIG_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let canonical_path = path
            .canonicalize()
            .with_context(|| format!("failed to resolve {}", path.display()))?;
        if !canonical_path.starts_with(&canonical_root) {
            bail!(
                "security policy violation: config path {} escapes scan root {}",
                path.display(),
                canonical_root.display()
            );
        }
        let raw = std::fs::read_to_string(&canonical_path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(&raw).with_context(|| format!("invalid {}", path.display()))
    }

    fn validate(&self) -> Result<()> {
        if self.scan.worker_timeout_seconds == 0 {
            bail!("scan.worker_timeout_seconds must be at least 1");
        }
        if self.scan.max_protocol_line_bytes == 0 {
            bail!("scan.max_protocol_line_bytes must be at least 1");
        }
        if self.scan.max_protocol_line_bytes > MAX_EVENT_LINE_BYTES {
            bail!(
                "scan.max_protocol_line_bytes must not exceed the protocol limit of {MAX_EVENT_LINE_BYTES}"
            );
        }
        if self.scan.max_protocol_bytes == 0 {
            bail!("scan.max_protocol_bytes must be at least 1");
        }
        if self.scan.max_protocol_bytes < self.scan.max_protocol_line_bytes {
            bail!("scan.max_protocol_bytes must be at least scan.max_protocol_line_bytes");
        }
        if self.scan.max_stderr_bytes == 0 {
            bail!("scan.max_stderr_bytes must be at least 1");
        }
        if self.scan.follow_symlinks {
            bail!("scan.follow_symlinks=true is not permitted by the safe-scan policy");
        }
        if !(10..=60_000).contains(&self.daemon.debounce_milliseconds) {
            bail!("daemon.debounce_milliseconds must be between 10 and 60000");
        }
        let mut ignored_paths = self.daemon.ignored_paths.clone();
        ignored_paths.sort();
        ignored_paths.dedup();
        if ignored_paths.len() != self.daemon.ignored_paths.len() {
            bail!("daemon.ignored_paths must not contain duplicates");
        }
        for path in &ignored_paths {
            validate_ignored_path(path)?;
        }
        if !matches!(self.profiles.rust_mode.as_str(), "check" | "build" | "test") {
            bail!("profiles.rust_mode must be check, build, or test");
        }
        if !matches!(self.profiles.go_call_graph.as_str(), "rta-cha" | "vta") {
            bail!("profiles.go_call_graph must be rta-cha or vta");
        }
        self.policy.validate()?;
        Ok(())
    }

    pub fn render_default() -> Result<String> {
        toml::to_string_pretty(&Self::default()).context("failed to serialize default config")
    }
}

fn validate_ignored_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("daemon ignored path {path:?} must be a normalized repository-relative path");
    }
    Ok(())
}

pub fn init_config(root: &Path, force: bool) -> Result<PathBuf> {
    let path = root.join(CONFIG_FILE);
    let existing = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if existing.is_some() && !force {
        bail!(
            "{} already exists; use --force to replace it",
            path.display()
        );
    }
    if force && let Some(metadata) = existing {
        if metadata.is_dir() {
            bail!("{} is a directory and cannot be replaced", path.display());
        }
        // Unlink first so --force cannot follow a symbolic or hard link and
        // overwrite content outside the repository.
        std::fs::remove_file(&path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
    }
    std::fs::write(&path, Config::render_default()?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

pub fn default_store_path(root: &Path) -> Result<PathBuf> {
    let identity = repository_identity(root);
    let project_dirs = ProjectDirs::from("com", "TamaT", "depgraph")
        .context("could not determine the operating system cache directory")?;
    Ok(project_dirs
        .cache_dir()
        .join("repositories")
        .join(identity)
        .join("graph.db"))
}

pub fn repository_identity(root: &Path) -> String {
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips() -> Result<()> {
        let rendered = Config::render_default()?;
        let parsed: Config = toml::from_str(&rendered)?;
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.scan.worker_timeout_seconds, 300);
        assert_eq!(parsed.daemon.debounce_milliseconds, 200);
        assert_eq!(parsed.strict.max_unresolved, 0);
        assert_eq!(parsed.profiles.rust_mode, "check");
        assert_eq!(parsed.profiles.go_call_graph, "rta-cha");
        assert_eq!(parsed.policy.schema_version, "1.0");
        Ok(())
    }

    #[test]
    fn versioned_policy_round_trips_through_toml_and_loads() -> Result<()> {
        let policy: PolicyConfig =
            serde_json::from_str(include_str!("../tests/fixtures/policy-v1.golden.json"))?;
        let config = Config {
            policy,
            ..Config::default()
        };
        let root = tempfile::tempdir()?;
        std::fs::write(
            root.path().join(CONFIG_FILE),
            toml::to_string_pretty(&config)?,
        )?;

        let loaded = Config::load(root.path())?;
        assert_eq!(loaded.policy.rules.len(), 2);
        assert_eq!(loaded.policy.suppressions.len(), 1);
        Ok(())
    }

    #[test]
    fn config_rejects_unknown_fields_and_invalid_worker_limits() -> Result<()> {
        let root = tempfile::tempdir()?;
        for raw in [
            "schema_version = 1\nunknown_option = true\n",
            "schema_version = 1\n[scan]\nworker_timout_seconds = 5\n",
            "schema_version = 1\n[scan]\nworker_timeout_seconds = 0\n",
            "schema_version = 1\n[scan]\nmax_protocol_line_bytes = 0\n",
            "schema_version = 1\n[scan]\nmax_protocol_bytes = 0\n",
            "schema_version = 1\n[scan]\nmax_stderr_bytes = 0\n",
            "schema_version = 1\n[scan]\nfollow_symlinks = true\n",
            "schema_version = 1\n[daemon]\ndebounce_milliseconds = 0\n",
            "schema_version = 1\n[daemon]\nignored_paths = ['../outside']\n",
            "schema_version = 1\n[daemon]\nignored_paths = ['vendor', 'vendor']\n",
            "schema_version = 1\n[profiles]\nrust_mode = 'release'\n",
            "schema_version = 1\n[profiles]\ngo_call_graph = 'pta'\n",
            "schema_version = 1\n[policy]\nschema_version = '2.0'\n",
            "schema_version = 1\n[policy]\nschema_version = '1.0'\nunknown = true\n",
        ] {
            std::fs::write(root.path().join(CONFIG_FILE), raw)?;
            assert!(Config::load(root.path()).is_err(), "accepted {raw:?}");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn config_symlink_must_not_escape_the_scan_root() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        std::fs::write(outside.path(), "schema_version = 1\n")?;
        symlink(outside.path(), root.path().join(CONFIG_FILE))?;

        let error = Config::load(root.path()).unwrap_err().to_string();
        assert!(error.contains("security policy"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn forced_init_replaces_a_symlink_without_overwriting_its_target() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        std::fs::write(outside.path(), "outside must remain unchanged\n")?;
        symlink(outside.path(), root.path().join(CONFIG_FILE))?;

        init_config(root.path(), true)?;
        assert_eq!(
            std::fs::read_to_string(outside.path())?,
            "outside must remain unchanged\n"
        );
        assert!(
            !std::fs::symlink_metadata(root.path().join(CONFIG_FILE))?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }
}
