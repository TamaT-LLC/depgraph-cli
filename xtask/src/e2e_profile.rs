//! The Cargo profile the e2e evidence gates (`resumable-analysis-e2e`,
//! `go-loader-scope-e2e`, `health-range-e2e`) build and run the CLI under.
//!
//! The gates are CPU-bound scans of generated fixtures, so they default to the
//! optimized `e2e` profile in the workspace `Cargo.toml`. A developer iterating
//! on a small fixture can set `DEPGRAPH_E2E_PROFILE=dev` to reuse an existing
//! `target/debug` build instead of compiling a second, optimized tree.

use std::{path::PathBuf, process::Command};

use anyhow::{Result, bail};

use crate::{cargo_target_dir, executable_name, run, workspace_root};

/// Environment variable that overrides [`DEFAULT_E2E_PROFILE`].
pub(crate) const E2E_PROFILE_ENV: &str = "DEPGRAPH_E2E_PROFILE";

/// The profile the gates use when [`E2E_PROFILE_ENV`] is unset or empty.
pub(crate) const DEFAULT_E2E_PROFILE: &str = "e2e";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct E2eProfile {
    name: String,
}

impl E2eProfile {
    /// The profile named by [`E2E_PROFILE_ENV`], or [`DEFAULT_E2E_PROFILE`].
    pub(crate) fn from_env() -> Result<Self> {
        let value = std::env::var(E2E_PROFILE_ENV).unwrap_or_default();
        Self::named(if value.is_empty() {
            DEFAULT_E2E_PROFILE
        } else {
            &value
        })
    }

    pub(crate) fn named(name: &str) -> Result<Self> {
        // Cargo profile names are restricted to this alphabet; rejecting
        // anything else keeps the value out of the output path unchecked.
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("{E2E_PROFILE_ENV} must be a Cargo profile name, got {name:?}");
        }
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// The `--profile` arguments for a cargo `build` or `run`.
    pub(crate) fn cargo_args(&self) -> [&str; 2] {
        ["--profile", &self.name]
    }

    /// The directory under the target directory that holds this profile's
    /// artifacts. Cargo keeps the built-in profiles in their historical
    /// directories; a custom profile uses its own name.
    pub(crate) fn output_dir(&self) -> &str {
        match self.name.as_str() {
            "dev" | "test" => "debug",
            "release" | "bench" => "release",
            name => name,
        }
    }

    /// Absolute path of the `depgraph` executable this profile produces.
    pub(crate) fn cli_path(&self) -> PathBuf {
        workspace_root()
            .join(cargo_target_dir())
            .join(self.output_dir())
            .join(executable_name("depgraph"))
    }

    /// Build `depgraph-cli` under this profile and return its executable.
    pub(crate) fn build_cli(&self) -> Result<PathBuf> {
        run(Command::new("cargo")
            .args(["build", "--locked"])
            .args(self.cargo_args())
            .args(["-p", "depgraph-cli"]))?;
        Ok(self.cli_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_maps_to_cargo_output_directory() -> Result<()> {
        for (name, directory) in [
            ("e2e", "e2e"),
            ("dev", "debug"),
            ("test", "debug"),
            ("release", "release"),
            ("bench", "release"),
            ("custom_profile-2", "custom_profile-2"),
        ] {
            let profile = E2eProfile::named(name)?;
            assert_eq!(profile.output_dir(), directory, "{name}");
            assert_eq!(profile.cargo_args(), ["--profile", name]);
        }
        Ok(())
    }

    #[test]
    fn profile_rejects_names_cargo_would_not_accept() {
        for name in ["", "../debug", "e2e/x", "e 2 e", "dev\n"] {
            assert!(E2eProfile::named(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn default_profile_is_declared_in_the_workspace_manifest() -> Result<()> {
        let manifest = std::fs::read_to_string(workspace_root().join("Cargo.toml"))?;
        let manifest: toml::Table = manifest.parse()?;
        let profile = &manifest["profile"][DEFAULT_E2E_PROFILE];
        assert_eq!(profile["inherits"].as_str(), Some("release"));
        // The gates keep checking the invariants the dev build checks.
        assert_eq!(profile["debug-assertions"].as_bool(), Some(true));
        assert_eq!(profile["overflow-checks"].as_bool(), Some(true));
        Ok(())
    }
}
