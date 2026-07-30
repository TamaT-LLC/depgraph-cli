use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Dot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub root: PathBuf,
    pub output: OutputFormat,
    pub include_tests: bool,
    pub ignored_paths: BTreeSet<PathBuf>,
    pub feature_sets: Vec<BTreeSet<String>>,
}

impl ProjectConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&bytes).context("parse project configuration")
    }
}
