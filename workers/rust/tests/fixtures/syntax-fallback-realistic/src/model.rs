use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleKind {
    Library,
    Binary,
    Test,
    Example,
    BuildScript,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub target: ModuleId,
    pub kind: String,
    pub optional: bool,
    pub features: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Module {
    pub id: ModuleId,
    pub name: String,
    pub kind: ModuleKind,
    pub source: PathBuf,
    pub dependencies: Vec<Dependency>,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files: usize,
    pub modules: usize,
    pub dependencies: usize,
    pub unresolved: usize,
    pub warnings: Vec<String>,
}
