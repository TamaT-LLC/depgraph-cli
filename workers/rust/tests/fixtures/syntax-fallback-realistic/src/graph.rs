use crate::config::ProjectConfig;
use crate::model::{Dependency, Module, ModuleId, ModuleKind, ScanSummary};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct DependencyGraph {
    pub modules: BTreeMap<ModuleId, Module>,
    pub reverse: BTreeMap<ModuleId, BTreeSet<ModuleId>>,
    pub summary: ScanSummary,
}

impl DependencyGraph {
    pub fn module(&self, id: &ModuleId) -> Option<&Module> {
        self.modules.get(id)
    }

    pub fn dependencies(&self, id: &ModuleId) -> Vec<&Dependency> {
        self.modules
            .get(id)
            .map(|module| module.dependencies.iter().collect())
            .unwrap_or_default()
    }

    pub fn transitive_dependencies(&self, root: &ModuleId) -> BTreeSet<ModuleId> {
        let mut visited = BTreeSet::new();
        let mut pending = VecDeque::from([root.clone()]);
        while let Some(current) = pending.pop_front() {
            for dependency in self.dependencies(&current) {
                if visited.insert(dependency.target.clone()) {
                    pending.push_back(dependency.target.clone());
                }
            }
        }
        visited
    }
}

#[derive(Clone, Debug)]
pub struct GraphBuilder {
    config: ProjectConfig,
}

impl GraphBuilder {
    pub fn new(config: ProjectConfig) -> Self {
        Self { config }
    }

    pub fn scan(&self, root: &Path) -> Result<DependencyGraph> {
        let canonical = root
            .canonicalize()
            .with_context(|| format!("canonicalize {}", root.display()))?;
        let mut graph = DependencyGraph::default();
        graph.modules.insert(
            ModuleId("root".into()),
            Module {
                id: ModuleId("root".into()),
                name: self
                    .config
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("root")
                    .to_owned(),
                kind: ModuleKind::Library,
                source: PathBuf::from(canonical),
                dependencies: Vec::new(),
                metadata: BTreeMap::new(),
            },
        );
        graph.summary.modules = graph.modules.len();
        Ok(graph)
    }
}
