//! Lossless dependency projection: declaration usage and its structural owners.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use depgraph_store::{
    EdgeRecord, GraphSnapshot, HealthInputIdentity, HealthWorkBudget, NodeRecord, Store,
};

use super::dependency::{
    MANIFEST_SITE_KINDS, canonical_manifest_scope, is_go_module_path, is_go_node, package_name,
};

/// Keep the same usage keys as the full analyzer, including Go subpackages and
/// requested module paths from replacement targets. Structural traversal stops
/// only at a valid direct manifest scope, exactly as the analyzer does.
pub(super) fn load(
    store: &Store,
    identity: &HealthInputIdentity,
    budget: &mut dyn HealthWorkBudget,
) -> Result<GraphSnapshot> {
    let (mut snapshot, _) = store.load_health_dependency_metadata(identity, budget)?;
    let mut exact = BTreeSet::new();
    let mut modules = BTreeSet::new();
    let mut requested_targets = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for site in &snapshot.sites {
        budget.step()?;
        if !MANIFEST_SITE_KINDS.contains(&site.kind.as_str()) {
            continue;
        }
        retained.insert(site.source.clone());
        for target in &site.target_ids {
            budget.step()?;
            retained.insert(target.clone());
            if site.kind == "module_requirement" {
                requested_targets.insert(target.clone());
            }
        }
        if let Some(specifier) = &site.specifier {
            exact.insert(specifier.clone());
            if site.kind == "module_requirement" {
                modules.insert(specifier.clone());
            }
        }
    }
    // Metadata arrives in node-ID order. Resolve the small set of requested
    // replacement targets by binary search, avoiding another whole-node pass.
    for target in requested_targets {
        budget.step()?;
        if let Ok(index) = snapshot.nodes.binary_search_by(|node| node.id.cmp(&target))
            && let Some(path) = snapshot.nodes[index]
                .properties
                .get("requested_module_path")
                .and_then(|v| v.as_str())
            && is_go_module_path(path)
        {
            exact.insert(path.to_owned());
            modules.insert(path.to_owned());
        }
    }
    snapshot
        .sites
        .extend(store.load_health_dependency_import_sites(identity, &exact, &modules, budget)?);
    let matches = |package: &str| {
        exact.contains(package)
            || package
                .match_indices('/')
                .any(|(index, _)| modules.contains(&package[..index]))
    };
    let mut nodes = BTreeMap::new();
    for node in std::mem::take(&mut snapshot.nodes) {
        budget.step()?;
        retained.insert(node.id.clone());
        nodes.insert(node.id.clone(), node);
    }
    let mut targets = Vec::new();
    for node in store.load_health_dependency_target_nodes(identity, &exact, &modules, budget)? {
        budget.step()?;
        if package_name(&node).is_some_and(|name| matches(&name)) {
            targets.push(node.id.clone());
        }
        nodes.insert(node.id.clone(), node);
    }
    let mut aliases = Vec::new();
    for site in &snapshot.sites {
        budget.step()?;
        if matches!(site.kind.as_str(), "import" | "side_effect_import")
            && site
                .specifier
                .as_deref()
                .is_some_and(|specifier| is_go_module_path(specifier) && matches(specifier))
        {
            aliases.push(site.id.clone());
        }
    }
    let mut edges = BTreeMap::new();
    let mut frontier = BTreeSet::new();
    let mut usage_sites = BTreeSet::new();
    for (ids, by_site) in [(&targets, false), (&aliases, true)] {
        for batch in ids.chunks(512) {
            let batch_edges =
                store.load_health_dependency_edges(identity, batch, by_site, false, budget)?;
            load_edge_nodes(store, identity, &batch_edges, &mut nodes, budget)?;
            for edge in batch_edges {
                budget.step()?;
                let Some(target) = nodes.get(&edge.target) else {
                    continue;
                };
                if !nodes.contains_key(&edge.source)
                    || package_name(target).is_none()
                    || (by_site
                        && (!is_go_node(target)
                            || !matches!(edge.kind.as_str(), "imports" | "side_effect_imports")))
                {
                    continue;
                }
                retained.insert(edge.source.clone());
                retained.insert(edge.target.clone());
                frontier.insert(edge.source.clone());
                if let Some(site) = &edge.site_id {
                    usage_sites.insert(site.clone());
                }
                edges.insert(edge.id.clone(), edge);
            }
        }
    }
    let mut visited = BTreeSet::new();
    while !frontier.is_empty() {
        let mut children = Vec::new();
        for id in std::mem::take(&mut frontier) {
            budget.step()?;
            if !visited.insert(id.clone()) {
                continue;
            }
            let Some(node) = nodes.get(&id) else { continue };
            if node
                .properties
                .get("manifest_path")
                .and_then(|v| v.as_str())
                .and_then(canonical_manifest_scope)
                .is_none()
            {
                children.push(id);
            }
        }
        for batch in children.chunks(512) {
            let batch_edges =
                store.load_health_dependency_edges(identity, batch, false, true, budget)?;
            load_edge_nodes(store, identity, &batch_edges, &mut nodes, budget)?;
            for edge in batch_edges {
                budget.step()?;
                if !nodes.contains_key(&edge.source) {
                    continue;
                }
                retained.insert(edge.source.clone());
                frontier.insert(edge.source.clone());
                edges.insert(edge.id.clone(), edge);
            }
        }
    }
    for id in retained {
        budget.step()?;
        if let Some(node) = nodes.remove(&id) {
            snapshot.nodes.push(node);
        }
    }
    let mut sites = Vec::new();
    for site in snapshot.sites {
        budget.step()?;
        if MANIFEST_SITE_KINDS.contains(&site.kind.as_str()) || usage_sites.contains(&site.id) {
            sites.push(site);
        }
    }
    snapshot.sites = sites;
    snapshot.edges = edges.into_values().collect();
    Ok(snapshot)
}

fn load_edge_nodes(
    store: &Store,
    identity: &HealthInputIdentity,
    edges: &[EdgeRecord],
    nodes: &mut BTreeMap<String, NodeRecord>,
    budget: &mut dyn HealthWorkBudget,
) -> Result<()> {
    let mut missing = BTreeSet::new();
    for edge in edges {
        for id in [&edge.source, &edge.target] {
            budget.step()?;
            if !nodes.contains_key(id) {
                missing.insert(id.clone());
            }
        }
    }
    let ids: Vec<_> = missing.into_iter().collect();
    for batch in ids.chunks(512) {
        for node in store.load_health_dependency_nodes(identity, batch, budget)? {
            budget.step()?;
            nodes.insert(node.id.clone(), node);
        }
    }
    Ok(())
}
