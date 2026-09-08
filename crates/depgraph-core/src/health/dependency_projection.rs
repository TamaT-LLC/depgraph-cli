//! Lossless dependency projection: declaration usage and its structural owners.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use depgraph_store::{GraphSnapshot, HealthInputIdentity, HealthWorkBudget, Store};

use super::dependency::{
    MANIFEST_SITE_KINDS, canonical_manifest_scope, is_go_module_path, package_name,
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
    let mut targets = Vec::new();
    let mut manifest_metadata = BTreeSet::new();
    for node in std::mem::take(&mut snapshot.nodes) {
        budget.step()?;
        if package_name(&node).is_some_and(|name| matches(&name)) {
            targets.push(node.id.clone());
        }
        // Manifest discovery and drift checks observe sets of paths/hashes.
        // Retain a real representative of each distinct observation, even if
        // the node has no relevant usage edges. Conflicting hashes stay distinct.
        let manifest = node
            .properties
            .get("manifest_path")
            .and_then(|v| v.as_str());
        let hash = ["content_hash", "content_digest"]
            .into_iter()
            .find_map(|key| node.properties.get(key).and_then(|v| v.as_str()));
        let path = hash.and_then(|_| node.properties.get("path").and_then(|v| v.as_str()));
        if (manifest.is_some() || path.is_some())
            && manifest_metadata.insert((
                manifest.map(str::to_owned),
                hash.map(str::to_owned),
                path.map(str::to_owned),
            ))
        {
            retained.insert(node.id.clone());
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
            for edge in
                store.load_health_dependency_edges(identity, batch, by_site, false, budget)?
            {
                budget.step()?;
                if !nodes.contains_key(&edge.source) || !nodes.contains_key(&edge.target) {
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
            for edge in store.load_health_dependency_edges(identity, batch, false, true, budget)? {
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
