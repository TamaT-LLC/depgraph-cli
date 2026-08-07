use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context as _, Result};
use depgraph_core::service::{
    DEPGRAPH_SERVICE_LIMITS_VERSION, DepgraphCapabilitySet, DepgraphService, DepgraphServiceConfig,
    DepgraphServiceError, DepgraphServiceLimits, GraphExportFormat, GraphExportRequest,
    PolicyEvaluateRequest, SnapshotDiffFilters, SnapshotDiffRequest,
};
use depgraph_core::{
    CancellationToken, GraphQueryFilter, SnapshotLocator,
    config::Config,
    policy::{PolicyCondition, PolicyConfig, PolicySelector},
};
use depgraph_store::Store;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn service(root: &Path, store_path: &Path) -> Result<DepgraphService> {
    service_with_output_limit(root, store_path, 16 * 1024 * 1024)
}

fn service_with_output_limit(
    root: &Path,
    store_path: &Path,
    max_output_bytes: usize,
) -> Result<DepgraphService> {
    Ok(DepgraphService::new(DepgraphServiceConfig::new(
        root,
        store_path,
        DepgraphCapabilitySet::read_only(),
        DepgraphServiceLimits::try_new(
            DEPGRAPH_SERVICE_LIMITS_VERSION,
            1024 * 1024,
            max_output_bytes,
            100,
            1_000,
        )?,
    )?))
}

fn seed_snapshot(
    store: &mut Store,
    root: &Path,
    scan_id: &str,
    revision: &str,
    target: bool,
) -> Result<String> {
    store.start_scan_with_revision(scan_id, root, false, Some(revision))?;
    let coverage = json!({
        "profiles": 1,
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "dependency_sites": 0,
        "resolved": 0,
        "candidates": 0,
        "external": 0,
        "unresolved": 0,
        "unsupported_syntax": 0,
        "project_code_executed": false,
        "completeness": ["syntax-complete"],
        "reasons": []
    });
    let common = |event: &str, seq: u64| {
        json!({
            "event": event,
            "protocol_version": "1.0",
            "scan_id": scan_id,
            "adapter": "issue-305-fixture",
            "adapter_version": "1.0",
            "seq": seq
        })
    };
    let mut started = common("scan_started", 1);
    started["root"] = json!(root);
    started["project_code_executed"] = json!(false);
    started["safe_mode"] = json!(true);
    store.ingest_event(&started)?;

    let mut profile = common("profile_declared", 2);
    profile["profile"] = json!({
        "id": "fixture:safe",
        "language": "fixture",
        "features": [],
        "environment": {"API_TOKEN": "RAW_PROFILE_SECRET"},
        "properties": {"private": "RAW_PROFILE_PROPERTY_SECRET"}
    });
    store.ingest_event(&profile)?;

    let nodes = if target {
        vec![
            ("file:a", "repo://src/a.rs", "a changed"),
            ("file:b", "repo://src/b.rs", "b"),
            ("file:c", "repo://src/c.rs", "c"),
        ]
    } else {
        vec![
            ("file:a", "repo://src/a.rs", "a"),
            ("file:b", "repo://src/b.rs", "b"),
        ]
    };
    let mut seq = 3_u64;
    for (id, locator, display_name) in nodes {
        let mut node = common("node_upsert", seq);
        node["node"] = json!({
            "id": id,
            "kind": "file",
            "locator": locator,
            "display_name": display_name,
            "properties": {
                "private": "RAW_NODE_PROPERTY_SECRET",
                "root": root
            }
        });
        store.ingest_event(&node)?;
        seq += 1;
    }
    for (id, source, destination) in if target {
        vec![
            ("edge:a-b", "file:a", "file:b"),
            ("edge:b-c", "file:b", "file:c"),
        ]
    } else {
        vec![("edge:a-b", "file:a", "file:b")]
    } {
        let mut edge = common("edge_upsert", seq);
        edge["edge"] = json!({
            "id": id,
            "source": source,
            "target": destination,
            "kind": "imports",
            "phase": "source",
            "environment": "host",
            "profile_id": "fixture:safe",
            "resolution_status": "resolved",
            "precision": "exact",
            "condition": {"op": "all", "conditions": []},
            "generated": false,
            "evidence": [{
                "kind": "source",
                "extractor": "fixture",
                "extractor_version": "1.0",
                "path": "src/a.rs",
                "start_line": 1,
                "start_column": 1,
                "end_line": 1,
                "end_column": 2,
                "properties": {"private": "RAW_EVIDENCE_PROPERTY_SECRET"}
            }]
        });
        store.ingest_event(&edge)?;
        seq += 1;
    }
    let mut profile_completed = common("profile_completed", seq);
    profile_completed["profile_id"] = json!("fixture:safe");
    profile_completed["coverage"] = coverage.clone();
    store.ingest_event(&profile_completed)?;
    seq += 1;
    let mut completed = common("scan_completed", seq);
    completed["coverage"] = coverage;
    store.ingest_event(&completed)?;
    store.finish_scan(scan_id, "completed", None, true)?;
    Ok(store
        .current_snapshot_id()?
        .expect("completed fixture snapshot is promoted"))
}

fn fixture() -> Result<(tempfile::TempDir, std::path::PathBuf, String, String)> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path().join("repository");
    let store_path = temporary.path().join("cache/graph.db");
    fs::create_dir_all(&root)?;
    let mut store = Store::open(&store_path)?;
    let baseline = seed_snapshot(&mut store, &root, "baseline-scan", "revision-1", false)?;
    store.create_snapshot_name("baseline", &baseline)?;
    let target = seed_snapshot(&mut store, &root, "target-scan", "revision-2", true)?;
    store.create_snapshot_name("target", &target)?;
    Ok((temporary, store_path, baseline, target))
}

fn artifact_policy_config() -> Result<PolicyConfig> {
    Ok(serde_json::from_value(json!({
        "schema_version": "1.0",
        "rules": [
            {
                "id": "artifact-rule-a",
                "kind": "forbidden_dependency",
                "severity": "warning",
                "source": {
                    "kind": "file", "field": "id", "match": "exact", "value": "file:a",
                    "cardinality": "one",
                    "exclude": [
                        {"field": "id", "match": "exact", "value": "file:x"},
                        {"field": "id", "match": "exact", "value": "file:y"}
                    ],
                    "scope": {"paths": [], "packages": []}
                },
                "target": {
                    "kind": "file", "field": "id", "match": "exact", "value": "file:b",
                    "cardinality": "one",
                    "exclude": [
                        {"field": "id", "match": "exact", "value": "file:x"},
                        {"field": "id", "match": "exact", "value": "file:y"}
                    ],
                    "scope": {"paths": [], "packages": []}
                },
                "profiles": {
                    "include": [
                        {"match": "exact", "value": "fixture:safe"},
                        {"match": "prefix", "value": "fixture:"}
                    ],
                    "exclude": [
                        {"match": "exact", "value": "fixture:excluded-a"},
                        {"match": "exact", "value": "fixture:excluded-b"}
                    ]
                },
                "condition": {
                    "op": "any",
                    "conditions": [
                        {"op": "eq", "key": "environment", "value": "host"},
                        {"op": "eq", "key": "environment", "value": "other"}
                    ]
                },
                "precisions": ["exact", "observed"],
                "resolution_statuses": ["resolved", "candidates"],
                "evidence": {
                    "kinds": ["source", "semantic"],
                    "minimum_spans": 1,
                    "primary_only": true
                }
            },
            {
                "id": "artifact-rule-b",
                "kind": "forbidden_dependency",
                "severity": "error",
                "source": {
                    "kind": "file", "field": "path", "match": "glob", "value": "src/**",
                    "cardinality": "many", "exclude": [],
                    "scope": {
                        "paths": [
                            {"match": "glob", "value": "src/**"},
                            {"match": "glob", "value": "tests/**"}
                        ],
                        "packages": [
                            {"match": "prefix", "value": "package:a"},
                            {"match": "prefix", "value": "package:b"}
                        ]
                    }
                },
                "target": {
                    "kind": "file", "field": "path", "match": "glob", "value": "src/**",
                    "cardinality": "many", "exclude": [],
                    "scope": {"paths": [], "packages": []}
                },
                "profiles": {"include": [], "exclude": []},
                "condition": {"op": "all", "conditions": []},
                "precisions": ["heuristic", "exact"],
                "resolution_statuses": ["candidates", "resolved"],
                "evidence": {
                    "kinds": ["semantic", "source"],
                    "minimum_spans": 1,
                    "primary_only": false
                }
            }
        ],
        "suppressions": [
            {
                "id": "artifact-suppression-a",
                "rule_id": "artifact-rule-a",
                "reason": "canonical first suppression",
                "scope": {
                    "source": {
                        "kind": "file", "field": "id", "match": "exact", "value": "file:a",
                        "cardinality": "one",
                        "exclude": [
                            {"field": "id", "match": "exact", "value": "file:x"},
                            {"field": "id", "match": "exact", "value": "file:y"}
                        ],
                        "scope": {"paths": [], "packages": []}
                    },
                    "profiles": {
                        "include": [
                            {"match": "prefix", "value": "fixture:"},
                            {"match": "exact", "value": "fixture:safe"}
                        ],
                        "exclude": []
                    },
                    "condition": {
                        "op": "in", "key": "environment", "values": ["host", "other"]
                    }
                }
            },
            {
                "id": "artifact-suppression-b",
                "rule_id": "artifact-rule-a",
                "reason": "canonical second suppression",
                "scope": {
                    "target": {
                        "kind": "file", "field": "id", "match": "exact", "value": "file:b",
                        "cardinality": "one", "exclude": [],
                        "scope": {"paths": [], "packages": []}
                    },
                    "profiles": {
                        "include": [
                            {"match": "exact", "value": "fixture:safe"},
                            {"match": "prefix", "value": "fixture:"}
                        ],
                        "exclude": []
                    }
                }
            }
        ]
    }))?)
}

fn reverse_policy_semantic_sets(policy: &mut PolicyConfig) {
    policy.rules.reverse();
    policy.suppressions.reverse();
    for rule in &mut policy.rules {
        reverse_selector_sets(&mut rule.source);
        reverse_selector_sets(&mut rule.target);
        rule.profiles.include.reverse();
        rule.profiles.exclude.reverse();
        reverse_condition_sets(&mut rule.condition);
        rule.precisions.reverse();
        rule.resolution_statuses.reverse();
        rule.evidence.kinds.reverse();
    }
    for suppression in &mut policy.suppressions {
        if let Some(source) = &mut suppression.scope.source {
            reverse_selector_sets(source);
        }
        if let Some(target) = &mut suppression.scope.target {
            reverse_selector_sets(target);
        }
        suppression.scope.profiles.include.reverse();
        suppression.scope.profiles.exclude.reverse();
        if let Some(condition) = &mut suppression.scope.condition {
            reverse_condition_sets(condition);
        }
    }
}

fn reverse_selector_sets(selector: &mut PolicySelector) {
    selector.exclude.reverse();
    selector.scope.paths.reverse();
    selector.scope.packages.reverse();
}

fn reverse_condition_sets(condition: &mut PolicyCondition) {
    match condition {
        PolicyCondition::All { conditions } | PolicyCondition::Any { conditions } => {
            for condition in &mut *conditions {
                reverse_condition_sets(condition);
            }
            conditions.reverse();
        }
        PolicyCondition::Not { condition } => reverse_condition_sets(condition),
        PolicyCondition::In { values, .. } => values.reverse(),
        PolicyCondition::Eq { .. } | PolicyCondition::Defined { .. } => {}
    }
}

fn write_policy(root: &Path, policy: PolicyConfig) -> Result<()> {
    fs::write(
        root.join(".depgraph.toml"),
        toml::to_string_pretty(&Config {
            policy,
            ..Config::default()
        })?,
    )?;
    Ok(())
}

#[test]
fn snapshot_diff_is_pinned_closed_filterable_and_maps_not_found() -> Result<()> {
    let (temporary, store_path, baseline, target) = fixture()?;
    let root = temporary.path().join("repository");
    let service = service(&root, &store_path)?;
    let root_text = root.to_string_lossy().into_owned();
    let request = SnapshotDiffRequest::new(
        SnapshotLocator::parse("baseline")?,
        SnapshotLocator::Current,
        SnapshotDiffFilters::default(),
    );
    let first = service.snapshot_diff(&request, &CancellationToken::new())?;
    let second = service.snapshot_diff(&request, &CancellationToken::new())?;
    assert_eq!(first, second);
    assert_eq!(first.from_snapshot_id, baseline);
    assert_eq!(first.to_snapshot_id, target);
    assert!(!first.is_empty());
    assert!(!first.collection_digest.is_empty());
    let encoded = serde_json::to_string(&first)?;
    for forbidden in ["RAW_NODE_PROPERTY_SECRET", "properties", root_text.as_str()] {
        assert!(!encoded.contains(forbidden), "diff disclosed {forbidden}");
    }

    let current_pair = service.snapshot_diff(
        &SnapshotDiffRequest::new(
            SnapshotLocator::Current,
            SnapshotLocator::Current,
            SnapshotDiffFilters::default(),
        ),
        &CancellationToken::new(),
    )?;
    assert_eq!(current_pair.from_snapshot_id, target);
    assert_eq!(current_pair.to_snapshot_id, target);
    assert!(current_pair.is_empty());

    let filtered = service.snapshot_diff(
        &SnapshotDiffRequest::new(
            SnapshotLocator::parse("baseline")?,
            SnapshotLocator::parse("target")?,
            SnapshotDiffFilters::try_new(vec!["imports".to_owned()], vec![], vec![], vec![])?,
        ),
        &CancellationToken::new(),
    )?;
    assert!(filtered.nodes.added.is_empty());
    assert_eq!(filtered.edges.added.len(), 1);

    let missing = service.snapshot_diff(
        &SnapshotDiffRequest::new(
            SnapshotLocator::parse("missing")?,
            SnapshotLocator::Current,
            SnapshotDiffFilters::default(),
        ),
        &CancellationToken::new(),
    );
    assert!(matches!(missing, Err(DepgraphServiceError::NotFound)));
    Ok(())
}

#[test]
fn policy_digest_is_canonical_in_result_identity_without_raw_config() -> Result<()> {
    let (temporary, store_path, _, _) = fixture()?;
    let root = temporary.path().join("repository");
    let config_path = root.join(".depgraph.toml");
    fs::write(
        &config_path,
        "schema_version = 1\n[policy]\nschema_version = '1.0'\nrules = []\nsuppressions = []\n",
    )?;
    let service = service(&root, &store_path)?;
    let request = PolicyEvaluateRequest::new(
        SnapshotLocator::parse("baseline")?,
        SnapshotLocator::parse("target")?,
    );
    let first = service
        .policy_evaluate(&request, &CancellationToken::new())
        .context("initial policy evaluation")?;
    fs::write(
        &config_path,
        "# formatting and TOML key order do not affect identity\nschema_version=1\n[policy]\nsuppressions=[]\nrules=[]\nschema_version='1.0'\n",
    )?;
    let equivalent = service
        .policy_evaluate(&request, &CancellationToken::new())
        .context("equivalent policy evaluation")?;
    assert_eq!(
        first.result.policy_config_digest,
        equivalent.result.policy_config_digest
    );
    assert_eq!(first.result.result_id, equivalent.result.result_id);

    fs::write(
        &config_path,
        r#"schema_version = 1
[policy]
schema_version = "1.0"

[[policy.rules]]
id = "policy-digest-test"
kind = "forbidden_dependency"
severity = "warning"
source = { kind = "file", field = "id", match = "exact", value = "file:a", cardinality = "one", exclude = [{ field = "id", match = "exact", value = "RAW_POLICY_SECRET_EXCLUDED" }], scope = { paths = [], packages = [] } }
target = { kind = "file", field = "id", match = "exact", value = "file:b", cardinality = "one", exclude = [], scope = { paths = [], packages = [] } }
profiles = { include = [{ match = "exact", value = "fixture:safe" }], exclude = [] }
condition = { op = "all", conditions = [] }
precisions = ["exact"]
resolution_statuses = ["resolved"]
evidence = { kinds = ["source"], minimum_spans = 1, primary_only = true }
"#,
    )?;
    let changed = service
        .policy_evaluate(&request, &CancellationToken::new())
        .context("changed policy evaluation")?;
    assert_ne!(
        first.result.policy_config_digest,
        changed.result.policy_config_digest
    );
    assert_ne!(first.result.result_id, changed.result.result_id);
    let encoded = serde_json::to_string(&changed)?;
    assert!(!encoded.contains("RAW_POLICY_SECRET"));
    assert!(encoded.contains(&changed.result.policy_config_digest));
    Ok(())
}

#[test]
fn policy_digest_and_result_identity_ignore_semantically_unordered_arrays() -> Result<()> {
    let (temporary, store_path, _, _) = fixture()?;
    let root = temporary.path().join("repository");
    let service = service(&root, &store_path)?;
    let request = PolicyEvaluateRequest::new(
        SnapshotLocator::parse("baseline")?,
        SnapshotLocator::parse("target")?,
    );

    let policy = artifact_policy_config()?;
    write_policy(&root, policy.clone())?;
    let first = service.policy_evaluate(&request, &CancellationToken::new())?;

    let mut reordered = policy;
    reverse_policy_semantic_sets(&mut reordered);
    assert_eq!(
        artifact_policy_config()?.normalized_identity()?,
        reordered.normalized_identity()?
    );
    write_policy(&root, reordered)?;
    let second = service.policy_evaluate(&request, &CancellationToken::new())?;

    assert_eq!(
        first.result.policy_config_digest,
        second.result.policy_config_digest
    );
    assert_eq!(first.result.result_id, second.result.result_id);
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn inline_exports_are_safe_deterministic_bounded_and_content_addressed() -> Result<()> {
    let (temporary, store_path, _, target) = fixture()?;
    let root = temporary.path().join("repository");
    let service = service(&root, &store_path)?;
    let root_text = root.to_string_lossy().into_owned();
    for format in [
        GraphExportFormat::Json,
        GraphExportFormat::Dot,
        GraphExportFormat::Mermaid,
        GraphExportFormat::Graphml,
    ] {
        let request = GraphExportRequest::try_new(
            SnapshotLocator::parse("target")?,
            format,
            None,
            GraphQueryFilter::default(),
            10,
            10,
        )?;
        let first = service.graph_export(&request, &CancellationToken::new())?;
        let second = service.graph_export(&request, &CancellationToken::new())?;
        assert_eq!(first, second);
        assert_eq!(first.snapshot_id, target);
        assert_eq!(first.node_count, 3);
        assert_eq!(first.edge_count, 2);
        assert_eq!(first.output_bytes, first.content.len() as u64);
        assert_eq!(
            first.content_sha256,
            hex::encode(Sha256::digest(first.content.as_bytes()))
        );
        for forbidden in [
            "RAW_NODE_PROPERTY_SECRET",
            "RAW_PROFILE_SECRET",
            "RAW_EVIDENCE_PROPERTY_SECRET",
            "properties",
            root_text.as_str(),
        ] {
            assert!(
                !first.content.contains(forbidden),
                "{format:?} export disclosed {forbidden}"
            );
        }
        match format {
            GraphExportFormat::Json => {
                let value: Value = serde_json::from_str(&first.content)?;
                let fields = value
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    fields,
                    BTreeSet::from([
                        "edges".to_owned(),
                        "nodes".to_owned(),
                        "schema_version".to_owned(),
                    ])
                );
            }
            GraphExportFormat::Dot => assert!(first.content.starts_with("digraph depgraph")),
            GraphExportFormat::Mermaid => assert!(first.content.starts_with("flowchart LR")),
            GraphExportFormat::Graphml => assert!(first.content.contains("<graphml xmlns=")),
        }
    }

    let nodes_exceeded = service.graph_export(
        &GraphExportRequest::try_new(
            SnapshotLocator::Current,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            1,
            10,
        )?,
        &CancellationToken::new(),
    );
    assert!(matches!(
        nodes_exceeded,
        Err(DepgraphServiceError::ResourceExhausted)
    ));

    let small_service = service_with_output_limit(&root, &store_path, 512)?;
    let overflow = small_service.graph_export(
        &GraphExportRequest::try_new(
            SnapshotLocator::Current,
            GraphExportFormat::Json,
            None,
            GraphQueryFilter::default(),
            10,
            10,
        )?,
        &CancellationToken::new(),
    );
    assert!(matches!(
        overflow,
        Err(DepgraphServiceError::InlineExportTooLarge { maximum: 512 })
    ));
    Ok(())
}

#[test]
fn shared_artifact_services_observe_pre_cancel_without_partial_results() -> Result<()> {
    let (temporary, store_path, _, _) = fixture()?;
    let root = temporary.path().join("repository");
    let service = service(&root, &store_path)?;
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert!(matches!(
        service.snapshot_diff(
            &SnapshotDiffRequest::new(
                SnapshotLocator::Current,
                SnapshotLocator::Current,
                SnapshotDiffFilters::default(),
            ),
            &cancellation,
        ),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(matches!(
        service.policy_evaluate(
            &PolicyEvaluateRequest::new(SnapshotLocator::Current, SnapshotLocator::Current),
            &cancellation,
        ),
        Err(DepgraphServiceError::Cancelled)
    ));
    assert!(matches!(
        service.graph_export(
            &GraphExportRequest::try_new(
                SnapshotLocator::Current,
                GraphExportFormat::Json,
                None,
                GraphQueryFilter::default(),
                10,
                10,
            )?,
            &cancellation,
        ),
        Err(DepgraphServiceError::Cancelled)
    ));
    Ok(())
}
