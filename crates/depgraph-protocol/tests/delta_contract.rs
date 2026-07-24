use depgraph_protocol::{
    CommonFields, CompletenessLevel, Condition, Coverage, CoverageDelete, CoverageUpsert,
    DELTA_CONTRACT_VERSION, DeltaBaseGraph, DeltaCompleted, DeltaCoverage, DeltaCoverageKey,
    DeltaEdgeUpsert, DeltaEvent, DeltaEvidenceKey, DeltaEvidenceOwner, DeltaEvidenceRecord,
    DeltaFileCoverage, DeltaNodeUpsert, DeltaScope, DeltaStarted, EdgeDelete, Evidence,
    EvidenceDelete, EvidenceKind, EvidenceUpsert, GraphEdge, GraphNode, NodeDelete,
    PROTOCOL_SCHEMA, Phase, Precision, ProtocolError, ResolutionStatus, SiteDelete, SiteUpsert,
    WORKER_DELTA_CAPABILITY, WorkerProtocolMode, build_delta_stable_id, delta_graph_digest,
    negotiate_worker_protocol, validate_delta_ndjson, validate_ndjson,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

const SNAPSHOT_ID: &str =
    "snapshot:sha256:1111111111111111111111111111111111111111111111111111111111111111";
const BASE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const RESULT_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const SOURCE_ID: &str =
    "file:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OLD_TARGET_ID: &str =
    "file:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OLD_SITE_ID: &str =
    "site:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OLD_EDGE_ID: &str =
    "edge:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const NEW_TARGET_ID: &str =
    "file:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const NEW_SITE_ID: &str =
    "site:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const NEW_EDGE_ID: &str =
    "edge:sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PROFILE_ID: &str = "web:production:server";
const DELTA_GOLDEN: &str = include_str!("fixtures/protocol-v1.delta.golden.ndjson");

#[test]
fn valid_delta_is_canonical_and_byte_equivalent_across_repeated_generation() {
    let first = delta_ndjson();
    let second = delta_ndjson();
    assert_eq!(first.as_bytes(), second.as_bytes());

    let validated =
        validate_delta_ndjson(Cursor::new(&first), base_graph()).expect("delta must validate");
    assert_eq!(validated.events.len(), 15);
    assert_eq!(
        validated.node_deletes,
        BTreeSet::from([OLD_TARGET_ID.into()])
    );
    assert_eq!(
        validated.node_upserts.keys().collect::<Vec<_>>(),
        [&NEW_TARGET_ID.to_owned()]
    );
    assert_eq!(validated.result_graph_digest, RESULT_DIGEST);
}

#[test]
fn graph_digest_is_canonical_and_payload_sensitive() {
    let first = base_graph();
    let mut reordered = base_graph();
    reordered.nodes = reordered.nodes.into_iter().rev().collect();
    assert_eq!(delta_graph_digest(&first), delta_graph_digest(&reordered));

    let mut changed = first.clone();
    changed
        .nodes
        .get_mut(SOURCE_ID)
        .unwrap()
        .properties
        .insert("content_hash".into(), json!("changed"));
    assert_ne!(delta_graph_digest(&first), delta_graph_digest(&changed));
}

#[test]
fn schema_accepts_every_delta_event_and_rejects_unknown_events() {
    let schema: Value = serde_json::from_str(PROTOCOL_SCHEMA).expect("schema JSON");
    let validator = jsonschema::draft202012::new(&schema).expect("schema compiles");
    for line in delta_ndjson().lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert!(validator.is_valid(&event), "schema rejected {event}");
    }

    let unknown = common_json(json!({"event": "future_delta_mutation"}), 2);
    assert!(!validator.is_valid(&unknown));
    let error = serde_json::from_value::<DeltaEvent>(unknown).unwrap_err();
    assert!(error.to_string().contains("unknown variant"));
}

#[test]
fn interrupted_or_noncanonical_delta_is_rejected_without_a_result() {
    let events = delta_events();
    let truncated = events[..events.len() - 1]
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let error = validate_delta_ndjson(Cursor::new(truncated), base_graph()).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("ended before delta_completed"))
    );

    let mut noncanonical = events;
    noncanonical.swap(1, 2);
    renumber(&mut noncanonical);
    let input = events_to_ndjson(&noncanonical);
    let error = validate_delta_ndjson(Cursor::new(input), base_graph()).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("canonical order"))
    );
}

#[test]
fn malformed_ids_and_dangling_references_fail_closed() {
    let mut malformed = delta_events();
    match &mut malformed[6] {
        DeltaEvent::NodeUpsert(event) => event.node.id = "file:not-a-stable-id".into(),
        _ => panic!("expected node upsert"),
    }
    let error =
        validate_delta_ndjson(Cursor::new(events_to_ndjson(&malformed)), base_graph()).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("stable SHA-256 ID"))
    );

    let mut dangling = delta_events();
    match &mut dangling[7] {
        DeltaEvent::SiteUpsert(event) => event.site.source = OLD_TARGET_ID.into(),
        _ => panic!("expected site upsert"),
    }
    reset_delta_id(&mut dangling);
    let error =
        validate_delta_ndjson(Cursor::new(events_to_ndjson(&dangling)), base_graph()).unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("missing source node"))
    );
}

#[test]
fn every_mutation_is_confined_to_the_declared_scope() {
    let mut out_of_scope_upsert = delta_events();
    match &mut out_of_scope_upsert[0] {
        DeltaEvent::DeltaStarted(started) => {
            started.scope.paths = vec!["src/index.ts".into(), "src/lib.ts".into()];
        }
        _ => unreachable!(),
    }
    reset_delta_id(&mut out_of_scope_upsert);
    let error = validate_delta_ndjson(
        Cursor::new(events_to_ndjson(&out_of_scope_upsert)),
        base_graph(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("node mutation") && message.contains("outside the declared scope"))
    );

    let mut out_of_scope_delete = delta_events();
    match &mut out_of_scope_delete[0] {
        DeltaEvent::DeltaStarted(started) => {
            started.scope.paths = vec!["src/index.ts".into(), "src/next.ts".into()];
        }
        _ => unreachable!(),
    }
    reset_delta_id(&mut out_of_scope_delete);
    let error = validate_delta_ndjson(
        Cursor::new(events_to_ndjson(&out_of_scope_delete)),
        base_graph(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("node mutation") && message.contains("outside the declared scope"))
    );

    let mut out_of_scope_coverage = delta_events();
    match &mut out_of_scope_coverage[11] {
        DeltaEvent::CoverageDelete(deleted) => {
            deleted.coverage_key = DeltaCoverageKey::File {
                adapter: "web".into(),
                path: "src/rogue.ts".into(),
            };
        }
        _ => unreachable!(),
    }
    reset_delta_id(&mut out_of_scope_coverage);
    let error = validate_delta_ndjson(
        Cursor::new(events_to_ndjson(&out_of_scope_coverage)),
        base_graph(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("coverage mutation") && message.contains("outside the declared scope"))
    );
}

#[test]
fn coverage_hierarchy_must_match_profiles_files_and_final_sites() {
    let mut graph_mismatch = delta_events();
    match &mut graph_mismatch[12] {
        DeltaEvent::CoverageUpsert(CoverageUpsert {
            coverage: DeltaCoverage::Aggregate { value },
            ..
        }) => {
            value.dependency_sites = 2;
            value.resolved = 2;
        }
        _ => unreachable!(),
    }
    reset_delta_id(&mut graph_mismatch);
    let error = validate_delta_ndjson(Cursor::new(events_to_ndjson(&graph_mismatch)), base_graph())
        .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("delta scan coverage site counts"))
    );

    let mut file_mismatch = delta_events();
    file_mismatch.remove(13);
    match file_mismatch.last_mut() {
        Some(DeltaEvent::DeltaCompleted(completed)) => completed.mutation_count -= 1,
        _ => unreachable!(),
    }
    renumber(&mut file_mismatch);
    reset_delta_id(&mut file_mismatch);
    let error = validate_delta_ndjson(Cursor::new(events_to_ndjson(&file_mismatch)), base_graph())
        .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("file coverage records exist"))
    );

    let mut profile_mismatch = delta_events();
    let mut completed = profile_mismatch.pop().expect("completion event");
    match &mut completed {
        DeltaEvent::DeltaCompleted(completed) => completed.mutation_count += 1,
        _ => unreachable!(),
    }
    let mut inconsistent_profile = coverage();
    inconsistent_profile.dependency_sites = 2;
    inconsistent_profile.resolved = 2;
    profile_mismatch.push(DeltaEvent::CoverageUpsert(CoverageUpsert {
        common: common(0),
        coverage: DeltaCoverage::Profile {
            profile_id: PROFILE_ID.into(),
            value: inconsistent_profile,
        },
    }));
    profile_mismatch.push(completed);
    renumber(&mut profile_mismatch);
    reset_delta_id(&mut profile_mismatch);
    let error = validate_delta_ndjson(
        Cursor::new(events_to_ndjson(&profile_mismatch)),
        base_graph(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ProtocolError::Invariant(message) if message.contains("delta profile") && message.contains("coverage site counts"))
    );
}

#[test]
fn capability_negotiation_preserves_legacy_full_snapshot_fallback() {
    let core = vec![
        "z-unknown-capability".to_owned(),
        WORKER_DELTA_CAPABILITY.to_owned(),
        "a-unknown-capability".to_owned(),
    ];
    let legacy_worker = Vec::new();
    assert_eq!(
        negotiate_worker_protocol(&core, &legacy_worker),
        WorkerProtocolMode::FullSnapshot
    );
    validate_ndjson(Cursor::new(include_str!(
        "fixtures/protocol-v1.golden.ndjson"
    )))
    .expect("legacy full snapshot fixture remains compatible");

    let delta_worker = vec![WORKER_DELTA_CAPABILITY.to_owned()];
    assert_eq!(
        negotiate_worker_protocol(&core, &delta_worker),
        WorkerProtocolMode::DeltaV1
    );

    let unknown_core = vec!["worker-delta-v2".to_owned()];
    assert_eq!(
        negotiate_worker_protocol(&unknown_core, &delta_worker),
        WorkerProtocolMode::FullSnapshot
    );
}

#[test]
fn golden_fixture_matches_the_canonical_builder_and_validates() {
    assert_eq!(DELTA_GOLDEN, delta_ndjson());
    validate_delta_ndjson(Cursor::new(DELTA_GOLDEN), base_graph())
        .expect("golden delta fixture must validate");
}

fn base_graph() -> DeltaBaseGraph {
    let source = node(SOURCE_ID, "src/index.ts");
    let target = node(OLD_TARGET_ID, "src/lib.ts");
    let evidence = source_evidence("./lib");
    let site = depgraph_protocol::DependencySite {
        id: OLD_SITE_ID.into(),
        source: SOURCE_ID.into(),
        kind: "import".into(),
        specifier: "./lib".into(),
        resolution_status: ResolutionStatus::Resolved,
        target_ids: vec![OLD_TARGET_ID.into()],
        profile_id: PROFILE_ID.into(),
        condition: Condition::All { conditions: vec![] },
        precision: Precision::Exact,
        reason: None,
        evidence: vec![evidence.clone()],
    };
    let edge = GraphEdge {
        id: OLD_EDGE_ID.into(),
        source: SOURCE_ID.into(),
        target: OLD_TARGET_ID.into(),
        kind: "imports".into(),
        site_id: Some(OLD_SITE_ID.into()),
        phase: Phase::Source,
        environment: Some("server".into()),
        profile_id: PROFILE_ID.into(),
        condition: Condition::All { conditions: vec![] },
        resolution_status: ResolutionStatus::Resolved,
        precision: Precision::Exact,
        generated: false,
        evidence: vec![evidence],
    };
    let aggregate = DeltaCoverage::Aggregate { value: coverage() };
    let profile = DeltaCoverage::Profile {
        profile_id: PROFILE_ID.into(),
        value: coverage(),
    };
    let file = DeltaCoverage::File {
        adapter: "web".into(),
        path: "src/index.ts".into(),
        value: DeltaFileCoverage {
            discovered_sites: 1,
            emitted_sites: 1,
            skipped_sites: 0,
            skipped: false,
            reason: None,
        },
    };
    let removed_file = DeltaCoverage::File {
        adapter: "web".into(),
        path: "src/lib.ts".into(),
        value: DeltaFileCoverage {
            discovered_sites: 0,
            emitted_sites: 0,
            skipped_sites: 0,
            skipped: false,
            reason: None,
        },
    };
    DeltaBaseGraph {
        snapshot_id: SNAPSHOT_ID.into(),
        graph_digest: BASE_DIGEST.into(),
        profiles: BTreeSet::from([PROFILE_ID.into()]),
        nodes: BTreeMap::from([(source.id.clone(), source), (target.id.clone(), target)]),
        sites: BTreeMap::from([(site.id.clone(), site)]),
        edges: BTreeMap::from([(edge.id.clone(), edge)]),
        evidence: BTreeMap::new(),
        coverage: BTreeMap::from([
            (aggregate.key(), aggregate),
            (profile.key(), profile),
            (file.key(), file),
            (removed_file.key(), removed_file),
        ]),
    }
}

fn delta_events() -> Vec<DeltaEvent> {
    let scope = DeltaScope {
        paths: vec![
            "src/index.ts".into(),
            "src/lib.ts".into(),
            "src/next.ts".into(),
        ],
        package_locators: vec!["npm:fixture@1.0.0".into()],
        profile_ids: vec![PROFILE_ID.into()],
        artifact_node_ids: vec![],
        adapters: vec!["web".into()],
    };
    let placeholder_delta_id =
        "delta:sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let evidence = source_evidence("./next");
    let site = depgraph_protocol::DependencySite {
        id: NEW_SITE_ID.into(),
        source: SOURCE_ID.into(),
        kind: "import".into(),
        specifier: "./next".into(),
        resolution_status: ResolutionStatus::Resolved,
        target_ids: vec![NEW_TARGET_ID.into()],
        profile_id: PROFILE_ID.into(),
        condition: Condition::All { conditions: vec![] },
        precision: Precision::Exact,
        reason: None,
        evidence: vec![],
    };
    let edge = GraphEdge {
        id: NEW_EDGE_ID.into(),
        source: SOURCE_ID.into(),
        target: NEW_TARGET_ID.into(),
        kind: "imports".into(),
        site_id: Some(NEW_SITE_ID.into()),
        phase: Phase::Source,
        environment: Some("server".into()),
        profile_id: PROFILE_ID.into(),
        condition: Condition::All { conditions: vec![] },
        resolution_status: ResolutionStatus::Resolved,
        precision: Precision::Exact,
        generated: false,
        evidence: vec![],
    };
    let mut events = vec![
        DeltaEvent::DeltaStarted(DeltaStarted {
            common: common(1),
            delta_contract_version: DELTA_CONTRACT_VERSION.into(),
            delta_id: placeholder_delta_id.into(),
            base_snapshot_id: SNAPSHOT_ID.into(),
            base_graph_digest: BASE_DIGEST.into(),
            scope: scope.clone(),
        }),
        DeltaEvent::EvidenceDelete(EvidenceDelete {
            common: common(2),
            evidence_key: DeltaEvidenceKey {
                owner_type: DeltaEvidenceOwner::Edge,
                owner_id: OLD_EDGE_ID.into(),
                ordinal: 0,
            },
        }),
        DeltaEvent::EvidenceDelete(EvidenceDelete {
            common: common(3),
            evidence_key: DeltaEvidenceKey {
                owner_type: DeltaEvidenceOwner::Site,
                owner_id: OLD_SITE_ID.into(),
                ordinal: 0,
            },
        }),
        DeltaEvent::EdgeDelete(EdgeDelete {
            common: common(4),
            edge_id: OLD_EDGE_ID.into(),
        }),
        DeltaEvent::SiteDelete(SiteDelete {
            common: common(5),
            site_id: OLD_SITE_ID.into(),
        }),
        DeltaEvent::NodeDelete(NodeDelete {
            common: common(6),
            node_id: OLD_TARGET_ID.into(),
        }),
        DeltaEvent::NodeUpsert(DeltaNodeUpsert {
            common: common(7),
            node: node(NEW_TARGET_ID, "src/next.ts"),
        }),
        DeltaEvent::SiteUpsert(SiteUpsert {
            common: common(8),
            site,
        }),
        DeltaEvent::EdgeUpsert(DeltaEdgeUpsert {
            common: common(9),
            edge,
        }),
        DeltaEvent::EvidenceUpsert(EvidenceUpsert {
            common: common(10),
            evidence: DeltaEvidenceRecord {
                key: DeltaEvidenceKey {
                    owner_type: DeltaEvidenceOwner::Edge,
                    owner_id: NEW_EDGE_ID.into(),
                    ordinal: 0,
                },
                evidence: evidence.clone(),
            },
        }),
        DeltaEvent::EvidenceUpsert(EvidenceUpsert {
            common: common(11),
            evidence: DeltaEvidenceRecord {
                key: DeltaEvidenceKey {
                    owner_type: DeltaEvidenceOwner::Site,
                    owner_id: NEW_SITE_ID.into(),
                    ordinal: 0,
                },
                evidence,
            },
        }),
        DeltaEvent::CoverageDelete(CoverageDelete {
            common: common(12),
            coverage_key: DeltaCoverageKey::File {
                adapter: "web".into(),
                path: "src/lib.ts".into(),
            },
        }),
        DeltaEvent::CoverageUpsert(CoverageUpsert {
            common: common(13),
            coverage: DeltaCoverage::Aggregate { value: coverage() },
        }),
        DeltaEvent::CoverageUpsert(CoverageUpsert {
            common: common(14),
            coverage: DeltaCoverage::File {
                adapter: "web".into(),
                path: "src/next.ts".into(),
                value: DeltaFileCoverage {
                    discovered_sites: 0,
                    emitted_sites: 0,
                    skipped_sites: 0,
                    skipped: false,
                    reason: None,
                },
            },
        }),
        DeltaEvent::DeltaCompleted(DeltaCompleted {
            common: common(15),
            delta_contract_version: DELTA_CONTRACT_VERSION.into(),
            delta_id: placeholder_delta_id.into(),
            mutation_count: 13,
            result_graph_digest: RESULT_DIGEST.into(),
        }),
    ];
    let last = events.len() - 1;
    let delta_id = build_delta_stable_id(SNAPSHOT_ID, BASE_DIGEST, &scope, &events[1..last])
        .expect("fixture delta ID");
    match &mut events[0] {
        DeltaEvent::DeltaStarted(event) => event.delta_id.clone_from(&delta_id),
        _ => unreachable!(),
    }
    match &mut events[last] {
        DeltaEvent::DeltaCompleted(event) => event.delta_id = delta_id,
        _ => unreachable!(),
    }
    events
}

fn reset_delta_id(events: &mut [DeltaEvent]) {
    let scope = match &events[0] {
        DeltaEvent::DeltaStarted(started) => started.scope.clone(),
        _ => panic!("expected delta start"),
    };
    let last = events.len() - 1;
    let delta_id =
        build_delta_stable_id(SNAPSHOT_ID, BASE_DIGEST, &scope, &events[1..last]).unwrap();
    match &mut events[0] {
        DeltaEvent::DeltaStarted(started) => started.delta_id.clone_from(&delta_id),
        _ => unreachable!(),
    }
    match &mut events[last] {
        DeltaEvent::DeltaCompleted(completed) => completed.delta_id = delta_id,
        _ => unreachable!(),
    }
}

fn renumber(events: &mut [DeltaEvent]) {
    for (index, event) in events.iter_mut().enumerate() {
        let seq = index as u64 + 1;
        match event {
            DeltaEvent::DeltaStarted(event) => event.common.seq = seq,
            DeltaEvent::EvidenceDelete(event) => event.common.seq = seq,
            DeltaEvent::EdgeDelete(event) => event.common.seq = seq,
            DeltaEvent::SiteDelete(event) => event.common.seq = seq,
            DeltaEvent::NodeDelete(event) => event.common.seq = seq,
            DeltaEvent::NodeUpsert(event) => event.common.seq = seq,
            DeltaEvent::SiteUpsert(event) => event.common.seq = seq,
            DeltaEvent::EdgeUpsert(event) => event.common.seq = seq,
            DeltaEvent::EvidenceUpsert(event) => event.common.seq = seq,
            DeltaEvent::CoverageDelete(event) => event.common.seq = seq,
            DeltaEvent::CoverageUpsert(event) => event.common.seq = seq,
            DeltaEvent::DeltaCompleted(event) => event.common.seq = seq,
        }
    }
}

fn node(id: &str, locator: &str) -> GraphNode {
    GraphNode {
        id: id.into(),
        kind: "file".into(),
        locator: locator.into(),
        display_name: Some(locator.into()),
        properties: BTreeMap::from([("language".into(), json!("typescript"))]),
    }
}

fn source_evidence(detail: &str) -> Evidence {
    Evidence {
        kind: EvidenceKind::Source,
        extractor: "typescript-static".into(),
        extractor_version: "0.4.0".into(),
        path: Some("src/index.ts".into()),
        start_line: Some(1),
        start_column: Some(1),
        end_line: Some(1),
        end_column: Some(24),
        detail: Some(detail.into()),
        properties: BTreeMap::new(),
    }
}

fn coverage() -> Coverage {
    Coverage {
        profiles: 1,
        files_discovered: 2,
        files_analyzed: 2,
        files_skipped: 0,
        dependency_sites: 1,
        resolved: 1,
        candidates: 0,
        external: 0,
        unresolved: 0,
        unsupported_syntax: 0,
        project_code_executed: false,
        completeness: vec![CompletenessLevel::SyntaxComplete],
        reasons: vec![],
    }
}

fn common(seq: u64) -> CommonFields {
    CommonFields {
        protocol_version: "1.0".into(),
        scan_id: "scan-delta-golden".into(),
        adapter: "web".into(),
        adapter_version: "0.4.0".into(),
        seq,
    }
}

fn common_json(mut value: Value, seq: u64) -> Value {
    let object = value.as_object_mut().unwrap();
    object.insert("protocol_version".into(), json!("1.0"));
    object.insert("scan_id".into(), json!("scan-delta-golden"));
    object.insert("adapter".into(), json!("web"));
    object.insert("adapter_version".into(), json!("0.4.0"));
    object.insert("seq".into(), json!(seq));
    value
}

fn delta_ndjson() -> String {
    events_to_ndjson(&delta_events())
}

fn events_to_ndjson(events: &[DeltaEvent]) -> String {
    let mut output = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}
