//! The opt-in `compact-evidence-v1` encoding (#578): a compact stream decodes
//! to the full protocol 1.0 stream it encodes, and the decoder rejects
//! streams it cannot decode exactly.

use depgraph_protocol::{
    COMPACT_EVIDENCE_ENCODING_V1, CompactEvidenceDecoder, EVIDENCE_ENCODING_PROPERTY,
    EVIDENCE_PROPERTY_DEFAULTS_PROPERTY, Evidence, EvidencePropertyDefaults, ProtocolError,
    ProtocolEvent, ProtocolValidator,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SOURCE_GOLDEN: &str = include_str!("fixtures/protocol-v1.golden.ndjson");
const SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.semantic.golden.ndjson");
const RUST_SEMANTIC_GOLDEN: &str = include_str!("fixtures/protocol-v1.rust-semantic.golden.ndjson");

/// The fixture's events, with every site-linked edge given its site's
/// evidence, as the Rust worker emits them.
fn events(fixture: &str) -> Vec<ProtocolEvent> {
    let mut events: Vec<ProtocolEvent> = fixture
        .lines()
        .map(|line| serde_json::from_str(line).expect("fixture line is a protocol event"))
        .collect();
    let mut site_evidence = BTreeMap::new();
    for event in &mut events {
        match event {
            ProtocolEvent::DependencySite(event) => {
                site_evidence.insert(event.site.id.clone(), event.site.evidence.clone());
            }
            ProtocolEvent::EdgeUpsert(event) => {
                if let Some(evidence) = event
                    .edge
                    .site_id
                    .as_ref()
                    .and_then(|site_id| site_evidence.get(site_id))
                {
                    event.edge.evidence.clone_from(evidence);
                }
            }
            _ => {}
        }
    }
    events
}

/// Validates a full stream and returns its canonical events.
fn validate_full(events: Vec<ProtocolEvent>) -> Vec<ProtocolEvent> {
    let mut validator = ProtocolValidator::for_safe_scan();
    for event in events {
        validator.push(event).expect("full stream is valid");
    }
    validator.finish().expect("full stream completes").events
}

/// Decodes and validates a compact stream.
fn decode(events: Vec<ProtocolEvent>) -> Result<Vec<ProtocolEvent>, String> {
    let mut validator = ProtocolValidator::for_safe_scan();
    let mut decoder = CompactEvidenceDecoder::new();
    for event in events {
        validator
            .push_compact(&mut decoder, event)
            .map_err(|error| error.to_string())?;
    }
    validator
        .finish()
        .map(|protocol| protocol.events)
        .map_err(|error| error.to_string())
}

/// Encodes a full stream: declares the encoding on every profile, moves the
/// properties every evidence item of one extractor shares to the profile, and
/// empties the evidence of every edge that equals its site's evidence.
fn encode(mut events: Vec<ProtocolEvent>) -> (Vec<ProtocolEvent>, usize, usize) {
    let mut groups = BTreeMap::<(String, String), Option<BTreeMap<String, Value>>>::new();
    for event in &events {
        let evidence = match event {
            ProtocolEvent::DependencySite(event) => &event.site.evidence,
            ProtocolEvent::EdgeUpsert(event) => &event.edge.evidence,
            ProtocolEvent::Diagnostic(event) => &event.diagnostic.evidence,
            _ => continue,
        };
        for item in evidence {
            let shared = groups
                .entry((item.extractor.clone(), item.extractor_version.clone()))
                .or_insert_with(|| Some(item.properties.clone()));
            if let Some(shared) = shared {
                shared.retain(|key, value| item.properties.get(key) == Some(value));
            }
        }
    }
    let defaults: Vec<_> = groups
        .into_iter()
        .filter_map(|((extractor, extractor_version), properties)| {
            let properties = properties?;
            (!properties.is_empty()).then_some(EvidencePropertyDefaults {
                extractor,
                extractor_version,
                properties,
            })
        })
        .collect();
    let mut site_evidence = BTreeMap::new();
    let mut omitted_edges = 0;
    let mut omitted_properties = 0;
    for event in &mut events {
        let evidence = match event {
            ProtocolEvent::ProfileDeclared(declared) => {
                let properties = &mut declared.profile.properties;
                properties.insert(
                    EVIDENCE_ENCODING_PROPERTY.into(),
                    COMPACT_EVIDENCE_ENCODING_V1.into(),
                );
                properties.insert(
                    EVIDENCE_PROPERTY_DEFAULTS_PROPERTY.into(),
                    serde_json::to_value(&defaults).unwrap(),
                );
                continue;
            }
            ProtocolEvent::DependencySite(event) => {
                site_evidence.insert(event.site.id.clone(), event.site.evidence.clone());
                &mut event.site.evidence
            }
            ProtocolEvent::EdgeUpsert(event) => {
                if event
                    .edge
                    .site_id
                    .as_ref()
                    .and_then(|site_id| site_evidence.get(site_id))
                    == Some(&event.edge.evidence)
                {
                    event.edge.evidence.clear();
                    omitted_edges += 1;
                }
                &mut event.edge.evidence
            }
            ProtocolEvent::Diagnostic(event) => &mut event.diagnostic.evidence,
            _ => continue,
        };
        for item in evidence {
            for entry in &defaults {
                if entry.extractor == item.extractor
                    && entry.extractor_version == item.extractor_version
                {
                    for key in entry.properties.keys() {
                        omitted_properties += usize::from(item.properties.remove(key).is_some());
                    }
                }
            }
        }
    }
    (events, omitted_edges, omitted_properties)
}

#[test]
fn compact_stream_decodes_to_the_full_stream() {
    for (name, fixture) in [
        ("source", SOURCE_GOLDEN),
        ("semantic", SEMANTIC_GOLDEN),
        ("rust-semantic", RUST_SEMANTIC_GOLDEN),
    ] {
        let expected = validate_full(events(fixture));
        let (compact, _, _) = encode(events(fixture));
        assert_eq!(decode(compact).unwrap(), expected, "{name}");
    }
    let (_, omitted_edges, omitted_properties) = encode(events(SEMANTIC_GOLDEN));
    assert!(omitted_edges > 0 && omitted_properties > 0);
}

#[test]
fn a_stream_without_the_encoding_passes_through_unchanged() {
    for fixture in [SOURCE_GOLDEN, SEMANTIC_GOLDEN, RUST_SEMANTIC_GOLDEN] {
        assert_eq!(
            decode(events(fixture)).unwrap(),
            validate_full(events(fixture))
        );
    }
}

#[test]
fn only_a_consumer_that_decodes_accepts_omitted_edge_evidence() {
    let (compact, _, _) = encode(events(SEMANTIC_GOLDEN));
    let mut validator = ProtocolValidator::for_safe_scan();
    let error = compact
        .into_iter()
        .find_map(|event| validator.push(event).err())
        .expect("the full-stream validator rejects the compact stream");
    assert!(
        error
            .to_string()
            .contains("must include at least one evidence item"),
        "{error}"
    );
}

#[test]
fn a_declared_default_never_replaces_a_property_the_item_carries() {
    let defaults = EvidencePropertyDefaults {
        extractor: "x".into(),
        extractor_version: "1".into(),
        properties: BTreeMap::from([
            ("backend".into(), json!("declared")),
            ("revision".into(), json!("declared")),
        ]),
    };
    let mut evidence: Evidence = serde_json::from_value(json!({
        "kind": "semantic", "extractor": "x", "extractor_version": "1",
        "properties": {"revision": "own"},
    }))
    .unwrap();
    let mut other_version = evidence.clone();
    other_version.extractor_version = "2".into();
    defaults.apply(&mut evidence);
    defaults.apply(&mut other_version);
    assert_eq!(evidence.properties["backend"], "declared");
    assert_eq!(evidence.properties["revision"], "own");
    // Defaults apply only to their extractor and version.
    assert!(!other_version.properties.contains_key("backend"));
}

#[test]
fn the_decoder_removes_the_encoding_from_the_profile() {
    let (compact, _, _) = encode(events(SEMANTIC_GOLDEN));
    for event in decode(compact).unwrap() {
        if let ProtocolEvent::ProfileDeclared(declared) = event {
            assert!(
                !declared
                    .profile
                    .properties
                    .contains_key(EVIDENCE_ENCODING_PROPERTY)
            );
            assert!(
                !declared
                    .profile
                    .properties
                    .contains_key(EVIDENCE_PROPERTY_DEFAULTS_PROPERTY)
            );
        }
    }
}

fn decode_error(mutate: impl FnOnce(&mut Vec<ProtocolEvent>)) -> String {
    let (mut compact, _, _) = encode(events(SEMANTIC_GOLDEN));
    mutate(&mut compact);
    decode(compact).expect_err("the decoder rejects the stream")
}

fn profile_properties(events: &mut [ProtocolEvent]) -> &mut BTreeMap<String, Value> {
    events
        .iter_mut()
        .find_map(|event| match event {
            ProtocolEvent::ProfileDeclared(declared) => Some(&mut declared.profile.properties),
            _ => None,
        })
        .unwrap()
}

#[test]
fn the_decoder_rejects_streams_it_cannot_decode_exactly() {
    // An edge that omits its evidence must follow its dependency site.
    let error = decode_error(|events| {
        let edge = events
            .iter()
            .position(|event| {
                matches!(event, ProtocolEvent::EdgeUpsert(upsert) if upsert.edge.evidence.is_empty())
            })
            .unwrap();
        let ProtocolEvent::EdgeUpsert(upsert) = &events[edge] else {
            unreachable!()
        };
        let site_id = upsert.edge.site_id.clone().unwrap();
        let site = events
            .iter()
            .position(|event| {
                matches!(event, ProtocolEvent::DependencySite(site) if site.site.id == site_id)
            })
            .unwrap();
        let moved = events.remove(edge);
        events.insert(site, moved);
    });
    assert!(error.contains("was not declared before it"), "{error}");

    // Without a site there is no evidence to copy.
    let error = decode_error(|events| {
        for event in events.iter_mut() {
            if let ProtocolEvent::EdgeUpsert(upsert) = event
                && upsert.edge.evidence.is_empty()
            {
                upsert.edge.site_id = None;
                break;
            }
        }
    });
    assert!(error.contains("has no dependency site"), "{error}");

    // Defaults need the encoding declaration.
    let error = decode_error(|events| {
        profile_properties(events).remove(EVIDENCE_ENCODING_PROPERTY);
    });
    assert!(error.contains("without evidence_encoding"), "{error}");

    // An unknown encoding fails closed.
    let error = decode_error(|events| {
        profile_properties(events).insert(
            EVIDENCE_ENCODING_PROPERTY.into(),
            json!("compact-evidence-v2"),
        );
    });
    assert!(error.contains("unsupported evidence_encoding"), "{error}");

    // One extractor and version has one set of defaults.
    let error = decode_error(|events| {
        let defaults = profile_properties(events)
            .get_mut(EVIDENCE_PROPERTY_DEFAULTS_PROPERTY)
            .unwrap()
            .as_array_mut()
            .unwrap();
        let first = defaults[0].clone();
        defaults.push(first);
    });
    assert!(error.contains("more than once"), "{error}");

    // Malformed and empty defaults.
    let error = decode_error(|events| {
        profile_properties(events).insert(
            EVIDENCE_PROPERTY_DEFAULTS_PROPERTY.into(),
            json!([{"extractor": "x", "extractor_version": "1", "properties": {}, "extra": 1}]),
        );
    });
    assert!(
        error.contains("malformed evidence_property_defaults"),
        "{error}"
    );
    let error = decode_error(|events| {
        profile_properties(events).insert(
            EVIDENCE_PROPERTY_DEFAULTS_PROPERTY.into(),
            json!([{"extractor": "x", "extractor_version": "1", "properties": {}}]),
        );
    });
    assert!(
        error.contains("empty evidence property defaults"),
        "{error}"
    );

    // A redeclared profile cannot switch encodings.
    let error = decode_error(|events| {
        let declared = events
            .iter()
            .position(|event| matches!(event, ProtocolEvent::ProfileDeclared(_)))
            .unwrap();
        let mut plain = events[declared].clone();
        let ProtocolEvent::ProfileDeclared(profile) = &mut plain else {
            unreachable!()
        };
        profile
            .profile
            .properties
            .remove(EVIDENCE_ENCODING_PROPERTY);
        profile
            .profile
            .properties
            .remove(EVIDENCE_PROPERTY_DEFAULTS_PROPERTY);
        events.insert(declared + 1, plain);
    });
    assert!(error.contains("changed its evidence encoding"), "{error}");
}

#[test]
fn a_bounded_decoder_stops_before_the_restored_evidence_outgrows_its_limit() {
    let decode_with_limit = |limit: usize| {
        let (compact, _, _) = encode(events(SEMANTIC_GOLDEN));
        let mut validator = ProtocolValidator::for_safe_scan();
        let mut decoder = CompactEvidenceDecoder::with_expansion_limit(limit);
        for event in compact {
            validator.push_compact(&mut decoder, event)?;
        }
        validator.finish().map(|protocol| protocol.events)
    };
    let error = decode_with_limit(1).unwrap_err();
    assert!(
        matches!(error, ProtocolError::ExpansionLimit { limit: 1 }),
        "{error}"
    );
    assert_eq!(
        decode_with_limit(SEMANTIC_GOLDEN.len()).unwrap(),
        validate_full(events(SEMANTIC_GOLDEN))
    );
}
