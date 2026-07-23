use std::{collections::BTreeMap, io::Write};

use anyhow::{Context, Result, bail};
use depgraph_store::{EvidenceRecord, GraphSnapshot, ProfileRecord, SiteRecord};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::query::render_condition;

pub const GRAPHML_SCHEMA_VERSION: &str = "1.0";
const XML_TEXT_BUFFER_BYTES: usize = 8 * 1024;

struct Key {
    id: &'static str,
    target: &'static str,
    name: &'static str,
    value_type: &'static str,
    description: Option<&'static str>,
}

const KEYS: &[Key] = &[
    Key {
        id: "g_schema_version",
        target: "graph",
        name: "depgraph.schema_version",
        value_type: "string",
        description: None,
    },
    Key {
        id: "g_profiles_json",
        target: "graph",
        name: "depgraph.profiles",
        value_type: "string",
        description: Some("Canonical JSON array of complete profile records."),
    },
    Key {
        id: "g_sites_json",
        target: "graph",
        name: "depgraph.sites",
        value_type: "string",
        description: Some(
            "Canonical JSON array of dependency site records and their evidence references.",
        ),
    },
    Key {
        id: "g_evidence_json",
        target: "graph",
        name: "depgraph.evidence",
        value_type: "string",
        description: Some(
            "Canonical JSON array of evidence records keyed by owner type, owner stable ID, and ordinal.",
        ),
    },
    Key {
        id: "n_stable_id",
        target: "node",
        name: "depgraph.node.id",
        value_type: "string",
        description: None,
    },
    Key {
        id: "n_kind",
        target: "node",
        name: "depgraph.node.kind",
        value_type: "string",
        description: None,
    },
    Key {
        id: "n_locator",
        target: "node",
        name: "depgraph.node.locator",
        value_type: "string",
        description: None,
    },
    Key {
        id: "n_display_name",
        target: "node",
        name: "depgraph.node.display_name",
        value_type: "string",
        description: None,
    },
    Key {
        id: "n_properties_json",
        target: "node",
        name: "depgraph.node.properties",
        value_type: "string",
        description: Some("Canonical JSON object containing all additional node properties."),
    },
    Key {
        id: "n_evidence_refs_json",
        target: "node",
        name: "depgraph.node.evidence_refs",
        value_type: "string",
        description: Some("Canonical JSON array of evidence references owned by this node."),
    },
    Key {
        id: "e_stable_id",
        target: "edge",
        name: "depgraph.edge.id",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_site_id",
        target: "edge",
        name: "depgraph.edge.site_id",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_kind",
        target: "edge",
        name: "depgraph.edge.kind",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_phase",
        target: "edge",
        name: "depgraph.edge.phase",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_environment",
        target: "edge",
        name: "depgraph.edge.environment",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_profile_id",
        target: "edge",
        name: "depgraph.edge.profile_id",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_resolution_status",
        target: "edge",
        name: "depgraph.edge.resolution_status",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_precision",
        target: "edge",
        name: "depgraph.edge.precision",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_condition_json",
        target: "edge",
        name: "depgraph.edge.condition",
        value_type: "string",
        description: Some("Canonical JSON representation of the complete edge condition."),
    },
    Key {
        id: "e_condition_text",
        target: "edge",
        name: "depgraph.edge.condition_text",
        value_type: "string",
        description: None,
    },
    Key {
        id: "e_generated",
        target: "edge",
        name: "depgraph.edge.generated",
        value_type: "boolean",
        description: None,
    },
    Key {
        id: "e_evidence_refs_json",
        target: "edge",
        name: "depgraph.edge.evidence_refs",
        value_type: "string",
        description: Some("Canonical JSON array of evidence references owned by this edge."),
    },
];

#[derive(Serialize)]
struct EvidenceReference<'a> {
    owner_type: &'a str,
    owner_id: &'a str,
    ordinal: i64,
}

#[derive(Serialize)]
struct SiteEnvelope<'a> {
    record: &'a SiteRecord,
    evidence_refs: Vec<EvidenceReference<'a>>,
}

#[derive(Serialize)]
struct EvidenceEnvelope<'a> {
    reference: EvidenceReference<'a>,
    record: &'a EvidenceRecord,
}

pub(crate) fn write_graphml<W: Write>(snapshot: &GraphSnapshot, writer: &mut W) -> Result<()> {
    let mut profiles = snapshot.profiles.iter().collect::<Vec<_>>();
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    ensure_unique_ids(
        "profile",
        profiles.iter().map(|profile| profile.id.as_str()),
    )?;

    let mut sites = snapshot.sites.iter().collect::<Vec<_>>();
    sites.sort_by(|left, right| left.id.cmp(&right.id));
    ensure_unique_ids("site", sites.iter().map(|site| site.id.as_str()))?;

    let mut evidence = snapshot.evidence.iter().collect::<Vec<_>>();
    evidence.sort_by(|left, right| {
        (
            left.owner_type.as_str(),
            left.owner_id.as_str(),
            left.ordinal,
            left.kind.as_str(),
            left.extractor.as_str(),
            left.path.as_str(),
        )
            .cmp(&(
                right.owner_type.as_str(),
                right.owner_id.as_str(),
                right.ordinal,
                right.kind.as_str(),
                right.extractor.as_str(),
                right.path.as_str(),
            ))
    });
    ensure_unique_evidence_references(&evidence)?;
    let evidence_ordinals = evidence_reference_ordinals(&evidence);

    let mut nodes = snapshot.nodes.iter().collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    ensure_unique_ids("node", nodes.iter().map(|node| node.id.as_str()))?;
    let node_indexes = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();

    let mut edges = snapshot.edges.iter().collect::<Vec<_>>();
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    ensure_unique_ids("edge", edges.iter().map(|edge| edge.id.as_str()))?;

    writeln!(writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(
        writer,
        "<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\""
    )?;
    writeln!(
        writer,
        "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
    )?;
    writeln!(
        writer,
        "         xsi:schemaLocation=\"http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd\">"
    )?;
    write_keys(writer)?;
    writeln!(writer, "  <graph id=\"depgraph\" edgedefault=\"directed\">")?;
    write_data(writer, "g_schema_version", GRAPHML_SCHEMA_VERSION, 4)?;
    write_profiles(writer, &profiles)?;
    write_sites(writer, &sites, &evidence_ordinals)?;
    write_evidence(writer, &evidence)?;

    for (index, node) in nodes.iter().enumerate() {
        writeln!(writer, "    <node id=\"n{index}\">")?;
        write_data(writer, "n_stable_id", &node.id, 6)?;
        write_data(writer, "n_kind", &node.kind, 6)?;
        write_data(writer, "n_locator", &node.locator, 6)?;
        write_data(writer, "n_display_name", &node.display_name, 6)?;
        write_data(
            writer,
            "n_properties_json",
            &canonical_json(&node.properties)?,
            6,
        )?;
        write_data(
            writer,
            "n_evidence_refs_json",
            &evidence_references_json(&evidence_ordinals, "node", &node.id)?,
            6,
        )?;
        writeln!(writer, "    </node>")?;
    }

    for (index, edge) in edges.iter().enumerate() {
        let source = node_indexes.get(edge.source.as_str()).with_context(|| {
            format!(
                "GraphML edge {} references missing source node {}",
                edge.id, edge.source
            )
        })?;
        let target = node_indexes.get(edge.target.as_str()).with_context(|| {
            format!(
                "GraphML edge {} references missing target node {}",
                edge.id, edge.target
            )
        })?;
        writeln!(
            writer,
            "    <edge id=\"e{index}\" source=\"n{source}\" target=\"n{target}\">"
        )?;
        write_data(writer, "e_stable_id", &edge.id, 6)?;
        if let Some(site_id) = &edge.site_id {
            write_data(writer, "e_site_id", site_id, 6)?;
        }
        write_data(writer, "e_kind", &edge.kind, 6)?;
        write_data(writer, "e_phase", &edge.phase, 6)?;
        write_data(writer, "e_environment", &edge.environment, 6)?;
        write_data(writer, "e_profile_id", &edge.profile_id, 6)?;
        write_data(writer, "e_resolution_status", &edge.resolution_status, 6)?;
        write_data(writer, "e_precision", &edge.precision, 6)?;
        let canonical_condition = canonicalize_json(edge.condition.clone());
        write_data(
            writer,
            "e_condition_json",
            &canonical_json(&canonical_condition)?,
            6,
        )?;
        write_data(
            writer,
            "e_condition_text",
            &render_condition(&canonical_condition),
            6,
        )?;
        write_data(
            writer,
            "e_generated",
            if edge.generated { "true" } else { "false" },
            6,
        )?;
        write_data(
            writer,
            "e_evidence_refs_json",
            &evidence_references_json(&evidence_ordinals, "edge", &edge.id)?,
            6,
        )?;
        writeln!(writer, "    </edge>")?;
    }

    writeln!(writer, "  </graph>")?;
    writeln!(writer, "</graphml>")?;
    Ok(())
}

fn write_keys<W: Write>(writer: &mut W) -> Result<()> {
    for key in KEYS {
        if let Some(description) = key.description {
            writeln!(
                writer,
                "  <key id=\"{}\" for=\"{}\" attr.name=\"{}\" attr.type=\"{}\">",
                key.id, key.target, key.name, key.value_type
            )?;
            write!(writer, "    <desc>")?;
            write_xml_text(writer, description)?;
            writeln!(writer, "</desc>")?;
            writeln!(writer, "  </key>")?;
        } else {
            writeln!(
                writer,
                "  <key id=\"{}\" for=\"{}\" attr.name=\"{}\" attr.type=\"{}\"/>",
                key.id, key.target, key.name, key.value_type
            )?;
        }
    }
    Ok(())
}

fn write_profiles<W: Write>(writer: &mut W, profiles: &[&ProfileRecord]) -> Result<()> {
    write!(writer, "    <data key=\"g_profiles_json\">")?;
    write_json_array_start(writer)?;
    for (index, profile) in profiles.iter().enumerate() {
        write_json_array_record(writer, index, *profile)?;
    }
    write_json_array_end(writer)?;
    writeln!(writer, "</data>")?;
    Ok(())
}

fn write_sites<W: Write>(
    writer: &mut W,
    sites: &[&SiteRecord],
    evidence_ordinals: &BTreeMap<(&str, &str), Vec<i64>>,
) -> Result<()> {
    write!(writer, "    <data key=\"g_sites_json\">")?;
    write_json_array_start(writer)?;
    for (index, site) in sites.iter().enumerate() {
        let envelope = SiteEnvelope {
            record: site,
            evidence_refs: evidence_references(evidence_ordinals, "site", &site.id),
        };
        write_json_array_record(writer, index, &envelope)?;
    }
    write_json_array_end(writer)?;
    writeln!(writer, "</data>")?;
    Ok(())
}

fn write_evidence<W: Write>(writer: &mut W, evidence: &[&EvidenceRecord]) -> Result<()> {
    write!(writer, "    <data key=\"g_evidence_json\">")?;
    write_json_array_start(writer)?;
    for (index, record) in evidence.iter().enumerate() {
        let envelope = EvidenceEnvelope {
            reference: EvidenceReference {
                owner_type: &record.owner_type,
                owner_id: &record.owner_id,
                ordinal: record.ordinal,
            },
            record,
        };
        write_json_array_record(writer, index, &envelope)?;
    }
    write_json_array_end(writer)?;
    writeln!(writer, "</data>")?;
    Ok(())
}

fn write_json_array_start<W: Write>(writer: &mut W) -> Result<()> {
    write_xml_text(writer, "[")
}

fn write_json_array_record<W: Write, T: Serialize>(
    writer: &mut W,
    index: usize,
    record: &T,
) -> Result<()> {
    if index != 0 {
        write_xml_text(writer, ",")?;
    }
    write_xml_text(writer, &canonical_json(record)?)
}

fn write_json_array_end<W: Write>(writer: &mut W) -> Result<()> {
    write_xml_text(writer, "]")
}

fn write_data<W: Write>(writer: &mut W, key: &str, value: &str, indentation: usize) -> Result<()> {
    write!(writer, "{:indentation$}<data key=\"{key}\">", "")?;
    write_xml_text(writer, value)?;
    writeln!(writer, "</data>")?;
    Ok(())
}

fn evidence_reference_ordinals<'a>(
    evidence: &[&'a EvidenceRecord],
) -> BTreeMap<(&'a str, &'a str), Vec<i64>> {
    let mut ordinals = BTreeMap::<_, Vec<_>>::new();
    for record in evidence {
        ordinals
            .entry((record.owner_type.as_str(), record.owner_id.as_str()))
            .or_default()
            .push(record.ordinal);
    }
    for owner_ordinals in ordinals.values_mut() {
        owner_ordinals.sort_unstable();
        owner_ordinals.dedup();
    }
    ordinals
}

fn evidence_references<'a>(
    evidence_ordinals: &BTreeMap<(&str, &str), Vec<i64>>,
    owner_type: &'a str,
    owner_id: &'a str,
) -> Vec<EvidenceReference<'a>> {
    evidence_ordinals
        .get(&(owner_type, owner_id))
        .into_iter()
        .flatten()
        .map(|ordinal| EvidenceReference {
            owner_type,
            owner_id,
            ordinal: *ordinal,
        })
        .collect()
}

fn evidence_references_json(
    evidence_ordinals: &BTreeMap<(&str, &str), Vec<i64>>,
    owner_type: &str,
    owner_id: &str,
) -> Result<String> {
    canonical_json(&evidence_references(
        evidence_ordinals,
        owner_type,
        owner_id,
    ))
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value).context("failed to encode GraphML JSON property")?;
    serde_json::to_string(&canonicalize_json(value))
        .context("failed to render canonical GraphML JSON property")
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        Value::Object(values) => {
            let mut keys = values.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                if let Some(value) = values.get(&key) {
                    canonical.insert(key, canonicalize_json(value.clone()));
                }
            }
            Value::Object(canonical)
        }
        scalar => scalar,
    }
}

fn ensure_unique_ids<'a>(kind: &str, ids: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut previous = None;
    for id in ids {
        if previous == Some(id) {
            bail!("GraphML export found duplicate {kind} stable ID {id}");
        }
        previous = Some(id);
    }
    Ok(())
}

fn ensure_unique_evidence_references(evidence: &[&EvidenceRecord]) -> Result<()> {
    let mut previous = None;
    for record in evidence {
        let reference = (
            record.owner_type.as_str(),
            record.owner_id.as_str(),
            record.ordinal,
        );
        if previous == Some(reference) {
            bail!(
                "GraphML export found duplicate evidence reference {}:{}#{}",
                record.owner_type,
                record.owner_id,
                record.ordinal
            );
        }
        previous = Some(reference);
    }
    Ok(())
}

fn write_xml_text<W: Write>(writer: &mut W, value: &str) -> Result<()> {
    let mut buffer = String::with_capacity(XML_TEXT_BUFFER_BYTES);
    for character in value.chars() {
        if !is_valid_xml_character(character) {
            bail!(
                "GraphML export cannot encode XML 1.0 control character U+{:04X}",
                character as u32
            );
        }
        let escaped = match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&apos;",
            '\r' => "&#13;",
            _ => {
                if buffer.len() + character.len_utf8() > XML_TEXT_BUFFER_BYTES {
                    writer.write_all(buffer.as_bytes())?;
                    buffer.clear();
                }
                buffer.push(character);
                if buffer.len() == XML_TEXT_BUFFER_BYTES {
                    writer.write_all(buffer.as_bytes())?;
                    buffer.clear();
                }
                continue;
            }
        };
        if buffer.len() + escaped.len() > XML_TEXT_BUFFER_BYTES {
            writer.write_all(buffer.as_bytes())?;
            buffer.clear();
        }
        buffer.push_str(escaped);
    }
    if !buffer.is_empty() {
        writer.write_all(buffer.as_bytes())?;
    }
    Ok(())
}

fn is_valid_xml_character(character: char) -> bool {
    matches!(
        character,
        '\u{9}'
            | '\u{A}'
            | '\u{D}'
            | '\u{20}'..='\u{D7FF}'
            | '\u{E000}'..='\u{FFFD}'
            | '\u{10000}'..='\u{10FFFF}'
    )
}

#[cfg(test)]
mod tests {
    use std::io;

    use depgraph_store::{
        CoverageRecord, EdgeRecord, GraphSnapshot, NodeRecord, ProfileRecord, ScanRecord,
        SiteRecord,
    };
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct DecodedEvidenceReference {
        owner_type: String,
        owner_id: String,
        ordinal: i64,
    }

    #[derive(Debug, Deserialize)]
    struct DecodedSiteEnvelope {
        record: SiteRecord,
        evidence_refs: Vec<DecodedEvidenceReference>,
    }

    #[derive(Debug, Deserialize)]
    struct DecodedEvidenceEnvelope {
        reference: DecodedEvidenceReference,
        record: EvidenceRecord,
    }

    #[test]
    fn graphml_matches_golden_and_is_independent_of_record_order() -> Result<()> {
        let snapshot = fixture_snapshot();
        let rendered = render(&snapshot)?;
        assert_eq!(
            rendered,
            crate::export::export(&snapshot, crate::export::ExportFormat::Graphml)?
        );
        assert_eq!(
            rendered,
            include_str!("../tests/fixtures/graphml-export.golden.xml")
        );

        let mut reordered = snapshot;
        reordered.profiles.reverse();
        reordered.nodes.reverse();
        reordered.sites.reverse();
        reordered.edges.reverse();
        reordered.evidence.reverse();
        reordered.profiles[0].properties = json!({"a": "雪<&\"", "z": 1});
        reordered
            .nodes
            .iter_mut()
            .find(|node| node.id.starts_with("node:a"))
            .expect("source fixture node")
            .properties = json!({"a": "<&\"", "z": "雪"});
        reordered.sites[0].condition =
            json!({"name": "feature", "op": "profile", "value": "雪<&\""});
        reordered.edges[0].condition =
            json!({"name": "feature", "op": "profile", "value": "雪<&\""});
        for evidence in &mut reordered.evidence {
            evidence.properties = json!({"a": "雪<&\"", "z": true});
        }
        assert_eq!(rendered, render(&reordered)?);
        Ok(())
    }

    #[test]
    fn graphml_records_round_trip_without_losing_references() -> Result<()> {
        let snapshot = fixture_snapshot();
        let rendered = render(&snapshot)?;

        let profiles: Vec<ProfileRecord> =
            serde_json::from_str(&data_value(&rendered, "g_profiles_json")?)?;
        assert_eq!(profiles, snapshot.profiles);

        let sites: Vec<DecodedSiteEnvelope> =
            serde_json::from_str(&data_value(&rendered, "g_sites_json")?)?;
        assert_eq!(
            sites
                .iter()
                .map(|envelope| envelope.record.clone())
                .collect::<Vec<_>>(),
            snapshot.sites
        );
        assert_eq!(
            sites[0].evidence_refs,
            vec![DecodedEvidenceReference {
                owner_type: "site".to_owned(),
                owner_id: snapshot.sites[0].id.clone(),
                ordinal: 0,
            }]
        );

        let evidence: Vec<DecodedEvidenceEnvelope> =
            serde_json::from_str(&data_value(&rendered, "g_evidence_json")?)?;
        assert_eq!(
            evidence
                .iter()
                .map(|envelope| envelope.record.clone())
                .collect::<Vec<_>>(),
            snapshot.evidence
        );
        for envelope in &evidence {
            assert_eq!(envelope.reference.owner_type, envelope.record.owner_type);
            assert_eq!(envelope.reference.owner_id, envelope.record.owner_id);
            assert_eq!(envelope.reference.ordinal, envelope.record.ordinal);
        }

        let node_blocks = element_blocks(&rendered, "node");
        let mut node_ids = BTreeMap::new();
        let mut decoded_nodes = Vec::new();
        for block in node_blocks {
            let element_id = attribute(block, "id")?;
            let data = block_data(block)?;
            let stable_id = required_data(&data, "n_stable_id")?.to_owned();
            node_ids.insert(element_id.to_owned(), stable_id.clone());
            let evidence_refs: Vec<DecodedEvidenceReference> =
                serde_json::from_str(required_data(&data, "n_evidence_refs_json")?)?;
            assert!(evidence_refs.is_empty());
            decoded_nodes.push(NodeRecord {
                id: stable_id,
                kind: required_data(&data, "n_kind")?.to_owned(),
                locator: required_data(&data, "n_locator")?.to_owned(),
                display_name: required_data(&data, "n_display_name")?.to_owned(),
                properties: serde_json::from_str(required_data(&data, "n_properties_json")?)?,
            });
        }
        assert_eq!(decoded_nodes, snapshot.nodes);

        let mut decoded_edges = Vec::new();
        for block in element_blocks(&rendered, "edge") {
            let data = block_data(block)?;
            let evidence_refs: Vec<DecodedEvidenceReference> =
                serde_json::from_str(required_data(&data, "e_evidence_refs_json")?)?;
            assert_eq!(
                evidence_refs,
                vec![DecodedEvidenceReference {
                    owner_type: "edge".to_owned(),
                    owner_id: required_data(&data, "e_stable_id")?.to_owned(),
                    ordinal: 0,
                }]
            );
            decoded_edges.push(EdgeRecord {
                id: required_data(&data, "e_stable_id")?.to_owned(),
                site_id: data.get("e_site_id").cloned(),
                source: node_ids
                    .get(attribute(block, "source")?)
                    .context("GraphML round-trip source reference was not reconstructable")?
                    .clone(),
                target: node_ids
                    .get(attribute(block, "target")?)
                    .context("GraphML round-trip target reference was not reconstructable")?
                    .clone(),
                kind: required_data(&data, "e_kind")?.to_owned(),
                phase: required_data(&data, "e_phase")?.to_owned(),
                environment: required_data(&data, "e_environment")?.to_owned(),
                profile_id: required_data(&data, "e_profile_id")?.to_owned(),
                resolution_status: required_data(&data, "e_resolution_status")?.to_owned(),
                precision: required_data(&data, "e_precision")?.to_owned(),
                condition: serde_json::from_str(required_data(&data, "e_condition_json")?)?,
                generated: required_data(&data, "e_generated")?.parse()?,
            });
        }
        assert_eq!(decoded_edges, snapshot.edges);
        Ok(())
    }

    #[test]
    fn graphml_streams_large_values_in_bounded_chunks() -> Result<()> {
        let mut snapshot = fixture_snapshot();
        snapshot.nodes[0].display_name = "雪<&\"".repeat(32 * 1024);
        let mut writer = ChunkWriter::default();
        write_graphml(&snapshot, &mut writer)?;
        assert!(writer.total_bytes > 256 * 1024);
        assert!(
            writer.largest_chunk <= XML_TEXT_BUFFER_BYTES,
            "largest GraphML write was {} bytes",
            writer.largest_chunk
        );
        Ok(())
    }

    #[test]
    fn graphml_rejects_xml_1_0_control_characters() {
        let mut snapshot = fixture_snapshot();
        snapshot.nodes[0].display_name.push('\u{1}');
        let error = render(&snapshot).unwrap_err();
        assert!(error.to_string().contains("U+0001"));
    }

    fn fixture_snapshot() -> GraphSnapshot {
        let profile_id = "profile:<&\"東京".to_owned();
        let source_id = "node:a<&\"雪".to_owned();
        let target_id = "node:b".to_owned();
        let site_id = "site:雪<&\"".to_owned();
        let edge_id = "edge:雪<&\"".to_owned();
        let condition = json!({
            "value": "雪<&\"",
            "name": "feature",
            "op": "profile"
        });
        GraphSnapshot {
            scan: ScanRecord {
                id: "scan-not-exported".to_owned(),
                root: "/checkout/not-exported".to_owned(),
                status: "completed".to_owned(),
                strict: false,
                started_at: "not-exported".to_owned(),
                completed_at: Some("not-exported".to_owned()),
                project_code_executed: false,
                error: None,
                parent_snapshot_id: None,
                source_revision: None,
            },
            profiles: vec![ProfileRecord {
                id: profile_id.clone(),
                language: "rust".to_owned(),
                toolchain: Some(json!({"version": "1.93<&\"", "channel": "stable"})),
                command: None,
                target: Some("aarch64-apple-darwin".to_owned()),
                features: vec!["雪<&\"".to_owned()],
                environment: json!({"runtime": "server<&\""}),
                source_revision: None,
                properties: json!({"z": 1, "a": "雪<&\""}),
                coverage: None,
            }],
            nodes: vec![
                NodeRecord {
                    id: source_id.clone(),
                    kind: "file".to_owned(),
                    locator: "src/a<&\"雪.rs".to_owned(),
                    display_name: "A <& \"雪\" '雪'\rline".to_owned(),
                    properties: json!({"z": "雪", "a": "<&\""}),
                },
                NodeRecord {
                    id: target_id.clone(),
                    kind: "module".to_owned(),
                    locator: "crate::雪".to_owned(),
                    display_name: "雪".to_owned(),
                    properties: json!({}),
                },
            ],
            sites: vec![SiteRecord {
                id: site_id.clone(),
                source: source_id.clone(),
                kind: "rust_use".to_owned(),
                specifier: Some("crate::<雪>&\"".to_owned()),
                profile_id: profile_id.clone(),
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition: condition.clone(),
                target_ids: vec![target_id.clone()],
                reason: None,
            }],
            edges: vec![EdgeRecord {
                id: edge_id.clone(),
                site_id: Some(site_id.clone()),
                source: source_id,
                target: target_id,
                kind: "imports".to_owned(),
                phase: "semantic".to_owned(),
                environment: "server<&\"".to_owned(),
                profile_id,
                resolution_status: "resolved".to_owned(),
                precision: "exact".to_owned(),
                condition,
                generated: false,
            }],
            evidence: vec![
                EvidenceRecord {
                    owner_type: "edge".to_owned(),
                    owner_id: edge_id,
                    ordinal: 0,
                    kind: "semantic".to_owned(),
                    extractor: "rust<&\"".to_owned(),
                    extractor_version: "1.0".to_owned(),
                    path: "src/a<&\"雪.rs".to_owned(),
                    start_line: 1,
                    start_column: 2,
                    end_line: 1,
                    end_column: 9,
                    detail: Some("edge <& \"雪\"".to_owned()),
                    properties: json!({"z": true, "a": "雪<&\""}),
                },
                EvidenceRecord {
                    owner_type: "site".to_owned(),
                    owner_id: site_id,
                    ordinal: 0,
                    kind: "semantic".to_owned(),
                    extractor: "rust<&\"".to_owned(),
                    extractor_version: "1.0".to_owned(),
                    path: "src/a<&\"雪.rs".to_owned(),
                    start_line: 1,
                    start_column: 2,
                    end_line: 1,
                    end_column: 9,
                    detail: Some("site <& \"雪\"".to_owned()),
                    properties: json!({"z": true, "a": "雪<&\""}),
                },
            ],
            diagnostics: Vec::new(),
            file_coverage: Vec::new(),
            adapter_logs: Vec::new(),
            coverage: CoverageRecord::default(),
            profile_matrix: depgraph_store::ProfileMatrixRecord::default(),
        }
    }

    fn render(snapshot: &GraphSnapshot) -> Result<String> {
        let mut output = Vec::new();
        write_graphml(snapshot, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    fn data_value(document: &str, key: &str) -> Result<String> {
        let opening = format!("<data key=\"{key}\">");
        let start = document
            .find(&opening)
            .with_context(|| format!("missing GraphML data key {key}"))?
            + opening.len();
        let end = document[start..]
            .find("</data>")
            .with_context(|| format!("unterminated GraphML data key {key}"))?
            + start;
        Ok(decode_xml_text(&document[start..end]))
    }

    fn element_blocks<'a>(document: &'a str, element: &str) -> Vec<&'a str> {
        let opening = format!("<{element} ");
        let closing = format!("</{element}>");
        let mut blocks = Vec::new();
        let mut remainder = document;
        while let Some(start) = remainder.find(&opening) {
            let block = &remainder[start..];
            let Some(end) = block.find(&closing) else {
                break;
            };
            blocks.push(&block[..end + closing.len()]);
            remainder = &block[end + closing.len()..];
        }
        blocks
    }

    fn attribute<'a>(block: &'a str, name: &str) -> Result<&'a str> {
        let marker = format!("{name}=\"");
        let start = block
            .find(&marker)
            .with_context(|| format!("missing GraphML attribute {name}"))?
            + marker.len();
        let end = block[start..]
            .find('"')
            .with_context(|| format!("unterminated GraphML attribute {name}"))?
            + start;
        Ok(&block[start..end])
    }

    fn block_data(block: &str) -> Result<BTreeMap<String, String>> {
        let mut data = BTreeMap::new();
        for line in block.lines() {
            let line = line.trim();
            let Some(key_start) = line.strip_prefix("<data key=\"") else {
                continue;
            };
            let (key, value) = key_start
                .split_once("\">")
                .context("malformed GraphML data element")?;
            let value = value
                .strip_suffix("</data>")
                .context("unterminated GraphML data element")?;
            data.insert(key.to_owned(), decode_xml_text(value));
        }
        Ok(data)
    }

    fn required_data<'a>(data: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
        data.get(key)
            .map(String::as_str)
            .with_context(|| format!("missing GraphML data key {key}"))
    }

    fn decode_xml_text(value: &str) -> String {
        value
            .replace("&#13;", "\r")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&gt;", ">")
            .replace("&lt;", "<")
            .replace("&amp;", "&")
    }

    #[derive(Default)]
    struct ChunkWriter {
        total_bytes: usize,
        largest_chunk: usize,
    }

    impl io::Write for ChunkWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.total_bytes += buffer.len();
            self.largest_chunk = self.largest_chunk.max(buffer.len());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
