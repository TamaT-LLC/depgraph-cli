//! Compact retention of one worker's validated event stream (#598).

use std::io::{BufRead, Write};

use anyhow::{Context, Result, bail};
use depgraph_protocol::ProtocolEvent;
use serde_json::Value;

/// Every protocol 1.0 event name, so an encoded event can carry its name
/// without owning a copy of it.
const EVENT_NAMES: [&str; 9] = [
    "scan_started",
    "profile_declared",
    "node_upsert",
    "dependency_site",
    "edge_upsert",
    "diagnostic",
    "file_completed",
    "profile_completed",
    "scan_completed",
];

/// The validated events of one worker stream, each kept as its compact JSON
/// text in stream order.
///
/// A `serde_json::Value` tree costs several times the bytes of its JSON, so a
/// large HIR stream held as values dominated the core's memory (#598).
/// Readers parse one event at a time. The event name is kept beside the text,
/// so selecting events by name parses only the selected events.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorkerEvents {
    events: Vec<EncodedEvent>,
}

/// One event of a [`WorkerEvents`] stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedEvent {
    name: Option<&'static str>,
    json: Box<str>,
}

impl EncodedEvent {
    pub(crate) fn from_value(event: &Value) -> Self {
        Self {
            name: event_name(event),
            json: serde_json::to_string(event)
                .expect("JSON values always serialize")
                .into_boxed_str(),
        }
    }

    fn from_protocol(event: &ProtocolEvent) -> Self {
        Self {
            name: Some(event.event_name()),
            json: serde_json::to_string(event)
                .expect("typed protocol events always serialize")
                .into_boxed_str(),
        }
    }

    /// The protocol event name, or `None` when the event has no known name.
    pub(crate) fn name(&self) -> Option<&'static str> {
        self.name
    }

    /// Parses the event into a JSON value.
    pub(crate) fn value(&self) -> Result<Value> {
        serde_json::from_str(&self.json).context("retained worker event is not valid JSON")
    }
}

fn event_name(event: &Value) -> Option<&'static str> {
    let name = event.get("event")?.as_str()?;
    EVENT_NAMES.into_iter().find(|known| *known == name)
}

impl WorkerEvents {
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn clear(&mut self) {
        self.events = Vec::new();
    }

    /// Parses every event in stream order.
    pub fn iter(&self) -> impl Iterator<Item = Value> + '_ {
        self.events.iter().map(|event| {
            event
                .value()
                .expect("worker events retain the JSON they serialized")
        })
    }

    /// Parses, in stream order, only the events whose name `keep` selects.
    pub fn select<'a>(
        &'a self,
        keep: impl Fn(&str) -> bool + 'a,
    ) -> impl Iterator<Item = Value> + 'a {
        self.events
            .iter()
            .filter(move |event| event.name.is_some_and(&keep))
            .map(|event| {
                event
                    .value()
                    .expect("worker events retain the JSON they serialized")
            })
    }

    /// Parses, in stream order, only the events named `name`.
    pub fn named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = Value> + 'a {
        self.select(move |event| event == name)
    }

    /// Materializes every event. Use this only for streams known to be small.
    #[must_use]
    pub fn to_values(&self) -> Vec<Value> {
        self.iter().collect()
    }

    /// Rewrites each event named `name` in place with `update`.
    pub fn update_named(
        &mut self,
        name: &str,
        mut update: impl FnMut(&mut Value) -> Result<()>,
    ) -> Result<()> {
        for event in &mut self.events {
            if event.name != Some(name) {
                continue;
            }
            let mut value = event.value()?;
            update(&mut value)?;
            *event = EncodedEvent::from_value(&value);
        }
        Ok(())
    }

    pub fn push_value(&mut self, event: &Value) {
        self.events.push(EncodedEvent::from_value(event));
    }

    pub(crate) fn push_protocol(&mut self, event: &ProtocolEvent) {
        self.events.push(EncodedEvent::from_protocol(event));
    }

    pub(crate) fn into_encoded(self) -> Vec<EncodedEvent> {
        self.events
    }

    /// Writes the stream as a count line followed by one event per line, so a
    /// truncated file is detected when it is read back.
    pub(crate) fn write_to(&self, mut writer: impl Write) -> Result<()> {
        writeln!(writer, "{}", self.events.len())?;
        for event in &self.events {
            writeln!(writer, "{}", event.json)?;
        }
        Ok(())
    }

    /// Reads a stream written by [`Self::write_to`].
    pub(crate) fn read_from(reader: impl BufRead) -> Result<Self> {
        let mut lines = reader.lines();
        let count = lines
            .next()
            .context("retained worker events have no count")??
            .parse::<usize>()
            .context("retained worker event count is invalid")?;
        let mut events = Vec::new();
        for line in lines {
            let json = line?;
            let value: Value =
                serde_json::from_str(&json).context("retained worker event is not valid JSON")?;
            events.push(EncodedEvent {
                name: event_name(&value),
                json: json.into_boxed_str(),
            });
        }
        if events.len() != count {
            bail!(
                "retained worker events hold {} of {count} events",
                events.len()
            );
        }
        Ok(Self { events })
    }
}

impl From<Vec<Value>> for WorkerEvents {
    fn from(events: Vec<Value>) -> Self {
        events.into_iter().collect()
    }
}

impl FromIterator<Value> for WorkerEvents {
    fn from_iter<I: IntoIterator<Item = Value>>(events: I) -> Self {
        Self {
            events: events
                .into_iter()
                .map(|event| EncodedEvent::from_value(&event))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stream() -> Vec<Value> {
        vec![
            json!({"event":"scan_started","seq":1,"ratio":0.5,"big":u64::MAX,"neg":-3}),
            json!({"event":"profile_declared","profile":{"id":"p","properties":{"z":"1","a":"2"}}}),
            json!({"event":"node_upsert","node":{"id":"n","properties":{"text":"\u{2028}\"\\"}}}),
            json!({"event":"custom","value":[1,2.25,null,true]}),
            json!({"no_event":true}),
        ]
    }

    #[test]
    fn encoded_events_parse_back_to_the_same_values() {
        let events = WorkerEvents::from(stream());
        assert_eq!(events.len(), 5);
        assert_eq!(events.to_values(), stream());
        assert_eq!(
            events.named("profile_declared").collect::<Vec<_>>(),
            vec![stream()[1].clone()]
        );
        assert_eq!(
            events
                .select(|name| matches!(name, "scan_started" | "node_upsert"))
                .collect::<Vec<_>>(),
            vec![stream()[0].clone(), stream()[2].clone()]
        );
        // An unknown or missing event name is retained but never selected.
        assert_eq!(events.select(|_| true).count(), 3);
    }

    /// The core used to hold `serde_json::to_value` of each typed event; the
    /// retained text must parse back to exactly that value, including key
    /// order and number representation.
    #[test]
    fn typed_events_round_trip_like_to_value() {
        let fixture = include_str!(
            "../../../depgraph-protocol/tests/fixtures/protocol-v1.rust-semantic.golden.ndjson"
        );
        let mut events = WorkerEvents::default();
        let mut expected = Vec::new();
        for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
            let event: ProtocolEvent = serde_json::from_str(line).expect("fixture event");
            events.push_protocol(&event);
            expected.push(serde_json::to_value(&event).expect("typed event"));
        }
        let actual = events.to_values();
        assert_eq!(actual, expected);
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(
                serde_json::to_string(actual).expect("value"),
                serde_json::to_string(expected).expect("value")
            );
        }
    }

    #[test]
    fn update_named_rewrites_only_the_named_events() -> Result<()> {
        let mut events = WorkerEvents::from(stream());
        events.update_named("profile_declared", |event| {
            event["profile"]["properties"]["added"] = json!("yes");
            Ok(())
        })?;
        let mut expected = stream();
        expected[1]["profile"]["properties"]["added"] = json!("yes");
        assert_eq!(events.to_values(), expected);
        assert!(
            events
                .update_named("node_upsert", |_| bail!("rejected"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn written_events_read_back_and_truncation_is_detected() -> Result<()> {
        let events = WorkerEvents::from(stream());
        let mut bytes = Vec::new();
        events.write_to(&mut bytes)?;
        assert_eq!(WorkerEvents::read_from(bytes.as_slice())?, events);

        let mut empty = Vec::new();
        WorkerEvents::default().write_to(&mut empty)?;
        assert!(WorkerEvents::read_from(empty.as_slice())?.is_empty());

        let truncated = &bytes[..bytes.len() - 10];
        assert!(WorkerEvents::read_from(truncated).is_err());
        assert!(WorkerEvents::read_from(&b""[..]).is_err());
        Ok(())
    }
}
