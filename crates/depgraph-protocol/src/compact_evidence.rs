//! The opt-in `compact-evidence-v1` evidence encoding of a protocol 1.0
//! stream (#578).
//!
//! A worker writes this encoding only when the core asks for it through
//! [`COMPACT_EVIDENCE_REQUEST_ENV`], and declares it on each profile that uses
//! it. The core expands every event with [`CompactEvidenceDecoder`] before it
//! validates or stores the event, so everything after the decoder sees the
//! ordinary protocol 1.0 stream. Two things are left out of the wire:
//!
//! - A site-linked edge whose evidence equals its dependency site's evidence
//!   writes `"evidence": []`; the decoder copies the site's evidence into it.
//!   The site must precede the edge in the stream.
//! - Evidence properties that every evidence item of one extractor and
//!   extractor version carries with the same value are declared once in the
//!   profile's [`EVIDENCE_PROPERTY_DEFAULTS_PROPERTY`]; the decoder inserts
//!   each declared property into every matching evidence item that does not
//!   carry that key.
//!
//! The decoder removes [`EVIDENCE_ENCODING_PROPERTY`] and
//! [`EVIDENCE_PROPERTY_DEFAULTS_PROPERTY`] from the profile, so the decoded
//! stream is the one the worker would have written without the encoding.
//! A stream without the profile declaration passes through unchanged, which
//! keeps workers that do not know the encoding compatible.

use crate::{DependencySite, Evidence, ProtocolError, ProtocolEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The environment variable through which the core asks a worker for the
/// compact evidence encoding. Its value is [`COMPACT_EVIDENCE_ENCODING_V1`].
pub const COMPACT_EVIDENCE_REQUEST_ENV: &str = "DEPGRAPH_EVIDENCE_ENCODING";
/// The profile property that declares the evidence encoding of the profile.
pub const EVIDENCE_ENCODING_PROPERTY: &str = "evidence_encoding";
/// The only evidence encoding besides the ordinary one.
pub const COMPACT_EVIDENCE_ENCODING_V1: &str = "compact-evidence-v1";
/// The profile property that lists [`EvidencePropertyDefaults`].
pub const EVIDENCE_PROPERTY_DEFAULTS_PROPERTY: &str = "evidence_property_defaults";

/// Evidence properties shared by every evidence item with one extractor and
/// extractor version in a profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePropertyDefaults {
    pub extractor: String,
    pub extractor_version: String,
    pub properties: BTreeMap<String, Value>,
}

impl EvidencePropertyDefaults {
    fn matches(&self, evidence: &Evidence) -> bool {
        evidence.extractor == self.extractor && evidence.extractor_version == self.extractor_version
    }

    /// Inserts each default into `evidence` when it matches and lacks the key,
    /// and returns about how many JSON bytes the inserted properties add.
    pub fn apply(&self, evidence: &mut Evidence) -> usize {
        if !self.matches(evidence) {
            return 0;
        }
        let mut added = 0;
        for (key, value) in &self.properties {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                evidence.properties.entry(key.clone())
            {
                // `"key":value,`
                added += key.len() + json_len(value) + 4;
                entry.insert(value.clone());
            }
        }
        added
    }
}

/// Applies every matching default to each evidence item, and returns about
/// how many JSON bytes the inserted properties add.
pub fn apply_evidence_property_defaults(
    defaults: &[EvidencePropertyDefaults],
    evidence: &mut [Evidence],
) -> usize {
    let mut added = 0;
    for item in evidence {
        for entry in defaults {
            added += entry.apply(item);
        }
    }
    added
}

/// The length of `value` as compact JSON, without allocating it.
fn json_len(value: &impl Serialize) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0 += buffer.len();
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    // Serializing a JSON value or evidence into a counter cannot fail.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

/// Expands `compact-evidence-v1` events into the ordinary protocol 1.0 form.
#[derive(Debug, Default)]
pub struct CompactEvidenceDecoder {
    /// The declared profiles: their defaults when they use the encoding, or
    /// `None` when they do not.
    profiles: BTreeMap<String, Option<Vec<EvidencePropertyDefaults>>>,
    /// The most JSON bytes decoding may add to the stream, if bounded.
    expansion_limit: Option<usize>,
    /// The JSON bytes decoding has added so far.
    expanded_bytes: usize,
}

impl CompactEvidenceDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A decoder that fails with [`ProtocolError::ExpansionLimit`] once the
    /// evidence it restores would add more than `limit` JSON bytes to the
    /// stream. A consumer that bounds the bytes it reads from a producer it
    /// does not trust bounds the decoded stream this way, too: a few short
    /// edges that each copy a large site's evidence could otherwise grow far
    /// beyond the bytes read.
    #[must_use]
    pub fn with_expansion_limit(limit: usize) -> Self {
        Self {
            expansion_limit: Some(limit),
            ..Self::default()
        }
    }

    fn account(&mut self, added: usize) -> Result<(), ProtocolError> {
        self.expanded_bytes = self.expanded_bytes.saturating_add(added);
        match self.expansion_limit {
            Some(limit) if self.expanded_bytes > limit => {
                Err(ProtocolError::ExpansionLimit { limit })
            }
            _ => Ok(()),
        }
    }

    /// Expands one event in place.
    ///
    /// `site` returns an already decoded dependency site by ID; the caller
    /// usually reads it from the validator that received the earlier events
    /// (`ProtocolValidator::dependency_site`).
    pub fn decode<'a>(
        &mut self,
        event: &mut ProtocolEvent,
        site: impl FnOnce(&str) -> Option<&'a DependencySite>,
    ) -> Result<(), ProtocolError> {
        match event {
            ProtocolEvent::ProfileDeclared(declared) => {
                let profile = &mut declared.profile;
                let encoding = profile.properties.remove(EVIDENCE_ENCODING_PROPERTY);
                let defaults = profile
                    .properties
                    .remove(EVIDENCE_PROPERTY_DEFAULTS_PROPERTY);
                let decoded = match encoding {
                    None if defaults.is_none() => None,
                    None => {
                        return invariant(format!(
                            "profile {} declares {EVIDENCE_PROPERTY_DEFAULTS_PROPERTY} without {EVIDENCE_ENCODING_PROPERTY}={COMPACT_EVIDENCE_ENCODING_V1}",
                            profile.id
                        ));
                    }
                    Some(Value::String(encoding)) if encoding == COMPACT_EVIDENCE_ENCODING_V1 => {
                        Some(parse_defaults(&profile.id, defaults)?)
                    }
                    Some(other) => {
                        return invariant(format!(
                            "profile {} declares unsupported {EVIDENCE_ENCODING_PROPERTY} {other}",
                            profile.id
                        ));
                    }
                };
                // A profile may be declared again with the same content; its
                // encoding must not change between the declarations.
                if let Some(previous) = self.profiles.get(&profile.id)
                    && previous != &decoded
                {
                    return invariant(format!(
                        "profile {} changed its evidence encoding",
                        profile.id
                    ));
                }
                self.profiles.insert(profile.id.clone(), decoded);
            }
            ProtocolEvent::DependencySite(event) => {
                if let Some(defaults) = self.defaults(&event.site.profile_id) {
                    let added =
                        apply_evidence_property_defaults(defaults, &mut event.site.evidence);
                    self.account(added)?;
                }
            }
            ProtocolEvent::EdgeUpsert(event) => {
                let edge = &mut event.edge;
                let Some(defaults) = self.defaults(&edge.profile_id) else {
                    return Ok(());
                };
                if !edge.evidence.is_empty() {
                    let added = apply_evidence_property_defaults(defaults, &mut edge.evidence);
                    return self.account(added);
                }
                let Some(site_id) = edge.site_id.as_deref() else {
                    return invariant(format!(
                        "edge {} omits its evidence but has no dependency site",
                        edge.id
                    ));
                };
                let Some(site) = site(site_id) else {
                    return invariant(format!(
                        "edge {} omits its evidence but its dependency site {site_id} was not declared before it",
                        edge.id
                    ));
                };
                if site.profile_id != edge.profile_id {
                    return invariant(format!(
                        "edge {} omits its evidence but its dependency site {site_id} belongs to profile {}",
                        edge.id, site.profile_id
                    ));
                }
                self.account(json_len(&site.evidence))?;
                edge.evidence.clone_from(&site.evidence);
            }
            ProtocolEvent::Diagnostic(event) => {
                if let Some(defaults) = event
                    .diagnostic
                    .profile_id
                    .as_deref()
                    .and_then(|profile_id| self.defaults(profile_id))
                {
                    let added =
                        apply_evidence_property_defaults(defaults, &mut event.diagnostic.evidence);
                    self.account(added)?;
                }
            }
            ProtocolEvent::ScanStarted(_)
            | ProtocolEvent::NodeUpsert(_)
            | ProtocolEvent::FileCompleted(_)
            | ProtocolEvent::ProfileCompleted(_)
            | ProtocolEvent::ScanCompleted(_) => {}
        }
        Ok(())
    }

    fn defaults(&self, profile_id: &str) -> Option<&[EvidencePropertyDefaults]> {
        self.profiles.get(profile_id)?.as_deref()
    }
}

fn parse_defaults(
    profile_id: &str,
    value: Option<Value>,
) -> Result<Vec<EvidencePropertyDefaults>, ProtocolError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let defaults: Vec<EvidencePropertyDefaults> =
        serde_json::from_value(value).map_err(|error| {
            ProtocolError::Invariant(format!(
                "profile {profile_id} has malformed {EVIDENCE_PROPERTY_DEFAULTS_PROPERTY}: {error}"
            ))
        })?;
    let mut seen = std::collections::BTreeSet::new();
    for entry in &defaults {
        if entry.extractor.is_empty() || entry.extractor_version.is_empty() {
            return invariant(format!(
                "profile {profile_id} declares evidence property defaults without an extractor and extractor version"
            ));
        }
        if entry.properties.is_empty() {
            return invariant(format!(
                "profile {profile_id} declares empty evidence property defaults for {} {}",
                entry.extractor, entry.extractor_version
            ));
        }
        if !seen.insert((entry.extractor.as_str(), entry.extractor_version.as_str())) {
            return invariant(format!(
                "profile {profile_id} declares evidence property defaults for {} {} more than once",
                entry.extractor, entry.extractor_version
            ));
        }
    }
    Ok(defaults)
}

fn invariant<T>(message: String) -> Result<T, ProtocolError> {
    Err(ProtocolError::Invariant(message))
}
