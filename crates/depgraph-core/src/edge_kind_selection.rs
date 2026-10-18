//! Edge-kind selection for dependency traversal (Issue #541).
//!
//! Structural edges describe how the graph is organized (a package contains a
//! file, a file declares a symbol, a generated file comes from its source)
//! rather than one unit depending on another. Dependency lists can drop them
//! or restrict the traversal to an allowlist of edge kinds; the selection is
//! applied while the adjacency is built, so every count derived from the
//! traversal covers only the selected edges.

use serde::{Deserialize, Serialize};

/// The structural edge kinds (system design §7.2 "Structure").
pub const STRUCTURAL_EDGE_KINDS: [&str; 3] = ["contains", "declares", "generated_from"];

/// Whether dependency lists keep structural edges when the caller does not
/// choose. Since v0.7.0 they are excluded by default so counts cover only
/// dependency edges; an explicit `include` restores the previous traversal.
pub const DEFAULT_STRUCTURAL_EDGE_SELECTION: StructuralEdgeSelection =
    StructuralEdgeSelection::Exclude;

/// Largest accepted edge-kind allowlist.
pub const MAX_DEPENDENCY_EDGE_KINDS: usize = 64;
/// Longest accepted edge kind, in bytes (the Agent token limit).
pub const MAX_DEPENDENCY_EDGE_KIND_BYTES: usize = 64;

#[must_use]
pub fn is_structural_edge_kind(kind: &str) -> bool {
    STRUCTURAL_EDGE_KINDS.contains(&kind)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralEdgeSelection {
    Include,
    Exclude,
}

impl StructuralEdgeSelection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "include" => Some(Self::Include),
            "exclude" => Some(Self::Exclude),
            _ => None,
        }
    }
}

impl Default for StructuralEdgeSelection {
    fn default() -> Self {
        DEFAULT_STRUCTURAL_EDGE_SELECTION
    }
}

/// Rejected edge-kind selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdgeKindFilterError {
    TooManyKinds,
    InvalidKind,
    /// A structural kind is allowlisted while structural edges are excluded.
    StructuralKindExcluded,
}

/// Which edge kinds a dependency traversal follows.
///
/// An empty allowlist means every kind; `structural_edges` then decides
/// whether [`STRUCTURAL_EDGE_KINDS`] are followed. A non-empty allowlist
/// follows only the listed kinds, so its identity always records
/// `structural_edges` as include once the contradiction check has passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeKindFilter {
    edge_kinds: Vec<String>,
    structural_edges: StructuralEdgeSelection,
}

impl EdgeKindFilter {
    /// Follow every edge kind: the traversal semantics before Issue #541,
    /// independent of [`DEFAULT_STRUCTURAL_EDGE_SELECTION`].
    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            edge_kinds: Vec::new(),
            structural_edges: StructuralEdgeSelection::Include,
        }
    }

    /// Validate an allowlist and return it sorted and deduplicated so
    /// equivalent selections share one identity.
    ///
    /// An omitted `structural_edges` means [`DEFAULT_STRUCTURAL_EDGE_SELECTION`]
    /// without an allowlist; with an allowlist the listed kinds alone decide,
    /// so structural kinds may be listed. Only an explicit exclude combined
    /// with a structural kind is contradictory.
    pub fn try_new(
        mut edge_kinds: Vec<String>,
        structural_edges: Option<StructuralEdgeSelection>,
    ) -> Result<Self, EdgeKindFilterError> {
        if edge_kinds.len() > MAX_DEPENDENCY_EDGE_KINDS {
            return Err(EdgeKindFilterError::TooManyKinds);
        }
        if !edge_kinds.iter().all(|kind| is_valid_edge_kind(kind)) {
            return Err(EdgeKindFilterError::InvalidKind);
        }
        if structural_edges == Some(StructuralEdgeSelection::Exclude)
            && edge_kinds.iter().any(|kind| is_structural_edge_kind(kind))
        {
            return Err(EdgeKindFilterError::StructuralKindExcluded);
        }
        edge_kinds.sort();
        edge_kinds.dedup();
        let structural_edges = if edge_kinds.is_empty() {
            structural_edges.unwrap_or(DEFAULT_STRUCTURAL_EDGE_SELECTION)
        } else {
            StructuralEdgeSelection::Include
        };
        Ok(Self {
            edge_kinds,
            structural_edges,
        })
    }

    #[must_use]
    pub fn edge_kinds(&self) -> &[String] {
        &self.edge_kinds
    }

    #[must_use]
    pub const fn structural_edges(&self) -> StructuralEdgeSelection {
        self.structural_edges
    }

    /// True when the selection follows every edge kind, which keeps request
    /// identities (cursor bindings) byte-identical to those before Issue #541.
    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.edge_kinds.is_empty() && self.structural_edges == StructuralEdgeSelection::Include
    }

    #[must_use]
    pub fn allows(&self, kind: &str) -> bool {
        if !self.edge_kinds.is_empty() {
            return self
                .edge_kinds
                .binary_search_by(|allowed| allowed.as_str().cmp(kind))
                .is_ok();
        }
        self.structural_edges == StructuralEdgeSelection::Include || !is_structural_edge_kind(kind)
    }
}

impl Default for EdgeKindFilter {
    fn default() -> Self {
        Self {
            edge_kinds: Vec::new(),
            structural_edges: DEFAULT_STRUCTURAL_EDGE_SELECTION,
        }
    }
}

/// Same grammar as the Agent token (`^[a-z][a-z0-9._:-]*$`), at most 64 bytes.
fn is_valid_edge_kind(kind: &str) -> bool {
    let mut bytes = kind.bytes();
    kind.len() <= MAX_DEPENDENCY_EDGE_KIND_BYTES
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}
