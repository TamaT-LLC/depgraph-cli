//! Closed Agent projection of import evidence (Issue #544).

use depgraph_core::import_evidence::{
    ImportBindingKind, ImportEvidence, is_public_import_name, is_public_import_specifier,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::{AgentImportSpecifier, AgentLabel, ContractBuildError};

/// How an import occurrence binds the imported module or symbol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentImportBindingKind {
    Default,
    Named,
    Namespace,
    ImportEquals,
    SideEffect,
    Require,
    Dynamic,
    ImportType,
    NamedReexport,
    NamespaceReexport,
    ExportStar,
    Reexport,
    Glob,
    GlobReexport,
    ExternCrate,
}

impl From<ImportBindingKind> for AgentImportBindingKind {
    fn from(value: ImportBindingKind) -> Self {
        match value {
            ImportBindingKind::Default => Self::Default,
            ImportBindingKind::Named => Self::Named,
            ImportBindingKind::Namespace => Self::Namespace,
            ImportBindingKind::ImportEquals => Self::ImportEquals,
            ImportBindingKind::SideEffect => Self::SideEffect,
            ImportBindingKind::Require => Self::Require,
            ImportBindingKind::Dynamic => Self::Dynamic,
            ImportBindingKind::ImportType => Self::ImportType,
            ImportBindingKind::NamedReexport => Self::NamedReexport,
            ImportBindingKind::NamespaceReexport => Self::NamespaceReexport,
            ImportBindingKind::ExportStar => Self::ExportStar,
            ImportBindingKind::Reexport => Self::Reexport,
            ImportBindingKind::Glob => Self::Glob,
            ImportBindingKind::GlobReexport => Self::GlobReexport,
            ImportBindingKind::ExternCrate => Self::ExternCrate,
        }
    }
}

/// Specifier and imported binding of one import occurrence. Absent fields are
/// facts the extractor did not record, not empty values.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentImportEvidence {
    specifier: AgentImportSpecifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding_kind: Option<AgentImportBindingKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    imported_name: Option<AgentLabel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    local_name: Option<AgentLabel>,
    #[serde(default, skip_serializing_if = "is_false")]
    type_only: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

impl AgentImportEvidence {
    /// Builds import evidence, rejecting credential-shaped values so they can
    /// neither be produced nor accepted by the closed contract.
    pub fn new(
        specifier: AgentImportSpecifier,
        binding_kind: Option<AgentImportBindingKind>,
        imported_name: Option<AgentLabel>,
        local_name: Option<AgentLabel>,
        type_only: bool,
    ) -> Result<Self, ContractBuildError> {
        let names_are_public = [imported_name.as_ref(), local_name.as_ref()]
            .into_iter()
            .flatten()
            .all(|name| is_public_import_name(name.as_str()));
        if !is_public_import_specifier(specifier.as_str()) || !names_are_public {
            return Err(ContractBuildError::ImportEvidence);
        }
        Ok(Self {
            specifier,
            binding_kind,
            imported_name,
            local_name,
            type_only,
        })
    }

    #[must_use]
    pub const fn specifier(&self) -> &AgentImportSpecifier {
        &self.specifier
    }

    #[must_use]
    pub const fn binding_kind(&self) -> Option<AgentImportBindingKind> {
        self.binding_kind
    }

    #[must_use]
    pub const fn imported_name(&self) -> Option<&AgentLabel> {
        self.imported_name.as_ref()
    }

    #[must_use]
    pub const fn local_name(&self) -> Option<&AgentLabel> {
        self.local_name.as_ref()
    }

    #[must_use]
    pub const fn type_only(&self) -> bool {
        self.type_only
    }

    /// Projects core import facts; values outside the contract are omitted.
    pub(crate) fn project(source: &ImportEvidence) -> Option<Self> {
        let specifier = AgentImportSpecifier::parse(source.specifier()).ok()?;
        let name = |value: Option<&str>| value.and_then(|value| AgentLabel::parse(value).ok());
        Self::new(
            specifier,
            source.binding_kind().map(Into::into),
            name(source.imported_name()),
            name(source.local_name()),
            source.type_only(),
        )
        .ok()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentImportEvidenceWire {
    specifier: AgentImportSpecifier,
    #[serde(default)]
    binding_kind: Option<AgentImportBindingKind>,
    #[serde(default)]
    imported_name: Option<AgentLabel>,
    #[serde(default)]
    local_name: Option<AgentLabel>,
    #[serde(default)]
    type_only: bool,
}

impl<'de> Deserialize<'de> for AgentImportEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentImportEvidenceWire::deserialize(deserializer)?;
        Self::new(
            wire.specifier,
            wire.binding_kind,
            wire.imported_name,
            wire.local_name,
            wire.type_only,
        )
        .map_err(D::Error::custom)
    }
}
