//! Allowlisted projection of import evidence (Issue #544).
//!
//! Worker evidence `properties` are open-ended JSON. Agent-facing projections
//! must never forward them wholesale (NFR-005), so this module reads only the
//! keys that describe an import occurrence and validates every value it keeps.

use serde_json::Value;

/// Maximum UTF-8 bytes of a projected import specifier.
pub const MAX_IMPORT_SPECIFIER_BYTES: usize = 1_024;
/// Maximum UTF-8 bytes of a projected imported or local binding name.
pub const MAX_IMPORT_NAME_BYTES: usize = 256;

/// Closed set of import binding shapes observed in worker evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImportBindingKind {
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

impl ImportBindingKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Named => "named",
            Self::Namespace => "namespace",
            Self::ImportEquals => "import_equals",
            Self::SideEffect => "side_effect",
            Self::Require => "require",
            Self::Dynamic => "dynamic",
            Self::ImportType => "import_type",
            Self::NamedReexport => "named_reexport",
            Self::NamespaceReexport => "namespace_reexport",
            Self::ExportStar => "export_star",
            Self::Reexport => "reexport",
            Self::Glob => "glob",
            Self::GlobReexport => "glob_reexport",
            Self::ExternCrate => "extern_crate",
        }
    }

    /// Maps the TypeScript worker's `occurrence_kind` to a binding kind.
    fn from_typescript_occurrence(value: &str) -> Option<Self> {
        Some(match value {
            "default_import" => Self::Default,
            "named_import" => Self::Named,
            "namespace_import" => Self::Namespace,
            "import_equals" => Self::ImportEquals,
            "side_effect_import" => Self::SideEffect,
            "require_call" => Self::Require,
            "dynamic_import" => Self::Dynamic,
            "import_type" => Self::ImportType,
            "named_reexport" => Self::NamedReexport,
            "namespace_reexport" => Self::NamespaceReexport,
            "export_star" => Self::ExportStar,
            _ => return None,
        })
    }
}

/// Site facts used when evidence properties carry no import description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportSiteHint<'a> {
    kind: &'a str,
    specifier: Option<&'a str>,
}

impl<'a> ImportSiteHint<'a> {
    #[must_use]
    pub const fn new(kind: &'a str, specifier: Option<&'a str>) -> Self {
        Self { kind, specifier }
    }
}

/// Bounded, credential-free description of one import occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportEvidence {
    specifier: String,
    binding_kind: Option<ImportBindingKind>,
    imported_name: Option<String>,
    local_name: Option<String>,
    type_only: bool,
}

impl ImportEvidence {
    #[must_use]
    pub fn specifier(&self) -> &str {
        &self.specifier
    }

    #[must_use]
    pub const fn binding_kind(&self) -> Option<ImportBindingKind> {
        self.binding_kind
    }

    #[must_use]
    pub fn imported_name(&self) -> Option<&str> {
        self.imported_name.as_deref()
    }

    #[must_use]
    pub fn local_name(&self) -> Option<&str> {
        self.local_name.as_deref()
    }

    #[must_use]
    pub const fn type_only(&self) -> bool {
        self.type_only
    }

    fn build(
        specifier: Option<&str>,
        binding_kind: Option<ImportBindingKind>,
        imported_name: Option<&str>,
        local_name: Option<&str>,
        type_only: bool,
    ) -> Option<Self> {
        let specifier = specifier.filter(|value| is_public_import_specifier(value))?;
        Some(Self {
            specifier: specifier.to_owned(),
            binding_kind,
            imported_name: imported_name
                .filter(|value| is_public_import_name(value))
                .map(str::to_owned),
            local_name: local_name
                .filter(|value| is_public_import_name(value))
                .map(str::to_owned),
            type_only,
        })
    }
}

/// Projects allowlisted import facts from evidence properties.
///
/// TypeScript semantic evidence is recognised by `occurrence_kind`, Rust HIR
/// evidence by `target_specifier`. Otherwise an import-like `site` lends its
/// specifier (Go and TypeScript syntax-only sites). Values that exceed the
/// bounds, contain control characters, or look like credentials are omitted.
#[must_use]
pub fn project_import_evidence(
    properties: &Value,
    site: Option<ImportSiteHint<'_>>,
) -> Option<ImportEvidence> {
    if let Some(occurrence) = properties.get("occurrence_kind") {
        return project_typescript(properties, occurrence, site);
    }
    if let Some(target) = properties.get("target_specifier") {
        return project_rust(properties, target);
    }
    project_site_only(site?)
}

fn project_typescript(
    properties: &Value,
    occurrence: &Value,
    site: Option<ImportSiteHint<'_>>,
) -> Option<ImportEvidence> {
    let binding_kind = ImportBindingKind::from_typescript_occurrence(occurrence.as_str()?)?;
    let specifier = match properties.get("module_specifier") {
        Some(value) => value.as_str(),
        None => site.and_then(|site| site.specifier),
    };
    ImportEvidence::build(
        specifier,
        Some(binding_kind),
        properties.get("imported_name").and_then(Value::as_str),
        None,
        properties.get("type_only").and_then(Value::as_bool) == Some(true),
    )
}

fn project_rust(properties: &Value, target: &Value) -> Option<ImportEvidence> {
    let target = target.as_str()?;
    let alias = properties.get("alias").and_then(Value::as_str);
    let reexport = properties.get("reexport").and_then(Value::as_bool) == Some(true);
    // `use` evidence always records `glob`; `extern crate` evidence never does.
    let (binding_kind, imported_name) = match properties.get("glob").map(Value::as_bool) {
        Some(Some(true)) if reexport => (ImportBindingKind::GlobReexport, None),
        Some(Some(true)) => (ImportBindingKind::Glob, None),
        Some(Some(false)) => {
            let name = target.trim_start_matches("::").rsplit("::").next();
            let kind = if reexport {
                ImportBindingKind::NamedReexport
            } else {
                ImportBindingKind::Named
            };
            (kind, name.filter(|name| !name.is_empty()))
        }
        Some(None) => return None,
        None => (ImportBindingKind::ExternCrate, None),
    };
    ImportEvidence::build(
        Some(target),
        Some(binding_kind),
        imported_name,
        alias,
        false,
    )
}

fn project_site_only(site: ImportSiteHint<'_>) -> Option<ImportEvidence> {
    // Only syntax-level import site kinds whose specifier is the literal module
    // string qualify. Semantic site kinds always carry evidence properties, and
    // e.g. `rust_use` specifiers embed the alias rather than the target path.
    let (binding_kind, type_only) = match site.kind {
        "import" => (None, false),
        "side_effect_import" => (Some(ImportBindingKind::SideEffect), false),
        "dynamic_import" => (Some(ImportBindingKind::Dynamic), false),
        "require" => (Some(ImportBindingKind::Require), false),
        "type_import" => (None, true),
        "type_import_equals" => (Some(ImportBindingKind::ImportEquals), true),
        "reexport" => (Some(ImportBindingKind::Reexport), false),
        "type_reexport" => (Some(ImportBindingKind::Reexport), true),
        _ => return None,
    };
    ImportEvidence::build(site.specifier, binding_kind, None, None, type_only)
}

/// Whether `value` may be disclosed as an import specifier: non-empty, at most
/// [`MAX_IMPORT_SPECIFIER_BYTES`], free of control characters, credential
/// shapes, and URL userinfo (`scheme://user:pass@host/...`).
#[must_use]
pub fn is_public_import_specifier(value: &str) -> bool {
    is_bounded_public_text(value, MAX_IMPORT_SPECIFIER_BYTES) && !has_url_userinfo(value)
}

/// Whether a `scheme://` URL carries userinfo, i.e. an `@` in the authority
/// before the first `/`, `?` or `#`. Specifiers without `://` (`@scope/pkg`,
/// `npm:@scope/pkg@1.0.0`, `jsr:@std/path`) have no authority and never match.
fn has_url_userinfo(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    rest.split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

/// Whether `value` may be disclosed as an imported or local binding name.
#[must_use]
pub fn is_public_import_name(value: &str) -> bool {
    is_bounded_public_text(value, MAX_IMPORT_NAME_BYTES)
}

fn is_bounded_public_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
        && !crate::service_lifecycle::contains_credential_shape(value)
}
