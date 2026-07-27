use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};

use crate::bounded_query::read_bounded_repository_file;
use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CROSS_LANGUAGE_COMPLETENESS_VERSION,
    CROSS_LANGUAGE_CONTRACT_PROPERTY, CROSS_LANGUAGE_CONTRACT_VERSION,
    CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY, Condition, CrossLanguageAdapterDelta,
    CrossLanguageCanonicalIdentity, CrossLanguageCapabilityStatus, CrossLanguageCompletenessLedger,
    CrossLanguageFormat, CrossLanguageFormatCoverage, CrossLanguageMappingKind,
    CrossLanguageNodeKind, CrossLanguageProfileIdentity, CrossLanguageRelationKind, DependencySite,
    Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Profile, Properties,
    ResolutionStatus, build_cross_language_edge_id, build_cross_language_site_id, canonical_json,
    cross_language_node_id, cross_language_profile_id, stable_id_from_value,
    validate_cross_language_adapter_delta,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

pub const FFI_CAPABILITY: &str = "ffi-contract-v1";
pub const FFI_FORMAT_VERSION: &str = "ffi-static-inventory-v1";
pub const MAX_FFI_FILE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FFI_TOTAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_FFI_FILES: usize = 4_096;
pub const MAX_FFI_DECLARATIONS: usize = 100_000;
pub const MAX_FFI_INVENTORY_ENTRIES: usize = 1_000_000;

const EXTRACTOR: &str = "depgraph-ffi-inventory";
const MAX_PARTICIPATING_PROFILES: usize = 64;
const MAX_EXPANDED_DECLARATIONS: usize = 250_000;
const MAX_BOUNDED_TEXT: usize = 4_096;
const MAX_REASONS: usize = 64;

/// Inventories supported Rust, Go, and Web native declarations without
/// loading a native library, running a compiler/plugin, or executing project
/// code. Static declarations retain their requested ABI/library/symbol, but an
/// imported declaration is at most a candidate until build/link evidence is
/// correlated by the supervised FFI adapter.
pub fn scan_ffi_repository(
    root: &Path,
    participating_profiles: &[Profile],
) -> Result<Option<CrossLanguageAdapterDelta>> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("FFI scan root {} is unavailable", root.display()))?;
    if !canonical_root.is_dir() {
        bail!("FFI scan root must be a directory");
    }
    let mut participating_profiles = participating_profiles.to_vec();
    participating_profiles.sort_by(|left, right| left.id.cmp(&right.id));
    if participating_profiles.is_empty()
        || participating_profiles.len() > MAX_PARTICIPATING_PROFILES
        || participating_profiles
            .iter()
            .any(|profile| !bounded_text(&profile.id))
        || participating_profiles
            .windows(2)
            .any(|profiles| profiles[0].id == profiles[1].id)
    {
        bail!("FFI participating profiles must be a bounded non-empty set");
    }
    let participating_profile_ids = participating_profiles
        .iter()
        .map(|profile| profile.id.clone())
        .collect::<Vec<_>>();

    let inventory = inventory_sources(&canonical_root)?;
    if inventory.declarations.is_empty() && inventory.skipped_count == 0 {
        return Ok(None);
    }
    let input_digest = digest_value(&json!({
        "files": inventory.files,
        "declarations": inventory.declarations,
        "reasons": inventory.reasons,
        "skipped_count": inventory.skipped_count,
    }));
    let profile_identity = CrossLanguageProfileIdentity {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        completeness_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        contract_input_digest: input_digest,
        adapter_capability_versions: vec![FFI_CAPABILITY.to_owned()],
        participating_profile_ids: participating_profile_ids.clone(),
    };
    let profile_id = cross_language_profile_id(&profile_identity);
    let expanded_declarations = inventory
        .declarations
        .len()
        .checked_mul(participating_profile_ids.len())
        .context("FFI expanded declaration count overflowed")?;
    if expanded_declarations > MAX_EXPANDED_DECLARATIONS {
        bail!("FFI inventory exceeds its closed expanded declaration limit");
    }
    let mut builder = FfiGraphBuilder::new(profile_id.clone());
    for declaration in &inventory.declarations {
        for target_profile_id in &participating_profile_ids {
            builder.add_declaration(declaration, target_profile_id)?;
        }
    }
    for reason in &inventory.reasons {
        builder.insert_reason(reason);
    }
    let status = if builder.unresolved_count > 0
        || inventory.skipped_count > 0
        || !builder.reasons.is_empty()
    {
        CrossLanguageCapabilityStatus::Incomplete
    } else {
        CrossLanguageCapabilityStatus::Complete
    };
    let ledger = CrossLanguageCompletenessLedger {
        schema_version: CROSS_LANGUAGE_COMPLETENESS_VERSION.to_owned(),
        entries: vec![CrossLanguageFormatCoverage {
            format: CrossLanguageFormat::Ffi,
            capability: FFI_CAPABILITY.to_owned(),
            status,
            input_count: inventory.declarations.len() as u64 + inventory.skipped_count,
            node_count: builder.cross_node_ids.len() as u64,
            site_count: builder.sites.len() as u64,
            edge_count: builder.edges.len() as u64,
            external_count: builder.external_count,
            unresolved_count: builder.unresolved_count,
            skipped_count: inventory.skipped_count,
            reasons: builder.reasons.iter().cloned().collect(),
        }],
    };
    let profile = Profile {
        id: profile_id,
        language: "cross-language".to_owned(),
        toolchain: None,
        command: None,
        target: None,
        features: Vec::new(),
        environment: BTreeMap::new(),
        source_revision: None,
        properties: BTreeMap::from([
            (
                CROSS_LANGUAGE_CONTRACT_PROPERTY.to_owned(),
                Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
            ),
            (
                CROSS_LANGUAGE_PROFILE_IDENTITY_PROPERTY.to_owned(),
                serde_json::to_value(profile_identity)?,
            ),
            (
                CROSS_LANGUAGE_COMPLETENESS_PROPERTY.to_owned(),
                serde_json::to_value(ledger)?,
            ),
        ]),
    };
    let delta = CrossLanguageAdapterDelta {
        contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
        profile,
        participating_profiles,
        nodes: builder.nodes.into_values().collect(),
        sites: builder.sites.into_values().collect(),
        edges: builder.edges.into_values().collect(),
    };
    validate_cross_language_adapter_delta(&delta).map_err(anyhow::Error::from)?;
    Ok(Some(delta))
}

#[derive(Clone, Debug, Serialize)]
struct FfiInventory {
    files: Vec<FileIdentity>,
    declarations: Vec<FfiDeclaration>,
    skipped_count: u64,
    reasons: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
struct FileIdentity {
    locator: String,
    language: FfiLanguage,
    digest: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum FfiLanguage {
    Go,
    Rust,
    Web,
}

impl FfiLanguage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Web => "web",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum FfiDirection {
    Export,
    Import,
}

impl FfiDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::Import => "import",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct FfiDeclaration {
    language: FfiLanguage,
    direction: FfiDirection,
    locator: String,
    source_digest: String,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
    abi: String,
    library: Option<String>,
    symbol: Option<String>,
    reason: Option<String>,
}

fn inventory_sources(root: &Path) -> Result<FfiInventory> {
    let entries = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(admit_entry);
    let mut files = Vec::new();
    let mut declarations = Vec::new();
    let mut skipped_count = 0_u64;
    let mut reasons = BTreeSet::new();
    let mut total_bytes = 0_usize;
    let mut inventory_entries = 0_usize;
    let mut source_files = 0_usize;

    for entry in entries {
        record_ffi_inventory_entry(&mut inventory_entries)?;
        let entry = entry.context("FFI source inventory traversal failed")?;
        let Some(language) = source_language(entry.path()) else {
            continue;
        };
        source_files = source_files
            .checked_add(1)
            .context("FFI source file count overflowed")?;
        if source_files > MAX_FFI_FILES {
            bail!("FFI source inventory exceeds its file limit");
        }
        let locator = relative_locator(root, entry.path())?;
        if entry.file_type().is_symlink() {
            skipped_count += 1;
            insert_reason(&mut reasons, "ffi-symlink-source-skipped");
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let bytes = match read_bounded_repository_file(root, entry.path(), MAX_FFI_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                skipped_count += 1;
                let reason = if error.code == "query_file_size_or_type_invalid" {
                    "ffi-source-file-too-large"
                } else {
                    "ffi-source-read-failed"
                };
                insert_reason(&mut reasons, reason);
                continue;
            }
        };
        let Some(next_total_bytes) = total_bytes.checked_add(bytes.len()) else {
            bail!("FFI source byte count overflowed");
        };
        if next_total_bytes > MAX_FFI_TOTAL_BYTES {
            bail!("FFI source inventory exceeds its total byte limit");
        }
        total_bytes = next_total_bytes;
        let digest = digest_bytes(&bytes);
        let Ok(source) = std::str::from_utf8(&bytes) else {
            skipped_count += 1;
            insert_reason(&mut reasons, "ffi-source-is-not-utf8");
            continue;
        };
        let (mut found, boundaries) =
            if generated_source(source) && has_ffi_signal(source, language) {
                (Vec::new(), vec!["ffi-generated-source-skipped".to_owned()])
            } else {
                match language {
                    FfiLanguage::Rust => parse_rust(&locator, &digest, source),
                    FfiLanguage::Go => parse_go(&locator, &digest, source),
                    FfiLanguage::Web => parse_web(&locator, &digest, source),
                }
            };
        if declarations.len() + found.len() > MAX_FFI_DECLARATIONS {
            bail!("FFI declaration inventory exceeds its declaration limit");
        }
        skipped_count += boundaries.len() as u64;
        for reason in boundaries {
            insert_reason(&mut reasons, &reason);
        }
        declarations.append(&mut found);
        files.push(FileIdentity {
            locator,
            language,
            digest,
        });
    }
    declarations.sort();
    declarations.dedup();
    Ok(FfiInventory {
        files,
        declarations,
        skipped_count,
        reasons,
    })
}

fn record_ffi_inventory_entry(inventory_entries: &mut usize) -> Result<()> {
    *inventory_entries = inventory_entries
        .checked_add(1)
        .context("FFI inventory entry count overflowed")?;
    if *inventory_entries > MAX_FFI_INVENTORY_ENTRIES {
        bail!("FFI inventory exceeds its closed entry limit");
    }
    Ok(())
}

fn parse_rust(locator: &str, digest: &str, source: &str) -> (Vec<FfiDeclaration>, Vec<String>) {
    let mut declarations = Vec::new();
    let mut boundaries = Vec::new();
    let mut block_comment_depth = 0_usize;
    let mut raw_string_hashes = None;
    let mut quoted_string = None;
    let mut pending_library = None;
    let mut pending_symbol = None;
    let mut pending_stable_export = false;
    let mut extern_abi: Option<String> = None;
    let mut extern_depth = 0_i32;
    let mut macro_depth = 0_i32;

    if source.contains("macro_rules!") && source.contains("extern \"") {
        boundaries.push("ffi-rust-macro-boundary".to_owned());
    }
    if [
        "libloading::",
        "Library::new(",
        "dlopen(",
        "GetProcAddress(",
    ]
    .iter()
    .any(|needle| source.contains(needle))
    {
        boundaries.push("ffi-rust-dynamic-load-boundary".to_owned());
    }

    for (index, line) in source.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let code = code_without_comments(
            line,
            &mut block_comment_depth,
            &mut raw_string_hashes,
            &mut quoted_string,
            false,
        );
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        if macro_depth > 0 {
            macro_depth += brace_delta(trimmed);
            continue;
        }
        if trimmed.contains("macro_rules!") {
            macro_depth = brace_delta(trimmed).max(0);
            continue;
        }
        if trimmed.starts_with("#[link(") {
            pending_library = attribute_string(trimmed, "name").filter(|value| safe_atom(value));
        }
        if trimmed.starts_with("#[link_name") {
            pending_symbol =
                attribute_string(trimmed, "link_name").filter(|value| safe_symbol(value));
        }
        if trimmed.starts_with("#[export_name") {
            pending_symbol =
                attribute_string(trimmed, "export_name").filter(|value| safe_symbol(value));
            pending_stable_export = pending_symbol.is_some();
        }
        if trimmed.contains("no_mangle") {
            pending_stable_export = true;
        }

        if extern_abi.is_none() && is_extern_block_header(trimmed) {
            extern_abi = quoted_after(trimmed, "extern").map(canonical_abi);
            extern_depth = brace_delta(trimmed);
            if let Some(abi) = extern_abi.as_deref()
                && let Some(symbol) = foreign_item_symbol(trimmed)
            {
                declarations.push(declaration(DeclarationInput {
                    language: FfiLanguage::Rust,
                    direction: FfiDirection::Import,
                    locator,
                    digest,
                    line: line_number,
                    source_line: trimmed,
                    abi,
                    library: pending_library.clone(),
                    symbol: Some(symbol),
                    reason: unsupported_abi_reason(abi),
                }));
            }
            if extern_depth <= 0 {
                extern_abi = None;
                pending_library = None;
                pending_symbol = None;
            }
            continue;
        }

        if let Some(abi) = extern_abi.as_deref() {
            if let Some(symbol) = foreign_item_symbol(trimmed) {
                let symbol = pending_symbol.take().unwrap_or(symbol);
                declarations.push(declaration(DeclarationInput {
                    language: FfiLanguage::Rust,
                    direction: FfiDirection::Import,
                    locator,
                    digest,
                    line: line_number,
                    source_line: trimmed,
                    abi,
                    library: pending_library.clone(),
                    symbol: Some(symbol),
                    reason: unsupported_abi_reason(abi),
                }));
            }
            extern_depth += brace_delta(trimmed);
            if extern_depth <= 0 {
                extern_abi = None;
                pending_library = None;
                pending_symbol = None;
            }
            continue;
        }

        if is_extern_function_declaration(trimmed) && !trimmed.ends_with(';') {
            let abi = quoted_after(trimmed, "extern")
                .map(canonical_abi)
                .unwrap_or_else(|| "unknown".to_owned());
            let symbol = pending_symbol
                .take()
                .or_else(|| identifier_after(trimmed, "fn"));
            let reason = unsupported_abi_reason(&abi).or_else(|| {
                (!pending_stable_export).then(|| "ffi-rust-export-symbol-not-stable".to_owned())
            });
            declarations.push(declaration(DeclarationInput {
                language: FfiLanguage::Rust,
                direction: FfiDirection::Export,
                locator,
                digest,
                line: line_number,
                source_line: trimmed,
                abi: &abi,
                library: None,
                symbol,
                reason,
            }));
            pending_stable_export = false;
        }
    }
    (declarations, boundaries)
}

fn parse_go(locator: &str, digest: &str, source: &str) -> (Vec<FfiDeclaration>, Vec<String>) {
    let mut declarations = Vec::new();
    let mut boundaries = Vec::new();
    let lines = source.lines().collect::<Vec<_>>();
    if source.contains("//go:linkname") {
        boundaries.push("ffi-go-unsafe-linkname-boundary".to_owned());
    }
    if source.contains("plugin.Open(") || source.contains("syscall.LoadDLL(") {
        boundaries.push("ffi-go-dynamic-load-boundary".to_owned());
    }

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == "import \"C\"" || trimmed == "import `C`" {
            let line_number = (index + 1) as u32;
            let preamble = cgo_preamble(source, index);
            let library = cgo_library(&preamble);
            let symbols = cgo_declarations(&preamble);
            if preamble
                .iter()
                .any(|item| item.trim_start().starts_with("#include"))
            {
                boundaries.push("ffi-cgo-header-declaration-not-expanded".to_owned());
            }
            if symbols.is_empty() {
                boundaries.push("ffi-cgo-preamble-has-no-admitted-declaration".to_owned());
            }
            for symbol in symbols {
                declarations.push(declaration(DeclarationInput {
                    language: FfiLanguage::Go,
                    direction: FfiDirection::Import,
                    locator,
                    digest,
                    line: line_number,
                    source_line: trimmed,
                    abi: "c",
                    library: library.clone(),
                    symbol: Some(symbol),
                    reason: None,
                }));
            }
        }
        if let Some(symbol) = trimmed.strip_prefix("//export ").map(str::trim)
            && safe_symbol(symbol)
        {
            let expected = format!("func {symbol}(");
            let declares_function = lines[index + 1..]
                .iter()
                .map(|line| line.trim())
                .find(|line| !line.is_empty() && !line.starts_with("//"))
                .is_some_and(|line| line.starts_with(&expected));
            if declares_function {
                declarations.push(declaration(DeclarationInput {
                    language: FfiLanguage::Go,
                    direction: FfiDirection::Export,
                    locator,
                    digest,
                    line: (index + 1) as u32,
                    source_line: trimmed,
                    abi: "c",
                    library: None,
                    symbol: Some(symbol.to_owned()),
                    reason: None,
                }));
            } else {
                boundaries.push("ffi-cgo-export-declaration-missing-function".to_owned());
            }
        }
    }
    (declarations, boundaries)
}

fn parse_web(locator: &str, digest: &str, source: &str) -> (Vec<FfiDeclaration>, Vec<String>) {
    let mut declarations = Vec::new();
    let mut boundaries = Vec::new();
    let mut block_comment_depth = 0_usize;
    let mut raw_string_hashes = None;
    let mut quoted_string = None;
    if ["process.dlopen(", "node-gyp-build(", "bindings("]
        .iter()
        .any(|needle| source.contains(needle))
    {
        boundaries.push("ffi-web-dynamic-native-binding".to_owned());
    }
    for (index, line) in source.lines().enumerate() {
        let code = code_without_comments(
            line,
            &mut block_comment_depth,
            &mut raw_string_hashes,
            &mut quoted_string,
            true,
        );
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut admitted = false;
        for literal in quoted_literal_spans(trimmed).into_iter().filter(|literal| {
            literal.value.ends_with(".node")
                && web_native_binding_literal_is_admitted(trimmed, literal.start, literal.end)
        }) {
            admitted = true;
            let wildcard = literal.value.contains('*');
            let symbol = web_binding_symbol(trimmed).or_else(|| Some("module".to_owned()));
            let reason = wildcard.then(|| "ffi-web-wildcard-native-binding".to_owned());
            declarations.push(declaration(DeclarationInput {
                language: FfiLanguage::Web,
                direction: FfiDirection::Import,
                locator,
                digest,
                line: (index + 1) as u32,
                source_line: trimmed,
                abi: "node-api",
                library: Some(literal.value),
                symbol,
                reason,
            }));
        }
        if trimmed.contains(".node") && !admitted && web_native_binding_syntax(trimmed) {
            boundaries.push("ffi-web-dynamic-native-binding".to_owned());
        }
    }
    (declarations, boundaries)
}

struct DeclarationInput<'a> {
    language: FfiLanguage,
    direction: FfiDirection,
    locator: &'a str,
    digest: &'a str,
    line: u32,
    source_line: &'a str,
    abi: &'a str,
    library: Option<String>,
    symbol: Option<String>,
    reason: Option<String>,
}

fn declaration(input: DeclarationInput<'_>) -> FfiDeclaration {
    let DeclarationInput {
        language,
        direction,
        locator,
        digest,
        line,
        source_line,
        abi,
        library,
        symbol,
        reason,
    } = input;
    let end_column = source_line
        .chars()
        .count()
        .saturating_add(1)
        .min(u32::MAX as usize) as u32;
    FfiDeclaration {
        language,
        direction,
        locator: locator.to_owned(),
        source_digest: digest.to_owned(),
        start_line: line,
        start_column: 1,
        end_line: line,
        end_column,
        abi: abi.to_owned(),
        library,
        symbol,
        reason,
    }
}

struct FfiGraphBuilder {
    profile_id: String,
    nodes: BTreeMap<String, GraphNode>,
    cross_node_ids: BTreeSet<String>,
    sites: BTreeMap<String, DependencySite>,
    edges: BTreeMap<String, GraphEdge>,
    reasons: BTreeSet<String>,
    external_count: u64,
    unresolved_count: u64,
}

impl FfiGraphBuilder {
    fn new(profile_id: String) -> Self {
        Self {
            profile_id,
            nodes: BTreeMap::new(),
            cross_node_ids: BTreeSet::new(),
            sites: BTreeMap::new(),
            edges: BTreeMap::new(),
            reasons: BTreeSet::new(),
            external_count: 0,
            unresolved_count: 0,
        }
    }

    fn add_declaration(
        &mut self,
        declaration: &FfiDeclaration,
        target_profile_id: &str,
    ) -> Result<()> {
        let source = self.source_node(declaration)?;
        let classification = classify(declaration);
        let target = match classification.status {
            ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                self.native_symbol_node(declaration, target_profile_id)?
            }
            ResolutionStatus::External | ResolutionStatus::Unresolved => {
                self.boundary_node(declaration, target_profile_id, classification.reason)?
            }
        };
        let condition = ffi_condition(declaration, target_profile_id);
        let evidence = vec![Evidence {
            kind: EvidenceKind::Source,
            extractor: EXTRACTOR.to_owned(),
            extractor_version: env!("CARGO_PKG_VERSION").to_owned(),
            path: Some(declaration.locator.clone()),
            start_line: Some(declaration.start_line),
            start_column: Some(declaration.start_column),
            end_line: Some(declaration.end_line),
            end_column: Some(declaration.end_column),
            detail: None,
            properties: Properties::from([
                (
                    "contract_version".to_owned(),
                    Value::String(CROSS_LANGUAGE_CONTRACT_VERSION.to_owned()),
                ),
                ("format".to_owned(), Value::String("ffi".to_owned())),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
                (
                    "format_version".to_owned(),
                    Value::String(FFI_FORMAT_VERSION.to_owned()),
                ),
                (
                    "contract_digest".to_owned(),
                    Value::String(declaration.source_digest.clone()),
                ),
                (
                    "occurrence_kind".to_owned(),
                    serde_json::to_value(CrossLanguageRelationKind::BindsNativeSymbol)?,
                ),
                (
                    "mapping_kind".to_owned(),
                    serde_json::to_value(classification.mapping)?,
                ),
                (
                    "target_profile_id".to_owned(),
                    Value::String(target_profile_id.to_owned()),
                ),
                (
                    "ffi_language".to_owned(),
                    Value::String(declaration.language.as_str().to_owned()),
                ),
                (
                    "ffi_direction".to_owned(),
                    Value::String(declaration.direction.as_str().to_owned()),
                ),
                ("ffi_abi".to_owned(), Value::String(declaration.abi.clone())),
                (
                    "library_request".to_owned(),
                    declaration
                        .library
                        .clone()
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                ),
                (
                    "symbol_request".to_owned(),
                    declaration
                        .symbol
                        .clone()
                        .map(Value::String)
                        .unwrap_or(Value::Null),
                ),
                (
                    "source_digest".to_owned(),
                    Value::String(declaration.source_digest.clone()),
                ),
            ]),
        }];
        let specifier = format!(
            "{}:{}:{}",
            declaration.language.as_str(),
            declaration.abi,
            declaration.symbol.as_deref().unwrap_or("unknown")
        );
        let mut site = DependencySite {
            id: String::new(),
            source: source.clone(),
            kind: CrossLanguageRelationKind::BindsNativeSymbol
                .as_str()
                .to_owned(),
            specifier,
            resolution_status: classification.status,
            target_ids: vec![target.clone()],
            profile_id: self.profile_id.clone(),
            condition: condition.clone(),
            precision: classification.precision,
            reason: classification.reason.map(str::to_owned),
            evidence: evidence.clone(),
        };
        site.id = build_cross_language_site_id(&site).map_err(anyhow::Error::from)?;
        let mut edge = GraphEdge {
            id: String::new(),
            source,
            target,
            kind: CrossLanguageRelationKind::BindsNativeSymbol
                .as_str()
                .to_owned(),
            site_id: Some(site.id.clone()),
            phase: Phase::Source,
            environment: None,
            profile_id: self.profile_id.clone(),
            condition,
            resolution_status: classification.status,
            precision: classification.precision,
            generated: false,
            evidence,
        };
        edge.id = build_cross_language_edge_id(&edge).map_err(anyhow::Error::from)?;
        insert_same(&mut self.sites, site.id.clone(), site, "FFI site")?;
        insert_same(&mut self.edges, edge.id.clone(), edge, "FFI edge")?;
        match classification.status {
            ResolutionStatus::External => self.external_count += 1,
            ResolutionStatus::Unresolved => {
                self.unresolved_count += 1;
                if let Some(reason) = classification.reason {
                    self.insert_reason(reason);
                }
            }
            ResolutionStatus::Resolved | ResolutionStatus::Candidates => {
                self.insert_reason("ffi-link-evidence-pending");
            }
        }
        Ok(())
    }

    fn source_node(&mut self, declaration: &FfiDeclaration) -> Result<String> {
        let id = stable_id_from_value(
            "symbol",
            &json!({
                "ffi_inventory_version": FFI_FORMAT_VERSION,
                "language": declaration.language,
                "direction": declaration.direction,
                "locator": declaration.locator,
                "start_line": declaration.start_line,
                "start_column": declaration.start_column,
                "symbol": declaration.symbol,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "symbol".to_owned(),
            locator: format!(
                "source:{}:{}:{}",
                declaration.language.as_str(),
                declaration.locator,
                declaration.start_line
            ),
            display_name: None,
            properties: BTreeMap::from([
                (
                    "ffi_language".to_owned(),
                    Value::String(declaration.language.as_str().to_owned()),
                ),
                (
                    "ffi_direction".to_owned(),
                    Value::String(declaration.direction.as_str().to_owned()),
                ),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node, "FFI source node")?;
        Ok(id)
    }

    fn native_symbol_node(
        &mut self,
        declaration: &FfiDeclaration,
        target_profile_id: &str,
    ) -> Result<String> {
        let coordinate = canonical_json(&json!({
            "abi": declaration.abi,
            "direction": declaration.direction,
            "language": declaration.language,
            "library_request": declaration.library,
            "symbol_request": declaration.symbol,
            "target_profile_id": target_profile_id,
        }));
        let identity = CrossLanguageCanonicalIdentity {
            contract_version: CROSS_LANGUAGE_CONTRACT_VERSION.to_owned(),
            format: CrossLanguageFormat::Ffi,
            repository_contract_locator: declaration.locator.clone(),
            format_version: FFI_FORMAT_VERSION.to_owned(),
            coordinate,
            profile_id: self.profile_id.clone(),
        };
        let id = cross_language_node_id(CrossLanguageNodeKind::NativeSymbol, &identity);
        let node = GraphNode {
            id: id.clone(),
            kind: CrossLanguageNodeKind::NativeSymbol.as_str().to_owned(),
            locator: format!("cross-language:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                (
                    "canonical_identity".to_owned(),
                    serde_json::to_value(identity)?,
                ),
                ("format".to_owned(), Value::String("ffi".to_owned())),
                (
                    "profile_id".to_owned(),
                    Value::String(self.profile_id.clone()),
                ),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node, "FFI native symbol node")?;
        self.cross_node_ids.insert(id.clone());
        Ok(id)
    }

    fn boundary_node(
        &mut self,
        declaration: &FfiDeclaration,
        target_profile_id: &str,
        reason: Option<&str>,
    ) -> Result<String> {
        let reason = reason.unwrap_or("ffi-declaration-is-unresolved");
        let id = stable_id_from_value(
            "unknown_target",
            &json!({
                "ffi_inventory_version": FFI_FORMAT_VERSION,
                "language": declaration.language,
                "locator": declaration.locator,
                "target_profile_id": target_profile_id,
                "reason": reason,
                "symbol": declaration.symbol,
            }),
        );
        let node = GraphNode {
            id: id.clone(),
            kind: "unknown_target".to_owned(),
            locator: format!("unknown:ffi:{id}"),
            display_name: None,
            properties: BTreeMap::from([
                ("format".to_owned(), Value::String("ffi".to_owned())),
                ("reason_code".to_owned(), Value::String(reason.to_owned())),
            ]),
        };
        insert_same(&mut self.nodes, id.clone(), node, "FFI boundary node")?;
        Ok(id)
    }

    fn insert_reason(&mut self, reason: &str) {
        insert_reason(&mut self.reasons, reason);
    }
}

#[derive(Clone, Copy)]
struct Classification {
    status: ResolutionStatus,
    precision: Precision,
    mapping: CrossLanguageMappingKind,
    reason: Option<&'static str>,
}

fn classify(declaration: &FfiDeclaration) -> Classification {
    if let Some(reason) = declaration.reason.as_deref() {
        return Classification {
            status: ResolutionStatus::Unresolved,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::Unresolved,
            reason: Some(match reason {
                "ffi-unsupported-abi" => "ffi-unsupported-abi",
                "ffi-rust-export-symbol-not-stable" => "ffi-rust-export-symbol-not-stable",
                "ffi-web-wildcard-native-binding" => "ffi-web-wildcard-native-binding",
                _ => "ffi-declaration-is-unresolved",
            }),
        };
    }
    if declaration.symbol.is_none() {
        return Classification {
            status: ResolutionStatus::Unresolved,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::Unresolved,
            reason: Some("ffi-symbol-request-missing"),
        };
    }
    if declaration.direction == FfiDirection::Export {
        return Classification {
            status: ResolutionStatus::Resolved,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::ManualDeclaration,
            reason: None,
        };
    }
    if declaration.language == FfiLanguage::Web
        && declaration
            .library
            .as_deref()
            .is_some_and(|library| !library.starts_with('.') && !library.starts_with('/'))
    {
        return Classification {
            status: ResolutionStatus::External,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::ExternalReference,
            reason: None,
        };
    }
    if declaration.library.is_some() {
        Classification {
            status: ResolutionStatus::Candidates,
            precision: Precision::Overapprox,
            mapping: CrossLanguageMappingKind::ClosedCandidates,
            reason: None,
        }
    } else {
        Classification {
            status: ResolutionStatus::Unresolved,
            precision: Precision::Heuristic,
            mapping: CrossLanguageMappingKind::Unresolved,
            reason: Some("ffi-library-request-missing"),
        }
    }
}

fn ffi_condition(declaration: &FfiDeclaration, target_profile_id: &str) -> Condition {
    let mut conditions = vec![
        Condition::Eq {
            key: "ffi.abi".to_owned(),
            value: Value::String(declaration.abi.clone()),
        },
        Condition::Eq {
            key: "ffi.direction".to_owned(),
            value: Value::String(declaration.direction.as_str().to_owned()),
        },
        Condition::Eq {
            key: "ffi.language".to_owned(),
            value: Value::String(declaration.language.as_str().to_owned()),
        },
        Condition::Eq {
            key: "ffi.target_profile_id".to_owned(),
            value: Value::String(target_profile_id.to_owned()),
        },
    ];
    if let Some(library) = &declaration.library {
        conditions.push(Condition::Eq {
            key: "ffi.library_request".to_owned(),
            value: Value::String(library.clone()),
        });
    }
    Condition::All { conditions }.canonicalize()
}

fn cgo_preamble(source: &str, import_line_index: usize) -> Vec<String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut index = import_line_index;
    while index > 0 {
        let line = lines[index - 1].trim();
        if let Some(comment) = line.strip_prefix("//") {
            result.push(comment.trim().to_owned());
            index -= 1;
        } else if line.is_empty() {
            index -= 1;
        } else {
            break;
        }
    }
    result.reverse();
    if !result.is_empty() {
        return result;
    }
    let prefix = lines[..import_line_index].join("\n");
    let Some(end) = prefix.rfind("*/") else {
        return Vec::new();
    };
    let Some(start) = prefix[..end].rfind("/*") else {
        return Vec::new();
    };
    prefix[start + 2..end]
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim().to_owned())
        .collect()
}

fn cgo_library(preamble: &[String]) -> Option<String> {
    preamble
        .iter()
        .filter(|line| line.contains("LDFLAGS:"))
        .flat_map(|line| line.split_ascii_whitespace())
        .find_map(|token| token.strip_prefix("-l"))
        .filter(|value| safe_atom(value))
        .map(str::to_owned)
}

fn cgo_declarations(preamble: &[String]) -> Vec<String> {
    let mut symbols = preamble
        .iter()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#')
                || line.starts_with("typedef")
                || !line.ends_with(';')
                || !line.contains('(')
            {
                return None;
            }
            let before = line.split_once('(')?.0;
            before
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .rfind(|part| !part.is_empty())
                .filter(|symbol| safe_symbol(symbol))
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    symbols.sort();
    symbols.dedup();
    symbols
}

fn foreign_item_symbol(line: &str) -> Option<String> {
    let item = line.rsplit_once('{').map_or(line, |(_, item)| item);
    let item = strip_rust_attributes(item.trim_start());
    let item = strip_rust_item_modifier(item, "pub");
    let item = strip_rust_item_modifier(item, "unsafe");
    let item = strip_rust_item_modifier(item, "safe");
    item.strip_prefix("fn ")
        .and_then(identifier_prefix)
        .or_else(|| item.strip_prefix("static ").and_then(identifier_prefix))
}

fn identifier_after(line: &str, keyword: &str) -> Option<String> {
    let (_, rest) = line.split_once(keyword)?;
    identifier_prefix(rest.trim_start())
}

fn identifier_prefix(rest: &str) -> Option<String> {
    let symbol = rest
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next()?;
    safe_symbol(symbol).then(|| symbol.to_owned())
}

fn quoted_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let (_, rest) = line.split_once(marker)?;
    let quote = rest.find('"')?;
    let value = &rest[quote + 1..];
    let end = value.find('"')?;
    Some(&value[..end])
}

fn attribute_string(line: &str, key: &str) -> Option<String> {
    let (_, rest) = line.split_once(key)?;
    let quote = rest.find('"')?;
    let value = &rest[quote + 1..];
    let end = value.find('"')?;
    Some(value[..end].to_owned())
}

fn code_without_comments(
    line: &str,
    block_comment_depth: &mut usize,
    raw_string_hashes: &mut Option<usize>,
    quoted_string: &mut Option<char>,
    single_quote_strings: bool,
) -> String {
    let characters = line.chars().collect::<Vec<_>>();
    let mut result = String::with_capacity(line.len());
    let mut index = 0;
    let mut quote = *quoted_string;
    let mut suppress_quote_contents = quote.is_some();
    if let Some(terminator) = quote {
        result.push(terminator);
    }
    while index < characters.len() {
        if let Some(hashes) = *raw_string_hashes {
            if let Some(after_end) = raw_string_end(&characters, index, hashes) {
                *raw_string_hashes = None;
                index = after_end;
                continue;
            }
            break;
        }
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        if *block_comment_depth > 0 {
            if !single_quote_strings && character == '/' && next == Some('*') {
                *block_comment_depth = block_comment_depth.saturating_add(1);
                index += 2;
            } else if character == '*' && next == Some('/') {
                *block_comment_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(terminator) = quote {
            if !suppress_quote_contents {
                result.push(character);
            }
            if character == '\\' {
                if let Some(escaped) = next {
                    if !suppress_quote_contents {
                        result.push(escaped);
                    }
                    index += 2;
                    continue;
                }
            } else if character == terminator {
                quote = None;
                if suppress_quote_contents {
                    result.push(terminator);
                    suppress_quote_contents = false;
                }
            }
            index += 1;
            continue;
        }
        if character == '/' && next == Some('/') {
            break;
        }
        if character == '/' && next == Some('*') {
            *block_comment_depth = 1;
            index += 2;
            continue;
        }
        if !single_quote_strings
            && let Some((after_start, hashes)) = raw_string_start(&characters, index)
        {
            result.push_str("\"\"");
            if let Some(after_end) = raw_string_end(&characters, after_start, hashes) {
                index = after_end;
            } else {
                *raw_string_hashes = Some(hashes);
                break;
            }
            continue;
        }
        let rust_character_literal = !single_quote_strings
            && character == '\''
            && (characters.get(index + 2) == Some(&'\'')
                || characters.get(index + 1) == Some(&'\\')
                    && characters.get(index + 3) == Some(&'\''));
        if matches!(character, '"' | '`')
            || character == '\'' && (single_quote_strings || rust_character_literal)
        {
            quote = Some(character);
        }
        result.push(character);
        index += 1;
    }
    *quoted_string = quote;
    result
}

fn raw_string_start(characters: &[char], index: usize) -> Option<(usize, usize)> {
    if index > 0 && (characters[index - 1].is_ascii_alphanumeric() || characters[index - 1] == '_')
    {
        return None;
    }
    let r_index = match (characters.get(index), characters.get(index + 1)) {
        (Some('r'), _) => index,
        (Some('b' | 'c'), Some('r')) => index + 1,
        _ => return None,
    };
    let mut quote_index = r_index + 1;
    while characters.get(quote_index) == Some(&'#') {
        quote_index += 1;
    }
    (characters.get(quote_index) == Some(&'"'))
        .then_some((quote_index + 1, quote_index - r_index - 1))
}

fn raw_string_end(characters: &[char], mut index: usize, hashes: usize) -> Option<usize> {
    while index < characters.len() {
        if characters[index] == '"'
            && (0..hashes).all(|offset| characters.get(index + 1 + offset) == Some(&'#'))
        {
            return Some(index + 1 + hashes);
        }
        index += 1;
    }
    None
}

struct QuotedLiteral {
    value: String,
    start: usize,
    end: usize,
}

fn quoted_literal_spans(line: &str) -> Vec<QuotedLiteral> {
    let mut result = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let quote = bytes[index];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            index += 1;
            continue;
        }
        let quote_start = index;
        let start = index + 1;
        index = start;
        while index < bytes.len() && bytes[index] != quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
            } else {
                index += 1;
            }
        }
        if index < bytes.len()
            && let Some(value) = line.get(start..index)
            && bounded_text(value)
            && !value.contains(['?', '#', '\\'])
        {
            result.push(QuotedLiteral {
                value: value.to_owned(),
                start: quote_start,
                end: index + 1,
            });
        }
        index = index.saturating_add(1);
    }
    result
}

fn web_native_binding_literal_is_admitted(
    line: &str,
    literal_start: usize,
    literal_end: usize,
) -> bool {
    let statement = line.trim_start();
    if web_type_only_statement(statement) {
        return false;
    }
    let Some(prefix) = line.get(..literal_start) else {
        return false;
    };
    if call_prefix_ends_with(prefix, "require") || call_prefix_ends_with(prefix, "import") {
        return line
            .get(literal_end..)
            .is_some_and(|suffix| matches!(suffix.trim_start().chars().next(), Some(')' | ',')));
    }

    let prefix = prefix.trim();
    if statement.starts_with("declare module ") {
        return prefix == "declare module";
    }
    if statement.starts_with("import ") {
        return prefix == "import" || token_suffix(prefix, "from");
    }
    statement.starts_with("export ") && token_suffix(prefix, "from")
}

fn web_native_binding_syntax(line: &str) -> bool {
    let statement = line.trim_start();
    if web_type_only_statement(statement) {
        return false;
    }
    statement.starts_with("import ")
        || statement.starts_with("export ")
        || statement.starts_with("declare module ")
        || ["require", "import"].iter().any(|function| {
            line.match_indices('(').any(|(index, _)| {
                line.get(..=index)
                    .is_some_and(|prefix| call_prefix_ends_with(prefix, function))
            })
        })
}

fn web_type_only_statement(statement: &str) -> bool {
    if statement.starts_with("import type ") || statement.starts_with("export type ") {
        return true;
    }
    let clause = statement
        .strip_prefix("import ")
        .or_else(|| statement.strip_prefix("export "))
        .and_then(|rest| rest.strip_prefix('{'))
        .and_then(|rest| rest.split_once('}'))
        .filter(|(_, suffix)| token_prefix(suffix.trim_start(), "from"))
        .map(|(clause, _)| clause);
    clause.is_some_and(|clause| {
        let entries = clause
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect::<Vec<_>>();
        !entries.is_empty() && entries.into_iter().all(web_inline_type_specifier)
    })
}

fn web_inline_type_specifier(entry: &str) -> bool {
    let Some(rest) = entry.strip_prefix("type") else {
        return false;
    };
    if !rest.starts_with(char::is_whitespace) {
        return false;
    }
    let rest = rest.trim_start();
    !rest.is_empty() && !rest.starts_with("as ")
}

fn call_prefix_ends_with(prefix: &str, function: &str) -> bool {
    let Some(before_parenthesis) = prefix.trim_end().strip_suffix('(') else {
        return false;
    };
    token_suffix(before_parenthesis.trim_end(), function)
}

fn token_suffix(value: &str, token: &str) -> bool {
    let Some(prefix) = value.strip_suffix(token) else {
        return false;
    };
    prefix
        .chars()
        .next_back()
        .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
}

fn token_prefix(value: &str, token: &str) -> bool {
    value.strip_prefix(token).is_some_and(|suffix| {
        suffix
            .chars()
            .next()
            .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    })
}

fn web_binding_symbol(line: &str) -> Option<String> {
    if let Some(start) = line.find('{')
        && let Some(end) = line[start + 1..].find('}')
    {
        return line[start + 1..start + 1 + end]
            .split([',', ':'])
            .map(str::trim)
            .find(|value| safe_symbol(value))
            .map(str::to_owned);
    }
    if line.trim_start().starts_with("import ") {
        let rest = line.trim_start()["import ".len()..].trim_start();
        let symbol = rest
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .trim_end_matches(',');
        if safe_symbol(symbol) {
            return Some(symbol.to_owned());
        }
    }
    None
}

fn generated_source(source: &str) -> bool {
    let header = source.lines().take(8).collect::<Vec<_>>().join("\n");
    header.contains("@generated")
        || header.to_ascii_lowercase().contains("code generated")
            && header.to_ascii_lowercase().contains("do not edit")
}

fn has_ffi_signal(source: &str, language: FfiLanguage) -> bool {
    match language {
        FfiLanguage::Rust => source.contains("extern \"") || source.contains("link_name"),
        FfiLanguage::Go => source.contains("import \"C\"") || source.contains("//export "),
        FfiLanguage::Web => source.contains(".node") || source.contains("process.dlopen("),
    }
}

fn unsupported_abi_reason(abi: &str) -> Option<String> {
    (!matches!(
        abi,
        "c" | "c-unwind" | "system" | "system-unwind" | "node-api"
    ))
    .then(|| "ffi-unsupported-abi".to_owned())
}

fn canonical_abi(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn brace_delta(line: &str) -> i32 {
    line.chars()
        .map(|character| match character {
            '{' => 1,
            '}' => -1,
            _ => 0,
        })
        .sum()
}

fn is_extern_block_header(line: &str) -> bool {
    if line.starts_with("type ") {
        return false;
    }
    let Some(extern_index) = line.find("extern \"") else {
        return false;
    };
    if !rust_extern_prefix_is_admitted(&line[..extern_index]) {
        return false;
    }
    let Some(brace_index) = line[extern_index..]
        .find('{')
        .map(|index| extern_index + index)
    else {
        return false;
    };
    line[extern_index..]
        .find("fn ")
        .map(|index| brace_index < extern_index + index)
        .unwrap_or(true)
}

fn is_extern_function_declaration(line: &str) -> bool {
    let Some(extern_index) = line.find("extern \"") else {
        return false;
    };
    if !rust_extern_prefix_is_admitted(&line[..extern_index]) {
        return false;
    }
    let Some(abi) = quoted_after(&line[extern_index..], "extern") else {
        return false;
    };
    let marker = format!("\"{abi}\"");
    line[extern_index..]
        .split_once(&marker)
        .is_some_and(|(_, suffix)| suffix.trim_start().starts_with("fn "))
}

fn rust_extern_prefix_is_admitted(prefix: &str) -> bool {
    let prefix = strip_rust_attributes(prefix.trim());
    let prefix = strip_rust_visibility(prefix);
    strip_rust_item_modifier(prefix, "unsafe").is_empty()
}

fn strip_rust_attributes(mut value: &str) -> &str {
    loop {
        let trimmed = value.trim_start();
        let Some(attribute) = trimmed.strip_prefix("#[") else {
            return trimmed;
        };
        let Some(end) = attribute.find(']') else {
            return trimmed;
        };
        value = &attribute[end + 1..];
    }
}

fn strip_rust_visibility(value: &str) -> &str {
    let value = value.trim_start();
    let Some(rest) = value.strip_prefix("pub") else {
        return value;
    };
    if rest.is_empty() || rest.starts_with(char::is_whitespace) {
        return rest.trim_start();
    }
    let Some(restricted) = rest.strip_prefix('(') else {
        return value;
    };
    let Some(end) = restricted.find(')') else {
        return value;
    };
    restricted[end + 1..].trim_start()
}

fn strip_rust_item_modifier<'a>(value: &'a str, modifier: &str) -> &'a str {
    let value = value.trim_start();
    value
        .strip_prefix(modifier)
        .filter(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        .map_or(value, str::trim_start)
}

fn safe_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.$@-".contains(character))
}

fn safe_atom(value: &str) -> bool {
    safe_symbol(value) && !value.starts_with('-')
}

fn source_language(path: &Path) -> Option<FfiLanguage> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => Some(FfiLanguage::Rust),
        Some("go") => Some(FfiLanguage::Go),
        Some("js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts") => Some(FfiLanguage::Web),
        _ => None,
    }
}

fn admit_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    !entry.file_type().is_dir()
        || !matches!(
            entry.file_name().to_str(),
            Some(".git" | "node_modules" | "target" | "vendor")
        )
}

fn relative_locator(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .context("FFI source escaped its canonical scan root")?;
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .context("FFI source locator is not valid UTF-8")?;
                if value.is_empty() || value.contains(['\\', '?', '#']) {
                    bail!("FFI source locator is unsafe");
                }
                components.push(value);
            }
            _ => bail!("FFI source locator is not repository-relative"),
        }
    }
    if components.is_empty() {
        bail!("FFI source locator is empty");
    }
    Ok(components.join("/"))
}

fn insert_same<T: PartialEq>(
    values: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> Result<()> {
    if let Some(existing) = values.get(&key)
        && existing != &value
    {
        bail!("{label} identity collides");
    }
    values.insert(key, value);
    Ok(())
}

fn insert_reason(reasons: &mut BTreeSet<String>, reason: &str) {
    if reasons.len() < MAX_REASONS || reasons.contains(reason) {
        reasons.insert(reason.chars().take(256).collect());
    }
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_BOUNDED_TEXT && !value.chars().any(char::is_control)
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn digest_value(value: &impl Serialize) -> String {
    digest_bytes(canonical_json(&serde_json::to_value(value).expect("serializable")).as_bytes())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use depgraph_protocol::{
        CROSS_LANGUAGE_COMPLETENESS_PROPERTY, CrossLanguageCompletenessLedger, Precision,
        ResolutionStatus, validate_cross_language_adapter_delta,
    };
    use tempfile::tempdir;

    use super::*;

    fn profiles(ids: &[&str]) -> Vec<Profile> {
        ids.iter()
            .map(|id| Profile {
                id: (*id).to_owned(),
                language: "polyglot".to_owned(),
                toolchain: None,
                command: None,
                target: None,
                features: Vec::new(),
                environment: BTreeMap::new(),
                source_revision: None,
                properties: BTreeMap::new(),
            })
            .collect()
    }

    #[test]
    fn rust_go_and_web_declarations_preserve_profile_abi_and_non_exact_imports() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("native.rs"),
            r#"
#[link(name = "crypto")]
unsafe extern "C" {
    fn EVP_sha256();
}

#[unsafe(no_mangle)]
pub extern "C" fn local_callback() {}
"#,
        )
        .unwrap();
        fs::write(
            root.path().join("native.go"),
            r#"
package native
/*
#cgo LDFLAGS: -lssl
int SSL_library_init(void);
*/
import "C"

//export GoCallback
func GoCallback() {}
"#,
        )
        .unwrap();
        fs::write(
            root.path().join("native.ts"),
            "import { hash } from './build/Release/addon.node';\n",
        )
        .unwrap();

        let delta = scan_ffi_repository(root.path(), &profiles(&["linux-x86_64"]))
            .unwrap()
            .unwrap();
        validate_cross_language_adapter_delta(&delta).unwrap();
        assert_eq!(delta.sites.len(), 5);
        assert_eq!(
            delta
                .sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::Resolved)
                .count(),
            2
        );
        assert_eq!(
            delta
                .sites
                .iter()
                .filter(|site| {
                    site.resolution_status == ResolutionStatus::Candidates
                        && site.precision == Precision::Overapprox
                })
                .count(),
            3
        );
        assert!(delta.sites.iter().all(|site| {
            canonical_json(&serde_json::to_value(&site.condition).unwrap()).contains("linux-x86_64")
                && site
                    .evidence
                    .first()
                    .unwrap()
                    .properties
                    .contains_key("ffi_abi")
        }));
    }

    #[test]
    fn external_and_unresolved_declarations_never_become_exact() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("boundary.rs"),
            r#"
extern "Rust" {
    fn unstable();
}
unsafe extern "C" {
    fn missing_library();
}
"#,
        )
        .unwrap();
        fs::write(
            root.path().join("boundary.ts"),
            "import native from 'vendor-addon.node';\ndeclare module '*.node';\n",
        )
        .unwrap();

        let delta = scan_ffi_repository(root.path(), &profiles(&["windows-x86_64"]))
            .unwrap()
            .unwrap();
        assert!(delta.sites.iter().any(|site| {
            site.resolution_status == ResolutionStatus::External
                && site.precision != Precision::Exact
        }));
        assert_eq!(
            delta
                .sites
                .iter()
                .filter(|site| site.resolution_status == ResolutionStatus::Unresolved)
                .count(),
            3
        );
        assert!(delta.sites.iter().all(|site| {
            site.resolution_status != ResolutionStatus::Resolved
                && site.precision != Precision::Exact
        }));
    }

    #[test]
    fn generated_macro_alias_and_dynamic_boundaries_are_reasoned_and_bounded() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("generated.rs"),
            "// @generated\nextern \"C\" { fn generated(); }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("macro.rs"),
            "macro_rules! native { () => { extern \"C\" { fn hidden(); } } }\n",
        )
        .unwrap();
        fs::write(
            root.path().join("alias.go"),
            "package alias\n//go:linkname local remote\n//export Missing\n",
        )
        .unwrap();
        fs::write(
            root.path().join("dynamic.ts"),
            "// import ignored from './comment.node';\n/* require('./block.node') */\nprocess.dlopen(module, computedPath);\n",
        )
        .unwrap();

        let delta = scan_ffi_repository(root.path(), &profiles(&["macos-aarch64"]))
            .unwrap()
            .unwrap();
        let ledger: CrossLanguageCompletenessLedger = serde_json::from_value(
            delta.profile.properties[CROSS_LANGUAGE_COMPLETENESS_PROPERTY].clone(),
        )
        .unwrap();
        let entry = &ledger.entries[0];
        assert_eq!(entry.status, CrossLanguageCapabilityStatus::Incomplete);
        assert!(entry.skipped_count >= 4);
        assert!(delta.sites.is_empty());
        assert!(
            entry
                .reasons
                .contains(&"ffi-generated-source-skipped".to_owned())
        );
        assert!(
            entry
                .reasons
                .contains(&"ffi-rust-macro-boundary".to_owned())
        );
        assert!(
            entry
                .reasons
                .contains(&"ffi-go-unsafe-linkname-boundary".to_owned())
        );
        assert!(
            entry
                .reasons
                .contains(&"ffi-cgo-export-declaration-missing-function".to_owned())
        );
        assert!(
            entry
                .reasons
                .contains(&"ffi-web-dynamic-native-binding".to_owned())
        );
    }

    #[test]
    fn rust_comments_and_inline_extern_blocks_do_not_leak_false_declarations() {
        let source = r####"
// extern "C" { fn line_comment(); }
/*
extern "C" { fn block_comment(); }
*/
let standard = "extern \"C\" { fn standard_string(); }";
let multiline_standard = "prefix
extern \"C\" { fn multiline_standard_string(); }
suffix";
let raw = r#"extern "C" { fn raw_string(); }"#;
let multiline = r##"
extern "C" { fn multiline_raw_string(); }
"##;
type Callback = extern "C" fn();
pub type UnsafeCallback = unsafe extern "C" fn();
extern "C" { fn admitted(); }
fn ordinary() {}
static ORDINARY: i32 = 0;
"####;
        let (declarations, boundaries) = parse_rust("native.rs", "sha256:test", source);
        assert!(boundaries.is_empty());
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].symbol.as_deref(), Some("admitted"));
    }

    #[test]
    fn web_native_bindings_require_an_import_require_or_declaration_context() {
        let source = r#"
const example = "addon.node";
const another = './not-a-load.node';
const multiline = `prefix
require("./multiline-template.node")
suffix`;
import { hash } from './real.node';
const native = require("./required.node");
declare module '*.node';
import type { NativeType } from './type-only.node';
export type { NativeExport } from './export-type-only.node';
import { type InlineType } from './inline-type-only.node';
export { type InlineExport } from './inline-export-type-only.node';
import { type TrailingType, } from './trailing-type-only.node';
export { type TrailingExport, } from './trailing-export-type-only.node';
import { type Metadata, load } from './mixed.node';
import { type as runtimeType } from './type-name-value.node';
console.log("also-not-a-load.node");
"#;
        let (declarations, boundaries) = parse_web("native.ts", "sha256:test", source);
        assert!(boundaries.is_empty());
        assert_eq!(
            declarations
                .iter()
                .filter_map(|declaration| declaration.library.as_deref())
                .collect::<Vec<_>>(),
            vec![
                "./real.node",
                "./required.node",
                "*.node",
                "./mixed.node",
                "./type-name-value.node"
            ]
        );
    }

    #[test]
    fn inventory_is_checkout_independent_and_profile_conditioned() {
        let first = tempdir().unwrap();
        let second = tempdir().unwrap();
        for root in [first.path(), second.path()] {
            fs::write(
                root.join("native.rs"),
                "#[link(name = \"z\")]\nextern \"C\" {\nfn zed();\n}\n",
            )
            .unwrap();
        }
        let profiles = profiles(&["linux", "windows"]);
        let first = scan_ffi_repository(first.path(), &profiles)
            .unwrap()
            .unwrap();
        let second = scan_ffi_repository(second.path(), &profiles)
            .unwrap()
            .unwrap();
        assert_eq!(
            canonical_json(&serde_json::to_value(first).unwrap()),
            canonical_json(&serde_json::to_value(second).unwrap())
        );
    }

    #[test]
    fn inventory_entry_limit_fails_closed() {
        let mut inventory_entries = MAX_FFI_INVENTORY_ENTRIES - 1;
        record_ffi_inventory_entry(&mut inventory_entries).unwrap();
        assert_eq!(inventory_entries, MAX_FFI_INVENTORY_ENTRIES);
        assert!(record_ffi_inventory_entry(&mut inventory_entries).is_err());
    }
}
