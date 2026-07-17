//! Deterministic Rust HIR semantic graph extraction.
//!
//! This pass consumes only the already-confined [`SafeProjectModel`] and emits
//! definitions, imports, re-exports, type references, and exact or conservative
//! candidate calls. All output is accumulated in a delta so the scanner can
//! validate and merge it atomically with the syntax graph.

use crate::{
    ADAPTER_VERSION, EXTRACTOR as SOURCE_EXTRACTOR, RUST_ANALYZER_CRATE_VERSION,
    RUST_ANALYZER_REVISION,
    hir_project::SafeProjectModel,
    source::{
        CallOccurrenceKey, CallSyntaxKind, Occurrence, SourceSpan, TypeUseContext,
        TypeUseOccurrenceKey, UseOccurrenceKey,
    },
};
use anyhow::{Result, bail};
use depgraph_protocol::{
    Condition, DependencySite, Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision,
    Properties, ResolutionStatus, stable_id_from_value,
};
use ra_ap_hir::{
    Adt, AsAssocItem, AssocItem, AssocItemContainer, CallableKind, Crate, GenericDef, GenericParam,
    HasVisibility, Impl, InFile, Module, ModuleDef, Mutability, PathResolution,
    PathResolutionPerNs, Semantics, Type, Visibility, attach_db,
};
use ra_ap_ide_db::{
    RootDatabase,
    base_db::FileId,
    defs::{Definition, NameClass, NameRefClass},
    line_index,
};
use ra_ap_syntax::{AstNode, SyntaxNode, TextRange, ast};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const EXTRACTOR: &str = "rust-analyzer-hir";

#[derive(Clone, Debug)]
pub(crate) struct SemanticCrateContext {
    pub package_locator: String,
    pub module_nodes: BTreeMap<Vec<String>, String>,
    pub ambiguous_module_paths: BTreeSet<Vec<String>>,
    pub cfg: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticIssue {
    pub code: &'static str,
    pub path: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SemanticDelta {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub sites: Vec<DependencySite>,
    pub refined_use_keys: BTreeSet<UseOccurrenceKey>,
    pub refined_type_use_keys: BTreeSet<TypeUseOccurrenceKey>,
    pub refined_call_keys: BTreeSet<CallOccurrenceKey>,
    pub issues: Vec<SemanticIssue>,
}

#[derive(Clone, Debug)]
struct SourceLocation {
    path: String,
    start_line: u32,
    start_column: u32,
    end_line: u32,
    end_column: u32,
    generated: bool,
}

impl SourceLocation {
    fn from_span(path: &str, span: SourceSpan) -> Self {
        Self {
            path: path.into(),
            start_line: span.start_line,
            start_column: span.start_column,
            end_line: span.end_line,
            end_column: span.end_column,
            generated: false,
        }
    }

    fn as_value(&self) -> Value {
        json!({
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        })
    }
}

struct Extractor<'a> {
    model: &'a SafeProjectModel,
    db: &'a RootDatabase,
    sema: Semantics<'a, RootDatabase>,
    contexts: &'a BTreeMap<String, SemanticCrateContext>,
    occurrences_by_path: &'a BTreeMap<String, Vec<Occurrence>>,
    profile_id: &'a str,
    paths_by_file: BTreeMap<u32, String>,
    crate_keys_by_base: HashMap<ra_ap_ide_db::base_db::Crate, String>,
    nodes: BTreeMap<String, GraphNode>,
    edges: BTreeMap<String, GraphEdge>,
    sites: BTreeMap<String, DependencySite>,
    refined_use_keys: BTreeSet<UseOccurrenceKey>,
    refined_type_use_keys: BTreeSet<TypeUseOccurrenceKey>,
    refined_call_keys: BTreeSet<CallOccurrenceKey>,
    node_ids: HashMap<Definition, String>,
    resolvers: HashMap<Definition, String>,
    impl_ids: HashMap<Impl, String>,
    impl_resolvers: HashMap<Impl, String>,
    external_crates: BTreeMap<(String, String), String>,
    external_aliases: BTreeMap<(String, Vec<String>, String), BTreeSet<ExternalAlias>>,
    closure_nodes_by_range: HashMap<(u32, TextRange), String>,
    closure_nodes_by_callable: BTreeMap<String, String>,
    generic_instances_by_range: HashMap<(u32, TextRange), String>,
    fn_pointer_targets: HashMap<ra_ap_hir::Local, CallCandidateSet>,
    issues: BTreeMap<(String, Option<String>, String), SemanticIssue>,
}

#[derive(Clone, Debug)]
struct SemanticResolution {
    target_ids: Vec<String>,
    status: ResolutionStatus,
    precision: Precision,
    reason: Option<String>,
}

#[derive(Clone, Debug)]
enum ClassifiedTarget {
    Concrete { node_id: String, external: bool },
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ExternalAlias {
    target_specifier: String,
    external_name: String,
    external_kind: String,
    condition_terms: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct CallCandidateSet {
    target_ids: BTreeSet<String>,
    complete: bool,
}

impl CallCandidateSet {
    fn incomplete() -> Self {
        Self::default()
    }

    fn exact(target_id: String) -> Self {
        Self {
            target_ids: BTreeSet::from([target_id]),
            complete: true,
        }
    }

    fn union(mut self, other: Self) -> Self {
        self.target_ids.extend(other.target_ids);
        self.complete &= other.complete;
        self
    }
}

pub(crate) fn extract_semantic_delta(
    model: &SafeProjectModel,
    contexts: &BTreeMap<String, SemanticCrateContext>,
    occurrences_by_path: &BTreeMap<String, Vec<Occurrence>>,
    profile_id: &str,
) -> Result<SemanticDelta> {
    let db = model.database();
    let crate_keys_by_base = model
        .crate_instances()
        .iter()
        .map(|(key, krate)| (*krate, key.clone()))
        .collect();
    let paths_by_file = model
        .snapshot()
        .files
        .iter()
        .map(|file| (file.file_id, file.path.clone()))
        .collect();
    let external_crates = model
        .snapshot()
        .externals
        .iter()
        .map(|external| {
            (
                (external.from_crate.clone(), external.name.clone()),
                serde_json::to_value(external.kind)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{:?}", external.kind)),
            )
        })
        .collect();
    let mut extractor = Extractor {
        model,
        db,
        sema: Semantics::new(db),
        contexts,
        occurrences_by_path,
        profile_id,
        paths_by_file,
        crate_keys_by_base,
        nodes: BTreeMap::new(),
        edges: BTreeMap::new(),
        sites: BTreeMap::new(),
        refined_use_keys: BTreeSet::new(),
        refined_type_use_keys: BTreeSet::new(),
        refined_call_keys: BTreeSet::new(),
        node_ids: HashMap::new(),
        resolvers: HashMap::new(),
        impl_ids: HashMap::new(),
        impl_resolvers: HashMap::new(),
        external_crates,
        external_aliases: BTreeMap::new(),
        closure_nodes_by_range: HashMap::new(),
        closure_nodes_by_callable: BTreeMap::new(),
        generic_instances_by_range: HashMap::new(),
        fn_pointer_targets: HashMap::new(),
        issues: BTreeMap::new(),
    };
    attach_db(db, || extractor.extract())?;
    Ok(SemanticDelta {
        nodes: extractor.nodes.into_values().collect(),
        edges: extractor.edges.into_values().collect(),
        sites: extractor.sites.into_values().collect(),
        refined_use_keys: extractor.refined_use_keys,
        refined_type_use_keys: extractor.refined_type_use_keys,
        refined_call_keys: extractor.refined_call_keys,
        issues: extractor.issues.into_values().collect(),
    })
}

impl Extractor<'_> {
    fn extract(&mut self) -> Result<()> {
        let ambiguous_modules: Vec<_> = self
            .contexts
            .iter()
            .flat_map(|(crate_key, context)| {
                context
                    .ambiguous_module_paths
                    .iter()
                    .cloned()
                    .map(|path| (crate_key.clone(), path))
            })
            .collect();
        for (crate_key, path) in ambiguous_modules {
            self.issue(
                "RUST_HIR_SEMANTIC_MODULE_OWNER_AMBIGUOUS",
                None,
                format!(
                    "syntax module owner is ambiguous for {crate_key}::{}; exact HIR declarations were skipped",
                    path.join("::")
                ),
            );
        }
        let mut crates = Vec::new();
        for (key, base) in self.model.crate_instances() {
            let Some(krate) = Crate::all(self.db)
                .into_iter()
                .find(|candidate| candidate.base() == *base)
            else {
                bail!("rust-analyzer crate instance for {key} disappeared");
            };
            if self.contexts.contains_key(key) {
                crates.push((key.clone(), krate));
            } else {
                self.issue(
                    "RUST_HIR_SEMANTIC_CONTEXT_MISSING",
                    None,
                    format!("syntax owner context is missing for crate {key}"),
                );
            }
        }
        crates.sort_by(|left, right| left.0.cmp(&right.0));

        // Register crate-bound named definitions before cross-definition
        // relations. This avoids depending on declaration traversal order.
        for (key, krate) in &crates {
            self.extract_named_definitions(key, *krate)?;
        }
        for (key, krate) in &crates {
            self.extract_impls(key, *krate)?;
        }
        for (key, krate) in &crates {
            self.extract_trait_relations(key, *krate)?;
        }

        // source-to-def has a documented first-answer ambiguity when a file
        // belongs to more than one crate instance. Only use it for exact local
        // and generic-reference identities when the owning crate is unique.
        self.extract_unambiguous_source_definitions()?;
        Ok(())
    }

    fn extract_named_definitions(&mut self, crate_key: &str, krate: Crate) -> Result<()> {
        let mut modules: Vec<_> = krate
            .modules(self.db)
            .into_iter()
            .filter(|module| module.nearest_non_block_module(self.db) == *module)
            .collect();
        modules.sort_by_key(|module| self.module_path(*module));

        for module in modules {
            let module_path = self.module_path(module);
            if let Some(module_id) = self.module_owner(crate_key, &module_path) {
                let definition = Definition::Module(module);
                self.node_ids.insert(definition, module_id);
                self.resolvers
                    .insert(definition, self.module_resolver(crate_key, &module_path));
            }
            if !module.is_crate_root(self.db) {
                self.emit_module_declaration(crate_key, module, &module_path)?;
            }
            let Some(owner_id) = self.module_owner(crate_key, &module_path) else {
                self.issue(
                    "RUST_HIR_SEMANTIC_MODULE_OWNER_MISSING",
                    None,
                    format!(
                        "syntax module owner is missing for {}::{}",
                        crate_key,
                        module_path.join("::")
                    ),
                );
                continue;
            };
            let mut declarations = module.declarations(self.db);
            declarations.sort_by_key(|definition| self.module_def_sort_key(*definition));
            for definition in declarations {
                match definition {
                    ModuleDef::Module(_) | ModuleDef::BuiltinType(_) | ModuleDef::Macro(_) => {}
                    ModuleDef::Function(function) => {
                        let resolver = self.item_resolver(
                            crate_key,
                            &module_path,
                            function.name(self.db).as_str(),
                        );
                        if let Some(node_id) = self.emit_named_symbol(
                            crate_key,
                            Definition::Function(function),
                            &owner_id,
                            "function",
                            resolver,
                            "HIR function definition",
                        )? {
                            self.emit_type_parameters(
                                crate_key,
                                GenericDef::Function(function),
                                &node_id,
                            )?;
                        }
                    }
                    ModuleDef::Adt(adt) => {
                        self.emit_adt(crate_key, &owner_id, &module_path, adt)?;
                    }
                    ModuleDef::EnumVariant(_) => {}
                    ModuleDef::Const(constant) => {
                        if let Some(name) = constant.name(self.db) {
                            let resolver =
                                self.item_resolver(crate_key, &module_path, name.as_str());
                            self.emit_named_symbol(
                                crate_key,
                                Definition::Const(constant),
                                &owner_id,
                                "constant",
                                resolver,
                                "HIR constant definition",
                            )?;
                        }
                    }
                    ModuleDef::Static(static_) => {
                        let resolver = self.item_resolver(
                            crate_key,
                            &module_path,
                            static_.name(self.db).as_str(),
                        );
                        self.emit_named_symbol(
                            crate_key,
                            Definition::Static(static_),
                            &owner_id,
                            "static",
                            resolver,
                            "HIR static definition",
                        )?;
                    }
                    ModuleDef::Trait(trait_) => {
                        self.emit_trait(crate_key, &owner_id, &module_path, trait_)?;
                    }
                    ModuleDef::TypeAlias(alias) => {
                        let resolver = self.item_resolver(
                            crate_key,
                            &module_path,
                            alias.name(self.db).as_str(),
                        );
                        let node_id = self.emit_named_type(
                            crate_key,
                            Definition::TypeAlias(alias),
                            &owner_id,
                            "type_alias",
                            resolver,
                            "HIR type alias definition",
                        )?;
                        if let Some(node_id) = node_id {
                            self.emit_type_parameters(
                                crate_key,
                                GenericDef::TypeAlias(alias),
                                &node_id,
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn emit_module_declaration(
        &mut self,
        crate_key: &str,
        module: Module,
        module_path: &[String],
    ) -> Result<()> {
        let Some(child) = self.module_owner(crate_key, module_path) else {
            return Ok(());
        };
        let Some(parent) = module.parent(self.db) else {
            return Ok(());
        };
        let parent_path = self.module_path(parent);
        let Some(parent_id) = self.module_owner(crate_key, &parent_path) else {
            return Ok(());
        };
        let Some(range) = module.declaration_source_range(self.db) else {
            return Ok(());
        };
        if let Some(evidence) =
            self.evidence_from_range(crate_key, range, "HIR module declaration", "module")
        {
            self.add_relation(crate_key, "declares", &parent_id, &child, evidence)?;
        }
        Ok(())
    }

    fn emit_adt(
        &mut self,
        crate_key: &str,
        owner_id: &str,
        module_path: &[String],
        adt: Adt,
    ) -> Result<()> {
        let (type_kind, detail) = match adt {
            Adt::Struct(_) => ("struct", "HIR struct definition"),
            Adt::Enum(_) => ("enum", "HIR enum definition"),
            Adt::Union(_) => ("union", "HIR union definition"),
        };
        let resolver = self.item_resolver(crate_key, module_path, adt.name(self.db).as_str());
        let Some(type_id) = self.emit_named_type(
            crate_key,
            Definition::Adt(adt),
            owner_id,
            type_kind,
            resolver.clone(),
            detail,
        )?
        else {
            return Ok(());
        };
        self.emit_type_parameters(crate_key, GenericDef::Adt(adt), &type_id)?;

        match adt {
            Adt::Struct(struct_) => {
                for field in struct_.fields(self.db) {
                    self.emit_field(crate_key, &type_id, &resolver, field)?;
                }
            }
            Adt::Union(union) => {
                for field in union.fields(self.db) {
                    self.emit_field(crate_key, &type_id, &resolver, field)?;
                }
            }
            Adt::Enum(enum_) => {
                for variant in enum_.variants(self.db) {
                    let variant_resolver =
                        format!("{resolver}::{}", variant.name(self.db).as_str());
                    let Some(variant_id) = self.emit_named_symbol(
                        crate_key,
                        Definition::EnumVariant(variant),
                        &type_id,
                        "enum_variant",
                        variant_resolver.clone(),
                        "HIR enum variant definition",
                    )?
                    else {
                        continue;
                    };
                    for field in variant.fields(self.db) {
                        self.emit_field(crate_key, &variant_id, &variant_resolver, field)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn emit_field(
        &mut self,
        crate_key: &str,
        owner_id: &str,
        owner_resolver: &str,
        field: ra_ap_hir::Field,
    ) -> Result<()> {
        let resolver = format!("{owner_resolver}::{}", field.name(self.db).as_str());
        self.emit_named_symbol(
            crate_key,
            Definition::Field(field),
            owner_id,
            "field",
            resolver,
            "HIR field definition",
        )?;
        Ok(())
    }

    fn emit_trait(
        &mut self,
        crate_key: &str,
        owner_id: &str,
        module_path: &[String],
        trait_: ra_ap_hir::Trait,
    ) -> Result<()> {
        let resolver = self.item_resolver(crate_key, module_path, trait_.name(self.db).as_str());
        let Some(trait_id) = self.emit_named_type(
            crate_key,
            Definition::Trait(trait_),
            owner_id,
            "trait",
            resolver.clone(),
            "HIR trait definition",
        )?
        else {
            return Ok(());
        };
        self.emit_type_parameters(crate_key, GenericDef::Trait(trait_), &trait_id)?;
        for item in trait_.items(self.db) {
            self.emit_assoc_item(crate_key, &trait_id, &resolver, item)?;
        }
        Ok(())
    }

    fn extract_impls(&mut self, crate_key: &str, krate: Crate) -> Result<()> {
        let mut impls = Impl::all_in_crate(self.db, krate);
        impls.sort_by_key(|impl_| {
            self.definition_location(Definition::SelfType(*impl_))
                .map(|location| {
                    (
                        location.path,
                        location.start_line,
                        location.start_column,
                        location.end_line,
                        location.end_column,
                    )
                })
        });
        for impl_ in impls {
            let definition = Definition::SelfType(impl_);
            let Some(location) = self.definition_location(definition) else {
                self.issue(
                    "RUST_HIR_GENERATED_IMPL_SKIPPED",
                    None,
                    "impl has no exact inventory source".into(),
                );
                continue;
            };
            if location.generated {
                // Builtin derives and macro-expanded impls have only an
                // upmapped call-site range. Without complete expansion
                // provenance they must not be promoted to ordinary exact
                // anonymous definitions.
                self.issue(
                    "RUST_HIR_GENERATED_IMPL_SKIPPED",
                    Some(location.path),
                    "generated impl was skipped because exact expansion provenance is unavailable"
                        .into(),
                );
                continue;
            }
            let has_explicit_trait = self.impl_has_explicit_trait(impl_);
            let module_path = self.module_path(impl_.module(self.db));
            let Some(module_owner) = self.module_owner(crate_key, &module_path) else {
                self.issue(
                    "RUST_HIR_SEMANTIC_MODULE_OWNER_MISSING",
                    Some(location.path.clone()),
                    format!("module owner is missing for impl in {crate_key}"),
                );
                continue;
            };
            let self_type = self.canonical_type(impl_.self_ty(self.db));
            let self_node = impl_
                .self_ty(self.db)
                .as_adt()
                .and_then(|adt| self.node_ids.get(&Definition::Adt(adt)).cloned());
            let trait_ = impl_.trait_(self.db);
            let trait_node =
                trait_.and_then(|trait_| self.node_ids.get(&Definition::Trait(trait_)).cloned());
            let trait_resolver =
                trait_.and_then(|trait_| self.resolvers.get(&Definition::Trait(trait_)).cloned());
            let generated_from = self_node.clone().unwrap_or_else(|| module_owner.clone());
            let impl_identity = match &trait_resolver {
                Some(trait_resolver) => format!(
                    "impl<{self_type} as {trait_resolver}>@{}:{}:{}",
                    location.path, location.start_line, location.start_column
                ),
                None if has_explicit_trait => format!(
                    "impl<{self_type} as <unavailable-trait>>@{}:{}:{}",
                    location.path, location.start_line, location.start_column
                ),
                None => format!(
                    "impl<{self_type}>@{}:{}:{}",
                    location.path, location.start_line, location.start_column
                ),
            };
            let context = self.context(crate_key)?;
            let identity = json!({
                "language": "rust",
                "package_locator": context.package_locator,
                "crate_identity": crate_key,
                "symbol_kind": "impl",
                "identity_kind": "anonymous",
                "generated_from": generated_from,
                "relative_path": location.path,
                "span": location.as_value(),
                "impl_identity": impl_identity,
                "self_type": self_type,
                "trait": trait_resolver,
                "trait_resolution": if trait_resolver.is_some() {
                    "resolved-local"
                } else if has_explicit_trait {
                    "unavailable"
                } else {
                    "inherent"
                },
            });
            let node_id = stable_id_from_value("symbol", &identity);
            let node = GraphNode {
                id: node_id.clone(),
                kind: "symbol".into(),
                locator: format!("rust-impl:{node_id}"),
                display_name: Some(impl_identity.clone()),
                properties: properties(json!({
                    "language": "rust",
                    "package_locator": context.package_locator,
                    "crate_identity": crate_key,
                    "symbol_kind": "impl",
                    "canonical_identity": identity,
                    "profile_id": self.profile_id,
                    "source_path": location.path,
                    "source_span": location.as_value(),
                    "self_type": self_type,
                    "trait_resolver_identity": trait_resolver,
                    "trait_resolution": if trait_resolver.is_some() {
                        "resolved-local"
                    } else if has_explicit_trait {
                        "unavailable"
                    } else {
                        "inherent"
                    },
                    "hir_provenance": EXTRACTOR,
                })),
            };
            self.insert_node(node)?;
            self.node_ids.insert(definition, node_id.clone());
            self.resolvers.insert(definition, impl_identity.clone());
            self.impl_ids.insert(impl_, node_id.clone());
            self.impl_resolvers.insert(impl_, impl_identity.clone());
            let evidence = self.evidence(crate_key, &location, "HIR impl definition", "impl");
            self.add_relation(
                crate_key,
                "declares",
                &module_owner,
                &node_id,
                evidence.clone(),
            )?;
            self.emit_type_parameters(crate_key, GenericDef::Impl(impl_), &node_id)?;
            for item in impl_.items(self.db) {
                self.emit_assoc_item(crate_key, &node_id, &impl_identity, item)?;
            }
            match (
                self_node.as_deref(),
                trait_node.as_deref(),
                has_explicit_trait,
            ) {
                (Some(self_node), Some(trait_node), true) => {
                    self.add_relation(crate_key, "implements", self_node, trait_node, evidence)?;
                }
                (None, Some(_), true) => self.issue(
                    "RUST_HIR_IMPL_SELF_TYPE_UNREPRESENTABLE",
                    Some(location.path.clone()),
                    "trait impl relation was skipped because its self type has no exact local type node"
                        .into(),
                ),
                (_, None, true) => self.issue(
                    "RUST_HIR_IMPL_TRAIT_TARGET_UNAVAILABLE",
                    Some(location.path.clone()),
                    "trait impl relation was skipped because its trait target has no exact local type node"
                        .into(),
                ),
                _ => {}
            }
        }
        Ok(())
    }

    fn extract_trait_relations(&mut self, crate_key: &str, krate: Crate) -> Result<()> {
        let mut traits = Vec::new();
        for module in krate.modules(self.db) {
            for declaration in module.declarations(self.db) {
                if let ModuleDef::Trait(trait_) = declaration {
                    traits.push(trait_);
                }
            }
        }
        traits.sort_by_key(|trait_| {
            self.resolvers
                .get(&Definition::Trait(*trait_))
                .cloned()
                .unwrap_or_default()
        });
        traits.dedup();
        for trait_ in traits {
            let Some(source) = self.node_ids.get(&Definition::Trait(trait_)).cloned() else {
                continue;
            };
            let Some(location) = self.definition_location(Definition::Trait(trait_)) else {
                continue;
            };
            let evidence = self.evidence(
                crate_key,
                &location,
                "HIR direct supertrait relation",
                "trait-supertrait",
            );
            let mut supertraits = trait_.direct_supertraits(self.db);
            supertraits.sort_by_key(|supertrait| {
                self.resolvers
                    .get(&Definition::Trait(*supertrait))
                    .cloned()
                    .unwrap_or_default()
            });
            for supertrait in supertraits {
                let Some(target) = self.node_ids.get(&Definition::Trait(supertrait)).cloned()
                else {
                    continue;
                };
                self.add_relation(crate_key, "extends", &source, &target, evidence.clone())?;
            }
        }
        Ok(())
    }

    fn impl_has_explicit_trait(&self, impl_: Impl) -> bool {
        self.sema
            .source_with_range(impl_)
            .and_then(|source| source.value.1)
            .and_then(|syntax| syntax.trait_())
            .is_some()
    }

    fn emit_assoc_item(
        &mut self,
        crate_key: &str,
        owner_id: &str,
        owner_resolver: &str,
        item: AssocItem,
    ) -> Result<()> {
        let Some(name) = item.name(self.db) else {
            return Ok(());
        };
        let resolver = format!("{owner_resolver}::{}", name.as_str());
        match item {
            AssocItem::Function(function) => {
                let kind = if function.has_self_param(self.db) {
                    "method"
                } else {
                    "associated_function"
                };
                if let Some(node_id) = self.emit_named_symbol(
                    crate_key,
                    Definition::Function(function),
                    owner_id,
                    kind,
                    resolver,
                    "HIR associated function definition",
                )? {
                    self.emit_type_parameters(crate_key, GenericDef::Function(function), &node_id)?;
                }
            }
            AssocItem::Const(constant) => {
                self.emit_named_symbol(
                    crate_key,
                    Definition::Const(constant),
                    owner_id,
                    "associated_constant",
                    resolver,
                    "HIR associated constant definition",
                )?;
            }
            AssocItem::TypeAlias(alias) => {
                if let Some(node_id) = self.emit_named_type(
                    crate_key,
                    Definition::TypeAlias(alias),
                    owner_id,
                    "associated_type",
                    resolver,
                    "HIR associated type definition",
                )? {
                    self.emit_type_parameters(crate_key, GenericDef::TypeAlias(alias), &node_id)?;
                }
            }
        }
        Ok(())
    }

    fn emit_type_parameters(
        &mut self,
        crate_key: &str,
        generic: GenericDef,
        owner_id: &str,
    ) -> Result<()> {
        let Some(owner_resolver) = self.resolvers.get(&Definition::from(generic)).cloned() else {
            return Ok(());
        };
        for parameter in generic.params(self.db) {
            let GenericParam::TypeParam(type_param) = parameter else {
                continue;
            };
            if type_param.is_implicit(self.db) {
                continue;
            }
            let definition = Definition::GenericParam(GenericParam::TypeParam(type_param));
            let resolver = format!("{owner_resolver}::<{}>", type_param.name(self.db).as_str());
            self.emit_named_type(
                crate_key,
                definition,
                owner_id,
                "type_parameter",
                resolver,
                "HIR type parameter definition",
            )?;
        }
        Ok(())
    }

    fn extract_unambiguous_source_definitions(&mut self) -> Result<()> {
        let files: Vec<_> = self
            .model
            .snapshot()
            .files
            .iter()
            .map(|file| (file.file_id, file.path.clone()))
            .collect();
        let mut dependency_sources = Vec::new();
        for (raw_file_id, path) in files {
            let file_id = FileId::from_raw(raw_file_id);
            let modules: Vec<_> = self
                .sema
                .file_to_module_defs(file_id)
                .filter(|module| {
                    self.crate_keys_by_base
                        .contains_key(&module.krate(self.db).base())
                })
                .collect();
            if modules.len() != 1 {
                if modules.len() > 1 {
                    self.issue(
                        "RUST_HIR_SOURCE_CONTEXT_AMBIGUOUS",
                        Some(path),
                        "local/reference HIR identity was not emitted because the file belongs to multiple module or crate instances"
                            .into(),
                    );
                }
                continue;
            }
            let module = modules.into_iter().next().expect("one module");
            let Some(crate_key) = self
                .crate_keys_by_base
                .get(&module.krate(self.db).base())
                .cloned()
            else {
                continue;
            };
            let parsed = self.sema.parse_guess_edition(file_id);
            self.emit_closures(&crate_key, file_id, module, &parsed)?;
            let mut seen_locals = HashSet::new();
            for name in parsed.syntax().descendants().filter_map(ast::Name::cast) {
                let Some(definition) =
                    NameClass::classify(&self.sema, &name).and_then(NameClass::defined)
                else {
                    continue;
                };
                if let Definition::Local(local) = definition
                    && seen_locals.insert(local)
                {
                    if self.has_unrepresented_anonymous_execution_ancestor(name.syntax()) {
                        self.issue(
                            "RUST_HIR_ANONYMOUS_BODY_DEFINITION_SKIPPED",
                            Some(path.clone()),
                            "local definition inside a closure, async block, const block, or generator was skipped until anonymous body identities are available"
                                .into(),
                        );
                        continue;
                    }
                    self.emit_local(&crate_key, file_id, local)?;
                }
            }
            for name_ref in parsed.syntax().descendants().filter_map(ast::NameRef::cast) {
                if self.has_unrepresented_anonymous_execution_ancestor(name_ref.syntax()) {
                    self.issue(
                        "RUST_HIR_ANONYMOUS_BODY_DEFINITION_SKIPPED",
                        Some(path.clone()),
                        "generic instantiation inside a closure, async block, const block, or generator was skipped until anonymous body identities are available"
                            .into(),
                    );
                    continue;
                }
                self.emit_generic_reference(&crate_key, file_id, &name_ref)?;
            }
            self.index_fn_pointer_targets(file_id, module, &parsed);
            let occurrences = self
                .occurrences_by_path
                .get(&path)
                .cloned()
                .unwrap_or_default();
            self.index_external_aliases(&crate_key, file_id, module, &parsed, &occurrences);
            dependency_sources.push((crate_key, file_id, path, module, parsed));
        }
        for (crate_key, file_id, path, module, parsed) in dependency_sources {
            self.extract_dependency_occurrences(&crate_key, file_id, &path, module, &parsed)?;
        }
        Ok(())
    }

    fn extract_dependency_occurrences(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        path: &str,
        module: Module,
        parsed: &ast::SourceFile,
    ) -> Result<()> {
        let occurrences = self
            .occurrences_by_path
            .get(path)
            .cloned()
            .unwrap_or_default();
        for occurrence in occurrences {
            let use_key = occurrence.use_key(path);
            let type_use_key = occurrence.type_use_key(path);
            let call_key = occurrence.call_key(path);
            match occurrence {
                Occurrence::Use {
                    target_specifier,
                    site_specifier,
                    alias,
                    glob,
                    reexport,
                    condition,
                    span,
                    ..
                } => {
                    self.emit_use_occurrence(
                        crate_key,
                        file_id,
                        path,
                        module,
                        parsed,
                        &target_specifier,
                        &site_specifier,
                        alias.as_deref(),
                        glob,
                        reexport,
                        condition,
                        span,
                        use_key.expect("use occurrence has a use key"),
                    )?;
                }
                Occurrence::TypeUse {
                    specifier,
                    context,
                    inline_ancestors,
                    condition,
                    span,
                } => {
                    self.emit_type_use_occurrence(
                        crate_key,
                        file_id,
                        path,
                        module,
                        parsed,
                        &specifier,
                        context,
                        &inline_ancestors,
                        condition,
                        span,
                        type_use_key.expect("type-use occurrence has a type-use key"),
                    )?;
                }
                Occurrence::Call {
                    specifier,
                    syntax_kind,
                    inline_ancestors,
                    condition,
                    span,
                } => {
                    self.emit_call_occurrence(
                        crate_key,
                        file_id,
                        path,
                        module,
                        parsed,
                        &specifier,
                        syntax_kind,
                        &inline_ancestors,
                        condition,
                        span,
                        call_key.expect("call occurrence has a call key"),
                    )?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn emit_closures(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        module: Module,
        parsed: &ast::SourceFile,
    ) -> Result<()> {
        let closures: Vec<_> = parsed
            .syntax()
            .descendants()
            .filter_map(ast::ClosureExpr::cast)
            .collect();
        for closure in closures {
            if closure
                .syntax()
                .ancestors()
                .skip(1)
                .any(|node| ast::MacroCall::can_cast(node.kind()))
            {
                continue;
            }
            let Some(owner_id) = self.semantic_call_owner_id(file_id, closure.syntax()) else {
                let path = self.paths_by_file.get(&file_id.index()).cloned();
                self.issue(
                    "RUST_HIR_CLOSURE_OWNER_UNAVAILABLE",
                    path,
                    "closure was skipped because it has no exact enclosing symbol".into(),
                );
                continue;
            };
            let range = InFile::new(
                ra_ap_hir::EditionedFileId::current_edition(self.db, file_id).into(),
                closure.syntax().text_range(),
            );
            let Some(location) = self.location_from_range(range) else {
                continue;
            };
            let context = self.context(crate_key)?;
            let identity = json!({
                "language": "rust",
                "package_locator": context.package_locator,
                "crate_identity": crate_key,
                "symbol_kind": "closure",
                "identity_kind": "anonymous",
                "enclosing_symbol": owner_id,
                "relative_path": location.path,
                "span": location.as_value(),
            });
            let node_id = stable_id_from_value("symbol", &identity);
            self.insert_node(GraphNode {
                id: node_id.clone(),
                kind: "symbol".into(),
                locator: format!(
                    "rust-closure:{}@{}:{}:{}",
                    owner_id, location.path, location.start_line, location.start_column
                ),
                display_name: Some(format!(
                    "closure@{}:{}:{}",
                    location.path, location.start_line, location.start_column
                )),
                properties: properties(json!({
                    "language": "rust",
                    "package_locator": context.package_locator,
                    "crate_identity": crate_key,
                    "symbol_kind": "closure",
                    "canonical_identity": identity,
                    "profile_id": self.profile_id,
                    "source_path": location.path,
                    "source_span": location.as_value(),
                    "hir_provenance": EXTRACTOR,
                })),
            })?;
            self.closure_nodes_by_range.insert(
                (file_id.index(), closure.syntax().text_range()),
                node_id.clone(),
            );

            let expression: ast::Expr = closure.clone().into();
            if let Some(callable) = self
                .sema
                .type_of_expr(&expression)
                .map(|info| info.original)
                .and_then(|ty| ty.as_callable(self.db))
                && let CallableKind::Closure(closure) = callable.kind()
            {
                let key = closure
                    .display_with_id(self.db, module.krate(self.db).to_display_target(self.db));
                if let Some(existing) = self.closure_nodes_by_callable.get(&key)
                    && existing != &node_id
                {
                    bail!("conflicting Rust HIR closure callable identity {key}");
                }
                self.closure_nodes_by_callable.insert(key, node_id.clone());
            }
            let evidence = self.evidence(crate_key, &location, "HIR closure definition", "closure");
            self.add_relation(crate_key, "declares", &owner_id, &node_id, evidence)?;
        }
        Ok(())
    }

    fn semantic_call_owner_id(&self, file_id: FileId, node: &SyntaxNode) -> Option<String> {
        for ancestor in node.ancestors().skip(1) {
            if ast::ClosureExpr::can_cast(ancestor.kind())
                && let Some(node_id) = self
                    .closure_nodes_by_range
                    .get(&(file_id.index(), ancestor.text_range()))
            {
                return Some(node_id.clone());
            }
        }
        let definition = self.enclosing_semantic_definition(node)?;
        let node_id = self.node_ids.get(&definition)?.clone();
        self.nodes
            .get(&node_id)
            .is_some_and(|node| node.kind == "symbol")
            .then_some(node_id)
    }

    fn index_fn_pointer_targets(
        &mut self,
        file_id: FileId,
        module: Module,
        parsed: &ast::SourceFile,
    ) {
        for statement in parsed.syntax().descendants().filter_map(ast::LetStmt::cast) {
            let Some(pattern) = statement.pat() else {
                continue;
            };
            let Some(initializer) = statement.initializer() else {
                continue;
            };
            let candidates = self.callable_initializer_targets(file_id, module, &initializer);
            let pattern_nodes =
                std::iter::once(pattern.syntax().clone()).chain(pattern.syntax().descendants());
            for ident in pattern_nodes.filter_map(ast::IdentPat::cast) {
                if ident.mut_token().is_some() || ident.ref_token().is_some() {
                    continue;
                }
                let Some(name) = ast::HasName::name(&ident) else {
                    continue;
                };
                let Some(Definition::Local(local)) =
                    NameClass::classify(&self.sema, &name).and_then(NameClass::defined)
                else {
                    continue;
                };
                self.fn_pointer_targets.insert(local, candidates.clone());
            }
        }
    }

    fn callable_initializer_targets(
        &self,
        file_id: FileId,
        module: Module,
        expression: &ast::Expr,
    ) -> CallCandidateSet {
        match expression {
            ast::Expr::ParenExpr(paren) => paren
                .expr()
                .map(|expr| self.callable_initializer_targets(file_id, module, &expr))
                .unwrap_or_else(CallCandidateSet::incomplete),
            ast::Expr::CastExpr(cast) => cast
                .expr()
                .map(|expr| self.callable_initializer_targets(file_id, module, &expr))
                .unwrap_or_else(CallCandidateSet::incomplete),
            ast::Expr::BlockExpr(block) => block
                .tail_expr()
                .map(|expr| self.callable_initializer_targets(file_id, module, &expr))
                .unwrap_or_else(CallCandidateSet::incomplete),
            ast::Expr::IfExpr(if_expression) => {
                let Some(then_expression) = if_expression
                    .then_branch()
                    .and_then(|block| block.tail_expr())
                else {
                    return CallCandidateSet::incomplete();
                };
                let Some(else_branch) = if_expression.else_branch() else {
                    return CallCandidateSet::incomplete();
                };
                let then_targets =
                    self.callable_initializer_targets(file_id, module, &then_expression);
                let else_targets = match else_branch {
                    ast::ElseBranch::Block(block) => block
                        .tail_expr()
                        .map(|expr| self.callable_initializer_targets(file_id, module, &expr))
                        .unwrap_or_else(CallCandidateSet::incomplete),
                    ast::ElseBranch::IfExpr(if_expression) => self.callable_initializer_targets(
                        file_id,
                        module,
                        &ast::Expr::IfExpr(if_expression),
                    ),
                };
                then_targets.union(else_targets)
            }
            ast::Expr::PathExpr(_) | ast::Expr::ClosureExpr(_) => {
                self.local_callable_target(file_id, module, expression)
            }
            _ => CallCandidateSet::incomplete(),
        }
    }

    fn local_callable_target(
        &self,
        file_id: FileId,
        module: Module,
        expression: &ast::Expr,
    ) -> CallCandidateSet {
        if let Some(instance) =
            self.generic_function_instance_target(file_id, expression.syntax(), None)
        {
            return CallCandidateSet::exact(instance);
        }
        if let ast::Expr::ClosureExpr(closure) = expression
            && let Some(target) = self
                .closure_nodes_by_range
                .get(&(file_id.index(), closure.syntax().text_range()))
        {
            return CallCandidateSet::exact(target.clone());
        }
        if let ast::Expr::PathExpr(path) = expression
            && let Some(name_ref) = path
                .syntax()
                .descendants()
                .filter_map(ast::NameRef::cast)
                .last()
            && let Some(NameRefClass::Definition(definition, _)) =
                NameRefClass::classify(&self.sema, &name_ref)
        {
            return match definition {
                Definition::Function(function) if !self.function_requires_instance(function) => {
                    self.node_ids
                        .get(&definition)
                        .cloned()
                        .map(CallCandidateSet::exact)
                        .unwrap_or_else(CallCandidateSet::incomplete)
                }
                Definition::Local(local) => self
                    .fn_pointer_targets
                    .get(&local)
                    .cloned()
                    .unwrap_or_else(CallCandidateSet::incomplete),
                _ => CallCandidateSet::incomplete(),
            };
        }
        let Some(callable) = self.sema.resolve_expr_as_callable(expression) else {
            return CallCandidateSet::incomplete();
        };
        match callable.kind() {
            CallableKind::Function(function) => self
                .node_ids
                .get(&Definition::Function(function))
                .cloned()
                .map(CallCandidateSet::exact)
                .unwrap_or_else(CallCandidateSet::incomplete),
            CallableKind::Closure(closure) => {
                let key = closure
                    .display_with_id(self.db, module.krate(self.db).to_display_target(self.db));
                self.closure_nodes_by_callable
                    .get(&key)
                    .cloned()
                    .map(CallCandidateSet::exact)
                    .unwrap_or_else(CallCandidateSet::incomplete)
            }
            CallableKind::FnPtr => self.fn_pointer_candidates(expression),
            _ => CallCandidateSet::incomplete(),
        }
    }

    fn generic_function_instance_target(
        &self,
        file_id: FileId,
        node: &SyntaxNode,
        function: Option<ra_ap_hir::Function>,
    ) -> Option<String> {
        let expected_origin = function
            .and_then(|function| self.node_ids.get(&Definition::Function(function)))
            .map(String::as_str);
        node.descendants()
            .filter_map(ast::NameRef::cast)
            .filter_map(|name_ref| {
                self.generic_instances_by_range
                    .get(&(file_id.index(), name_ref.syntax().text_range()))
            })
            .filter(|node_id| {
                self.nodes.get(*node_id).is_some_and(|node| {
                    node.kind == "symbol"
                        && node.properties["symbol_kind"] == "function_instance"
                        && expected_origin.is_none_or(|origin| {
                            node.properties["generic_origin_node"].as_str() == Some(origin)
                        })
                })
            })
            .last()
            .cloned()
    }

    fn index_external_aliases(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        module: Module,
        parsed: &ast::SourceFile,
        occurrences: &[Occurrence],
    ) {
        for occurrence in occurrences {
            let (target_specifier, alias, glob, inline_ancestors, condition, span, extern_crate) =
                match occurrence {
                    Occurrence::Use {
                        target_specifier,
                        alias,
                        glob,
                        inline_ancestors,
                        condition,
                        span,
                        ..
                    } => (
                        target_specifier,
                        alias,
                        *glob,
                        inline_ancestors,
                        condition,
                        *span,
                        false,
                    ),
                    Occurrence::ExternCrate {
                        specifier,
                        alias,
                        inline_ancestors,
                        condition,
                        span,
                    } => (
                        specifier,
                        alias,
                        false,
                        inline_ancestors,
                        condition,
                        *span,
                        true,
                    ),
                    _ => continue,
                };
            if glob || alias.as_deref() == Some("_") {
                continue;
            }
            let Some((external_name, external_kind)) =
                self.external_metadata(crate_key, target_specifier)
            else {
                continue;
            };
            let module_level = if extern_crate {
                let mut matches = parsed
                    .syntax()
                    .descendants()
                    .filter_map(ast::ExternCrate::cast)
                    .filter(|item| {
                        self.range_matches_span(file_id, item.syntax().text_range(), span)
                    });
                let Some(item) = matches.next() else {
                    continue;
                };
                matches.next().is_none()
                    && !item
                        .syntax()
                        .ancestors()
                        .any(|node| ast::StmtList::can_cast(node.kind()))
            } else {
                let mut matches = parsed
                    .syntax()
                    .descendants()
                    .filter_map(ast::UseTree::cast)
                    .filter(|tree| tree.use_tree_list().is_none())
                    .filter(|tree| {
                        self.range_matches_span(file_id, tree.syntax().text_range(), span)
                    })
                    .filter(|tree| tree.star_token().is_some() == glob)
                    .filter(|tree| self.use_tree_alias(tree).as_deref() == alias.as_deref());
                let Some(tree) = matches.next() else {
                    continue;
                };
                matches.next().is_none()
                    && !tree
                        .syntax()
                        .ancestors()
                        .any(|node| ast::StmtList::can_cast(node.kind()))
            };
            if !module_level {
                // Block-local aliases require lexical scope ranges. Keep their
                // downstream type uses unresolved rather than leaking a name
                // into the surrounding module.
                continue;
            }
            let visible_name = alias.as_deref().or_else(|| {
                target_specifier
                    .trim_start_matches("::")
                    .rsplit("::")
                    .next()
            });
            let Some(visible_name) = visible_name.filter(|name| !name.is_empty()) else {
                continue;
            };
            let mut module_path = self.module_path(module);
            module_path.extend(inline_ancestors.iter().cloned());
            let key = (crate_key.into(), module_path, visible_name.into());
            self.external_aliases
                .entry(key)
                .or_default()
                .insert(ExternalAlias {
                    target_specifier: target_specifier.clone(),
                    external_name,
                    external_kind,
                    condition_terms: condition_conjuncts(condition),
                });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_use_occurrence(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        path: &str,
        module: Module,
        parsed: &ast::SourceFile,
        target_specifier: &str,
        site_specifier: &str,
        alias: Option<&str>,
        glob: bool,
        reexport: bool,
        condition: Condition,
        span: SourceSpan,
        use_key: UseOccurrenceKey,
    ) -> Result<()> {
        let mut matches: Vec<_> = parsed
            .syntax()
            .descendants()
            .filter_map(ast::UseTree::cast)
            .filter(|tree| tree.use_tree_list().is_none())
            .filter(|tree| self.range_matches_span(file_id, tree.syntax().text_range(), span))
            .filter(|tree| tree.star_token().is_some() == glob)
            .filter(|tree| self.use_tree_alias(tree).as_deref() == alias)
            .collect();
        if matches.len() != 1 {
            self.issue(
                "RUST_HIR_USE_SOURCE_UNAVAILABLE",
                Some(path.into()),
                format!(
                    "semantic use leaf {site_specifier:?} at {}:{} matched {} rust-analyzer syntax nodes",
                    span.start_line,
                    span.start_column,
                    matches.len()
                ),
            );
            return Ok(());
        }
        let tree = matches.pop().expect("one use tree");
        if tree
            .syntax()
            .ancestors()
            .any(|node| ast::MacroCall::can_cast(node.kind()))
        {
            self.issue(
                "RUST_HIR_MACRO_USE_SKIPPED",
                Some(path.into()),
                format!(
                    "use leaf {site_specifier:?} was skipped because exact macro provenance is unavailable"
                ),
            );
            return Ok(());
        }
        let Some(source) = self.semantic_owner_id(tree.syntax(), module, false) else {
            self.issue(
                "RUST_HIR_USE_OWNER_UNAVAILABLE",
                Some(path.into()),
                format!("use leaf {site_specifier:?} has no exact semantic owner"),
            );
            return Ok(());
        };
        let resolution_path = tree.path().or_else(|| {
            tree.syntax()
                .ancestors()
                .skip(1)
                .filter_map(ast::UseTree::cast)
                .find_map(|parent| parent.path())
        });
        let per_namespace = resolution_path
            .as_ref()
            .and_then(|resolution_path| self.sema.resolve_path_per_ns(resolution_path));
        let location = SourceLocation::from_span(path, span);
        let (site_kind, edge_kind) = if reexport {
            ("rust_reexport", "reexports")
        } else {
            ("rust_use", "imports")
        };
        let (resolution, namespaces) = self.classify_import_resolution(
            crate_key,
            site_kind,
            target_specifier,
            &location,
            per_namespace,
        )?;
        let mut evidence_properties = Properties::new();
        evidence_properties.insert("target_specifier".into(), json!(target_specifier));
        evidence_properties.insert("glob".into(), json!(glob));
        evidence_properties.insert("reexport".into(), json!(reexport));
        evidence_properties.insert("namespaces".into(), json!(namespaces));
        if let Some(alias) = alias {
            evidence_properties.insert("alias".into(), json!(alias));
        }
        self.add_dependency_site(
            crate_key,
            site_kind,
            edge_kind,
            &source,
            site_specifier,
            condition,
            resolution,
            &location,
            "HIR-resolved Rust use",
            "use",
            evidence_properties,
        )?;
        self.refined_use_keys.insert(use_key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_type_use_occurrence(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        path: &str,
        module: Module,
        parsed: &ast::SourceFile,
        specifier: &str,
        context: TypeUseContext,
        inline_ancestors: &[String],
        condition: Condition,
        span: SourceSpan,
        type_use_key: TypeUseOccurrenceKey,
    ) -> Result<()> {
        let mut matches: Vec<_> = parsed
            .syntax()
            .descendants()
            .filter_map(ast::PathType::cast)
            .filter_map(|path_type| path_type.path().map(|path| (path_type, path)))
            .filter(|(_, type_path)| {
                self.range_matches_span(file_id, type_path.syntax().text_range(), span)
            })
            .collect();
        if matches.len() != 1 {
            // syn represents a receiver such as `&self` as a synthetic
            // `Self` type. There is no explicit path for rust-analyzer to
            // attach a PathType (and therefore no dependency site) to.
            if specifier == "Self" && matches.is_empty() {
                return Ok(());
            }
            self.issue(
                "RUST_HIR_TYPE_USE_SOURCE_UNAVAILABLE",
                Some(path.into()),
                format!(
                    "type reference {specifier:?} at {}:{} matched {} rust-analyzer path-type nodes",
                    span.start_line,
                    span.start_column,
                    matches.len()
                ),
            );
            return Ok(());
        }
        let (path_type, type_path) = matches.pop().expect("one type path");
        if path_type
            .syntax()
            .ancestors()
            .any(|node| ast::MacroCall::can_cast(node.kind()))
        {
            self.issue(
                "RUST_HIR_MACRO_TYPE_USE_SKIPPED",
                Some(path.into()),
                format!(
                    "type reference {specifier:?} was skipped because exact macro provenance is unavailable"
                ),
            );
            return Ok(());
        }
        let Some(source) = self.semantic_owner_id(path_type.syntax(), module, true) else {
            self.issue(
                "RUST_HIR_TYPE_USE_OWNER_UNAVAILABLE",
                Some(path.into()),
                format!("type reference {specifier:?} has no exact symbol/type owner"),
            );
            return Ok(());
        };
        let type_resolution = self
            .sema
            .resolve_path_per_ns(&type_path)
            .and_then(|resolution| resolution.type_ns);
        let location = SourceLocation::from_span(path, span);
        let mut lexical_module_path = self.module_path(module);
        lexical_module_path.extend(inline_ancestors.iter().cloned());
        let resolution = self.classify_type_resolution(
            crate_key,
            specifier,
            &lexical_module_path,
            &condition,
            &location,
            type_resolution,
        )?;
        let mut evidence_properties = Properties::new();
        evidence_properties.insert("type_use_context".into(), json!(context.as_str()));
        self.add_dependency_site(
            crate_key,
            "type_use",
            "type_uses",
            &source,
            specifier,
            condition,
            resolution,
            &location,
            "HIR-resolved Rust type reference",
            "type-use",
            evidence_properties,
        )?;
        self.refined_type_use_keys.insert(type_use_key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_call_occurrence(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        path: &str,
        module: Module,
        parsed: &ast::SourceFile,
        specifier: &str,
        syntax_kind: CallSyntaxKind,
        inline_ancestors: &[String],
        condition: Condition,
        span: SourceSpan,
        call_key: CallOccurrenceKey,
    ) -> Result<()> {
        let location = SourceLocation::from_span(path, span);
        match syntax_kind {
            CallSyntaxKind::MacroBoundary => {
                let mut matches: Vec<_> = parsed
                    .syntax()
                    .descendants()
                    .filter_map(ast::MacroCall::cast)
                    .filter(|call| {
                        self.range_matches_span(file_id, call.syntax().text_range(), span)
                    })
                    .collect();
                if matches.len() != 1 {
                    self.issue(
                        "RUST_HIR_MACRO_CALL_SOURCE_UNAVAILABLE",
                        Some(path.into()),
                        format!(
                            "macro call boundary {specifier:?} at {}:{} matched {} rust-analyzer syntax nodes",
                            span.start_line,
                            span.start_column,
                            matches.len()
                        ),
                    );
                    return Ok(());
                }
                let macro_call = matches.pop().expect("one macro call");
                if self.has_unrepresented_anonymous_execution_ancestor(macro_call.syntax()) {
                    self.issue(
                        "RUST_HIR_ANONYMOUS_CALLER_UNREPRESENTED",
                        Some(path.into()),
                        format!(
                            "macro call boundary {specifier:?} was skipped because its nearest caller is an async, const, or generator body without a canonical symbol identity"
                        ),
                    );
                    return Ok(());
                }
                let Some(expansion) = self.sema.expand_macro_call(&macro_call) else {
                    self.issue(
                        "RUST_HIR_MACRO_CALL_EXPANSION_UNAVAILABLE",
                        Some(path.into()),
                        format!(
                            "macro call boundary {specifier:?} could not be expanded without executing project code"
                        ),
                    );
                    return Ok(());
                };
                let generated_call_count = expansion
                    .value
                    .descendants()
                    .filter(|node| {
                        ast::CallExpr::can_cast(node.kind())
                            || ast::MethodCallExpr::can_cast(node.kind())
                    })
                    .count();
                if generated_call_count == 0 {
                    return Ok(());
                }
                let Some(source) = self.semantic_call_owner_id(file_id, macro_call.syntax()) else {
                    self.issue(
                        "RUST_HIR_CALL_OWNER_UNAVAILABLE",
                        Some(path.into()),
                        format!("macro call boundary {specifier:?} has no exact caller symbol"),
                    );
                    return Ok(());
                };
                let reason = format!(
                    "macro expansion contains {generated_call_count} generated call(s) whose individual source provenance cannot be represented exactly"
                );
                let resolution =
                    self.unresolved_resolution(crate_key, "call", specifier, &location, &reason)?;
                let mut properties = Properties::new();
                properties.insert("call_syntax".into(), json!(syntax_kind.as_str()));
                properties.insert("dispatch".into(), json!("macro_boundary"));
                properties.insert(
                    "macro_provenance".into(),
                    json!("declarative-expansion-boundary"),
                );
                properties.insert("generated_call_count".into(), json!(generated_call_count));
                let mut generated_location = location.clone();
                generated_location.generated = true;
                self.add_dependency_site(
                    crate_key,
                    "call",
                    "calls",
                    &source,
                    specifier,
                    condition,
                    resolution,
                    &generated_location,
                    "HIR macro-generated call boundary",
                    "macro-call-boundary",
                    properties,
                )?;
                self.refined_call_keys.insert(call_key);
                return Ok(());
            }
            CallSyntaxKind::Function | CallSyntaxKind::Method => {}
        }

        let (syntax, resolution, dispatch, algorithm) = match syntax_kind {
            CallSyntaxKind::Function => {
                let mut matches: Vec<_> = parsed
                    .syntax()
                    .descendants()
                    .filter_map(ast::CallExpr::cast)
                    .filter(|call| {
                        self.range_matches_span(file_id, call.syntax().text_range(), span)
                    })
                    .collect();
                if matches.len() != 1 {
                    self.issue(
                        "RUST_HIR_CALL_SOURCE_UNAVAILABLE",
                        Some(path.into()),
                        format!(
                            "function call {specifier:?} at {}:{} matched {} rust-analyzer syntax nodes",
                            span.start_line,
                            span.start_column,
                            matches.len()
                        ),
                    );
                    return Ok(());
                }
                let call = matches.pop().expect("one call expression");
                if self.has_unrepresented_anonymous_execution_ancestor(call.syntax()) {
                    self.issue(
                        "RUST_HIR_ANONYMOUS_CALLER_UNREPRESENTED",
                        Some(path.into()),
                        format!(
                            "function call {specifier:?} was skipped because its nearest caller is an async, const, or generator body without a canonical symbol identity"
                        ),
                    );
                    return Ok(());
                }
                let Some(callee) = call.expr() else {
                    return Ok(());
                };
                let Some((resolution, dispatch, algorithm)) = self.classify_function_call(
                    crate_key,
                    file_id,
                    module,
                    &callee,
                    specifier,
                    inline_ancestors,
                    &condition,
                    &location,
                )?
                else {
                    // Tuple struct and tuple variant construction are not
                    // function calls in the shared call graph vocabulary.
                    return Ok(());
                };
                (call.syntax().clone(), resolution, dispatch, algorithm)
            }
            CallSyntaxKind::Method => {
                let mut matches: Vec<_> = parsed
                    .syntax()
                    .descendants()
                    .filter_map(ast::MethodCallExpr::cast)
                    .filter(|call| {
                        self.range_matches_span(file_id, call.syntax().text_range(), span)
                    })
                    .collect();
                if matches.len() != 1 {
                    self.issue(
                        "RUST_HIR_METHOD_CALL_SOURCE_UNAVAILABLE",
                        Some(path.into()),
                        format!(
                            "method call {specifier:?} at {}:{} matched {} rust-analyzer syntax nodes",
                            span.start_line,
                            span.start_column,
                            matches.len()
                        ),
                    );
                    return Ok(());
                }
                let call = matches.pop().expect("one method-call expression");
                if self.has_unrepresented_anonymous_execution_ancestor(call.syntax()) {
                    self.issue(
                        "RUST_HIR_ANONYMOUS_CALLER_UNREPRESENTED",
                        Some(path.into()),
                        format!(
                            "method call {specifier:?} was skipped because its nearest caller is an async, const, or generator body without a canonical symbol identity"
                        ),
                    );
                    return Ok(());
                }
                let (resolution, dispatch, algorithm) = self.classify_method_call(
                    crate_key,
                    file_id,
                    module,
                    &call,
                    specifier,
                    inline_ancestors,
                    &condition,
                    &location,
                )?;
                (call.syntax().clone(), resolution, dispatch, algorithm)
            }
            CallSyntaxKind::MacroBoundary => unreachable!("macro calls returned above"),
        };
        let Some(source) = self.semantic_call_owner_id(file_id, &syntax) else {
            self.issue(
                "RUST_HIR_CALL_OWNER_UNAVAILABLE",
                Some(path.into()),
                format!("call {specifier:?} has no exact caller symbol"),
            );
            return Ok(());
        };
        let edge_kind = if resolution.status == ResolutionStatus::Candidates {
            "may_call"
        } else {
            "calls"
        };
        let mut properties = Properties::new();
        properties.insert("call_syntax".into(), json!(syntax_kind.as_str()));
        properties.insert("dispatch".into(), json!(dispatch));
        if let Some(algorithm) = algorithm {
            properties.insert("algorithm".into(), json!(algorithm));
        }
        self.add_dependency_site(
            crate_key,
            "call",
            edge_kind,
            &source,
            specifier,
            condition,
            resolution,
            &location,
            "HIR-resolved Rust call",
            "call",
            properties,
        )?;
        self.refined_call_keys.insert(call_key);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_function_call(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        module: Module,
        callee: &ast::Expr,
        specifier: &str,
        inline_ancestors: &[String],
        condition: &Condition,
        location: &SourceLocation,
    ) -> Result<Option<(SemanticResolution, &'static str, Option<&'static str>)>> {
        let Some(callable) = self.sema.resolve_expr_as_callable(callee) else {
            let resolution = self.external_call_or_unresolved(
                crate_key,
                module,
                specifier,
                inline_ancestors,
                condition,
                location,
                "rust-analyzer could not resolve the callable expression",
            )?;
            let dispatch = if resolution.status == ResolutionStatus::External {
                "external"
            } else {
                "unresolved"
            };
            return Ok(Some((resolution, dispatch, None)));
        };
        match callable.kind() {
            CallableKind::Function(function) => {
                if let Some(AssocItemContainer::Trait(trait_)) = function
                    .as_assoc_item(self.db)
                    .map(|item| item.container(self.db))
                {
                    if let Some((resolution, dispatch)) = self.concrete_trait_function_resolution(
                        crate_key, file_id, callee, function, specifier, location,
                    )? {
                        return Ok(Some((resolution, dispatch, None)));
                    }
                    let resolution = self.closed_trait_call_resolution(
                        crate_key, trait_, function, specifier, location,
                    )?;
                    let algorithm = (resolution.status == ResolutionStatus::Candidates)
                        .then_some("rust-analyzer-local-trait-impls-v1");
                    return Ok(Some((resolution, "trait_associated", algorithm)));
                }
                let resolution = self.exact_function_resolution(
                    crate_key,
                    file_id,
                    callee.syntax(),
                    function,
                    specifier,
                    location,
                )?;
                let dispatch = if resolution.status == ResolutionStatus::External {
                    "external"
                } else {
                    "static"
                };
                Ok(Some((resolution, dispatch, None)))
            }
            CallableKind::Closure(closure) => {
                let key = closure
                    .display_with_id(self.db, module.krate(self.db).to_display_target(self.db));
                let resolution = if let Some(target) =
                    self.closure_nodes_by_callable.get(&key).cloned()
                {
                    SemanticResolution {
                        target_ids: vec![target],
                        status: ResolutionStatus::Resolved,
                        precision: Precision::Exact,
                        reason: None,
                    }
                } else {
                    self.unresolved_resolution(
                        crate_key,
                        "call",
                        specifier,
                        location,
                        "rust-analyzer resolved a closure callable whose source identity is unavailable",
                    )?
                };
                Ok(Some((resolution, "closure", None)))
            }
            CallableKind::FnPtr => {
                let candidates = self.fn_pointer_candidates(callee);
                let resolution = if candidates.complete && !candidates.target_ids.is_empty() {
                    SemanticResolution {
                        target_ids: candidates.target_ids.into_iter().collect(),
                        status: ResolutionStatus::Candidates,
                        precision: Precision::Overapprox,
                        reason: Some(
                            "immutable local function-pointer flow produced a closed candidate set"
                                .into(),
                        ),
                    }
                } else {
                    self.unresolved_resolution(
                        crate_key,
                        "call",
                        specifier,
                        location,
                        "function-pointer targets are not a complete immutable local points-to set",
                    )?
                };
                let algorithm = (resolution.status == ResolutionStatus::Candidates)
                    .then_some("rust-immutable-fn-pointer-flow-v1");
                Ok(Some((resolution, "function_pointer", algorithm)))
            }
            CallableKind::FnImpl(_) => {
                let resolution = self.unresolved_resolution(
                    crate_key,
                    "call",
                    specifier,
                    location,
                    "Fn trait dispatch has no complete local points-to set",
                )?;
                Ok(Some((resolution, "fn_trait", None)))
            }
            CallableKind::TupleStruct(_) | CallableKind::TupleEnumVariant(_) => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn classify_method_call(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        module: Module,
        call: &ast::MethodCallExpr,
        specifier: &str,
        inline_ancestors: &[String],
        condition: &Condition,
        location: &SourceLocation,
    ) -> Result<(SemanticResolution, &'static str, Option<&'static str>)> {
        let Some(function) = self.sema.resolve_method_call(call) else {
            let resolution = self.external_call_or_unresolved(
                crate_key,
                module,
                specifier,
                inline_ancestors,
                condition,
                location,
                "rust-analyzer could not resolve the method call",
            )?;
            let dispatch = if resolution.status == ResolutionStatus::External {
                "external"
            } else {
                "unresolved"
            };
            return Ok((resolution, dispatch, None));
        };
        if let Some(AssocItemContainer::Trait(trait_)) = function
            .as_assoc_item(self.db)
            .map(|item| item.container(self.db))
        {
            let concrete_receiver = call
                .receiver()
                .and_then(|receiver| self.sema.type_of_expr(&receiver))
                .map(|info| info.adjusted.unwrap_or(info.original))
                .is_some_and(|ty| self.is_concrete_call_receiver(ty));
            if concrete_receiver && function.has_body(self.db) {
                let anchor = call
                    .name_ref()
                    .map(|name_ref| name_ref.syntax().clone())
                    .unwrap_or_else(|| call.syntax().clone());
                let resolution = self.exact_function_resolution(
                    crate_key, file_id, &anchor, function, specifier, location,
                )?;
                return Ok((resolution, "trait_default_static", None));
            }
            let resolution = self
                .closed_trait_call_resolution(crate_key, trait_, function, specifier, location)?;
            let algorithm = (resolution.status == ResolutionStatus::Candidates)
                .then_some("rust-analyzer-local-trait-impls-v1");
            return Ok((resolution, "trait_dynamic", algorithm));
        }
        let anchor = call
            .name_ref()
            .map(|name_ref| name_ref.syntax().clone())
            .unwrap_or_else(|| call.syntax().clone());
        let resolution = self.exact_function_resolution(
            crate_key, file_id, &anchor, function, specifier, location,
        )?;
        Ok((resolution, "method_static", None))
    }

    fn exact_function_resolution(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        anchor: &SyntaxNode,
        function: ra_ap_hir::Function,
        specifier: &str,
        location: &SourceLocation,
    ) -> Result<SemanticResolution> {
        if let Some(instance) =
            self.generic_function_instance_target(file_id, anchor, Some(function))
        {
            return Ok(SemanticResolution {
                target_ids: vec![instance],
                status: ResolutionStatus::Resolved,
                precision: Precision::Exact,
                reason: None,
            });
        }
        let definition = Definition::Function(function);
        if self.node_ids.contains_key(&definition) && self.function_requires_instance(function) {
            return self.unresolved_resolution(
                crate_key,
                "call",
                specifier,
                location,
                "generic function call could not be mapped to a complete canonical function instance",
            );
        }
        match self.classify_definition_target(crate_key, specifier, "call", definition)? {
            ClassifiedTarget::Concrete { node_id, external } => Ok(SemanticResolution {
                target_ids: vec![node_id],
                status: if external {
                    ResolutionStatus::External
                } else {
                    ResolutionStatus::Resolved
                },
                precision: Precision::Exact,
                reason: None,
            }),
            ClassifiedTarget::Unsupported(reason) => {
                self.unresolved_resolution(crate_key, "call", specifier, location, &reason)
            }
        }
    }

    fn function_requires_instance(&self, function: ra_ap_hir::Function) -> bool {
        if !GenericDef::Function(function).params(self.db).is_empty() {
            return true;
        }
        function
            .as_assoc_item(self.db)
            .map(|item| item.container(self.db))
            .is_some_and(|container| match container {
                AssocItemContainer::Impl(impl_) => {
                    !GenericDef::Impl(impl_).params(self.db).is_empty()
                }
                AssocItemContainer::Trait(trait_) => {
                    !GenericDef::Trait(trait_).params(self.db).is_empty()
                }
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn concrete_trait_function_resolution(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        callee: &ast::Expr,
        trait_function: ra_ap_hir::Function,
        specifier: &str,
        location: &SourceLocation,
    ) -> Result<Option<(SemanticResolution, &'static str)>> {
        let Some(name_ref) = callee
            .syntax()
            .descendants()
            .filter_map(ast::NameRef::cast)
            .last()
        else {
            return Ok(None);
        };
        let Some(NameRefClass::Definition(Definition::Function(resolved), Some(substitution))) =
            NameRefClass::classify(&self.sema, &name_ref)
        else {
            return Ok(None);
        };
        if resolved != trait_function
            && matches!(
                resolved
                    .as_assoc_item(self.db)
                    .map(|item| item.container(self.db)),
                Some(AssocItemContainer::Impl(_))
            )
        {
            let resolution = self.exact_function_resolution(
                crate_key,
                file_id,
                callee.syntax(),
                resolved,
                specifier,
                location,
            )?;
            return Ok(Some((resolution, "trait_associated_static")));
        }
        if resolved != trait_function {
            return Ok(None);
        }
        let has_concrete_self = substitution
            .types(self.db)
            .into_iter()
            .find(|(name, _)| name.as_str() == "Self")
            .map(|(_, ty)| ty)
            .filter(|ty| self.is_concrete_call_receiver(ty.clone()))
            .is_some();
        if !has_concrete_self {
            return Ok(None);
        }
        if trait_function.has_body(self.db) {
            let resolution = self.exact_function_resolution(
                crate_key,
                file_id,
                callee.syntax(),
                trait_function,
                specifier,
                location,
            )?;
            return Ok(Some((resolution, "trait_associated_default_static")));
        }
        Ok(None)
    }

    fn closed_trait_call_resolution(
        &mut self,
        crate_key: &str,
        trait_: ra_ap_hir::Trait,
        trait_function: ra_ap_hir::Function,
        specifier: &str,
        location: &SourceLocation,
    ) -> Result<SemanticResolution> {
        if matches!(trait_.visibility(self.db), Visibility::Public) {
            return self.unresolved_resolution(
                crate_key,
                "call",
                specifier,
                location,
                "public trait dispatch is open to implementations outside the confined crate graph",
            );
        }
        let method_name = trait_function.name(self.db);
        let mut targets = BTreeSet::new();
        let mut complete = true;
        let impls = Impl::all_for_trait(self.db, trait_);
        for impl_ in impls
            .iter()
            .copied()
            .filter(|impl_| !impl_.is_negative(self.db))
        {
            let implementation = impl_.items(self.db).into_iter().find_map(|item| {
                let function = item.as_function()?;
                (function.name(self.db) == method_name).then_some(function)
            });
            if let Some(function) = implementation {
                if let Some(target) = self.node_ids.get(&Definition::Function(function)).cloned() {
                    targets.insert(target);
                } else {
                    complete = false;
                }
            } else if trait_function.has_body(self.db) {
                if let Some(target) = self
                    .node_ids
                    .get(&Definition::Function(trait_function))
                    .cloned()
                {
                    targets.insert(target);
                } else {
                    complete = false;
                }
            } else {
                complete = false;
            }
        }
        if impls.is_empty() || !complete || targets.is_empty() {
            return self.unresolved_resolution(
                crate_key,
                "call",
                specifier,
                location,
                "trait dispatch candidates are not complete in the confined crate graph",
            );
        }
        Ok(SemanticResolution {
            target_ids: targets.into_iter().collect(),
            status: ResolutionStatus::Candidates,
            precision: Precision::Overapprox,
            reason: Some("closed non-public trait implementation set".into()),
        })
    }

    fn fn_pointer_candidates(&self, callee: &ast::Expr) -> CallCandidateSet {
        let Some(name_ref) = callee
            .syntax()
            .descendants()
            .filter_map(ast::NameRef::cast)
            .last()
        else {
            return CallCandidateSet::incomplete();
        };
        let Some(NameRefClass::Definition(Definition::Local(local), _)) =
            NameRefClass::classify(&self.sema, &name_ref)
        else {
            return CallCandidateSet::incomplete();
        };
        self.fn_pointer_targets
            .get(&local)
            .cloned()
            .unwrap_or_else(CallCandidateSet::incomplete)
    }

    fn is_concrete_call_receiver(&self, ty: Type<'_>) -> bool {
        if ty.as_adt().is_some() || ty.as_builtin().is_some() {
            return true;
        }
        ty.as_reference()
            .is_some_and(|(inner, _)| self.is_concrete_call_receiver(inner))
    }

    #[allow(clippy::too_many_arguments)]
    fn external_call_or_unresolved(
        &mut self,
        crate_key: &str,
        module: Module,
        specifier: &str,
        inline_ancestors: &[String],
        condition: &Condition,
        location: &SourceLocation,
        unresolved_reason: &str,
    ) -> Result<SemanticResolution> {
        let mut module_path = self.module_path(module);
        module_path.extend(inline_ancestors.iter().cloned());
        let external = self
            .external_metadata(crate_key, specifier)
            .map(|(name, kind)| (name, kind, specifier.into()))
            .or_else(|| {
                self.external_alias_metadata(crate_key, &module_path, specifier, condition)
            });
        let Some((external_name, external_kind, target_specifier)) = external else {
            return self.unresolved_resolution(
                crate_key,
                "call",
                specifier,
                location,
                unresolved_reason,
            );
        };
        let target = self.ensure_external_target(
            crate_key,
            &target_specifier,
            "call",
            &external_name,
            &external_kind,
            None,
        )?;
        Ok(SemanticResolution {
            target_ids: vec![target],
            status: ResolutionStatus::External,
            precision: Precision::Heuristic,
            reason: Some(format!(
                "call target is rooted in external crate {external_name}, whose source is outside the confined rust-analyzer model"
            )),
        })
    }

    fn use_tree_alias(&self, tree: &ast::UseTree) -> Option<String> {
        tree.rename().map(|rename| {
            ast::HasName::name(&rename)
                .map(|name| name.text().to_string())
                .unwrap_or_else(|| "_".into())
        })
    }

    fn range_matches_span(&self, file_id: FileId, range: TextRange, span: SourceSpan) -> bool {
        let index = line_index(self.db, file_id);
        let Some(start) = index.try_line_col(range.start()) else {
            return false;
        };
        let Some(end) = index.try_line_col(range.end()) else {
            return false;
        };
        start.line + 1 == span.start_line
            && start.col + 1 == span.start_column
            && end.line + 1 == span.end_line
            && end.col + 1 == span.end_column
    }

    fn semantic_owner_id(
        &self,
        node: &SyntaxNode,
        root_module: Module,
        type_use: bool,
    ) -> Option<String> {
        let definition = self.enclosing_semantic_definition(node);
        let node_id = definition
            .and_then(|definition| self.node_ids.get(&definition).cloned())
            .or_else(|| {
                (!type_use)
                    .then(|| self.node_ids.get(&Definition::Module(root_module)).cloned())
                    .flatten()
            })?;
        if type_use
            && self
                .nodes
                .get(&node_id)
                .is_none_or(|owner| !matches!(owner.kind.as_str(), "symbol" | "type"))
        {
            return None;
        }
        Some(node_id)
    }

    fn enclosing_semantic_definition(&self, node: &SyntaxNode) -> Option<Definition> {
        for ancestor in node.ancestors().skip(1) {
            if let Some(parameter) = ast::TypeParam::cast(ancestor.clone()) {
                return self
                    .sema
                    .to_def(&parameter)
                    .map(GenericParam::TypeParam)
                    .map(Definition::GenericParam);
            }
            if let Some(field) = ast::RecordField::cast(ancestor.clone()) {
                return self.sema.to_def(&field).map(Definition::Field);
            }
            if let Some(field) = ast::TupleField::cast(ancestor.clone()) {
                return self.sema.to_def(&field).map(Definition::Field);
            }
            if let Some(function) = ast::Fn::cast(ancestor.clone()) {
                return self.sema.to_fn_def(&function).map(Definition::Function);
            }
            if let Some(constant) = ast::Const::cast(ancestor.clone()) {
                return self.sema.to_def(&constant).map(Definition::Const);
            }
            if let Some(static_) = ast::Static::cast(ancestor.clone()) {
                return self.sema.to_def(&static_).map(Definition::Static);
            }
            if let Some(alias) = ast::TypeAlias::cast(ancestor.clone()) {
                return self.sema.to_def(&alias).map(Definition::TypeAlias);
            }
            if let Some(struct_) = ast::Struct::cast(ancestor.clone()) {
                return self
                    .sema
                    .to_def(&struct_)
                    .map(Adt::Struct)
                    .map(Definition::Adt);
            }
            if let Some(enum_) = ast::Enum::cast(ancestor.clone()) {
                return self.sema.to_def(&enum_).map(Adt::Enum).map(Definition::Adt);
            }
            if let Some(union) = ast::Union::cast(ancestor.clone()) {
                return self
                    .sema
                    .to_def(&union)
                    .map(Adt::Union)
                    .map(Definition::Adt);
            }
            if let Some(trait_) = ast::Trait::cast(ancestor.clone()) {
                return self.sema.to_def(&trait_).map(Definition::Trait);
            }
            if let Some(impl_) = ast::Impl::cast(ancestor.clone()) {
                return self.sema.to_def(&impl_).map(Definition::SelfType);
            }
            if let Some(module) = ast::Module::cast(ancestor) {
                return self.sema.to_module_def(&module).map(Definition::Module);
            }
        }
        None
    }

    fn classify_import_resolution(
        &mut self,
        crate_key: &str,
        site_kind: &str,
        specifier: &str,
        location: &SourceLocation,
        per_namespace: Option<PathResolutionPerNs>,
    ) -> Result<(SemanticResolution, Vec<String>)> {
        let Some(per_namespace) = per_namespace else {
            return Ok((
                self.external_or_unresolved(
                    crate_key,
                    site_kind,
                    "import",
                    specifier,
                    location,
                    "rust-analyzer could not resolve the use path",
                )?,
                Vec::new(),
            ));
        };

        let mut namespaces = Vec::new();
        let mut targets = BTreeMap::<String, bool>::new();
        let mut unsupported = Vec::new();
        for (namespace, resolution) in [
            ("type", per_namespace.type_ns),
            ("value", per_namespace.value_ns),
            ("macro", per_namespace.macro_ns),
        ] {
            let Some(resolution) = resolution else {
                continue;
            };
            namespaces.push(namespace.to_owned());
            match self.classify_import_target(crate_key, specifier, resolution)? {
                ClassifiedTarget::Concrete { node_id, external } => {
                    targets
                        .entry(node_id)
                        .and_modify(|seen_external| *seen_external &= external)
                        .or_insert(external);
                }
                ClassifiedTarget::Unsupported(reason) => unsupported.push(reason),
            }
        }

        if !unsupported.is_empty() {
            let reason = format!(
                "the HIR use target cannot be represented exactly: {}",
                unsupported.join("; ")
            );
            self.issue(
                "RUST_HIR_USE_TARGET_UNREPRESENTABLE",
                Some(location.path.clone()),
                reason.clone(),
            );
            return Ok((
                self.unresolved_resolution(crate_key, site_kind, specifier, location, &reason)?,
                namespaces,
            ));
        }

        let target_ids: Vec<_> = targets.keys().cloned().collect();
        let resolution = match target_ids.len() {
            0 => self.external_or_unresolved(
                crate_key,
                site_kind,
                "import",
                specifier,
                location,
                "rust-analyzer returned no representable use target",
            )?,
            1 => {
                let external = targets.values().next().copied().unwrap_or(false);
                SemanticResolution {
                    target_ids,
                    status: if external {
                        ResolutionStatus::External
                    } else {
                        ResolutionStatus::Resolved
                    },
                    precision: Precision::Exact,
                    reason: None,
                }
            }
            _ => SemanticResolution {
                target_ids,
                status: ResolutionStatus::Candidates,
                precision: Precision::Overapprox,
                reason: Some("the use path resolves to distinct Rust namespace targets".into()),
            },
        };
        Ok((resolution, namespaces))
    }

    fn classify_import_target(
        &mut self,
        crate_key: &str,
        specifier: &str,
        resolution: PathResolution,
    ) -> Result<ClassifiedTarget> {
        match resolution {
            PathResolution::Def(ModuleDef::BuiltinType(builtin)) => {
                let node_id = self.ensure_external_target(
                    crate_key,
                    specifier,
                    "import",
                    "builtin",
                    "rust-builtin",
                    Some(builtin.name().as_str()),
                )?;
                Ok(ClassifiedTarget::Concrete {
                    node_id,
                    external: true,
                })
            }
            PathResolution::Def(ModuleDef::Macro(_)) => Ok(ClassifiedTarget::Unsupported(
                "macro namespace target has no exact non-expanded semantic node".into(),
            )),
            PathResolution::Def(definition) => {
                self.classify_definition_target(crate_key, specifier, "import", definition.into())
            }
            PathResolution::TypeParam(parameter) => self.classify_definition_target(
                crate_key,
                specifier,
                "import",
                Definition::GenericParam(GenericParam::TypeParam(parameter)),
            ),
            PathResolution::Local(local) => self.classify_definition_target(
                crate_key,
                specifier,
                "import",
                Definition::Local(local),
            ),
            PathResolution::SelfType(_) => Ok(ClassifiedTarget::Unsupported(
                "Self in a use path has no concrete import target".into(),
            )),
            PathResolution::ConstParam(_) => Ok(ClassifiedTarget::Unsupported(
                "const parameter cannot be represented as an import target".into(),
            )),
            PathResolution::BuiltinAttr(_)
            | PathResolution::ToolModule(_)
            | PathResolution::DeriveHelper(_) => Ok(ClassifiedTarget::Unsupported(
                "attribute/tool resolution is outside the import graph vocabulary".into(),
            )),
        }
    }

    fn classify_definition_target(
        &mut self,
        crate_key: &str,
        specifier: &str,
        target_kind: &str,
        definition: Definition,
    ) -> Result<ClassifiedTarget> {
        if let Some(node_id) = self.node_ids.get(&definition).cloned() {
            return Ok(ClassifiedTarget::Concrete {
                node_id,
                external: false,
            });
        }

        let local_definition = definition
            .krate(self.db)
            .is_some_and(|krate| self.crate_keys_by_base.contains_key(&krate.base()));
        if local_definition {
            return Ok(ClassifiedTarget::Unsupported(format!(
                "local definition {:?} was omitted from the exact HIR node graph",
                definition
            )));
        }

        let (external_name, external_kind) = self
            .external_metadata(crate_key, specifier)
            .unwrap_or_else(|| ("external".into(), "rust-analyzer-external".into()));
        let display_name = self.definition_name(definition);
        let node_id = self.ensure_external_target(
            crate_key,
            specifier,
            target_kind,
            &external_name,
            &external_kind,
            display_name.as_deref(),
        )?;
        Ok(ClassifiedTarget::Concrete {
            node_id,
            external: true,
        })
    }

    fn classify_type_resolution(
        &mut self,
        crate_key: &str,
        specifier: &str,
        lexical_module_path: &[String],
        condition: &Condition,
        location: &SourceLocation,
        resolution: Option<PathResolution>,
    ) -> Result<SemanticResolution> {
        let Some(resolution) = resolution else {
            return self.external_type_or_unresolved(
                crate_key,
                specifier,
                lexical_module_path,
                condition,
                location,
                "rust-analyzer could not resolve the type path",
            );
        };

        let target = match resolution {
            PathResolution::Def(ModuleDef::BuiltinType(builtin)) => {
                let node_id = self.ensure_external_target(
                    crate_key,
                    specifier,
                    "type",
                    "builtin",
                    "rust-builtin",
                    Some(builtin.name().as_str()),
                )?;
                ClassifiedTarget::Concrete {
                    node_id,
                    external: true,
                }
            }
            PathResolution::Def(ModuleDef::Macro(_)) => ClassifiedTarget::Unsupported(
                "macro resolution cannot be represented as a type target".into(),
            ),
            PathResolution::Def(definition) => {
                self.classify_definition_target(crate_key, specifier, "type", definition.into())?
            }
            PathResolution::TypeParam(parameter) if !parameter.is_implicit(self.db) => self
                .classify_definition_target(
                    crate_key,
                    specifier,
                    "type",
                    Definition::GenericParam(GenericParam::TypeParam(parameter)),
                )?,
            PathResolution::TypeParam(parameter) => match parameter.parent(self.db) {
                GenericDef::Trait(trait_) => self.classify_definition_target(
                    crate_key,
                    specifier,
                    "type",
                    Definition::Trait(trait_),
                )?,
                _ => ClassifiedTarget::Unsupported(
                    "implicit impl-Trait parameter has no exact type node".into(),
                ),
            },
            PathResolution::SelfType(impl_) => {
                if let Some(adt) = impl_.self_ty(self.db).as_adt() {
                    self.classify_definition_target(
                        crate_key,
                        specifier,
                        "type",
                        Definition::Adt(adt),
                    )?
                } else {
                    ClassifiedTarget::Unsupported(
                        "impl Self type is not a concrete nominal type".into(),
                    )
                }
            }
            PathResolution::Local(_) | PathResolution::ConstParam(_) => {
                ClassifiedTarget::Unsupported("value resolution is not a type target".into())
            }
            PathResolution::BuiltinAttr(_)
            | PathResolution::ToolModule(_)
            | PathResolution::DeriveHelper(_) => ClassifiedTarget::Unsupported(
                "attribute/tool resolution is not a type target".into(),
            ),
        };

        match target {
            ClassifiedTarget::Concrete { node_id, external } => {
                if !external
                    && self
                        .nodes
                        .get(&node_id)
                        .is_none_or(|node| node.kind != "type")
                {
                    let reason = "resolved HIR target is not represented by a semantic type node";
                    return self
                        .unresolved_resolution(crate_key, "type_use", specifier, location, reason);
                }
                Ok(SemanticResolution {
                    target_ids: vec![node_id],
                    status: if external {
                        ResolutionStatus::External
                    } else {
                        ResolutionStatus::Resolved
                    },
                    precision: Precision::Exact,
                    reason: None,
                })
            }
            ClassifiedTarget::Unsupported(reason) => {
                self.unresolved_resolution(crate_key, "type_use", specifier, location, &reason)
            }
        }
    }

    fn external_or_unresolved(
        &mut self,
        crate_key: &str,
        site_kind: &str,
        target_kind: &str,
        specifier: &str,
        location: &SourceLocation,
        unresolved_reason: &str,
    ) -> Result<SemanticResolution> {
        if let Some((external_name, external_kind)) = self.external_metadata(crate_key, specifier) {
            let node_id = self.ensure_external_target(
                crate_key,
                specifier,
                target_kind,
                &external_name,
                &external_kind,
                None,
            )?;
            return Ok(SemanticResolution {
                target_ids: vec![node_id],
                status: ResolutionStatus::External,
                precision: Precision::Heuristic,
                reason: Some(format!(
                    "the {external_name} crate is outside the confined rust-analyzer source model"
                )),
            });
        }
        self.unresolved_resolution(crate_key, site_kind, specifier, location, unresolved_reason)
    }

    fn external_type_or_unresolved(
        &mut self,
        crate_key: &str,
        specifier: &str,
        lexical_module_path: &[String],
        condition: &Condition,
        location: &SourceLocation,
        unresolved_reason: &str,
    ) -> Result<SemanticResolution> {
        let external = self
            .external_metadata(crate_key, specifier)
            .map(|(name, kind)| {
                (
                    name.clone(),
                    kind,
                    format!(
                        "qualified path is rooted in external crate {name}, whose source is outside the confined rust-analyzer model"
                    ),
                )
            })
            .or_else(|| {
                self.external_alias_metadata(
                    crate_key,
                    lexical_module_path,
                    specifier,
                    condition,
                )
                .map(|(name, kind, imported)| {
                    (
                        name.clone(),
                        kind,
                        format!(
                            "module-level external import maps {specifier} to {imported} in crate {name}"
                        ),
                    )
                })
            });
        let Some((external_name, external_kind, reason)) = external else {
            return self.unresolved_resolution(
                crate_key,
                "type_use",
                specifier,
                location,
                unresolved_reason,
            );
        };
        let node_id = self.ensure_external_target(
            crate_key,
            specifier,
            "type",
            &external_name,
            &external_kind,
            None,
        )?;
        Ok(SemanticResolution {
            target_ids: vec![node_id],
            status: ResolutionStatus::External,
            precision: Precision::Heuristic,
            reason: Some(reason),
        })
    }

    fn external_alias_metadata(
        &self,
        crate_key: &str,
        lexical_module_path: &[String],
        specifier: &str,
        condition: &Condition,
    ) -> Option<(String, String, String)> {
        if specifier.starts_with("::") {
            return None;
        }
        let segments: Vec<_> = specifier.split("::").collect();
        let mut index = 0;
        let mut lookup_module_path = lexical_module_path.to_vec();
        match segments.first().copied()? {
            "self" => index = 1,
            "crate" => {
                lookup_module_path.clear();
                index = 1;
            }
            "super" => {
                while segments.get(index).copied() == Some("super") {
                    lookup_module_path.pop()?;
                    index += 1;
                }
            }
            _ => {}
        }
        let visible_name = *segments.get(index)?;
        if visible_name.is_empty() {
            return None;
        }
        let suffix = segments[index + 1..].join("::");
        let key = (crate_key.into(), lookup_module_path, visible_name.into());
        let site_condition_terms = condition_conjuncts(condition);
        let candidates: BTreeSet<_> = self
            .external_aliases
            .get(&key)?
            .iter()
            .filter(|alias| {
                alias
                    .condition_terms
                    .iter()
                    .all(|term| site_condition_terms.binary_search(term).is_ok())
            })
            .map(|alias| {
                let target = if suffix.is_empty() {
                    alias.target_specifier.clone()
                } else {
                    format!("{}::{suffix}", alias.target_specifier)
                };
                (
                    alias.external_name.clone(),
                    alias.external_kind.clone(),
                    target,
                )
            })
            .collect();
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
    }

    fn unresolved_resolution(
        &mut self,
        crate_key: &str,
        site_kind: &str,
        specifier: &str,
        location: &SourceLocation,
        reason: &str,
    ) -> Result<SemanticResolution> {
        let node_id =
            self.ensure_unknown_target(crate_key, site_kind, specifier, location, reason)?;
        Ok(SemanticResolution {
            target_ids: vec![node_id],
            status: ResolutionStatus::Unresolved,
            precision: Precision::Heuristic,
            reason: Some(reason.into()),
        })
    }

    fn external_metadata(&self, crate_key: &str, specifier: &str) -> Option<(String, String)> {
        let root = specifier
            .trim_start_matches("::")
            .split("::")
            .next()?
            .trim_start_matches("r#");
        if root.is_empty() || matches!(root, "crate" | "self" | "super" | "Self") {
            return None;
        }
        if let Some(kind) = self
            .external_crates
            .get(&(crate_key.into(), root.into()))
            .cloned()
        {
            return Some((root.into(), kind));
        }
        let normalized: BTreeSet<_> = self
            .external_crates
            .iter()
            .filter(|((from_crate, _), _)| from_crate == crate_key)
            .filter(|((_, name), _)| name.replace('-', "_") == root)
            .map(|((_, name), kind)| (name.clone(), kind.clone()))
            .collect();
        (normalized.len() == 1)
            .then(|| normalized.into_iter().next())
            .flatten()
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_external_target(
        &mut self,
        crate_key: &str,
        specifier: &str,
        target_kind: &str,
        external_name: &str,
        external_kind: &str,
        display_name: Option<&str>,
    ) -> Result<String> {
        let identity = json!({
            "language": "rust",
            "profile_id": self.profile_id,
            "crate_identity": crate_key,
            "target_kind": target_kind,
            "specifier": specifier,
            "external_name": external_name,
            "external_kind": external_kind,
        });
        let node_id = stable_id_from_value("external_system", &identity);
        self.insert_node(GraphNode {
            id: node_id.clone(),
            kind: "external_system".into(),
            locator: format!("rust-external:{external_name}:{specifier}"),
            display_name: Some(display_name.unwrap_or(specifier).into()),
            properties: properties(json!({
                "language": "rust",
                "ecosystem": "cargo",
                "external": true,
                "profile_id": self.profile_id,
                "crate_identity": crate_key,
                "target_kind": target_kind,
                "specifier": specifier,
                "external_name": external_name,
                "external_kind": external_kind,
                "canonical_identity": identity,
                "hir_provenance": EXTRACTOR,
            })),
        })?;
        Ok(node_id)
    }

    fn ensure_unknown_target(
        &mut self,
        crate_key: &str,
        site_kind: &str,
        specifier: &str,
        location: &SourceLocation,
        reason: &str,
    ) -> Result<String> {
        let identity = json!({
            "language": "rust",
            "profile_id": self.profile_id,
            "crate_identity": crate_key,
            "site_kind": site_kind,
            "specifier": specifier,
            "relative_path": location.path,
            "span": location.as_value(),
        });
        let node_id = stable_id_from_value("unknown_target", &identity);
        self.insert_node(GraphNode {
            id: node_id.clone(),
            kind: "unknown_target".into(),
            locator: format!(
                "unknown:rust:{site_kind}:{specifier}@{}:{}:{}",
                location.path, location.start_line, location.start_column
            ),
            display_name: Some(specifier.into()),
            properties: properties(json!({
                "language": "rust",
                "profile_id": self.profile_id,
                "crate_identity": crate_key,
                "site_kind": site_kind,
                "specifier": specifier,
                "reason": reason,
                "canonical_identity": identity,
            })),
        })?;
        Ok(node_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_dependency_site(
        &mut self,
        crate_key: &str,
        site_kind: &str,
        edge_kind: &str,
        source: &str,
        specifier: &str,
        condition: Condition,
        mut resolution: SemanticResolution,
        location: &SourceLocation,
        detail: &str,
        hir_kind: &str,
        evidence_properties: Properties,
    ) -> Result<()> {
        let condition = condition.canonicalize();
        resolution.target_ids.sort();
        resolution.target_ids.dedup();

        let mut primary = self.evidence(crate_key, location, detail, hir_kind);
        primary.properties.extend(evidence_properties);
        primary
            .properties
            .entry("macro_provenance".into())
            .or_insert_with(|| json!("direct-source"));
        primary.properties.insert(
            "resolution_status".into(),
            serde_json::to_value(resolution.status)?,
        );
        primary.properties.insert(
            "precision".into(),
            serde_json::to_value(resolution.precision)?,
        );
        if let Some(reason) = resolution.reason.as_deref() {
            primary
                .properties
                .insert("resolution_reason".into(), json!(reason));
            if resolution.precision == Precision::Heuristic {
                primary
                    .properties
                    .insert("heuristic_basis".into(), json!(reason));
            }
        }
        if resolution.status == ResolutionStatus::Candidates {
            primary
                .properties
                .entry("algorithm".into())
                .or_insert_with(|| json!("rust-analyzer-path-resolution-per-namespace"));
        }
        let supporting = Evidence {
            kind: EvidenceKind::Source,
            extractor: SOURCE_EXTRACTOR.into(),
            extractor_version: ADAPTER_VERSION.into(),
            path: Some(location.path.clone()),
            start_line: Some(location.start_line),
            start_column: Some(location.start_column),
            end_line: Some(location.end_line),
            end_column: Some(location.end_column),
            detail: Some(format!("Rust {site_kind} syntax")),
            properties: Properties::new(),
        };
        let evidence = vec![primary, supporting];
        let site_id = stable_id_from_value(
            "site",
            &json!({
                "condition": condition,
                "kind": site_kind,
                "path": location.path,
                "profile_id": self.profile_id,
                "source": source,
                "span": location.as_value(),
            }),
        );
        let site = DependencySite {
            id: site_id.clone(),
            source: source.into(),
            kind: site_kind.into(),
            specifier: specifier.into(),
            resolution_status: resolution.status,
            target_ids: resolution.target_ids.clone(),
            profile_id: self.profile_id.into(),
            condition: condition.clone(),
            precision: resolution.precision,
            reason: resolution.reason.clone(),
            evidence: evidence.clone(),
        };
        if let Some(existing) = self.sites.get(&site_id)
            && existing != &site
        {
            bail!("conflicting Rust HIR dependency site {site_id}");
        }

        let mut edges = Vec::with_capacity(resolution.target_ids.len());
        for target in &resolution.target_ids {
            let edge_id = stable_id_from_value(
                "edge",
                &json!({
                    "kind": edge_kind,
                    "site_id": site_id,
                    "target": target,
                }),
            );
            let edge = GraphEdge {
                id: edge_id.clone(),
                source: source.into(),
                target: target.clone(),
                kind: edge_kind.into(),
                site_id: Some(site_id.clone()),
                phase: Phase::Semantic,
                environment: Some("any".into()),
                profile_id: self.profile_id.into(),
                condition: condition.clone(),
                resolution_status: resolution.status,
                precision: resolution.precision,
                generated: location.generated,
                evidence: evidence.clone(),
            };
            if let Some(existing) = self.edges.get(&edge_id)
                && existing != &edge
            {
                bail!("conflicting Rust HIR dependency edge {edge_id}");
            }
            edges.push(edge);
        }

        self.sites.entry(site_id).or_insert(site);
        for edge in edges {
            self.edges.entry(edge.id.clone()).or_insert(edge);
        }
        Ok(())
    }

    fn emit_local(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        local: ra_ap_hir::Local,
    ) -> Result<()> {
        let primary_source = local.primary_source(self.db).source;
        let range = primary_source
            .as_ref()
            .map(|syntax| syntax.syntax().text_range());
        let Some(location) = self.location_from_range(range) else {
            return Ok(());
        };
        let Some(owner_id) = self.semantic_call_owner_id(file_id, primary_source.value.syntax())
        else {
            return Ok(());
        };
        if self
            .nodes
            .get(&owner_id)
            .is_none_or(|owner| owner.kind != "symbol")
        {
            self.issue(
                "RUST_HIR_LOCAL_OWNER_UNSUPPORTED",
                Some(location.path),
                "local definition was skipped because its HIR owner is not a symbol node".into(),
            );
            return Ok(());
        }
        let context = self.context(crate_key)?;
        let symbol_kind = if local.is_param(self.db) {
            "parameter"
        } else {
            "local_variable"
        };
        let identity = json!({
            "language": "rust",
            "package_locator": context.package_locator,
            "crate_identity": crate_key,
            "symbol_kind": symbol_kind,
            "identity_kind": "local",
            "enclosing_symbol": owner_id,
            "relative_path": location.path,
            "span": location.as_value(),
        });
        let node_id = stable_id_from_value("symbol", &identity);
        let node = GraphNode {
            id: node_id.clone(),
            kind: "symbol".into(),
            locator: format!(
                "rust-local:{}@{}:{}:{}",
                owner_id, location.path, location.start_line, location.start_column
            ),
            display_name: Some(local.name(self.db).as_str().to_owned()),
            properties: properties(json!({
                "language": "rust",
                "package_locator": context.package_locator,
                "crate_identity": crate_key,
                "symbol_kind": symbol_kind,
                "canonical_identity": identity,
                "profile_id": self.profile_id,
                "source_path": location.path,
                "source_span": location.as_value(),
                "inferred_type": self.canonical_type(local.ty(self.db)),
                "hir_provenance": EXTRACTOR,
            })),
        };
        self.insert_node(node)?;
        self.node_ids
            .insert(Definition::Local(local), node_id.clone());
        let evidence = self.evidence(crate_key, &location, "HIR local definition", symbol_kind);
        self.add_relation(crate_key, "declares", &owner_id, &node_id, evidence)
    }

    fn emit_generic_reference(
        &mut self,
        crate_key: &str,
        file_id: FileId,
        name_ref: &ast::NameRef,
    ) -> Result<()> {
        let Some(NameRefClass::Definition(origin, Some(substitution))) =
            NameRefClass::classify(&self.sema, name_ref)
        else {
            return Ok(());
        };
        let Some(origin_id) = self.node_ids.get(&origin).cloned() else {
            return Ok(());
        };
        let Some(origin_resolver) = self.resolvers.get(&origin).cloned() else {
            return Ok(());
        };
        let Ok(generic_origin) = GenericDef::try_from(origin) else {
            // NameRefClass also reports substitutions on fields and other
            // members reached through a generic owner. Those are not generic
            // declarations and must not become synthetic function instances.
            return Ok(());
        };
        if self.generic_has_const_parameters(generic_origin) {
            // GenericSubstitution::types intentionally omits const arguments;
            // emitting an exact instance would therefore collapse identities.
            self.issue(
                "RUST_HIR_CONST_GENERIC_INSTANCE_SKIPPED",
                self.paths_by_file.get(&file_id.index()).cloned(),
                "generic instance was skipped because rust-analyzer omits const arguments from the exposed substitution"
                    .into(),
            );
            return Ok(());
        }
        if self.generic_has_lifetime_parameters(generic_origin) {
            self.issue(
                "RUST_HIR_LIFETIME_GENERIC_INSTANCE_SKIPPED",
                self.paths_by_file.get(&file_id.index()).cloned(),
                "generic instance was skipped because rust-analyzer omits lifetime arguments from the exposed substitution"
                    .into(),
            );
            return Ok(());
        }
        let owner_id = if name_ref
            .syntax()
            .ancestors()
            .skip(1)
            .any(|ancestor| ast::ClosureExpr::can_cast(ancestor.kind()))
        {
            let Some(owner_id) = self.semantic_call_owner_id(file_id, name_ref.syntax()) else {
                return Ok(());
            };
            owner_id
        } else {
            let Some(owner) = self.enclosing_item(name_ref) else {
                return Ok(());
            };
            let Some(owner_id) = self.node_ids.get(&owner).cloned() else {
                return Ok(());
            };
            owner_id
        };
        let type_arguments: Vec<_> = substitution
            .types(self.db)
            .into_iter()
            .map(|(name, ty)| {
                let canonical = self.canonical_type(ty);
                format!("{}={canonical}", name.as_str())
            })
            .collect();
        if type_arguments
            .iter()
            .any(|argument| argument.contains("<unsupported-const-generic>"))
        {
            self.issue(
                "RUST_HIR_CONST_GENERIC_INSTANCE_SKIPPED",
                self.paths_by_file.get(&file_id.index()).cloned(),
                "generic instance was skipped because a nested const generic argument cannot be represented exactly"
                    .into(),
            );
            return Ok(());
        }
        if type_arguments.iter().any(|argument| {
            argument.contains("<unsupported-type-parameter>")
                || argument.contains("<unsupported-dyn-trait>")
        }) {
            self.issue(
                "RUST_HIR_GENERIC_INSTANCE_UNREPRESENTABLE",
                self.paths_by_file.get(&file_id.index()).cloned(),
                "generic instance was skipped because an implicit type parameter or complete dynamic-trait bound cannot be represented exactly"
                    .into(),
            );
            return Ok(());
        }
        if type_arguments
            .iter()
            .any(|argument| argument.contains("<unsupported-lifetime-generic>"))
        {
            self.issue(
                "RUST_HIR_LIFETIME_GENERIC_INSTANCE_SKIPPED",
                self.paths_by_file.get(&file_id.index()).cloned(),
                "generic instance was skipped because a nested lifetime argument cannot be represented exactly"
                    .into(),
            );
            return Ok(());
        }
        if type_arguments.is_empty()
            || type_arguments.iter().any(|argument| {
                argument.contains("<unknown>")
                    || argument.contains("<unsupported")
                    || argument.contains("external:")
            })
        {
            return Ok(());
        }
        let location = self.location_from_range(InFile::new(
            ra_ap_hir::EditionedFileId::current_edition(self.db, file_id).into(),
            name_ref.syntax().text_range(),
        ));
        let Some(location) = location else {
            return Ok(());
        };
        let Some(origin_node) = self.nodes.get(&origin_id).cloned() else {
            return Ok(());
        };
        let Some(origin_package_locator) = origin_node
            .properties
            .get("package_locator")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Ok(());
        };
        let Some(origin_crate_identity) = origin_node
            .properties
            .get("crate_identity")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return Ok(());
        };
        let resolver = format!("{origin_resolver}::<{}>", type_arguments.join(","));
        let (node_kind, kind_property, semantic_kind) = if origin_node.kind == "type" {
            ("type", "type_kind", "generic_instance")
        } else if origin_node.kind == "symbol" {
            ("symbol", "symbol_kind", "function_instance")
        } else {
            return Ok(());
        };
        let mut identity = json!({
            "language": "rust",
            "package_locator": origin_package_locator,
            "crate_identity": origin_crate_identity,
            "resolver_identity": resolver,
            "generic_origin": origin_resolver,
            "generic_origin_node": origin_id,
            "type_arguments": type_arguments,
        });
        identity[kind_property] = json!(semantic_kind);
        if node_kind == "symbol" {
            identity["identity_kind"] = json!("named");
        }
        let node_id = stable_id_from_value(node_kind, &identity);
        let mut node_properties = properties(json!({
            "language": "rust",
            "package_locator": origin_package_locator,
            "crate_identity": origin_crate_identity,
            "canonical_identity": identity,
            "resolver_identity": resolver,
            "profile_id": self.profile_id,
            "generic_origin_node": origin_id,
            "generic_origin": origin_resolver,
            "type_arguments": type_arguments,
            "hir_provenance": EXTRACTOR,
        }));
        node_properties.insert(kind_property.into(), json!(semantic_kind));
        self.insert_node(GraphNode {
            id: node_id.clone(),
            kind: node_kind.into(),
            locator: format!("rust-{node_kind}:{resolver}"),
            display_name: Some(resolver.clone()),
            properties: node_properties,
        })?;
        self.generic_instances_by_range.insert(
            (file_id.index(), name_ref.syntax().text_range()),
            node_id.clone(),
        );
        let evidence = self.evidence(
            crate_key,
            &location,
            "HIR generic instantiation",
            "generic-instance",
        );
        self.add_relation(crate_key, "instantiates", &owner_id, &node_id, evidence)
    }

    fn enclosing_item(&self, name_ref: &ast::NameRef) -> Option<Definition> {
        for node in name_ref.syntax().ancestors().skip(1) {
            if let Some(function) = ast::Fn::cast(node.clone()) {
                return self.sema.to_fn_def(&function).map(Definition::Function);
            }
            if let Some(constant) = ast::Const::cast(node.clone()) {
                return self.sema.to_def(&constant).map(Definition::Const);
            }
            if let Some(static_) = ast::Static::cast(node.clone()) {
                return self.sema.to_def(&static_).map(Definition::Static);
            }
            if let Some(alias) = ast::TypeAlias::cast(node.clone()) {
                return self.sema.to_def(&alias).map(Definition::TypeAlias);
            }
            if let Some(struct_) = ast::Struct::cast(node.clone()) {
                return self
                    .sema
                    .to_def(&struct_)
                    .map(Adt::Struct)
                    .map(Definition::Adt);
            }
            if let Some(enum_) = ast::Enum::cast(node.clone()) {
                return self.sema.to_def(&enum_).map(Adt::Enum).map(Definition::Adt);
            }
            if let Some(union) = ast::Union::cast(node.clone()) {
                return self
                    .sema
                    .to_def(&union)
                    .map(Adt::Union)
                    .map(Definition::Adt);
            }
            if let Some(trait_) = ast::Trait::cast(node.clone()) {
                return self.sema.to_def(&trait_).map(Definition::Trait);
            }
            if let Some(impl_) = ast::Impl::cast(node) {
                return self.sema.to_def(&impl_).map(Definition::SelfType);
            }
        }
        None
    }

    fn has_unrepresented_anonymous_execution_ancestor(&self, node: &SyntaxNode) -> bool {
        for ancestor in node.ancestors().skip(1) {
            if ast::ClosureExpr::can_cast(ancestor.kind()) {
                return false;
            }
            if ast::ConstArg::can_cast(ancestor.kind()) {
                return true;
            }
            if ast::BlockExpr::cast(ancestor).is_some_and(|block| {
                block.async_token().is_some()
                    || block.const_token().is_some()
                    || block.gen_token().is_some()
            }) {
                return true;
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_named_symbol(
        &mut self,
        crate_key: &str,
        definition: Definition,
        owner_id: &str,
        symbol_kind: &str,
        resolver: String,
        detail: &str,
    ) -> Result<Option<String>> {
        let Some(location) = self.definition_location(definition) else {
            return Ok(None);
        };
        if location.generated {
            self.issue(
                "RUST_HIR_GENERATED_DEFINITION_SKIPPED",
                Some(location.path),
                format!(
                    "generated {symbol_kind} definition was skipped because exact expansion provenance is unavailable"
                ),
            );
            return Ok(None);
        }
        let context = self.context(crate_key)?;
        let identity = json!({
            "language": "rust",
            "package_locator": context.package_locator,
            "crate_identity": crate_key,
            "symbol_kind": symbol_kind,
            "identity_kind": "named",
            "resolver_identity": resolver,
        });
        let node_id = stable_id_from_value("symbol", &identity);
        let display_name = self.definition_name(definition);
        self.insert_node(GraphNode {
            id: node_id.clone(),
            kind: "symbol".into(),
            locator: format!("rust-symbol:{resolver}"),
            display_name,
            properties: properties(json!({
                "language": "rust",
                "package_locator": context.package_locator,
                "crate_identity": crate_key,
                "symbol_kind": symbol_kind,
                "canonical_identity": identity,
                "resolver_identity": resolver,
                "profile_id": self.profile_id,
                "source_path": location.path,
                "source_span": location.as_value(),
                "hir_provenance": EXTRACTOR,
            })),
        })?;
        self.node_ids.insert(definition, node_id.clone());
        self.resolvers.insert(definition, resolver);
        let evidence = self.evidence(crate_key, &location, detail, symbol_kind);
        self.add_relation(crate_key, "declares", owner_id, &node_id, evidence)?;
        Ok(Some(node_id))
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_named_type(
        &mut self,
        crate_key: &str,
        definition: Definition,
        owner_id: &str,
        type_kind: &str,
        resolver: String,
        detail: &str,
    ) -> Result<Option<String>> {
        let Some(location) = self.definition_location(definition) else {
            return Ok(None);
        };
        if location.generated {
            self.issue(
                "RUST_HIR_GENERATED_DEFINITION_SKIPPED",
                Some(location.path),
                format!(
                    "generated {type_kind} definition was skipped because exact expansion provenance is unavailable"
                ),
            );
            return Ok(None);
        }
        let context = self.context(crate_key)?;
        let identity = json!({
            "language": "rust",
            "package_locator": context.package_locator,
            "crate_identity": crate_key,
            "type_kind": type_kind,
            "resolver_identity": resolver,
        });
        let node_id = stable_id_from_value("type", &identity);
        let display_name = self.definition_name(definition);
        self.insert_node(GraphNode {
            id: node_id.clone(),
            kind: "type".into(),
            locator: format!("rust-type:{resolver}"),
            display_name,
            properties: properties(json!({
                "language": "rust",
                "package_locator": context.package_locator,
                "crate_identity": crate_key,
                "type_kind": type_kind,
                "canonical_identity": identity,
                "resolver_identity": resolver,
                "profile_id": self.profile_id,
                "source_path": location.path,
                "source_span": location.as_value(),
                "hir_provenance": EXTRACTOR,
            })),
        })?;
        self.node_ids.insert(definition, node_id.clone());
        self.resolvers.insert(definition, resolver);
        let evidence = self.evidence(crate_key, &location, detail, type_kind);
        self.add_relation(crate_key, "declares", owner_id, &node_id, evidence)?;
        Ok(Some(node_id))
    }

    fn add_relation(
        &mut self,
        crate_key: &str,
        kind: &str,
        source: &str,
        target: &str,
        evidence: Evidence,
    ) -> Result<()> {
        let condition = Condition::Eq {
            key: "rust.crate_instance".into(),
            value: Value::String(crate_key.into()),
        }
        .canonicalize();
        let span = json!({
            "start_line": evidence.start_line.expect("semantic evidence start line"),
            "start_column": evidence.start_column.expect("semantic evidence start column"),
            "end_line": evidence.end_line.expect("semantic evidence end line"),
            "end_column": evidence.end_column.expect("semantic evidence end column"),
        });
        let path = evidence.path.as_deref().expect("semantic evidence path");
        let id = stable_id_from_value(
            "edge",
            &json!({
                "condition": condition,
                "kind": kind,
                "profile_id": self.profile_id,
                "source": source,
                "target": target,
                "path": path,
                "span": span,
            }),
        );
        let edge = GraphEdge {
            id: id.clone(),
            source: source.into(),
            target: target.into(),
            kind: kind.into(),
            site_id: None,
            phase: Phase::Semantic,
            environment: Some("any".into()),
            profile_id: self.profile_id.into(),
            condition,
            resolution_status: ResolutionStatus::Resolved,
            precision: Precision::Exact,
            generated: false,
            evidence: vec![evidence],
        };
        if let Some(existing) = self.edges.get(&id) {
            if existing != &edge {
                bail!("conflicting Rust HIR semantic edge {id}");
            }
        } else {
            self.edges.insert(id, edge);
        }
        Ok(())
    }

    fn insert_node(&mut self, node: GraphNode) -> Result<()> {
        if let Some(existing) = self.nodes.get(&node.id) {
            if existing != &node {
                bail!("conflicting Rust HIR semantic node {}", node.id);
            }
        } else {
            self.nodes.insert(node.id.clone(), node);
        }
        Ok(())
    }

    fn evidence_from_range(
        &self,
        crate_key: &str,
        range: InFile<TextRange>,
        detail: &str,
        hir_kind: &str,
    ) -> Option<Evidence> {
        self.location_from_range(range).and_then(|location| {
            (!location.generated).then(|| self.evidence(crate_key, &location, detail, hir_kind))
        })
    }

    fn evidence(
        &self,
        crate_key: &str,
        location: &SourceLocation,
        detail: &str,
        hir_kind: &str,
    ) -> Evidence {
        let cfg = self
            .contexts
            .get(crate_key)
            .map(|context| context.cfg.clone())
            .unwrap_or_default();
        Evidence {
            kind: EvidenceKind::Semantic,
            extractor: EXTRACTOR.into(),
            extractor_version: RUST_ANALYZER_CRATE_VERSION.into(),
            path: Some(location.path.clone()),
            start_line: Some(location.start_line),
            start_column: Some(location.start_column),
            end_line: Some(location.end_line),
            end_column: Some(location.end_column),
            detail: Some(detail.into()),
            properties: properties(json!({
                "backend": "rust-analyzer-library",
                "rust_analyzer_version": RUST_ANALYZER_CRATE_VERSION,
                "rust_analyzer_revision": RUST_ANALYZER_REVISION,
                "crate_identity": crate_key,
                "active_cfg": cfg,
                "hir_kind": hir_kind,
            })),
        }
    }

    fn definition_location(&self, definition: Definition) -> Option<SourceLocation> {
        let (range, missing_source_ast) = match definition {
            Definition::Module(module) => (module.declaration_source_range(self.db)?, false),
            Definition::Function(function) => source_range(self.sema.source_with_range(function)?),
            Definition::Adt(Adt::Struct(struct_)) => {
                source_range(self.sema.source_with_range(struct_)?)
            }
            Definition::Adt(Adt::Enum(enum_)) => source_range(self.sema.source_with_range(enum_)?),
            Definition::Adt(Adt::Union(union)) => source_range(self.sema.source_with_range(union)?),
            Definition::EnumVariant(variant) => source_range(self.sema.source_with_range(variant)?),
            Definition::Const(constant) => source_range(self.sema.source_with_range(constant)?),
            Definition::Static(static_) => source_range(self.sema.source_with_range(static_)?),
            Definition::Trait(trait_) => source_range(self.sema.source_with_range(trait_)?),
            Definition::TypeAlias(alias) => source_range(self.sema.source_with_range(alias)?),
            Definition::SelfType(impl_) => source_range(self.sema.source_with_range(impl_)?),
            Definition::Field(field) => source_range(self.sema.source_with_range(field)?),
            Definition::GenericParam(GenericParam::TypeParam(parameter)) => {
                source_range(self.sema.source_with_range(parameter.merge())?)
            }
            Definition::Local(local) => {
                let source = local.primary_source(self.db).source;
                (
                    source.as_ref().map(|syntax| syntax.syntax().text_range()),
                    false,
                )
            }
            _ => return None,
        };
        let mut location = self.location_from_range(range)?;
        location.generated |= missing_source_ast;
        Some(location)
    }

    fn location_from_range(&self, range: InFile<TextRange>) -> Option<SourceLocation> {
        let generated = range.file_id.is_macro();
        let display = self.sema.diagnostics_display_range_for_range(range);
        let path = self.paths_by_file.get(&display.file_id.index())?.clone();
        let index = line_index(self.db, display.file_id);
        let start = index.try_line_col(display.range.start())?;
        let end = index.try_line_col(display.range.end())?;
        Some(SourceLocation {
            path,
            start_line: start.line + 1,
            start_column: start.col + 1,
            end_line: end.line + 1,
            end_column: end.col + 1,
            generated,
        })
    }

    fn canonical_type(&self, ty: Type<'_>) -> String {
        if ty.contains_unknown() {
            return "<unknown>".into();
        }
        if let Some(parameter) = ty.as_type_param(self.db) {
            let definition = Definition::GenericParam(GenericParam::TypeParam(parameter));
            return self
                .resolvers
                .get(&definition)
                .cloned()
                .unwrap_or_else(|| "<unsupported-type-parameter>".into());
        }
        if let Some((adt, arguments)) = ty.as_adt_with_args() {
            if self.generic_has_const_parameters(GenericDef::Adt(adt)) {
                return "<unsupported-const-generic>".into();
            }
            if self.generic_has_lifetime_parameters(GenericDef::Adt(adt)) {
                return "<unsupported-lifetime-generic>".into();
            }
            let resolver = self
                .resolvers
                .get(&Definition::Adt(adt))
                .cloned()
                .unwrap_or_else(|| format!("external:{}", adt.name(self.db).as_str()));
            let arguments: Vec<_> = arguments
                .into_iter()
                .flatten()
                .map(|argument| self.canonical_type(argument))
                .collect();
            return if arguments.is_empty() {
                resolver
            } else {
                format!("{resolver}<{}>", arguments.join(","))
            };
        }
        if let Some((inner, mutability)) = ty.as_reference() {
            let prefix = match mutability {
                Mutability::Shared => "&",
                Mutability::Mut => "&mut ",
            };
            return format!("{prefix}{}", self.canonical_type(inner));
        }
        if let Some(inner) = ty.as_slice() {
            return format!("[{}]", self.canonical_type(inner));
        }
        if let Some((inner, length)) = ty.as_array(self.db) {
            return format!("[{};{length}]", self.canonical_type(inner));
        }
        if let Some((inner, mutability)) = ty.as_raw_ptr() {
            let prefix = match mutability {
                Mutability::Shared => "*const ",
                Mutability::Mut => "*mut ",
            };
            return format!("{prefix}{}", self.canonical_type(inner));
        }
        let tuple = ty.tuple_fields(self.db);
        if !tuple.is_empty() || ty.is_unit() {
            return format!(
                "({})",
                tuple
                    .into_iter()
                    .map(|item| self.canonical_type(item))
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
        if let Some(builtin) = ty.as_builtin() {
            return format!("builtin:{}", builtin.name().as_str());
        }
        if ty.as_dyn_trait().is_some() {
            // The public HIR helper exposes only the principal trait, not the
            // complete auto-trait/lifetime bound set. Treating that partial
            // view as canonical would collapse distinct `dyn Trait + ...`
            // instances.
            return "<unsupported-dyn-trait>".into();
        }
        "<unsupported>".into()
    }

    fn generic_has_const_parameters(&self, generic: GenericDef) -> bool {
        let has_const = |generic: GenericDef| {
            generic
                .params(self.db)
                .iter()
                .any(|parameter| matches!(parameter, GenericParam::ConstParam(_)))
        };
        if has_const(generic) {
            return true;
        }
        generic
            .as_assoc_item(self.db)
            .is_some_and(|item| match item.container(self.db) {
                AssocItemContainer::Trait(trait_) => has_const(GenericDef::Trait(trait_)),
                AssocItemContainer::Impl(impl_) => has_const(GenericDef::Impl(impl_)),
            })
    }

    fn generic_has_lifetime_parameters(&self, generic: GenericDef) -> bool {
        let has_lifetime = |generic: GenericDef| !generic.lifetime_params(self.db).is_empty();
        if has_lifetime(generic) {
            return true;
        }
        generic
            .as_assoc_item(self.db)
            .is_some_and(|item| match item.container(self.db) {
                AssocItemContainer::Trait(trait_) => has_lifetime(GenericDef::Trait(trait_)),
                AssocItemContainer::Impl(impl_) => has_lifetime(GenericDef::Impl(impl_)),
            })
    }

    fn module_owner(&self, crate_key: &str, module_path: &[String]) -> Option<String> {
        let context = self.contexts.get(crate_key)?;
        context.module_nodes.get(module_path).cloned()
    }

    fn module_path(&self, module: Module) -> Vec<String> {
        module
            .path_to_root(self.db)
            .into_iter()
            .rev()
            .filter_map(|module| module.name(self.db))
            .map(|name| name.as_str().to_owned())
            .collect()
    }

    fn item_resolver(&self, crate_key: &str, module_path: &[String], name: &str) -> String {
        let mut resolver = self.module_resolver(crate_key, module_path);
        resolver.push_str("::");
        resolver.push_str(name);
        resolver
    }

    fn module_resolver(&self, crate_key: &str, module_path: &[String]) -> String {
        let mut resolver = format!("{crate_key}::crate");
        for segment in module_path {
            resolver.push_str("::");
            resolver.push_str(segment);
        }
        resolver
    }

    fn module_def_sort_key(&self, definition: ModuleDef) -> (String, String) {
        let kind = match definition {
            ModuleDef::Module(_) => "module",
            ModuleDef::Function(_) => "function",
            ModuleDef::Adt(_) => "adt",
            ModuleDef::EnumVariant(_) => "variant",
            ModuleDef::Const(_) => "const",
            ModuleDef::Static(_) => "static",
            ModuleDef::Trait(_) => "trait",
            ModuleDef::TypeAlias(_) => "type-alias",
            ModuleDef::BuiltinType(_) => "builtin",
            ModuleDef::Macro(_) => "macro",
        };
        let name = definition
            .name(self.db)
            .map(|name| name.as_str().to_owned())
            .unwrap_or_default();
        (kind.into(), name)
    }

    fn definition_name(&self, definition: Definition) -> Option<String> {
        let name = match definition {
            Definition::Field(field) => field.name(self.db),
            Definition::Module(module) => module.name(self.db)?,
            Definition::Function(function) => function.name(self.db),
            Definition::Adt(adt) => adt.name(self.db),
            Definition::EnumVariant(variant) => variant.name(self.db),
            Definition::Const(constant) => constant.name(self.db)?,
            Definition::Static(static_) => static_.name(self.db),
            Definition::Trait(trait_) => trait_.name(self.db),
            Definition::TypeAlias(alias) => alias.name(self.db),
            Definition::GenericParam(parameter) => parameter.name(self.db),
            Definition::Local(local) => local.name(self.db),
            _ => return None,
        };
        Some(name.as_str().to_owned())
    }

    fn context(&self, crate_key: &str) -> Result<&SemanticCrateContext> {
        self.contexts
            .get(crate_key)
            .ok_or_else(|| anyhow::anyhow!("missing Rust semantic crate context {crate_key}"))
    }

    fn issue(&mut self, code: &'static str, path: Option<String>, reason: String) {
        self.issues.insert(
            (code.into(), path.clone(), reason.clone()),
            SemanticIssue { code, path, reason },
        );
    }
}

fn condition_conjuncts(condition: &Condition) -> Vec<String> {
    let canonical = condition.clone().canonicalize();
    let mut terms = match canonical {
        Condition::All { conditions } => conditions
            .into_iter()
            .map(|condition| condition.render())
            .collect(),
        condition if condition.render() == "true" => Vec::new(),
        condition => vec![condition.render()],
    };
    terms.sort();
    terms.dedup();
    terms
}

fn source_range<Ast>(source: InFile<(TextRange, Option<Ast>)>) -> (InFile<TextRange>, bool) {
    let missing_source_ast = source.value.1.is_none();
    (source.map(|(range, _)| range), missing_source_ast)
}

fn properties(value: Value) -> Properties {
    value
        .as_object()
        .expect("properties must be a JSON object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}
