//! Deterministic Rust HIR definition graph extraction.
//!
//! This pass consumes only the already-confined [`SafeProjectModel`]. It does
//! not perform import/type-use or call-site extraction; those are deliberately
//! separate vertical slices. All output is accumulated in a delta so the
//! scanner can validate and merge it atomically with the syntax graph.

use crate::{RUST_ANALYZER_CRATE_VERSION, RUST_ANALYZER_REVISION, hir_project::SafeProjectModel};
use anyhow::{Result, bail};
use depgraph_protocol::{
    Condition, Evidence, EvidenceKind, GraphEdge, GraphNode, Phase, Precision, Properties,
    ResolutionStatus, stable_id_from_value,
};
use ra_ap_hir::{
    Adt, AsAssocItem, AssocItem, AssocItemContainer, Crate, GenericDef, GenericParam, Impl, InFile,
    Module, ModuleDef, Mutability, Semantics, Type, attach_db,
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
    profile_id: &'a str,
    paths_by_file: BTreeMap<u32, String>,
    crate_keys_by_base: HashMap<ra_ap_ide_db::base_db::Crate, String>,
    nodes: BTreeMap<String, GraphNode>,
    edges: BTreeMap<String, GraphEdge>,
    node_ids: HashMap<Definition, String>,
    resolvers: HashMap<Definition, String>,
    impl_ids: HashMap<Impl, String>,
    impl_resolvers: HashMap<Impl, String>,
    issues: BTreeMap<(String, Option<String>, String), SemanticIssue>,
}

pub(crate) fn extract_semantic_delta(
    model: &SafeProjectModel,
    contexts: &BTreeMap<String, SemanticCrateContext>,
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
    let mut extractor = Extractor {
        model,
        db,
        sema: Semantics::new(db),
        contexts,
        profile_id,
        paths_by_file,
        crate_keys_by_base,
        nodes: BTreeMap::new(),
        edges: BTreeMap::new(),
        node_ids: HashMap::new(),
        resolvers: HashMap::new(),
        impl_ids: HashMap::new(),
        impl_resolvers: HashMap::new(),
        issues: BTreeMap::new(),
    };
    attach_db(db, || extractor.extract())?;
    Ok(SemanticDelta {
        nodes: extractor.nodes.into_values().collect(),
        edges: extractor.edges.into_values().collect(),
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
                    if self.has_anonymous_execution_ancestor(name.syntax()) {
                        self.issue(
                            "RUST_HIR_ANONYMOUS_BODY_DEFINITION_SKIPPED",
                            Some(path.clone()),
                            "local definition inside a closure, async block, const block, or generator was skipped until anonymous body identities are available"
                                .into(),
                        );
                        continue;
                    }
                    self.emit_local(&crate_key, local)?;
                }
            }
            for name_ref in parsed.syntax().descendants().filter_map(ast::NameRef::cast) {
                if self.has_anonymous_execution_ancestor(name_ref.syntax()) {
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
        }
        Ok(())
    }

    fn emit_local(&mut self, crate_key: &str, local: ra_ap_hir::Local) -> Result<()> {
        let primary_source = local.primary_source(self.db).source;
        let range = primary_source
            .as_ref()
            .map(|syntax| syntax.syntax().text_range());
        let Some(location) = self.location_from_range(range) else {
            return Ok(());
        };
        let Ok(owner_definition) = Definition::try_from(local.parent(self.db)) else {
            return Ok(());
        };
        let Some(owner_id) = self.node_ids.get(&owner_definition).cloned() else {
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
        let Some(owner) = self.enclosing_item(name_ref) else {
            return Ok(());
        };
        let Some(owner_id) = self.node_ids.get(&owner).cloned() else {
            return Ok(());
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

    fn has_anonymous_execution_ancestor(&self, node: &SyntaxNode) -> bool {
        node.ancestors().skip(1).any(|ancestor| {
            if ast::ClosureExpr::can_cast(ancestor.kind())
                || ast::ConstArg::can_cast(ancestor.kind())
            {
                return true;
            }
            ast::BlockExpr::cast(ancestor).is_some_and(|block| {
                block.async_token().is_some()
                    || block.const_token().is_some()
                    || block.gen_token().is_some()
            })
        })
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
        let mut resolver = format!("{crate_key}::crate");
        for segment in module_path {
            resolver.push_str("::");
            resolver.push_str(segment);
        }
        resolver.push_str("::");
        resolver.push_str(name);
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
