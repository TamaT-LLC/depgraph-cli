use depgraph_protocol::Condition;
use proc_macro2::Span;
use serde_json::{Number, Value};
use syn::{
    Attribute, Expr, ExprLit, ItemExternCrate, ItemMod, ItemUse, Lit, Macro, Meta, Token, UseTree,
    parse::Parser,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SourceSpan {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl SourceSpan {
    fn from_span(span: Span) -> Self {
        let start = span.start();
        let end = span.end();
        Self {
            start_line: start.line.max(1) as u32,
            start_column: start.column.saturating_add(1) as u32,
            end_line: end.line.max(start.line).max(1) as u32,
            end_column: end.column.saturating_add(1) as u32,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TypeUseContext {
    Signature,
    Body,
    Field,
    GenericBound,
    TraitBound,
    WherePredicate,
    TypeAlias,
    ImplTrait,
    ImplHeader,
    ConstStatic,
}

impl TypeUseContext {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Body => "body",
            Self::Field => "field",
            Self::GenericBound => "generic_bound",
            Self::TraitBound => "trait_bound",
            Self::WherePredicate => "where_predicate",
            Self::TypeAlias => "type_alias",
            Self::ImplTrait => "impl_trait",
            Self::ImplHeader => "impl_header",
            Self::ConstStatic => "const_static",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UseOccurrenceKey {
    pub relative_path: String,
    pub span: SourceSpan,
    pub target_specifier: String,
    pub alias: Option<String>,
    pub glob: bool,
    pub reexport: bool,
    pub inline_ancestors: Vec<String>,
    pub condition_key: String,
}

impl UseOccurrenceKey {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_occurrence(
        relative_path: &str,
        target_specifier: &str,
        alias: Option<&str>,
        glob: bool,
        reexport: bool,
        inline_ancestors: &[String],
        condition: &Condition,
        span: SourceSpan,
    ) -> Self {
        Self {
            relative_path: relative_path.into(),
            span,
            target_specifier: target_specifier.into(),
            alias: alias.map(str::to_owned),
            glob,
            reexport,
            inline_ancestors: inline_ancestors.to_vec(),
            condition_key: condition.render(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TypeUseOccurrenceKey {
    pub relative_path: String,
    pub span: SourceSpan,
    pub specifier: String,
    pub context: TypeUseContext,
    pub inline_ancestors: Vec<String>,
    pub condition_key: String,
}

impl TypeUseOccurrenceKey {
    pub(crate) fn from_occurrence(
        relative_path: &str,
        specifier: &str,
        context: TypeUseContext,
        inline_ancestors: &[String],
        condition: &Condition,
        span: SourceSpan,
    ) -> Self {
        Self {
            relative_path: relative_path.into(),
            span,
            specifier: specifier.into(),
            context,
            inline_ancestors: inline_ancestors.to_vec(),
            condition_key: condition.render(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Occurrence {
    Use {
        target_specifier: String,
        site_specifier: String,
        alias: Option<String>,
        glob: bool,
        reexport: bool,
        inline_ancestors: Vec<String>,
        condition: Condition,
        span: SourceSpan,
    },
    TypeUse {
        specifier: String,
        context: TypeUseContext,
        inline_ancestors: Vec<String>,
        condition: Condition,
        span: SourceSpan,
    },
    ExternCrate {
        specifier: String,
        alias: Option<String>,
        inline_ancestors: Vec<String>,
        condition: Condition,
        span: SourceSpan,
    },
    Module {
        name: String,
        inline: bool,
        inline_ancestors: Vec<String>,
        path_override: Option<String>,
        condition: Condition,
        span: SourceSpan,
    },
    Include {
        macro_name: String,
        argument: Option<String>,
        raw_argument: String,
        condition: Condition,
        span: SourceSpan,
    },
}

impl Occurrence {
    pub(crate) fn use_key(&self, relative_path: &str) -> Option<UseOccurrenceKey> {
        let Self::Use {
            target_specifier,
            alias,
            glob,
            reexport,
            inline_ancestors,
            condition,
            span,
            ..
        } = self
        else {
            return None;
        };
        Some(UseOccurrenceKey::from_occurrence(
            relative_path,
            target_specifier,
            alias.as_deref(),
            *glob,
            *reexport,
            inline_ancestors,
            condition,
            *span,
        ))
    }

    pub(crate) fn type_use_key(&self, relative_path: &str) -> Option<TypeUseOccurrenceKey> {
        let Self::TypeUse {
            specifier,
            context,
            inline_ancestors,
            condition,
            span,
        } = self
        else {
            return None;
        };
        Some(TypeUseOccurrenceKey::from_occurrence(
            relative_path,
            specifier,
            *context,
            inline_ancestors,
            condition,
            *span,
        ))
    }
}

pub(crate) fn collect_occurrences(file: &syn::File) -> Vec<Occurrence> {
    let mut collector = Collector {
        occurrences: Vec::new(),
        inherited_conditions: Vec::new(),
        inline_modules: Vec::new(),
        type_use_frames: Vec::new(),
    };
    collector.visit_file(file);
    collector.occurrences
}

struct Collector {
    occurrences: Vec<Occurrence>,
    inherited_conditions: Vec<Condition>,
    inline_modules: Vec<String>,
    type_use_frames: Vec<TypeUseFrame>,
}

#[derive(Clone)]
struct TypeUseFrame {
    context: TypeUseContext,
    condition: Condition,
}

struct UseLeaf {
    target_specifier: String,
    alias: Option<String>,
    glob: bool,
    span: SourceSpan,
}

impl Collector {
    fn condition(&self, attributes: &[Attribute]) -> Condition {
        let mut conditions = self.inherited_conditions.clone();
        conditions.extend(cfg_conditions(attributes));
        Condition::All { conditions }.canonicalize()
    }

    fn child_condition(&self, parent: &Condition, attributes: &[Attribute]) -> Condition {
        let mut conditions = vec![parent.clone()];
        conditions.extend(cfg_conditions(attributes));
        Condition::All { conditions }.canonicalize()
    }

    fn collect_type(&mut self, ty: &syn::Type, context: TypeUseContext, condition: &Condition) {
        self.type_use_frames.push(TypeUseFrame {
            context,
            condition: condition.clone(),
        });
        self.visit_type(ty);
        self.type_use_frames.pop();
    }

    fn collect_bounds(
        &mut self,
        bounds: &Punctuated<syn::TypeParamBound, Token![+]>,
        context: TypeUseContext,
        condition: &Condition,
    ) {
        self.type_use_frames.push(TypeUseFrame {
            context,
            condition: condition.clone(),
        });
        for bound in bounds {
            self.visit_type_param_bound(bound);
        }
        self.type_use_frames.pop();
    }

    fn collect_path(&mut self, path: &syn::Path, context: TypeUseContext, condition: &Condition) {
        self.record_type_path(path, context, condition, type_reference_span(path));
        self.type_use_frames.push(TypeUseFrame {
            context,
            condition: condition.clone(),
        });
        visit::visit_path(self, path);
        self.type_use_frames.pop();
    }

    fn collect_generics(&mut self, generics: &syn::Generics, condition: &Condition) {
        for parameter in &generics.params {
            match parameter {
                syn::GenericParam::Type(parameter) => {
                    let condition = self.child_condition(condition, &parameter.attrs);
                    self.collect_bounds(
                        &parameter.bounds,
                        TypeUseContext::GenericBound,
                        &condition,
                    );
                    if let Some(default) = &parameter.default {
                        self.collect_type(default, TypeUseContext::GenericBound, &condition);
                    }
                }
                syn::GenericParam::Const(parameter) => {
                    let condition = self.child_condition(condition, &parameter.attrs);
                    self.collect_type(&parameter.ty, TypeUseContext::GenericBound, &condition);
                }
                syn::GenericParam::Lifetime(_) => {}
            }
        }
        let Some(where_clause) = &generics.where_clause else {
            return;
        };
        for predicate in &where_clause.predicates {
            let syn::WherePredicate::Type(predicate) = predicate else {
                continue;
            };
            self.collect_type(
                &predicate.bounded_ty,
                TypeUseContext::WherePredicate,
                condition,
            );
            self.collect_bounds(&predicate.bounds, TypeUseContext::WherePredicate, condition);
        }
    }

    fn collect_signature(&mut self, signature: &syn::Signature, condition: &Condition) {
        self.collect_generics(&signature.generics, condition);
        for input in &signature.inputs {
            match input {
                syn::FnArg::Receiver(receiver) => {
                    if receiver.colon_token.is_some() {
                        let input_condition = self.child_condition(condition, &receiver.attrs);
                        self.collect_type(
                            &receiver.ty,
                            TypeUseContext::Signature,
                            &input_condition,
                        );
                    }
                }
                syn::FnArg::Typed(input) => {
                    let input_condition = self.child_condition(condition, &input.attrs);
                    self.collect_type(&input.ty, TypeUseContext::Signature, &input_condition);
                }
            }
        }
        if let syn::ReturnType::Type(_, output) = &signature.output {
            self.collect_type(output, TypeUseContext::Signature, condition);
        }
    }

    fn collect_fields(&mut self, fields: &syn::Fields, condition: &Condition) {
        for field in fields {
            let field_condition = self.child_condition(condition, &field.attrs);
            self.collect_type(&field.ty, TypeUseContext::Field, &field_condition);
        }
    }

    fn visit_body_block(&mut self, block: &syn::Block, condition: &Condition) {
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: TypeUseContext::Body,
            condition: condition.clone(),
        });
        self.visit_block(block);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_body_expr(&mut self, expression: &Expr, condition: &Condition) {
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: TypeUseContext::Body,
            condition: condition.clone(),
        });
        self.visit_expr(expression);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn record_type_path(
        &mut self,
        path: &syn::Path,
        context: TypeUseContext,
        condition: &Condition,
        span: SourceSpan,
    ) {
        let specifier = type_specifier(path);
        if specifier.is_empty() || is_primitive_path(path) {
            return;
        }
        self.occurrences.push(Occurrence::TypeUse {
            specifier,
            context,
            inline_ancestors: self.inline_modules.clone(),
            condition: condition.clone().canonicalize(),
            span,
        });
    }

    fn collect_macro(&mut self, mac: &Macro, condition: Condition) {
        let Some(segment) = mac.path.segments.last() else {
            return;
        };
        let macro_name = segment.ident.to_string();
        if !matches!(
            macro_name.as_str(),
            "include" | "include_str" | "include_bytes"
        ) {
            return;
        }
        let argument = syn::parse2::<syn::LitStr>(mac.tokens.clone())
            .ok()
            .map(|literal| literal.value());
        self.occurrences.push(Occurrence::Include {
            macro_name,
            argument,
            raw_argument: mac.tokens.to_string(),
            condition,
            span: SourceSpan::from_span(mac.span()),
        });
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let mut leaves = Vec::new();
        flatten_use_tree(
            &node.tree,
            Vec::new(),
            node.leading_colon.as_ref().map(Spanned::span),
            &mut leaves,
        );
        let condition = self.condition(&node.attrs);
        let reexport = !matches!(node.vis, syn::Visibility::Inherited);
        for mut leaf in leaves {
            if node.leading_colon.is_some() {
                leaf.target_specifier.insert_str(0, "::");
            }
            let site_specifier = match &leaf.alias {
                Some(alias) => format!("{} as {alias}", leaf.target_specifier),
                None => leaf.target_specifier.clone(),
            };
            self.occurrences.push(Occurrence::Use {
                target_specifier: leaf.target_specifier,
                site_specifier,
                alias: leaf.alias,
                glob: leaf.glob,
                reexport,
                inline_ancestors: self.inline_modules.clone(),
                condition: condition.clone(),
                span: leaf.span,
            });
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast ItemExternCrate) {
        self.occurrences.push(Occurrence::ExternCrate {
            specifier: node.ident.to_string(),
            alias: node.rename.as_ref().map(|(_, alias)| alias.to_string()),
            inline_ancestors: self.inline_modules.clone(),
            condition: self.condition(&node.attrs),
            span: SourceSpan::from_span(node.span()),
        });
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let condition = self.condition(&node.attrs);
        self.collect_signature(&node.sig, &condition);
        self.visit_body_block(&node.block, &condition);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_fields(&node.fields, &condition);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        for variant in &node.variants {
            let variant_condition = self.child_condition(&condition, &variant.attrs);
            self.collect_fields(&variant.fields, &variant_condition);
            if let Some((_, discriminant)) = &variant.discriminant {
                self.visit_body_expr(discriminant, &variant_condition);
            }
        }
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        for field in &node.fields.named {
            let field_condition = self.child_condition(&condition, &field.attrs);
            self.collect_type(&field.ty, TypeUseContext::Field, &field_condition);
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_type(&node.ty, TypeUseContext::TypeAlias, &condition);
    }

    fn visit_item_trait_alias(&mut self, node: &'ast syn::ItemTraitAlias) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_bounds(&node.bounds, TypeUseContext::TraitBound, &condition);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_bounds(&node.supertraits, TypeUseContext::TraitBound, &condition);
        self.inherited_conditions.push(condition);
        for item in &node.items {
            self.visit_trait_item(item);
        }
        self.inherited_conditions.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        if let Some((_, trait_path, _)) = &node.trait_ {
            self.collect_path(trait_path, TypeUseContext::ImplHeader, &condition);
        }
        self.collect_type(&node.self_ty, TypeUseContext::ImplHeader, &condition);
        self.inherited_conditions.push(condition);
        for item in &node.items {
            self.visit_impl_item(item);
        }
        self.inherited_conditions.pop();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_type(&node.ty, TypeUseContext::ConstStatic, &condition);
        self.visit_body_expr(&node.expr, &condition);
    }

    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        let condition = self.condition(&node.attrs);
        self.collect_type(&node.ty, TypeUseContext::ConstStatic, &condition);
        self.visit_body_expr(&node.expr, &condition);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        let condition = self.condition(&node.attrs);
        self.inherited_conditions.push(condition);
        for item in &node.items {
            self.visit_foreign_item(item);
        }
        self.inherited_conditions.pop();
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast syn::ForeignItemFn) {
        let condition = self.condition(&node.attrs);
        self.collect_signature(&node.sig, &condition);
    }

    fn visit_foreign_item_static(&mut self, node: &'ast syn::ForeignItemStatic) {
        let condition = self.condition(&node.attrs);
        self.collect_type(&node.ty, TypeUseContext::ConstStatic, &condition);
    }

    fn visit_foreign_item_type(&mut self, node: &'ast syn::ForeignItemType) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        let condition = self.condition(&node.attrs);
        self.collect_signature(&node.sig, &condition);
        if let Some(block) = &node.default {
            self.visit_body_block(block, &condition);
        }
    }

    fn visit_trait_item_type(&mut self, node: &'ast syn::TraitItemType) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_bounds(&node.bounds, TypeUseContext::TraitBound, &condition);
        if let Some((_, default)) = &node.default {
            self.collect_type(default, TypeUseContext::TypeAlias, &condition);
        }
    }

    fn visit_trait_item_const(&mut self, node: &'ast syn::TraitItemConst) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_type(&node.ty, TypeUseContext::ConstStatic, &condition);
        if let Some((_, default)) = &node.default {
            self.visit_body_expr(default, &condition);
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let condition = self.condition(&node.attrs);
        self.collect_signature(&node.sig, &condition);
        self.visit_body_block(&node.block, &condition);
    }

    fn visit_impl_item_type(&mut self, node: &'ast syn::ImplItemType) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_type(&node.ty, TypeUseContext::TypeAlias, &condition);
    }

    fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
        let condition = self.condition(&node.attrs);
        self.collect_generics(&node.generics, &condition);
        self.collect_type(&node.ty, TypeUseContext::ConstStatic, &condition);
        self.visit_body_expr(&node.expr, &condition);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let condition = self.condition(&node.attrs);
        let inline = node.content.is_some();
        let direct_path = path_override(&node.attrs);
        let conditional_paths = conditional_path_overrides(&node.attrs);
        if !inline && direct_path.is_none() && !conditional_paths.is_empty() {
            let predicates: Vec<_> = conditional_paths
                .iter()
                .map(|(predicate, _)| predicate.clone())
                .collect();
            for (predicate, path_override) in conditional_paths {
                self.occurrences.push(Occurrence::Module {
                    name: node.ident.to_string(),
                    inline,
                    inline_ancestors: self.inline_modules.clone(),
                    path_override: Some(path_override),
                    condition: Condition::All {
                        conditions: vec![condition.clone(), predicate],
                    }
                    .canonicalize(),
                    span: SourceSpan::from_span(node.span()),
                });
            }
            self.occurrences.push(Occurrence::Module {
                name: node.ident.to_string(),
                inline,
                inline_ancestors: self.inline_modules.clone(),
                path_override: None,
                condition: Condition::All {
                    conditions: vec![
                        condition.clone(),
                        Condition::Not {
                            condition: Box::new(Condition::Any {
                                conditions: predicates,
                            }),
                        },
                    ],
                }
                .canonicalize(),
                span: SourceSpan::from_span(node.span()),
            });
        } else {
            self.occurrences.push(Occurrence::Module {
                name: node.ident.to_string(),
                inline,
                inline_ancestors: self.inline_modules.clone(),
                path_override: direct_path,
                condition: condition.clone(),
                span: SourceSpan::from_span(node.span()),
            });
        }
        if let Some((_, items)) = &node.content {
            self.inline_modules.push(node.ident.to_string());
            self.inherited_conditions.push(condition);
            for item in items {
                self.visit_item(item);
            }
            self.inherited_conditions.pop();
            self.inline_modules.pop();
        }
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        self.collect_macro(&node.mac, self.condition(&node.attrs));
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        self.collect_macro(node, self.condition(&[]));
        visit::visit_macro(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_local(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_local(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_expr(self, node);
            return;
        };
        let attrs = expr_attributes(node);
        if attrs.is_empty() {
            visit::visit_expr(self, node);
            return;
        }
        let condition = self.child_condition(&frame.condition, attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_expr(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_stmt_macro(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_stmt_macro(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        if let Some(frame) = self.type_use_frames.last().cloned() {
            self.record_type_path(
                &node.path,
                frame.context,
                &frame.condition,
                type_reference_span(&node.path),
            );
        }
        visit::visit_type_path(self, node);
    }

    fn visit_trait_bound(&mut self, node: &'ast syn::TraitBound) {
        if let Some(frame) = self.type_use_frames.last().cloned() {
            self.record_type_path(
                &node.path,
                frame.context,
                &frame.condition,
                type_reference_span(&node.path),
            );
        }
        visit::visit_trait_bound(self, node);
    }

    fn visit_type_impl_trait(&mut self, node: &'ast syn::TypeImplTrait) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_type_impl_trait(self, node);
            return;
        };
        self.collect_bounds(&node.bounds, TypeUseContext::ImplTrait, &frame.condition);
    }

    fn visit_type_trait_object(&mut self, node: &'ast syn::TypeTraitObject) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_type_trait_object(self, node);
            return;
        };
        self.collect_bounds(&node.bounds, TypeUseContext::TraitBound, &frame.condition);
    }
}

fn flatten_use_tree(
    tree: &UseTree,
    mut prefix: Vec<String>,
    leaf_start: Option<Span>,
    output: &mut Vec<UseLeaf>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(
                &path.tree,
                prefix,
                leaf_start.or_else(|| Some(path.ident.span())),
                output,
            );
        }
        UseTree::Name(name) => {
            if name.ident != "self" || prefix.is_empty() {
                prefix.push(name.ident.to_string());
            }
            output.push(UseLeaf {
                target_specifier: prefix.join("::"),
                alias: None,
                glob: false,
                span: SourceSpan::from_span(
                    leaf_start
                        .and_then(|start| start.join(name.span()))
                        .unwrap_or_else(|| name.span()),
                ),
            });
        }
        UseTree::Rename(rename) => {
            if rename.ident != "self" || prefix.is_empty() {
                prefix.push(rename.ident.to_string());
            }
            output.push(UseLeaf {
                target_specifier: prefix.join("::"),
                alias: Some(rename.rename.to_string()),
                glob: false,
                span: SourceSpan::from_span(
                    leaf_start
                        .and_then(|start| start.join(rename.span()))
                        .unwrap_or_else(|| rename.span()),
                ),
            });
        }
        UseTree::Glob(glob) => {
            prefix.push("*".into());
            output.push(UseLeaf {
                target_specifier: prefix.join("::"),
                alias: None,
                glob: true,
                span: SourceSpan::from_span(
                    leaf_start
                        .and_then(|start| start.join(glob.span()))
                        .unwrap_or_else(|| glob.span()),
                ),
            });
        }
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix.clone(), None, output);
            }
        }
    }
}

fn type_reference_span(path: &syn::Path) -> SourceSpan {
    SourceSpan::from_span(path.span())
}

fn expr_attributes(expression: &Expr) -> &[Attribute] {
    match expression {
        Expr::Array(expression) => &expression.attrs,
        Expr::Assign(expression) => &expression.attrs,
        Expr::Async(expression) => &expression.attrs,
        Expr::Await(expression) => &expression.attrs,
        Expr::Binary(expression) => &expression.attrs,
        Expr::Block(expression) => &expression.attrs,
        Expr::Break(expression) => &expression.attrs,
        Expr::Call(expression) => &expression.attrs,
        Expr::Cast(expression) => &expression.attrs,
        Expr::Closure(expression) => &expression.attrs,
        Expr::Const(expression) => &expression.attrs,
        Expr::Continue(expression) => &expression.attrs,
        Expr::Field(expression) => &expression.attrs,
        Expr::ForLoop(expression) => &expression.attrs,
        Expr::Group(expression) => &expression.attrs,
        Expr::If(expression) => &expression.attrs,
        Expr::Index(expression) => &expression.attrs,
        Expr::Infer(expression) => &expression.attrs,
        Expr::Let(expression) => &expression.attrs,
        Expr::Lit(expression) => &expression.attrs,
        Expr::Loop(expression) => &expression.attrs,
        Expr::Macro(expression) => &expression.attrs,
        Expr::Match(expression) => &expression.attrs,
        Expr::MethodCall(expression) => &expression.attrs,
        Expr::Paren(expression) => &expression.attrs,
        Expr::Path(expression) => &expression.attrs,
        Expr::Range(expression) => &expression.attrs,
        Expr::RawAddr(expression) => &expression.attrs,
        Expr::Reference(expression) => &expression.attrs,
        Expr::Repeat(expression) => &expression.attrs,
        Expr::Return(expression) => &expression.attrs,
        Expr::Struct(expression) => &expression.attrs,
        Expr::Try(expression) => &expression.attrs,
        Expr::TryBlock(expression) => &expression.attrs,
        Expr::Tuple(expression) => &expression.attrs,
        Expr::Unary(expression) => &expression.attrs,
        Expr::Unsafe(expression) => &expression.attrs,
        Expr::While(expression) => &expression.attrs,
        Expr::Yield(expression) => &expression.attrs,
        _ => &[],
    }
}

fn is_primitive_path(path: &syn::Path) -> bool {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return false;
    }
    matches!(
        path.segments[0].ident.to_string().as_str(),
        "bool"
            | "char"
            | "str"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f16"
            | "f32"
            | "f64"
            | "f128"
    )
}

fn path_override(attributes: &[Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        match &attribute.meta {
            Meta::NameValue(value) => match &value.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(path),
                    ..
                }) => Some(path.value()),
                _ => None,
            },
            _ => None,
        }
    })
}

fn conditional_path_overrides(attributes: &[Attribute]) -> Vec<(Condition, String)> {
    let mut overrides = Vec::new();
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg_attr"))
    {
        let Meta::List(list) = &attribute.meta else {
            continue;
        };
        let items = parse_meta_list(&list.tokens);
        let Some(predicate) = items.first() else {
            continue;
        };
        let condition = condition_from_meta(predicate).canonicalize();
        for meta in items.iter().skip(1) {
            let Meta::NameValue(value) = meta else {
                continue;
            };
            if !value.path.is_ident("path") {
                continue;
            }
            if let Expr::Lit(ExprLit {
                lit: Lit::Str(path),
                ..
            }) = &value.value
            {
                overrides.push((condition.clone(), path.value()));
            }
        }
    }
    overrides
}

fn cfg_conditions(attributes: &[Attribute]) -> Vec<Condition> {
    let mut conditions = Vec::new();
    for attribute in attributes {
        if attribute.path().is_ident("cfg") {
            if let Meta::List(list) = &attribute.meta
                && let Some(meta) = parse_meta_list(&list.tokens).into_iter().next()
            {
                conditions.push(condition_from_meta(&meta));
            }
            continue;
        }
        if !attribute.path().is_ident("cfg_attr") {
            continue;
        }
        let Meta::List(list) = &attribute.meta else {
            continue;
        };
        let items = parse_meta_list(&list.tokens);
        let Some(predicate) = items.first() else {
            continue;
        };
        let gated_cfg: Vec<_> = items
            .iter()
            .skip(1)
            .filter(|meta| meta.path().is_ident("cfg"))
            .filter_map(|meta| match meta {
                Meta::List(list) => parse_meta_list(&list.tokens).into_iter().next(),
                _ => None,
            })
            .map(|meta| condition_from_meta(&meta))
            .collect();
        if gated_cfg.is_empty() {
            continue;
        }
        conditions.push(
            Condition::Any {
                conditions: vec![
                    Condition::Not {
                        condition: Box::new(condition_from_meta(predicate)),
                    },
                    Condition::All {
                        conditions: gated_cfg,
                    },
                ],
            }
            .canonicalize(),
        );
    }
    conditions
}

fn parse_meta_list(tokens: &proc_macro2::TokenStream) -> Vec<Meta> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .map(|items| items.into_iter().collect())
        .unwrap_or_default()
}

pub(crate) fn condition_from_meta(meta: &Meta) -> Condition {
    match meta {
        Meta::Path(path) => Condition::Defined {
            key: format!("rust.cfg.{}", path_to_string(path)),
        },
        Meta::NameValue(name_value) => Condition::Eq {
            key: cfg_key(&path_to_string(&name_value.path)),
            value: expression_value(&name_value.value),
        },
        Meta::List(list) => {
            let operator = path_to_string(&list.path);
            let conditions: Vec<_> = parse_meta_list(&list.tokens)
                .iter()
                .map(condition_from_meta)
                .collect();
            match operator.as_str() {
                "all" => Condition::All { conditions }.canonicalize(),
                "any" => Condition::Any { conditions }.canonicalize(),
                "not" => conditions
                    .into_iter()
                    .next()
                    .map(|condition| Condition::Not {
                        condition: Box::new(condition),
                    })
                    .unwrap_or(Condition::Any { conditions: vec![] }),
                "cfg" => conditions.into_iter().next().unwrap_or_default(),
                _ => Condition::Defined {
                    key: format!("rust.cfg.{operator}({})", list.tokens),
                },
            }
        }
    }
}

fn cfg_key(key: &str) -> String {
    if key == "feature" {
        "rust.feature".into()
    } else {
        format!("rust.cfg.{key}")
    }
}

fn expression_value(expression: &Expr) -> Value {
    match expression {
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::Str(value) => Value::String(value.value()),
            Lit::Bool(value) => Value::Bool(value.value),
            Lit::Int(value) => value
                .base10_parse::<i64>()
                .ok()
                .map(Number::from)
                .map(Value::Number)
                .unwrap_or_else(|| Value::String(value.to_string())),
            other => Value::String(quote_literal(other)),
        },
        _ => Value::String("<expression>".into()),
    }
}

fn quote_literal(literal: &Lit) -> String {
    match literal {
        Lit::Byte(value) => value.value().to_string(),
        Lit::ByteStr(value) => String::from_utf8_lossy(&value.value()).into_owned(),
        Lit::Char(value) => value.value().to_string(),
        Lit::Float(value) => value.to_string(),
        Lit::Verbatim(value) => value.to_string(),
        _ => "<literal>".into(),
    }
}

fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn type_specifier(path: &syn::Path) -> String {
    let specifier = path_to_string(path);
    if path.leading_colon.is_some() {
        format!("::{specifier}")
    } else {
        specifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_at_span(source: &str, span: SourceSpan) -> &str {
        assert_eq!(span.start_line, span.end_line, "test span must be one line");
        let line = source
            .lines()
            .nth(span.start_line.saturating_sub(1) as usize)
            .expect("span line exists");
        &line[span.start_column.saturating_sub(1) as usize
            ..span.end_column.saturating_sub(1) as usize]
    }

    fn find_type_use(
        occurrences: &[Occurrence],
        specifier: &str,
        context: TypeUseContext,
    ) -> (Condition, SourceSpan) {
        occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::TypeUse {
                    specifier: actual,
                    context: actual_context,
                    condition,
                    span,
                    ..
                } if actual == specifier && *actual_context == context => {
                    Some((condition.clone(), *span))
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing {context:?} type use {specifier}"))
    }

    fn find_use_condition(occurrences: &[Occurrence], specifier: &str) -> Condition {
        occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::Use {
                    target_specifier,
                    condition,
                    ..
                } if target_specifier == specifier => Some(condition.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing use {specifier}"))
    }

    fn find_include_condition(occurrences: &[Occurrence], argument: &str) -> Condition {
        occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::Include {
                    argument: Some(actual),
                    condition,
                    ..
                } if actual == argument => Some(condition.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing include {argument}"))
    }

    #[test]
    fn extracts_structured_grouped_use_reexport_cfg_and_include() {
        let source = concat!(
            "#[cfg(all(unix, feature = \"fast\"))]\n",
            "pub use crate::model::{self, Item as Renamed, *};\n",
            "include_str!(\"data.txt\");\n",
        );
        let file = syn::parse_file(source).unwrap();
        let occurrences = collect_occurrences(&file);
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Use {
                target_specifier,
                site_specifier,
                alias: None,
                glob: false,
                reexport: true,
                condition,
                ..
            } if target_specifier == "crate::model"
                && site_specifier == "crate::model"
                && condition.render().contains("rust.feature")
        )));
        let renamed = occurrences
            .iter()
            .find(|occurrence| {
                matches!(
                    occurrence,
                    Occurrence::Use { alias: Some(alias), .. } if alias == "Renamed"
                )
            })
            .expect("renamed use leaf");
        assert!(matches!(
            renamed,
            Occurrence::Use {
                target_specifier,
                site_specifier,
                alias: Some(alias),
                glob: false,
                ..
            } if target_specifier == "crate::model::Item"
                && site_specifier == "crate::model::Item as Renamed"
                && alias == "Renamed"
        ));
        let Occurrence::Use { span, .. } = renamed else {
            unreachable!();
        };
        assert_eq!(text_at_span(source, *span), "Item as Renamed");

        let glob = occurrences
            .iter()
            .find(|occurrence| matches!(occurrence, Occurrence::Use { glob: true, .. }))
            .expect("glob use leaf");
        assert!(matches!(
            glob,
            Occurrence::Use { target_specifier, site_specifier, alias: None, .. }
                if target_specifier == "crate::model::*"
                    && site_specifier == "crate::model::*"
        ));
        let Occurrence::Use { span, .. } = glob else {
            unreachable!();
        };
        assert_eq!(text_at_span(source, *span), "*");

        let key = renamed.use_key("src/lib.rs").expect("use key");
        assert_eq!(key.relative_path, "src/lib.rs");
        assert_eq!(key.target_specifier, "crate::model::Item");
        assert_eq!(key.alias.as_deref(), Some("Renamed"));
        assert!(key.reexport);
        assert!(!key.glob);
        assert!(key.condition_key.contains("rust.feature"));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Include { argument: Some(path), .. } if path == "data.txt"
        )));
    }

    #[test]
    fn preserves_absolute_use_alias_and_leaf_span() {
        let source = "use ::external::Thing as LocalThing;\n";
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        let occurrence = occurrences
            .iter()
            .find(|occurrence| matches!(occurrence, Occurrence::Use { .. }))
            .expect("use occurrence");
        assert!(matches!(
            occurrence,
            Occurrence::Use {
                target_specifier,
                site_specifier,
                alias: Some(alias),
                glob: false,
                reexport: false,
                ..
            } if target_specifier == "::external::Thing"
                && site_specifier == "::external::Thing as LocalThing"
                && alias == "LocalThing"
        ));
        let Occurrence::Use { span, .. } = occurrence else {
            unreachable!();
        };
        assert_eq!(
            text_at_span(source, *span),
            "::external::Thing as LocalThing"
        );
    }

    #[test]
    fn preserves_extern_crate_alias() {
        let occurrences =
            collect_occurrences(&syn::parse_file("extern crate std as sys;\n").unwrap());
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::ExternCrate {
                specifier,
                alias: Some(alias),
                ..
            } if specifier == "std" && alias == "sys"
        )));
    }

    #[test]
    fn extracts_type_uses_from_all_supported_item_positions() {
        let source = concat!(
            "#[cfg(feature = \"outer\")]\n",
            "mod nested {\n",
            "#[cfg(unix)]\n",
            "struct Record<T: GenericTrait> where T: WhereTrait {\n",
            "#[cfg(target_os = \"linux\")] field: crate::model::FieldType,\n",
            "primitive: u32,\n",
            "}\n",
            "type Alias = ResultType;\n",
            "trait Service: SuperTrait {\n",
            "type Associated: AssocBound;\n",
            "fn run<'a, U: MethodBound>(&self, input: Input<'a>) -> impl OutputTrait\n",
            "where U: WhereMethod;\n",
            "}\n",
            "impl<T> Service for Record<T> where T: ImplWhere {}\n",
            "}\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        find_type_use(&occurrences, "GenericTrait", TypeUseContext::GenericBound);
        find_type_use(&occurrences, "WhereTrait", TypeUseContext::WherePredicate);
        let (field_condition, field_span) = find_type_use(
            &occurrences,
            "crate::model::FieldType",
            TypeUseContext::Field,
        );
        let rendered = field_condition.render();
        assert!(rendered.contains("rust.feature"));
        assert!(rendered.contains("rust.cfg.unix"));
        assert!(rendered.contains("rust.cfg.target_os"));
        assert_eq!(text_at_span(source, field_span), "crate::model::FieldType");
        find_type_use(&occurrences, "ResultType", TypeUseContext::TypeAlias);
        find_type_use(&occurrences, "SuperTrait", TypeUseContext::TraitBound);
        find_type_use(&occurrences, "AssocBound", TypeUseContext::TraitBound);
        find_type_use(&occurrences, "MethodBound", TypeUseContext::GenericBound);
        let (_, input_span) = find_type_use(&occurrences, "Input", TypeUseContext::Signature);
        assert_eq!(text_at_span(source, input_span), "Input<'a>");
        find_type_use(&occurrences, "OutputTrait", TypeUseContext::ImplTrait);
        find_type_use(&occurrences, "WhereMethod", TypeUseContext::WherePredicate);
        find_type_use(&occurrences, "Service", TypeUseContext::ImplHeader);
        let (_, record_span) = find_type_use(&occurrences, "Record", TypeUseContext::ImplHeader);
        assert_eq!(text_at_span(source, record_span), "Record<T>");
        find_type_use(&occurrences, "ImplWhere", TypeUseContext::WherePredicate);
        assert!(!occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::TypeUse { specifier, .. }
                if matches!(specifier.as_str(), "u32" | "'a" | "Self")
        )));
    }

    #[test]
    fn extracts_const_static_foreign_and_trait_object_types() {
        let source = concat!(
            "const ITEM: ConstType = make();\n",
            "static VALUE: StaticType = make();\n",
            "extern \"C\" { fn foreign(value: ForeignInput) -> ForeignOutput; }\n",
            "type Object = dyn DisplayTrait + SendTrait;\n",
            "type Absolute = ::external::AbsoluteType;\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        find_type_use(&occurrences, "ConstType", TypeUseContext::ConstStatic);
        find_type_use(&occurrences, "StaticType", TypeUseContext::ConstStatic);
        find_type_use(&occurrences, "ForeignInput", TypeUseContext::Signature);
        find_type_use(&occurrences, "ForeignOutput", TypeUseContext::Signature);
        find_type_use(&occurrences, "DisplayTrait", TypeUseContext::TraitBound);
        find_type_use(&occurrences, "SendTrait", TypeUseContext::TraitBound);
        find_type_use(
            &occurrences,
            "::external::AbsoluteType",
            TypeUseContext::TypeAlias,
        );
    }

    #[test]
    fn skips_implicit_receivers_but_keeps_explicit_receiver_types() {
        let source = concat!(
            "trait Receivers {\n",
            "fn owned(self);\n",
            "fn borrowed(&self);\n",
            "fn mutable(&mut self);\n",
            "fn explicit(self: Box<Self>);\n",
            "}\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        let signature_specifiers: Vec<_> = occurrences
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::TypeUse {
                    specifier,
                    context: TypeUseContext::Signature,
                    ..
                } => Some(specifier.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(signature_specifiers, ["Box", "Self"]);
    }

    #[test]
    fn cfg_attr_cfg_is_preserved_as_an_implication() {
        let source = concat!(
            "#[cfg_attr(feature = \"gate\", cfg(unix))]\n",
            "type Conditional = Target;\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        let (condition, _) = find_type_use(&occurrences, "Target", TypeUseContext::TypeAlias);
        let rendered = condition.render();
        assert!(rendered.contains("rust.feature"));
        assert!(rendered.contains("rust.cfg.unix"));
        assert!(rendered.contains('!'));
    }

    #[test]
    fn preserves_module_and_include_occurrences_with_inherited_cfg() {
        let source = concat!(
            "#[cfg(feature = \"nested\")]\n",
            "mod inline {\n",
            "mod external;\n",
            "include_bytes!(\"asset.bin\");\n",
            "}\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Module {
                name,
                inline: true,
                inline_ancestors,
                condition,
                ..
            } if name == "inline"
                && inline_ancestors.is_empty()
                && condition.render().contains("rust.feature")
        )));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Module {
                name,
                inline: false,
                inline_ancestors,
                condition,
                ..
            } if name == "external"
                && inline_ancestors.len() == 1
                && inline_ancestors[0] == "inline"
                && condition.render().contains("rust.feature")
        )));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Include {
                macro_name,
                argument: Some(argument),
                condition,
                ..
            } if macro_name == "include_bytes"
                && argument == "asset.bin"
                && condition.render().contains("rust.feature")
        )));
    }

    #[test]
    fn body_occurrences_inherit_function_method_const_and_static_cfg() {
        let source = concat!(
            "#[cfg(feature = \"function\")]\n",
            "fn gated_function() {\n",
            "#[cfg(target_os = \"linux\")] use crate::function::Thing;\n",
            "include_str!(\"function.txt\");\n",
            "}\n",
            "#[cfg(target_arch = \"aarch64\")]\n",
            "trait GatedTrait {\n",
            "#[cfg(feature = \"trait_default\")]\n",
            "fn defaulted(&self) {\n",
            "use crate::trait_default::Thing;\n",
            "include_bytes!(\"trait.bin\");\n",
            "}\n",
            "#[cfg(feature = \"trait_const\")]\n",
            "const VALUE: usize = { use crate::trait_const::Thing; 0 };\n",
            "}\n",
            "struct Host;\n",
            "#[cfg(target_family = \"unix\")]\n",
            "impl Host {\n",
            "#[cfg(feature = \"method\")]\n",
            "fn method(&self) { use crate::method::Thing; }\n",
            "#[cfg(target_pointer_width = \"64\")]\n",
            "const VALUE: usize = { use crate::impl_const::Thing; 0 };\n",
            "}\n",
            "#[cfg(feature = \"const_item\")]\n",
            "const ITEM: usize = { use crate::const_item::Thing; include_bytes!(\"const.bin\"); 0 };\n",
            "#[cfg(target_os = \"macos\")]\n",
            "static STATIC_ITEM: usize = { use crate::static_item::Thing; 0 };\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        let function_use = find_use_condition(&occurrences, "crate::function::Thing").render();
        assert!(function_use.contains("rust.feature"));
        assert!(function_use.contains("rust.cfg.target_os"));
        assert!(
            find_include_condition(&occurrences, "function.txt")
                .render()
                .contains("rust.feature")
        );

        let trait_default =
            find_use_condition(&occurrences, "crate::trait_default::Thing").render();
        assert!(trait_default.contains("rust.cfg.target_arch"));
        assert!(trait_default.contains("rust.feature"));
        let trait_include = find_include_condition(&occurrences, "trait.bin").render();
        assert!(trait_include.contains("rust.cfg.target_arch"));
        assert!(trait_include.contains("rust.feature"));

        let trait_const = find_use_condition(&occurrences, "crate::trait_const::Thing").render();
        assert!(trait_const.contains("rust.cfg.target_arch"));
        assert!(trait_const.contains("rust.feature"));
        let method = find_use_condition(&occurrences, "crate::method::Thing").render();
        assert!(method.contains("rust.cfg.target_family"));
        assert!(method.contains("rust.feature"));
        let impl_const = find_use_condition(&occurrences, "crate::impl_const::Thing").render();
        assert!(impl_const.contains("rust.cfg.target_family"));
        assert!(impl_const.contains("rust.cfg.target_pointer_width"));
        assert!(
            find_use_condition(&occurrences, "crate::const_item::Thing")
                .render()
                .contains("rust.feature")
        );
        assert!(
            find_include_condition(&occurrences, "const.bin")
                .render()
                .contains("rust.feature")
        );
        assert!(
            find_use_condition(&occurrences, "crate::static_item::Thing")
                .render()
                .contains("rust.cfg.target_os")
        );
    }

    #[test]
    fn extracts_body_type_uses_without_reclassifying_declaration_types() {
        let source = concat!(
            "#[cfg(all(feature = \"body\", target_os = \"linux\"))]\n",
            "fn inspect(#[cfg(unix)] input: SignatureType) -> OutputType {\n",
            "let _: LetType = loop {};\n",
            "#[cfg(target_arch = \"x86_64\")] let _: GatedLocalType = loop {};\n",
            "let value = 0usize;\n",
            "let _ = value as CastType;\n",
            "#[cfg(target_env = \"gnu\")] std::mem::size_of::<GatedExprType>();\n",
            "#[cfg(target_pointer_width = \"64\")] include_bytes!(\"body.bin\");\n",
            "let _ = std::mem::size_of::<Option<MissingImport>>();\n",
            "}\n",
            "#[cfg(feature = \"const_body\")]\n",
            "const CONST_SIZE: usize = std::mem::size_of::<ConstBodyType>();\n",
            "#[cfg(target_arch = \"aarch64\")]\n",
            "static STATIC_SIZE: usize = std::mem::size_of::<StaticBodyType>();\n",
            "trait WithDefault {\n",
            "#[cfg(feature = \"trait_body\")]\n",
            "fn defaulted(&self, input: TraitSignatureType) {\n",
            "let _: TraitBodyType = loop {};\n",
            "}\n",
            "#[cfg(target_os = \"windows\")]\n",
            "const SIZE: usize = std::mem::size_of::<TraitConstBodyType>();\n",
            "}\n",
            "struct Host;\n",
            "impl Host {\n",
            "#[cfg(feature = \"impl_body\")]\n",
            "fn method(&self) { let _: ImplBodyType = loop {}; }\n",
            "#[cfg(target_pointer_width = \"64\")]\n",
            "const SIZE: usize = std::mem::size_of::<ImplConstBodyType>();\n",
            "}\n",
            "#[cfg(feature = \"enum_body\")]\n",
            "enum Discriminant {\n",
            "#[cfg(target_arch = \"x86_64\")]\n",
            "Value = std::mem::size_of::<EnumBodyType>() as isize,\n",
            "}\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        let (missing_condition, missing_span) =
            find_type_use(&occurrences, "MissingImport", TypeUseContext::Body);
        let rendered = missing_condition.render();
        assert!(rendered.contains("rust.feature"));
        assert!(rendered.contains("rust.cfg.target_os"));
        assert_eq!(text_at_span(source, missing_span), "MissingImport");
        for specifier in [
            "LetType",
            "CastType",
            "Option",
            "ConstBodyType",
            "StaticBodyType",
            "TraitBodyType",
            "TraitConstBodyType",
            "ImplBodyType",
            "ImplConstBodyType",
            "GatedLocalType",
            "GatedExprType",
            "EnumBodyType",
        ] {
            find_type_use(&occurrences, specifier, TypeUseContext::Body);
        }
        let (signature_condition, _) =
            find_type_use(&occurrences, "SignatureType", TypeUseContext::Signature);
        assert!(signature_condition.render().contains("rust.cfg.unix"));
        let (local_condition, _) =
            find_type_use(&occurrences, "GatedLocalType", TypeUseContext::Body);
        assert!(local_condition.render().contains("rust.cfg.target_arch"));
        let (expression_condition, _) =
            find_type_use(&occurrences, "GatedExprType", TypeUseContext::Body);
        assert!(
            expression_condition
                .render()
                .contains("rust.cfg.target_env")
        );
        let include_condition = find_include_condition(&occurrences, "body.bin").render();
        assert!(include_condition.contains("rust.cfg.target_pointer_width"));
        let (enum_condition, _) = find_type_use(&occurrences, "EnumBodyType", TypeUseContext::Body);
        assert!(enum_condition.render().contains("rust.feature"));
        assert!(enum_condition.render().contains("rust.cfg.target_arch"));
        assert_eq!(TypeUseContext::Body.as_str(), "body");

        for specifier in ["SignatureType", "OutputType", "TraitSignatureType"] {
            let matches: Vec<_> = occurrences
                .iter()
                .filter(|occurrence| {
                    matches!(
                        occurrence,
                        Occurrence::TypeUse {
                            specifier: actual,
                            context: TypeUseContext::Signature,
                            ..
                        } if actual == specifier
                    )
                })
                .collect();
            assert_eq!(matches.len(), 1, "declaration type {specifier}");
            assert!(!occurrences.iter().any(|occurrence| matches!(
                occurrence,
                Occurrence::TypeUse {
                    specifier: actual,
                    context: TypeUseContext::Body,
                    ..
                } if actual == specifier
            )));
        }
    }

    #[test]
    fn collection_and_use_keys_are_deterministic() {
        let file =
            syn::parse_file("use crate::{Alpha as A, Beta};\ntype Selected = crate::Alpha;\n")
                .unwrap();
        let first = collect_occurrences(&file);
        let second = collect_occurrences(&file);
        assert_eq!(first, second);
        let first_keys: Vec<_> = first
            .iter()
            .filter_map(|occurrence| occurrence.use_key("src/lib.rs"))
            .collect();
        let second_keys: Vec<_> = second
            .iter()
            .filter_map(|occurrence| occurrence.use_key("src/lib.rs"))
            .collect();
        assert_eq!(first_keys, second_keys);
        let first_type_keys: Vec<_> = first
            .iter()
            .filter_map(|occurrence| occurrence.type_use_key("src/lib.rs"))
            .collect();
        let second_type_keys: Vec<_> = second
            .iter()
            .filter_map(|occurrence| occurrence.type_use_key("src/lib.rs"))
            .collect();
        assert!(!first_type_keys.is_empty());
        assert_eq!(first_type_keys, second_type_keys);
    }
}
