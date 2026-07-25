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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CallSyntaxKind {
    Function,
    Method,
    MacroBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MacroExpansionBoundaryKind {
    Bang,
    Attribute,
    Derive,
}

impl MacroExpansionBoundaryKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Bang => "bang",
            Self::Attribute => "attribute",
            Self::Derive => "derive",
        }
    }
}

impl CallSyntaxKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Method => "method",
            Self::MacroBoundary => "macro_boundary",
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CallOccurrenceKey {
    pub relative_path: String,
    pub span: SourceSpan,
    pub specifier: String,
    pub syntax_kind: CallSyntaxKind,
    pub inline_ancestors: Vec<String>,
    pub condition_key: String,
}

impl CallOccurrenceKey {
    pub(crate) fn from_occurrence(
        relative_path: &str,
        specifier: &str,
        syntax_kind: CallSyntaxKind,
        inline_ancestors: &[String],
        condition: &Condition,
        span: SourceSpan,
    ) -> Self {
        Self {
            relative_path: relative_path.into(),
            span,
            specifier: specifier.into(),
            syntax_kind,
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
    Call {
        specifier: String,
        syntax_kind: CallSyntaxKind,
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
    MacroExpansionBoundary {
        specifier: String,
        boundary_kind: MacroExpansionBoundaryKind,
        condition: Condition,
        span: SourceSpan,
    },
    BuildEnvironmentMacro {
        macro_name: String,
        variable: Option<String>,
        raw_argument: String,
        condition: Condition,
        span: SourceSpan,
    },
    UnsupportedAttribute {
        specifier: String,
        reason: String,
        condition: Condition,
        span: SourceSpan,
    },
    UnsupportedMacroArguments {
        specifier: String,
        condition: Condition,
        span: SourceSpan,
    },
}

impl Occurrence {
    pub(crate) fn use_key(&self, relative_path: &str) -> Option<UseOccurrenceKey> {
        let (target_specifier, alias, glob, reexport, inline_ancestors, condition, span) =
            match self {
                Self::Use {
                    target_specifier,
                    alias,
                    glob,
                    reexport,
                    inline_ancestors,
                    condition,
                    span,
                    ..
                } => (
                    target_specifier,
                    alias.as_deref(),
                    *glob,
                    *reexport,
                    inline_ancestors,
                    condition,
                    *span,
                ),
                Self::ExternCrate {
                    specifier,
                    alias,
                    inline_ancestors,
                    condition,
                    span,
                } => (
                    specifier,
                    alias.as_deref(),
                    false,
                    false,
                    inline_ancestors,
                    condition,
                    *span,
                ),
                _ => return None,
            };
        Some(UseOccurrenceKey::from_occurrence(
            relative_path,
            target_specifier,
            alias,
            glob,
            reexport,
            inline_ancestors,
            condition,
            span,
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

    pub(crate) fn call_key(&self, relative_path: &str) -> Option<CallOccurrenceKey> {
        let Self::Call {
            specifier,
            syntax_kind,
            inline_ancestors,
            condition,
            span,
        } = self
        else {
            return None;
        };
        Some(CallOccurrenceKey::from_occurrence(
            relative_path,
            specifier,
            *syntax_kind,
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

    fn child_condition(&mut self, parent: &Condition, attributes: &[Attribute]) -> Condition {
        let mut conditions = vec![parent.clone()];
        conditions.extend(cfg_conditions(attributes));
        let condition = Condition::All { conditions }.canonicalize();
        self.collect_attribute_boundaries(attributes, &condition);
        condition
    }

    fn inherited_condition(&self) -> Condition {
        Condition::All {
            conditions: self.inherited_conditions.clone(),
        }
        .canonicalize()
    }

    fn active_condition(&self) -> Condition {
        self.type_use_frames
            .last()
            .map(|frame| frame.condition.clone())
            .unwrap_or_else(|| self.inherited_condition())
    }

    fn record_call(&mut self, specifier: String, syntax_kind: CallSyntaxKind, span: SourceSpan) {
        if self.type_use_frames.is_empty() {
            return;
        }
        self.occurrences.push(Occurrence::Call {
            specifier,
            syntax_kind,
            inline_ancestors: self.inline_modules.clone(),
            condition: self.inherited_condition(),
            span,
        });
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
                    if let Some(default) = &parameter.default {
                        self.visit_body_expr(default, &condition);
                    }
                }
                syn::GenericParam::Lifetime(parameter) => {
                    self.child_condition(condition, &parameter.attrs);
                }
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
                    let input_condition = self.child_condition(condition, &receiver.attrs);
                    if receiver.colon_token.is_some() {
                        self.collect_type(
                            &receiver.ty,
                            TypeUseContext::Signature,
                            &input_condition,
                        );
                    }
                }
                syn::FnArg::Typed(input) => {
                    let input_condition = self.child_condition(condition, &input.attrs);
                    self.inherited_conditions.push(input_condition.clone());
                    self.type_use_frames.push(TypeUseFrame {
                        context: TypeUseContext::Signature,
                        condition: input_condition.clone(),
                    });
                    self.visit_pat(&input.pat);
                    self.type_use_frames.pop();
                    self.inherited_conditions.pop();
                    self.collect_type(&input.ty, TypeUseContext::Signature, &input_condition);
                }
            }
        }
        if let Some(variadic) = &signature.variadic {
            self.child_condition(condition, &variadic.attrs);
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

    fn record_macro_expansion_boundary(
        &mut self,
        specifier: String,
        boundary_kind: MacroExpansionBoundaryKind,
        condition: Condition,
        span: SourceSpan,
    ) {
        let condition = condition.canonicalize();
        if self.occurrences.iter().any(|occurrence| {
            matches!(
                occurrence,
                Occurrence::MacroExpansionBoundary {
                    specifier: existing_specifier,
                    boundary_kind: existing_kind,
                    condition: existing_condition,
                    span: existing_span,
                } if existing_specifier == &specifier
                    && *existing_kind == boundary_kind
                    && existing_condition == &condition
                    && *existing_span == span
            )
        }) {
            return;
        }
        self.occurrences.push(Occurrence::MacroExpansionBoundary {
            specifier,
            boundary_kind,
            condition,
            span,
        });
    }

    fn record_build_environment_macro(
        &mut self,
        macro_name: String,
        variable: Option<String>,
        raw_argument: String,
        condition: Condition,
        span: SourceSpan,
    ) {
        let condition = condition.canonicalize();
        if self.occurrences.iter().any(|occurrence| {
            matches!(
                occurrence,
                Occurrence::BuildEnvironmentMacro {
                    macro_name: existing_name,
                    variable: existing_variable,
                    raw_argument: existing_raw,
                    condition: existing_condition,
                    span: existing_span,
                } if existing_name == &macro_name
                    && existing_variable == &variable
                    && existing_raw == &raw_argument
                    && existing_condition == &condition
                    && *existing_span == span
            )
        }) {
            return;
        }
        self.occurrences.push(Occurrence::BuildEnvironmentMacro {
            macro_name,
            variable,
            raw_argument,
            condition,
            span,
        });
    }

    fn record_unsupported_attribute(
        &mut self,
        specifier: String,
        reason: &'static str,
        condition: Condition,
        span: SourceSpan,
    ) {
        let condition = condition.canonicalize();
        if self.occurrences.iter().any(|occurrence| {
            matches!(
                occurrence,
                Occurrence::UnsupportedAttribute {
                    specifier: existing_specifier,
                    reason: existing_reason,
                    condition: existing_condition,
                    span: existing_span,
                } if existing_specifier == &specifier
                    && existing_reason == reason
                    && existing_condition == &condition
                    && *existing_span == span
            )
        }) {
            return;
        }
        self.occurrences.push(Occurrence::UnsupportedAttribute {
            specifier,
            reason: reason.into(),
            condition,
            span,
        });
    }

    fn record_unsupported_macro_arguments(
        &mut self,
        specifier: String,
        condition: Condition,
        span: SourceSpan,
    ) {
        let condition = condition.canonicalize();
        if self.occurrences.iter().any(|occurrence| {
            matches!(
                occurrence,
                Occurrence::UnsupportedMacroArguments {
                    specifier: existing_specifier,
                    condition: existing_condition,
                    span: existing_span,
                } if existing_specifier == &specifier
                    && existing_condition == &condition
                    && *existing_span == span
            )
        }) {
            return;
        }
        self.occurrences
            .push(Occurrence::UnsupportedMacroArguments {
                specifier,
                condition,
                span,
            });
    }

    fn collect_attribute_boundaries(&mut self, attributes: &[Attribute], condition: &Condition) {
        for attribute in attributes {
            self.collect_attribute_meta(&attribute.meta, condition, attribute.span());
        }
    }

    fn collect_attribute_meta(&mut self, meta: &Meta, condition: &Condition, span: Span) {
        if let Meta::NameValue(name_value) = meta {
            self.collect_attribute_expression_macros(&name_value.value, condition);
        }

        if meta.path().is_ident("derive") {
            let Meta::List(list) = meta else {
                self.record_unsupported_attribute(
                    "derive".into(),
                    "derive attribute payload is not a trait path list",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
                return;
            };
            let derives = match Punctuated::<syn::Path, Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
            {
                Ok(derives) => derives,
                Err(_) => {
                    self.record_unsupported_attribute(
                        format!("derive({})", list.tokens),
                        "derive attribute payload could not be parsed",
                        condition.clone(),
                        SourceSpan::from_span(span),
                    );
                    return;
                }
            };
            for derive in derives {
                self.record_macro_expansion_boundary(
                    type_specifier(&derive),
                    MacroExpansionBoundaryKind::Derive,
                    condition.clone(),
                    SourceSpan::from_span(derive.span()),
                );
            }
            return;
        }

        if meta.path().is_ident("cfg") {
            let valid = match meta {
                Meta::List(list) => try_parse_meta_list(&list.tokens)
                    .is_ok_and(|items| items.len() == 1 && valid_cfg_predicate(&items[0])),
                _ => false,
            };
            if !valid {
                let specifier = match meta {
                    Meta::List(list) => format!("cfg({})", list.tokens),
                    Meta::NameValue(_) => "cfg=<value>".into(),
                    Meta::Path(_) => "cfg".into(),
                };
                self.record_unsupported_attribute(
                    specifier,
                    "cfg attribute payload could not be parsed",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
            }
            return;
        }

        if meta.path().is_ident("cfg_attr") {
            let Meta::List(list) = meta else {
                self.record_unsupported_attribute(
                    "cfg_attr".into(),
                    "cfg_attr payload is not a predicate and attribute list",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
                return;
            };
            let Ok(items) = try_parse_meta_list(&list.tokens) else {
                self.record_unsupported_attribute(
                    format!("cfg_attr({})", list.tokens),
                    "cfg_attr payload could not be parsed",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
                return;
            };
            let Some(predicate) = items.first().filter(|_| items.len() >= 2) else {
                self.record_unsupported_attribute(
                    format!("cfg_attr({})", list.tokens),
                    "cfg_attr payload could not be parsed",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
                return;
            };
            if !valid_cfg_predicate(predicate) {
                self.record_unsupported_attribute(
                    format!("cfg_attr({})", list.tokens),
                    "cfg_attr predicate is not a supported cfg expression",
                    condition.clone(),
                    SourceSpan::from_span(span),
                );
                for nested in items.iter().skip(1) {
                    self.collect_attribute_meta(nested, condition, nested.span());
                }
                return;
            }
            let nested_condition = Condition::All {
                conditions: vec![condition.clone(), condition_from_meta(predicate)],
            }
            .canonicalize();
            for nested in items.iter().skip(1) {
                self.collect_attribute_meta(nested, &nested_condition, nested.span());
            }
            return;
        }

        if let Meta::List(list) = meta {
            let nested = try_parse_meta_list(&list.tokens).unwrap_or_default();
            for nested_meta in &nested {
                self.collect_nested_meta_expression_macros(nested_meta, condition);
            }
        }

        if is_builtin_attribute(meta.path()) {
            self.record_unsupported_attribute(
                attribute_specifier(meta),
                "built-in attribute semantics are not statically verified",
                condition.clone(),
                SourceSpan::from_span(span),
            );
            return;
        }
        self.record_macro_expansion_boundary(
            type_specifier(meta.path()),
            MacroExpansionBoundaryKind::Attribute,
            condition.clone(),
            SourceSpan::from_span(span),
        );
    }

    fn collect_nested_meta_expression_macros(&mut self, meta: &Meta, condition: &Condition) {
        match meta {
            Meta::NameValue(name_value) => {
                self.collect_attribute_expression_macros(&name_value.value, condition);
            }
            Meta::List(list) => match try_parse_meta_list(&list.tokens) {
                Ok(nested) => {
                    for nested in nested {
                        self.collect_nested_meta_expression_macros(&nested, condition);
                    }
                }
                Err(_) => {
                    self.collect_expression_macros_from_tokens(&list.tokens, condition);
                    self.record_unsupported_attribute(
                        format!("{}({})", type_specifier(&list.path), list.tokens),
                        "nested attribute payload could not be parsed",
                        condition.clone(),
                        SourceSpan::from_span(list.span()),
                    );
                }
            },
            Meta::Path(_) => {}
        }
    }

    fn collect_expression_macros_from_tokens(
        &mut self,
        tokens: &proc_macro2::TokenStream,
        condition: &Condition,
    ) {
        let Ok(expressions) =
            Punctuated::<Expr, Token![,]>::parse_terminated.parse2(tokens.clone())
        else {
            return;
        };
        for expression in expressions {
            self.collect_attribute_expression_macros(&expression, condition);
        }
    }

    fn collect_attribute_expression_macros(&mut self, expression: &Expr, condition: &Condition) {
        struct ExpressionMacroCollector<'collector> {
            collector: &'collector mut Collector,
            condition: &'collector Condition,
        }

        impl<'ast> Visit<'ast> for ExpressionMacroCollector<'_> {
            fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
                self.collector
                    .collect_macro(&node.mac, self.condition.clone());
            }
        }

        let mut collector = ExpressionMacroCollector {
            collector: self,
            condition,
        };
        collector.visit_expr(expression);
    }

    fn collect_macro(&mut self, mac: &Macro, condition: Condition) {
        if mac.path.is_ident("macro_rules") {
            return;
        }
        // syn keeps macro arguments as opaque tokens. Recursively parse the
        // expression-shaped subset so safety boundaries nested inside benign
        // built-ins (for example concat!(env!("OUT_DIR"), ...)) are not lost.
        let arguments = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone());
        if let Ok(arguments) = &arguments {
            for argument in arguments {
                self.collect_attribute_expression_macros(argument, &condition);
            }
        }
        let Some(segment) = mac.path.segments.last() else {
            return;
        };
        let macro_name = segment.ident.to_string();
        if mac.path.is_ident("include")
            || mac.path.is_ident("include_str")
            || mac.path.is_ident("include_bytes")
        {
            let argument = syn::parse2::<syn::LitStr>(mac.tokens.clone())
                .ok()
                .map(|literal| literal.value());
            let occurrence = Occurrence::Include {
                macro_name: macro_name.clone(),
                argument,
                raw_argument: mac.tokens.to_string(),
                condition: condition.clone(),
                span: SourceSpan::from_span(mac.span()),
            };
            if !self.occurrences.contains(&occurrence) {
                self.occurrences.push(occurrence);
            }
            self.record_macro_expansion_boundary(
                format!("{macro_name}!"),
                MacroExpansionBoundaryKind::Bang,
                condition,
                SourceSpan::from_span(mac.span()),
            );
            return;
        }

        if mac.path.is_ident("env") || mac.path.is_ident("option_env") {
            self.record_build_environment_macro(
                macro_name,
                first_string_literal_argument(&mac.tokens),
                mac.tokens.to_string(),
                condition,
                SourceSpan::from_span(mac.span()),
            );
            return;
        }

        if is_builtin_macro(&mac.path) && arguments.is_err() && !mac.tokens.is_empty() {
            self.record_unsupported_macro_arguments(
                format!("{}!", type_specifier(&mac.path)),
                condition.clone(),
                SourceSpan::from_span(mac.span()),
            );
        }
        self.record_macro_expansion_boundary(
            format!("{}!", type_specifier(&mac.path)),
            MacroExpansionBoundaryKind::Bang,
            condition,
            SourceSpan::from_span(mac.span()),
        );
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_attribute(&mut self, node: &'ast Attribute) {
        let condition = self.active_condition();
        self.collect_attribute_meta(&node.meta, &condition, node.span());
    }

    fn visit_file(&mut self, node: &'ast syn::File) {
        let condition = self.condition(&node.attrs);
        self.collect_attribute_boundaries(&node.attrs, &condition);
        for item in &node.items {
            self.visit_item(item);
        }
    }

    fn visit_item(&mut self, node: &'ast syn::Item) {
        let attributes = item_attributes(node);
        let condition = self.condition(attributes);
        self.collect_attribute_boundaries(attributes, &condition);
        visit::visit_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        let attributes = trait_item_attributes(node);
        let condition = self.condition(attributes);
        self.collect_attribute_boundaries(attributes, &condition);
        visit::visit_trait_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        let attributes = impl_item_attributes(node);
        let condition = self.condition(attributes);
        self.collect_attribute_boundaries(attributes, &condition);
        visit::visit_impl_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        let attributes = foreign_item_attributes(node);
        let condition = self.condition(attributes);
        self.collect_attribute_boundaries(attributes, &condition);
        visit::visit_foreign_item(self, node);
    }

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

    fn visit_trait_item_macro(&mut self, node: &'ast syn::TraitItemMacro) {
        self.collect_macro(&node.mac, self.condition(&node.attrs));
    }

    fn visit_impl_item_macro(&mut self, node: &'ast syn::ImplItemMacro) {
        self.collect_macro(&node.mac, self.condition(&node.attrs));
    }

    fn visit_foreign_item_macro(&mut self, node: &'ast syn::ForeignItemMacro) {
        self.collect_macro(&node.mac, self.condition(&node.attrs));
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        let condition = self.active_condition();
        self.collect_macro(node, condition);
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

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_arm(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_arm(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_bare_fn_arg(&mut self, node: &'ast syn::BareFnArg) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_bare_fn_arg(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_bare_fn_arg(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_field_pat(&mut self, node: &'ast syn::FieldPat) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_field_pat(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_field_pat(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_field_value(self, node);
            return;
        };
        let condition = self.child_condition(&frame.condition, &node.attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_field_value(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_pat(&mut self, node: &'ast syn::Pat) {
        let Some(frame) = self.type_use_frames.last().cloned() else {
            visit::visit_pat(self, node);
            return;
        };
        let attrs = pat_attributes(node);
        if attrs.is_empty() {
            visit::visit_pat(self, node);
            return;
        }
        let condition = self.child_condition(&frame.condition, attrs);
        self.inherited_conditions.push(condition.clone());
        self.type_use_frames.push(TypeUseFrame {
            context: frame.context,
            condition,
        });
        visit::visit_pat(self, node);
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
        self.record_call(
            format!("{}!", type_specifier(&node.mac.path)),
            CallSyntaxKind::MacroBoundary,
            SourceSpan::from_span(node.mac.span()),
        );
        visit::visit_stmt_macro(self, node);
        self.type_use_frames.pop();
        self.inherited_conditions.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.record_call(
            callable_specifier(&node.func),
            CallSyntaxKind::Function,
            SourceSpan::from_span(node.span()),
        );
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.record_call(
            node.method.to_string(),
            CallSyntaxKind::Method,
            SourceSpan::from_span(node.span()),
        );
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let specifier = format!("{}!", type_specifier(&node.mac.path));
        self.record_call(
            specifier,
            CallSyntaxKind::MacroBoundary,
            SourceSpan::from_span(node.span()),
        );
        visit::visit_expr_macro(self, node);
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

fn first_string_literal_argument(tokens: &proc_macro2::TokenStream) -> Option<String> {
    let arguments = Punctuated::<Expr, Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .ok()?;
    let Expr::Lit(ExprLit {
        lit: Lit::Str(variable),
        ..
    }) = arguments.first()?
    else {
        return None;
    };
    Some(variable.value())
}

fn is_builtin_macro(path: &syn::Path) -> bool {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return false;
    }
    matches!(
        path.segments[0].ident.to_string().as_str(),
        "asm"
            | "cfg"
            | "column"
            | "compile_error"
            | "concat"
            | "concat_bytes"
            | "assert"
            | "assert_eq"
            | "assert_ne"
            | "dbg"
            | "debug_assert"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "eprint"
            | "eprintln"
            | "file"
            | "format"
            | "format_args"
            | "format_args_nl"
            | "global_asm"
            | "line"
            | "log_syntax"
            | "matches"
            | "module_path"
            | "offset_of"
            | "panic"
            | "print"
            | "println"
            | "stringify"
            | "thread_local"
            | "todo"
            | "trace_macros"
            | "unimplemented"
            | "unreachable"
            | "vec"
            | "write"
            | "writeln"
    )
}

fn is_builtin_attribute(path: &syn::Path) -> bool {
    if path.leading_colon.is_some() || path.segments.len() != 1 {
        return false;
    }
    let name = path.segments[0].ident.to_string();
    name.starts_with("rustc_")
        || matches!(
            name.as_str(),
            "alloc_error_handler"
                | "allow"
                | "automatically_derived"
                | "bench"
                | "cfg"
                | "cfg_attr"
                | "cold"
                | "collapse_debuginfo"
                | "coverage"
                | "crate_name"
                | "crate_type"
                | "debugger_visualizer"
                | "deny"
                | "deprecated"
                | "derive"
                | "diagnostic"
                | "doc"
                | "expect"
                | "export_name"
                | "feature"
                | "ffi_const"
                | "ffi_pure"
                | "forbid"
                | "fundamental"
                | "global_allocator"
                | "ignore"
                | "inline"
                | "instruction_set"
                | "lang"
                | "link"
                | "link_name"
                | "link_ordinal"
                | "link_section"
                | "lint_reasons"
                | "macro_export"
                | "macro_use"
                | "marker"
                | "must_use"
                | "naked"
                | "no_builtins"
                | "no_implicit_prelude"
                | "no_link"
                | "no_main"
                | "no_mangle"
                | "no_std"
                | "non_exhaustive"
                | "optimize"
                | "panic_handler"
                | "path"
                | "prelude_import"
                | "proc_macro"
                | "proc_macro_attribute"
                | "proc_macro_derive"
                | "recursion_limit"
                | "register_attr"
                | "register_tool"
                | "repr"
                | "should_panic"
                | "stable"
                | "start"
                | "target_feature"
                | "test"
                | "thread_local"
                | "track_caller"
                | "type_length_limit"
                | "unsafe"
                | "unstable"
                | "used"
                | "warn"
                | "windows_subsystem"
        )
}

fn item_attributes(item: &syn::Item) -> &[Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> &[Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> &[Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        _ => &[],
    }
}

fn foreign_item_attributes(item: &syn::ForeignItem) -> &[Attribute] {
    match item {
        syn::ForeignItem::Fn(item) => &item.attrs,
        syn::ForeignItem::Macro(item) => &item.attrs,
        syn::ForeignItem::Static(item) => &item.attrs,
        syn::ForeignItem::Type(item) => &item.attrs,
        _ => &[],
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

fn pat_attributes(pattern: &syn::Pat) -> &[Attribute] {
    match pattern {
        syn::Pat::Const(pattern) => &pattern.attrs,
        syn::Pat::Ident(pattern) => &pattern.attrs,
        syn::Pat::Lit(pattern) => &pattern.attrs,
        syn::Pat::Macro(pattern) => &pattern.attrs,
        syn::Pat::Or(pattern) => &pattern.attrs,
        syn::Pat::Paren(pattern) => &pattern.attrs,
        syn::Pat::Path(pattern) => &pattern.attrs,
        syn::Pat::Range(pattern) => &pattern.attrs,
        syn::Pat::Reference(pattern) => &pattern.attrs,
        syn::Pat::Rest(pattern) => &pattern.attrs,
        syn::Pat::Slice(pattern) => &pattern.attrs,
        syn::Pat::Struct(pattern) => &pattern.attrs,
        syn::Pat::Tuple(pattern) => &pattern.attrs,
        syn::Pat::TupleStruct(pattern) => &pattern.attrs,
        syn::Pat::Type(pattern) => &pattern.attrs,
        syn::Pat::Wild(pattern) => &pattern.attrs,
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
        let Ok(items) = try_parse_meta_list(&list.tokens) else {
            continue;
        };
        let Some(predicate) = items
            .first()
            .filter(|predicate| items.len() >= 2 && valid_cfg_predicate(predicate))
        else {
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
        if let Ok(attribute_conditions) = cfg_conditions_from_meta(&attribute.meta) {
            conditions.extend(attribute_conditions);
        }
    }
    conditions
}

fn cfg_conditions_from_meta(meta: &Meta) -> Result<Vec<Condition>, ()> {
    if meta.path().is_ident("cfg") {
        let Meta::List(list) = meta else {
            return Err(());
        };
        let items = try_parse_meta_list(&list.tokens).map_err(|_| ())?;
        if items.len() != 1 || !valid_cfg_predicate(&items[0]) {
            return Err(());
        }
        return Ok(vec![condition_from_meta(&items[0])]);
    }

    if !meta.path().is_ident("cfg_attr") {
        return Ok(Vec::new());
    }
    let Meta::List(list) = meta else {
        return Err(());
    };
    let items = try_parse_meta_list(&list.tokens).map_err(|_| ())?;
    let Some(predicate) = items
        .first()
        .filter(|predicate| items.len() >= 2 && valid_cfg_predicate(predicate))
    else {
        return Err(());
    };
    let mut gated_conditions = Vec::new();
    for nested in items.iter().skip(1) {
        gated_conditions.extend(cfg_conditions_from_meta(nested)?);
    }
    if gated_conditions.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![
        Condition::Any {
            conditions: vec![
                Condition::Not {
                    condition: Box::new(condition_from_meta(predicate)),
                },
                Condition::All {
                    conditions: gated_conditions,
                },
            ],
        }
        .canonicalize(),
    ])
}

fn parse_meta_list(tokens: &proc_macro2::TokenStream) -> Vec<Meta> {
    try_parse_meta_list(tokens).unwrap_or_default()
}

fn try_parse_meta_list(tokens: &proc_macro2::TokenStream) -> syn::Result<Vec<Meta>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .map(|items| items.into_iter().collect())
}

fn valid_cfg_predicate(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => is_plain_cfg_key(path),
        Meta::NameValue(name_value) => {
            is_plain_cfg_key(&name_value.path)
                && matches!(
                    &name_value.value,
                    Expr::Lit(ExprLit {
                        lit: Lit::Str(_),
                        ..
                    })
                )
        }
        Meta::List(list) => {
            let Ok(items) = try_parse_meta_list(&list.tokens) else {
                return false;
            };
            if list.path.is_ident("not") {
                return items.len() == 1 && valid_cfg_predicate(&items[0]);
            }
            if list.path.is_ident("all") || list.path.is_ident("any") {
                return items.iter().all(valid_cfg_predicate);
            }
            false
        }
    }
}

fn is_plain_cfg_key(path: &syn::Path) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 1
        && matches!(path.segments[0].arguments, syn::PathArguments::None)
}

fn attribute_specifier(meta: &Meta) -> String {
    match meta {
        Meta::Path(path) => type_specifier(path),
        Meta::NameValue(name_value) => format!("{}=<value>", type_specifier(&name_value.path)),
        Meta::List(list) => format!("{}({})", type_specifier(&list.path), list.tokens),
    }
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

fn callable_specifier(expression: &Expr) -> String {
    match expression {
        Expr::Path(path) => type_specifier(&path.path),
        Expr::Paren(paren) => callable_specifier(&paren.expr),
        Expr::Group(group) => callable_specifier(&group.expr),
        Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => name.to_string(),
            syn::Member::Unnamed(index) => index.index.to_string(),
        },
        Expr::Closure(_) => "<closure>".into(),
        _ => "<callable-expression>".into(),
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
        let occurrence = occurrences
            .iter()
            .find(|occurrence| matches!(occurrence, Occurrence::ExternCrate { .. }))
            .expect("extern crate occurrence");
        assert!(matches!(
            occurrence,
            Occurrence::ExternCrate {
                specifier,
                alias: Some(alias),
                ..
            } if specifier == "std" && alias == "sys"
        ));
        let key = occurrence
            .use_key("src/lib.rs")
            .expect("extern crate refinement key");
        assert_eq!(key.relative_path, "src/lib.rs");
        assert_eq!(key.target_specifier, "std");
        assert_eq!(key.alias.as_deref(), Some("sys"));
        assert!(!key.glob);
        assert!(!key.reexport);
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
            "#[cfg_attr(feature = \"p\", cfg_attr(feature = \"q\", cfg(unix)))]\n",
            "type NestedConditional = NestedTarget;\n",
        );
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());
        let (condition, _) = find_type_use(&occurrences, "Target", TypeUseContext::TypeAlias);
        let rendered = condition.render();
        assert!(rendered.contains("rust.feature"));
        assert!(rendered.contains("rust.cfg.unix"));
        assert!(rendered.contains('!'));

        let (nested_condition, _) =
            find_type_use(&occurrences, "NestedTarget", TypeUseContext::TypeAlias);
        let nested_rendered = nested_condition.render();
        assert!(nested_rendered.contains("\"p\""));
        assert!(nested_rendered.contains("\"q\""));
        assert!(nested_rendered.contains("rust.cfg.unix"));
        assert!(nested_rendered.matches('!').count() >= 2);
        assert!(
            !occurrences
                .iter()
                .any(|occurrence| matches!(occurrence, Occurrence::UnsupportedAttribute { .. }))
        );
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

    #[test]
    fn extracts_call_specifiers_spans_cfg_macro_boundaries_and_stable_keys() {
        let source = concat!(
            "#[cfg(feature = \"caller\")]\n",
            "fn caller(mut value: Receiver) {\n",
            "#[cfg(unix)] crate::direct(value);\n",
            "value.method(2);\n",
            "#[cfg(target_os = \"linux\")] generated!(3);\n",
            "match value { #[cfg(target_arch = \"x86_64\")] _ => arm_call(), _ => () }\n",
            "}\n",
        );
        let file = syn::parse_file(source).unwrap();
        let first = collect_occurrences(&file);
        let second = collect_occurrences(&file);
        let calls: Vec<_> = first
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::Call {
                    specifier,
                    syntax_kind,
                    condition,
                    span,
                    ..
                } => Some((specifier.as_str(), *syntax_kind, condition, *span)),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 4);

        let function = calls
            .iter()
            .find(|(specifier, ..)| *specifier == "crate::direct")
            .expect("function call occurrence");
        assert_eq!(function.1, CallSyntaxKind::Function);
        assert_eq!(function.1.as_str(), "function");
        assert_eq!(
            text_at_span(source, function.3),
            "#[cfg(unix)] crate::direct(value)"
        );
        let function_condition = function.2.render();
        assert!(function_condition.contains("rust.feature"));
        assert!(function_condition.contains("rust.cfg.unix"));

        let method = calls
            .iter()
            .find(|(specifier, ..)| *specifier == "method")
            .expect("method call occurrence");
        assert_eq!(method.1, CallSyntaxKind::Method);
        assert_eq!(method.1.as_str(), "method");
        assert_eq!(text_at_span(source, method.3), "value.method(2)");
        assert!(method.2.render().contains("rust.feature"));

        let macro_boundary = calls
            .iter()
            .find(|(specifier, ..)| *specifier == "generated!")
            .expect("macro call boundary occurrence");
        assert_eq!(macro_boundary.1, CallSyntaxKind::MacroBoundary);
        assert_eq!(macro_boundary.1.as_str(), "macro_boundary");
        assert_eq!(text_at_span(source, macro_boundary.3), "generated!(3)");
        let macro_condition = macro_boundary.2.render();
        assert!(macro_condition.contains("rust.feature"));
        assert!(macro_condition.contains("rust.cfg.target_os"));

        let arm_call = calls
            .iter()
            .find(|(specifier, ..)| *specifier == "arm_call")
            .expect("match-arm call occurrence");
        assert_eq!(arm_call.1, CallSyntaxKind::Function);
        assert_eq!(text_at_span(source, arm_call.3), "arm_call()");
        let arm_condition = arm_call.2.render();
        assert!(arm_condition.contains("rust.feature"));
        assert!(arm_condition.contains("rust.cfg.target_arch"));

        let first_keys: Vec<_> = first
            .iter()
            .filter_map(|occurrence| occurrence.call_key("src/lib.rs"))
            .collect();
        let second_keys: Vec<_> = second
            .iter()
            .filter_map(|occurrence| occurrence.call_key("src/lib.rs"))
            .collect();
        assert_eq!(first_keys, second_keys);
        assert_eq!(first_keys.len(), calls.len());
        let function_key = first_keys
            .iter()
            .find(|key| key.specifier == "crate::direct")
            .expect("function call key");
        assert_eq!(function_key.relative_path, "src/lib.rs");
        assert_eq!(function_key.syntax_kind, CallSyntaxKind::Function);
        assert_eq!(function_key.span, function.3);
        assert!(function_key.inline_ancestors.is_empty());
        assert_eq!(function_key.condition_key, function.2.render());
    }

    #[test]
    fn collects_expansion_and_build_environment_boundaries_once_in_source_order() {
        let source = concat!(
            "#![allow(dead_code)]\n",
            "#[cfg(test)]\n",
            "#[derive(Debug, Clone, serde::Serialize, ExternalDerive)]\n",
            "#[tokio::main]\n",
            "struct Job;\n",
            "#[cfg_attr(feature = \"serde\", serde::container)]\n",
            "#[cfg_attr(feature = \"serde\", derive(serde::Deserialize, Debug))]\n",
            "struct Config;\n",
            "macro_rules! local { () => {} }\n",
            "#[cfg(feature = \"inventory\")]\n",
            "inventory::submit! { Job }\n",
            "#[test]\n",
            "fn run() {\n",
            "#[cfg(target_arch = \"x86_64\")] let _ = env!(\"BUILD_TARGET\", \"missing build target\");\n",
            "let _ = option_env!(DYNAMIC_NAME);\n",
            "let _ = cfg!(unix);\n",
            "let _ = concat!(\"a\", \"b\");\n",
            "external::expand!();\n",
            "custom!();\n",
            "external::env!(\"NOT_A_BUILTIN_PATH\");\n",
            "}\n",
        );
        let file = syn::parse_file(source).unwrap();
        let first = collect_occurrences(&file);
        let second = collect_occurrences(&file);
        assert_eq!(first, second, "boundary inventory must be deterministic");

        let boundaries: Vec<_> = first
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::MacroExpansionBoundary {
                    specifier,
                    boundary_kind,
                    condition,
                    span,
                } => Some((specifier.as_str(), *boundary_kind, condition, *span)),
                _ => None,
            })
            .collect();
        assert_eq!(
            boundaries
                .iter()
                .map(|(specifier, kind, ..)| (*specifier, *kind))
                .collect::<Vec<_>>(),
            [
                ("Debug", MacroExpansionBoundaryKind::Derive),
                ("Clone", MacroExpansionBoundaryKind::Derive),
                ("serde::Serialize", MacroExpansionBoundaryKind::Derive),
                ("ExternalDerive", MacroExpansionBoundaryKind::Derive),
                ("tokio::main", MacroExpansionBoundaryKind::Attribute),
                ("serde::container", MacroExpansionBoundaryKind::Attribute),
                ("serde::Deserialize", MacroExpansionBoundaryKind::Derive,),
                ("Debug", MacroExpansionBoundaryKind::Derive),
                ("inventory::submit!", MacroExpansionBoundaryKind::Bang),
                ("cfg!", MacroExpansionBoundaryKind::Bang),
                ("concat!", MacroExpansionBoundaryKind::Bang),
                ("external::expand!", MacroExpansionBoundaryKind::Bang),
                ("custom!", MacroExpansionBoundaryKind::Bang),
                ("external::env!", MacroExpansionBoundaryKind::Bang),
            ],
            "each expansion boundary must appear exactly once in source order",
        );
        assert_eq!(MacroExpansionBoundaryKind::Bang.as_str(), "bang");
        assert_eq!(MacroExpansionBoundaryKind::Attribute.as_str(), "attribute");
        assert_eq!(MacroExpansionBoundaryKind::Derive.as_str(), "derive");

        let external_derive = boundaries
            .iter()
            .find(|(specifier, ..)| *specifier == "serde::Serialize")
            .expect("external derive boundary");
        assert!(external_derive.2.render().contains("rust.cfg.test"));
        assert_eq!(text_at_span(source, external_derive.3), "serde::Serialize");

        let cfg_attr_boundary = boundaries
            .iter()
            .find(|(specifier, ..)| *specifier == "serde::container")
            .expect("cfg_attr boundary");
        assert!(cfg_attr_boundary.2.render().contains("rust.feature"));
        assert_eq!(
            text_at_span(source, cfg_attr_boundary.3),
            "serde::container"
        );

        let item_macro = boundaries
            .iter()
            .find(|(specifier, ..)| *specifier == "inventory::submit!")
            .expect("item macro boundary");
        assert!(item_macro.2.render().contains("rust.feature"));

        let environments: Vec<_> = first
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::BuildEnvironmentMacro {
                    macro_name,
                    variable,
                    raw_argument,
                    condition,
                    span,
                } => Some((
                    macro_name.as_str(),
                    variable.as_deref(),
                    raw_argument.as_str(),
                    condition,
                    *span,
                )),
                _ => None,
            })
            .collect();
        assert_eq!(environments.len(), 2);
        assert_eq!(environments[0].0, "env");
        assert_eq!(environments[0].1, Some("BUILD_TARGET"));
        assert!(environments[0].2.contains("missing build target"));
        assert!(environments[0].3.render().contains("rust.cfg.target_arch"));
        assert_eq!(
            text_at_span(source, environments[0].4),
            "env!(\"BUILD_TARGET\", \"missing build target\")"
        );
        assert_eq!(environments[1].0, "option_env");
        assert_eq!(environments[1].1, None);
        assert_eq!(environments[1].2, "DYNAMIC_NAME");

        assert!(
            !boundaries
                .iter()
                .any(|(specifier, ..)| *specifier == "macro_rules!"),
            "a macro definition must not become an invocation boundary",
        );
    }

    #[test]
    fn inventories_nested_attribute_generic_and_builtin_macro_boundaries() {
        let source = r#"#![doc = include_str!(concat!(env!("OUT_DIR"), "/crate.md"))]
pub struct Docs<const N: usize = { include_bytes!(concat!(env!("OUT_DIR"), "/blob")).len() }> {
    #[cfg(feature = "field-doc")]
    #[doc = include_str!(concat!(env!("OUT_DIR"), "/field.md"))]
    value: [u8; N],
}

#[unsafe(export_name = env!("SYM"))]
pub extern "C" fn exported() {}

pub const GENERATED: &str = concat!(env!("OUT_DIR"), "/generated");
global_asm!(include_str!("boot.s"), options(att_syntax));

#[cfg(feature = "typed-macro")]
pub type Generated = custom_type!();
"#;
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        let includes: Vec<_> = occurrences
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::Include {
                    macro_name,
                    raw_argument,
                    condition,
                    ..
                } => Some((macro_name.as_str(), raw_argument.as_str(), condition)),
                _ => None,
            })
            .collect();
        assert_eq!(includes.len(), 4, "includes: {includes:?}");
        assert!(
            includes
                .iter()
                .any(|(name, raw, _)| { *name == "include_str" && raw.contains("/crate.md") })
        );
        assert!(includes.iter().any(|(name, raw, condition)| {
            *name == "include_str"
                && raw.contains("/field.md")
                && condition.render().contains("rust.feature")
        }));
        assert!(
            includes
                .iter()
                .any(|(name, raw, _)| { *name == "include_bytes" && raw.contains("/blob") })
        );
        assert!(
            includes
                .iter()
                .any(|(name, raw, _)| { *name == "include_str" && raw.contains("boot.s") })
        );

        let environment_variables: Vec<_> = occurrences
            .iter()
            .filter_map(|occurrence| match occurrence {
                Occurrence::BuildEnvironmentMacro { variable, .. } => variable.as_deref(),
                _ => None,
            })
            .collect();
        assert_eq!(
            environment_variables
                .iter()
                .filter(|variable| **variable == "OUT_DIR")
                .count(),
            4
        );
        assert!(environment_variables.contains(&"SYM"));

        let typed_macro = occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::MacroExpansionBoundary {
                    specifier,
                    condition,
                    ..
                } if specifier == "custom_type!" => Some(condition),
                _ => None,
            })
            .expect("typed macro boundary");
        assert!(typed_macro.render().contains("rust.feature"));
    }

    #[test]
    fn invalid_attributes_and_uninspectable_builtin_macros_block_completeness() {
        let source = r#"#[derive(Foo + Bar)]
pub struct Invalid;

#[repr = "C"]
pub struct InvalidReprShape(u8);

#[repr(C, Rust)]
pub struct ConflictingRepr(u8);

#[inline(foo)]
pub fn InvalidInline() {}

#[cfg(not(unix, windows))]
pub fn InvalidCfg() {}

pub fn assembly(value: usize) {
    asm!("", in(reg) value);
    println!("{value}");
    let _ = vec![1, 2, 3];
}

macro_rules! concat { () => { env!("OUT_DIR") } }
pub const SHADOWED: &str = concat!();
macro_rules! include_str { ($path:literal) => { "shadowed" } }
pub const SHADOWED_INCLUDE: &str = include_str!("safe.txt");
"#;
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::UnsupportedAttribute { specifier, .. }
                if specifier.starts_with("derive(")
        )));
        for expected in ["repr=<value>", "repr(C , Rust)", "inline(foo)", "cfg(not"] {
            assert!(
                occurrences.iter().any(|occurrence| matches!(
                    occurrence,
                    Occurrence::UnsupportedAttribute { specifier, .. }
                        if specifier.starts_with(expected)
                )),
                "missing unsupported attribute {expected}"
            );
        }
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::UnsupportedMacroArguments { specifier, .. }
                if specifier == "asm!"
        )));
        for expected in ["println!", "vec!", "concat!"] {
            assert!(occurrences.iter().any(|occurrence| matches!(
                occurrence,
                Occurrence::MacroExpansionBoundary {
                    specifier: actual,
                    ..
                } if actual == expected
            )));
        }
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Include {
                argument: Some(argument),
                ..
            } if argument == "safe.txt"
        )));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::MacroExpansionBoundary { specifier, .. }
                if specifier == "include_str!"
        )));
    }

    #[test]
    fn invalid_nested_builtin_attribute_payload_is_never_silently_complete() {
        let source = "#[repr(align(env!(\"OUT_DIR\")))]\npub struct Broken(u8);\n";
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::UnsupportedAttribute { specifier, .. }
                if specifier.starts_with("align(")
        )));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::BuildEnvironmentMacro {
                variable: Some(variable),
                ..
            } if variable == "OUT_DIR"
        )));
    }

    #[test]
    fn invalid_cfg_predicates_are_unsupported_without_narrowing_sites() {
        let source = r#"#[cfg(foo::bar)]
pub type Qualified = external::Qualified;

#[cfg(foo::bar = "x")]
pub type QualifiedValue = external::QualifiedValue;

#[cfg_attr(foo::bar, cfg(unix))]
pub type QualifiedCfgAttr = external::QualifiedCfgAttr;

#[cfg_attr(unix, cfg(not(a, b)))]
pub type InvalidNestedCfg = external::InvalidNestedCfg;

#[cfg_attr(foo::bar, doc = include_str!("generated.md"))]
pub struct InvalidPredicateWithNestedMacro;
"#;
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        for specifier in [
            "external::Qualified",
            "external::QualifiedValue",
            "external::QualifiedCfgAttr",
            "external::InvalidNestedCfg",
        ] {
            let (condition, _) = find_type_use(&occurrences, specifier, TypeUseContext::TypeAlias);
            assert_eq!(condition.render(), "true", "specifier: {specifier}");
        }
        assert!(
            occurrences
                .iter()
                .filter(|occurrence| matches!(occurrence, Occurrence::UnsupportedAttribute { .. }))
                .count()
                >= 5
        );
        let include_condition = find_include_condition(&occurrences, "generated.md");
        assert_eq!(include_condition.render(), "true");
    }

    #[test]
    fn cfg_on_expression_pattern_fields_and_bare_fn_args_is_inherited() {
        let source = r#"pub struct Record { pub value: usize }

pub fn make() -> Record {
    Record {
        #[cfg(feature = "generated")]
        value: env!("OUT_DIR").len(),
    }
}

pub fn inspect(record: Record) {
    let Record {
        #[cfg(feature = "pattern")]
        value: generated!(),
    } = record;
}

pub type Callback = extern "C" fn(
    #[cfg(feature = "argument")]
    external::Argument,
);

pub fn parameter(
    Record {
        #[cfg(feature = "parameter-pattern")]
        value: parameter_pattern!(),
    }: Record,
) {}

"#;
        let occurrences = collect_occurrences(&syn::parse_file(source).unwrap());

        let environment_condition = occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::BuildEnvironmentMacro {
                    variable: Some(variable),
                    condition,
                    ..
                } if variable == "OUT_DIR" => Some(condition),
                _ => None,
            })
            .expect("field-value environment boundary");
        assert!(environment_condition.render().contains("generated"));

        let pattern_condition = occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::MacroExpansionBoundary {
                    specifier,
                    condition,
                    ..
                } if specifier == "generated!" => Some(condition),
                _ => None,
            })
            .expect("field-pattern macro boundary");
        assert!(pattern_condition.render().contains("pattern"));

        let (argument_condition, _) = find_type_use(
            &occurrences,
            "external::Argument",
            TypeUseContext::TypeAlias,
        );
        assert!(argument_condition.render().contains("argument"));

        let parameter_pattern_condition = occurrences
            .iter()
            .find_map(|occurrence| match occurrence {
                Occurrence::MacroExpansionBoundary {
                    specifier,
                    condition,
                    ..
                } if specifier == "parameter_pattern!" => Some(condition),
                _ => None,
            })
            .expect("parameter pattern macro boundary");
        assert!(
            parameter_pattern_condition
                .render()
                .contains("parameter-pattern")
        );
    }
}
