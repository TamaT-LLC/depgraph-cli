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

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Debug)]
pub(crate) enum Occurrence {
    Use {
        specifier: String,
        reexport: bool,
        inline_ancestors: Vec<String>,
        condition: Condition,
        span: SourceSpan,
    },
    ExternCrate {
        specifier: String,
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

pub(crate) fn collect_occurrences(file: &syn::File) -> Vec<Occurrence> {
    let mut collector = Collector {
        occurrences: Vec::new(),
        inherited_conditions: Vec::new(),
        inline_modules: Vec::new(),
    };
    collector.visit_file(file);
    collector.occurrences
}

struct Collector {
    occurrences: Vec<Occurrence>,
    inherited_conditions: Vec<Condition>,
    inline_modules: Vec<String>,
}

impl Collector {
    fn condition(&self, attributes: &[Attribute]) -> Condition {
        let mut conditions = self.inherited_conditions.clone();
        conditions.extend(cfg_conditions(attributes));
        Condition::All { conditions }.canonicalize()
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
        let mut specifiers = Vec::new();
        flatten_use_tree(&node.tree, Vec::new(), &mut specifiers);
        let condition = self.condition(&node.attrs);
        let reexport = !matches!(node.vis, syn::Visibility::Inherited);
        let span = SourceSpan::from_span(node.span());
        for specifier in specifiers {
            self.occurrences.push(Occurrence::Use {
                specifier,
                reexport,
                inline_ancestors: self.inline_modules.clone(),
                condition: condition.clone(),
                span,
            });
        }
    }

    fn visit_item_extern_crate(&mut self, node: &'ast ItemExternCrate) {
        self.occurrences.push(Occurrence::ExternCrate {
            specifier: node.ident.to_string(),
            inline_ancestors: self.inline_modules.clone(),
            condition: self.condition(&node.attrs),
            span: SourceSpan::from_span(node.span()),
        });
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
}

fn flatten_use_tree(tree: &UseTree, mut prefix: Vec<String>, output: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, output);
        }
        UseTree::Name(name) => {
            if name.ident != "self" || prefix.is_empty() {
                prefix.push(name.ident.to_string());
            }
            output.push(prefix.join("::"));
        }
        UseTree::Rename(rename) => {
            if rename.ident != "self" || prefix.is_empty() {
                prefix.push(rename.ident.to_string());
            }
            output.push(prefix.join("::"));
        }
        UseTree::Glob(_) => {
            prefix.push("*".into());
            output.push(prefix.join("::"));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix.clone(), output);
            }
        }
    }
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
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .filter_map(|attribute| match &attribute.meta {
            Meta::List(list) => parse_meta_list(&list.tokens).into_iter().next(),
            _ => None,
        })
        .map(|meta| condition_from_meta(&meta))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_grouped_use_reexport_cfg_and_include() {
        let file = syn::parse_file(
            r#"
            #[cfg(all(unix, feature = "fast"))]
            pub use crate::model::{self, Item as Renamed, *};
            include_str!("data.txt");
            "#,
        )
        .unwrap();
        let occurrences = collect_occurrences(&file);
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Use { specifier, reexport: true, condition, .. }
                if specifier == "crate::model" && condition.render().contains("rust.feature")
        )));
        assert!(occurrences.iter().any(|occurrence| matches!(
            occurrence,
            Occurrence::Include { argument: Some(path), .. } if path == "data.txt"
        )));
    }
}
