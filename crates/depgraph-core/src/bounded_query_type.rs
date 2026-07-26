use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bounded_query::{
    BOUNDED_QUERY_CONTRACT_VERSION, EntityExpression, Expression, FieldReference, Literal,
    MatchClause, NodePattern, OrderItem, Projection, QuantifierKind, QueryAst, QueryDiagnostic,
    QueryFailureClass, QueryResult, RelationshipPattern, ReturnClause, ScalarOperator,
    ScalarPredicate, SortDirection, parse_bounded_query,
};

pub const BOUNDED_QUERY_TYPE_CONTRACT_VERSION: &str = "bounded-query-types-v1";

const RESERVED_BINDING_WORDS: &[&str] = &[
    "AND",
    "ASC",
    "BY",
    "DESC",
    "DISTINCT",
    "EVERY",
    "FALSE",
    "IN",
    "LIMIT",
    "MATCH",
    "NOT",
    "NULL",
    "OR",
    "ORDER",
    "RETURN",
    "SATISFIES",
    "SOME",
    "STARTS",
    "TRUE",
    "WHERE",
    "WITH",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Node,
    Path,
    Edge,
    Site,
    Evidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    String,
    UnsignedInteger,
    Boolean,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum QueryType {
    Entity(EntityType),
    Scalar(ScalarType),
    List(ScalarType),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldDefinition {
    pub entity_type: EntityType,
    pub name: &'static str,
    pub scalar_type: ScalarType,
    pub nullable: bool,
    pub where_allowed: bool,
}

pub const FIELD_REGISTRY: &[FieldDefinition] = &[
    field(EntityType::Node, "id", ScalarType::String, false, true),
    field(EntityType::Node, "kind", ScalarType::String, false, true),
    field(EntityType::Node, "locator", ScalarType::String, false, true),
    field(
        EntityType::Node,
        "display_name",
        ScalarType::String,
        false,
        true,
    ),
    field(EntityType::Path, "id", ScalarType::String, false, false),
    field(
        EntityType::Path,
        "depth",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
    field(
        EntityType::Path,
        "direction",
        ScalarType::String,
        false,
        true,
    ),
    field(EntityType::Edge, "id", ScalarType::String, false, true),
    field(EntityType::Edge, "kind", ScalarType::String, false, true),
    field(EntityType::Edge, "phase", ScalarType::String, false, true),
    field(
        EntityType::Edge,
        "environment",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Edge,
        "profile_id",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Edge,
        "resolution_status",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Edge,
        "precision",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Edge,
        "condition",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Edge,
        "generated",
        ScalarType::Boolean,
        false,
        true,
    ),
    field(EntityType::Site, "id", ScalarType::String, true, true),
    field(EntityType::Site, "kind", ScalarType::String, true, true),
    field(
        EntityType::Site,
        "specifier",
        ScalarType::String,
        true,
        true,
    ),
    field(
        EntityType::Site,
        "profile_id",
        ScalarType::String,
        true,
        true,
    ),
    field(
        EntityType::Site,
        "resolution_status",
        ScalarType::String,
        true,
        true,
    ),
    field(
        EntityType::Site,
        "precision",
        ScalarType::String,
        true,
        true,
    ),
    field(
        EntityType::Site,
        "condition",
        ScalarType::String,
        true,
        true,
    ),
    field(EntityType::Site, "reason", ScalarType::String, true, true),
    field(
        EntityType::Evidence,
        "owner_type",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "kind",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "extractor",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "extractor_version",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "path",
        ScalarType::String,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "start_line",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "start_column",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "end_line",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "end_column",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
    field(
        EntityType::Evidence,
        "ordinal",
        ScalarType::UnsignedInteger,
        false,
        true,
    ),
];

const fn field(
    entity_type: EntityType,
    name: &'static str,
    scalar_type: ScalarType,
    nullable: bool,
    where_allowed: bool,
) -> FieldDefinition {
    FieldDefinition {
        entity_type,
        name,
        scalar_type,
        nullable,
        where_allowed,
    }
}

pub fn field_registry() -> &'static [FieldDefinition] {
    FIELD_REGISTRY
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedQuery {
    pub ast: TypedQueryAst,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedQueryAst {
    pub contract_version: String,
    pub type_contract_version: String,
    pub match_clause: TypedMatchClause,
    pub where_clause: Option<TypedExpression>,
    pub return_clause: TypedReturnClause,
    pub order_by: Vec<TypedOrderItem>,
    pub limit: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedMatchClause {
    pub path: BindingDefinition,
    pub source: TypedNodePattern,
    pub relationship: RelationshipPattern,
    pub target: TypedNodePattern,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedNodePattern {
    pub binding: BindingDefinition,
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BindingDefinition {
    pub name: String,
    pub entity_type: EntityType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TypedExpression {
    Or(Vec<TypedExpression>),
    And(Vec<TypedExpression>),
    Not(Box<TypedExpression>),
    Scalar(TypedScalarPredicate),
    Quantifier(TypedQuantifierPredicate),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedQuantifierPredicate {
    pub binding: BindingDefinition,
    pub path_binding: String,
    pub expression: TypedEntityExpression,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TypedEntityExpression {
    Or(Vec<TypedEntityExpression>),
    And(Vec<TypedEntityExpression>),
    Not(Box<TypedEntityExpression>),
    Scalar(TypedScalarPredicate),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedScalarPredicate {
    pub field: TypedFieldReference,
    pub operator: ScalarOperator,
    pub operand_type: QueryType,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TypedFieldReference {
    pub binding: String,
    pub entity_type: EntityType,
    pub field: String,
    pub scalar_type: ScalarType,
    pub nullable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedReturnClause {
    pub distinct: bool,
    pub projections: Vec<TypedProjection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TypedProjection {
    Binding(BindingDefinition),
    Field(TypedFieldReference),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TypedOrderItem {
    pub projection: TypedProjection,
    pub direction: SortDirection,
}

pub fn parse_and_type_check_bounded_query(query: &str) -> QueryResult<TypedQuery> {
    let ast = parse_bounded_query(query)?;
    type_check_bounded_query(&ast)
}

pub fn type_check_bounded_query(ast: &QueryAst) -> QueryResult<TypedQuery> {
    if ast.contract_version != BOUNDED_QUERY_CONTRACT_VERSION {
        return Err(diagnostic(
            "query_contract_version_invalid",
            QueryFailureClass::Type,
            "query",
            "contract_version",
            "query contract version is not supported",
        ));
    }

    let mut checker = TypeChecker::new(&ast.match_clause)?;
    let typed_ast = checker.check(ast)?;
    let digest = typed_query_ast_digest(&typed_ast);
    Ok(TypedQuery {
        ast: typed_ast,
        digest,
    })
}

pub fn canonical_typed_query_ast_json(ast: &TypedQueryAst) -> String {
    serde_json::to_string(ast).expect("typed bounded query AST serialization cannot fail")
}

pub fn typed_query_ast_digest(ast: &TypedQueryAst) -> String {
    let canonical = canonical_typed_query_ast_json(ast);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("typed-query-ast:sha256:{}", hex::encode(digest))
}

struct TypeChecker {
    top_level: BTreeMap<String, EntityType>,
    quantified_bindings: BTreeSet<String>,
}

impl TypeChecker {
    fn new(match_clause: &MatchClause) -> QueryResult<Self> {
        let bindings = [
            (&match_clause.source.binding, EntityType::Node),
            (&match_clause.path_binding, EntityType::Path),
            (&match_clause.target.binding, EntityType::Node),
        ];
        let mut top_level = BTreeMap::new();
        for (name, entity_type) in bindings {
            validate_binding_name(name, "match")?;
            if top_level.insert(name.clone(), entity_type).is_some() {
                return Err(diagnostic(
                    "query_binding_shadowed",
                    QueryFailureClass::Binding,
                    "match",
                    "identifier",
                    "query binding shadows another binding",
                ));
            }
        }
        Ok(Self {
            top_level,
            quantified_bindings: BTreeSet::new(),
        })
    }

    fn check(&mut self, ast: &QueryAst) -> QueryResult<TypedQueryAst> {
        let match_clause = self.check_match_clause(&ast.match_clause)?;
        let where_clause = ast
            .where_clause
            .as_ref()
            .map(|expression| self.check_expression(expression))
            .transpose()?;
        let return_clause = self.check_return_clause(&ast.return_clause)?;
        let order_by = ast
            .order_by
            .iter()
            .map(|item| self.check_order_item(item, &return_clause.projections))
            .collect::<QueryResult<Vec<_>>>()?;

        Ok(TypedQueryAst {
            contract_version: BOUNDED_QUERY_CONTRACT_VERSION.to_owned(),
            type_contract_version: BOUNDED_QUERY_TYPE_CONTRACT_VERSION.to_owned(),
            match_clause,
            where_clause,
            return_clause,
            order_by,
            limit: ast.limit,
        })
    }

    fn check_match_clause(&self, match_clause: &MatchClause) -> QueryResult<TypedMatchClause> {
        let mut relationship = match_clause.relationship.clone();
        relationship.kinds.sort();
        if relationship.kinds.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(diagnostic(
                "query_duplicate_relationship_kind",
                QueryFailureClass::Type,
                "match",
                "string",
                "relationship kind set contains a duplicate",
            ));
        }
        Ok(TypedMatchClause {
            path: BindingDefinition {
                name: match_clause.path_binding.clone(),
                entity_type: EntityType::Path,
            },
            source: typed_node_pattern(&match_clause.source),
            relationship,
            target: typed_node_pattern(&match_clause.target),
        })
    }

    fn check_expression(&mut self, expression: &Expression) -> QueryResult<TypedExpression> {
        Ok(match expression {
            Expression::Or(terms) => canonical_expression_or(
                terms
                    .iter()
                    .map(|term| self.check_expression(term))
                    .collect::<QueryResult<Vec<_>>>()?,
            ),
            Expression::And(terms) => canonical_expression_and(
                terms
                    .iter()
                    .map(|term| self.check_expression(term))
                    .collect::<QueryResult<Vec<_>>>()?,
            ),
            Expression::Not(expression) => {
                TypedExpression::Not(Box::new(self.check_expression(expression)?))
            }
            Expression::Scalar(predicate) => {
                TypedExpression::Scalar(self.check_top_level_scalar(predicate)?)
            }
            Expression::Quantifier(predicate) => {
                if self
                    .top_level
                    .get(&predicate.path_binding)
                    .copied()
                    .filter(|entity_type| *entity_type == EntityType::Path)
                    .is_none()
                {
                    return Err(diagnostic(
                        "query_quantifier_path_binding_invalid",
                        QueryFailureClass::Binding,
                        "where",
                        "identifier",
                        "quantifier collection must reference the matched path binding",
                    ));
                }
                validate_binding_name(&predicate.binding, "where")?;
                if self.top_level.contains_key(&predicate.binding)
                    || !self.quantified_bindings.insert(predicate.binding.clone())
                {
                    return Err(diagnostic(
                        "query_binding_shadowed",
                        QueryFailureClass::Binding,
                        "where",
                        "identifier",
                        "query binding shadows another binding",
                    ));
                }
                let entity_type = match predicate.kind {
                    QuantifierKind::EveryEdge => EntityType::Edge,
                    QuantifierKind::SomeSite => EntityType::Site,
                    QuantifierKind::SomeEvidence => EntityType::Evidence,
                };
                let expression = self.check_entity_expression(
                    &predicate.expression,
                    &predicate.binding,
                    entity_type,
                )?;
                TypedExpression::Quantifier(TypedQuantifierPredicate {
                    binding: BindingDefinition {
                        name: predicate.binding.clone(),
                        entity_type,
                    },
                    path_binding: predicate.path_binding.clone(),
                    expression,
                })
            }
        })
    }

    fn check_entity_expression(
        &self,
        expression: &EntityExpression,
        binding: &str,
        entity_type: EntityType,
    ) -> QueryResult<TypedEntityExpression> {
        Ok(match expression {
            EntityExpression::Or(terms) => canonical_entity_or(
                terms
                    .iter()
                    .map(|term| self.check_entity_expression(term, binding, entity_type))
                    .collect::<QueryResult<Vec<_>>>()?,
            ),
            EntityExpression::And(terms) => canonical_entity_and(
                terms
                    .iter()
                    .map(|term| self.check_entity_expression(term, binding, entity_type))
                    .collect::<QueryResult<Vec<_>>>()?,
            ),
            EntityExpression::Not(expression) => TypedEntityExpression::Not(Box::new(
                self.check_entity_expression(expression, binding, entity_type)?,
            )),
            EntityExpression::Scalar(predicate) => {
                if predicate.field.binding != binding {
                    return Err(diagnostic(
                        "query_quantifier_binding_capture",
                        QueryFailureClass::Binding,
                        "where",
                        "field",
                        "quantifier expression may reference only its introduced binding",
                    ));
                }
                TypedEntityExpression::Scalar(self.check_scalar(predicate, entity_type, true)?)
            }
        })
    }

    fn check_top_level_scalar(
        &self,
        predicate: &ScalarPredicate,
    ) -> QueryResult<TypedScalarPredicate> {
        let Some(entity_type) = self.top_level.get(&predicate.field.binding).copied() else {
            return Err(diagnostic(
                "query_binding_unknown",
                QueryFailureClass::Binding,
                "where",
                "field",
                "predicate references an unknown binding",
            ));
        };
        self.check_scalar(predicate, entity_type, true)
    }

    fn check_scalar(
        &self,
        predicate: &ScalarPredicate,
        entity_type: EntityType,
        where_context: bool,
    ) -> QueryResult<TypedScalarPredicate> {
        let field = resolve_field(&predicate.field, entity_type, where_context)?;
        let (operator, operand_type) = check_operator(&field, &predicate.operator)?;
        Ok(TypedScalarPredicate {
            field,
            operator,
            operand_type,
        })
    }

    fn check_return_clause(&self, clause: &ReturnClause) -> QueryResult<TypedReturnClause> {
        let projections = clause
            .projections
            .iter()
            .map(|projection| self.check_projection(projection, "return"))
            .collect::<QueryResult<Vec<_>>>()?;
        Ok(TypedReturnClause {
            distinct: clause.distinct,
            projections,
        })
    }

    fn check_order_item(
        &self,
        item: &OrderItem,
        projections: &[TypedProjection],
    ) -> QueryResult<TypedOrderItem> {
        let projection = self.check_projection(&item.projection, "order_by")?;
        if !projections.contains(&projection) {
            return Err(diagnostic(
                "query_order_projection_missing",
                QueryFailureClass::Type,
                "order_by",
                "projection",
                "ORDER BY item is not present in RETURN",
            ));
        }
        Ok(TypedOrderItem {
            projection,
            direction: item.direction,
        })
    }

    fn check_projection(
        &self,
        projection: &Projection,
        clause: &'static str,
    ) -> QueryResult<TypedProjection> {
        match projection {
            Projection::Binding(binding) => {
                let Some(entity_type) = self.top_level.get(binding).copied() else {
                    return Err(diagnostic(
                        "query_projection_binding_invalid",
                        QueryFailureClass::Binding,
                        clause,
                        "projection",
                        "projection references a non-top-level binding",
                    ));
                };
                Ok(TypedProjection::Binding(BindingDefinition {
                    name: binding.clone(),
                    entity_type,
                }))
            }
            Projection::Field(reference) => {
                let Some(entity_type) = self.top_level.get(&reference.binding).copied() else {
                    return Err(diagnostic(
                        "query_projection_binding_invalid",
                        QueryFailureClass::Binding,
                        clause,
                        "projection",
                        "projection references a non-top-level binding",
                    ));
                };
                resolve_field(reference, entity_type, false).map(TypedProjection::Field)
            }
        }
    }
}

fn typed_node_pattern(pattern: &NodePattern) -> TypedNodePattern {
    TypedNodePattern {
        binding: BindingDefinition {
            name: pattern.binding.clone(),
            entity_type: EntityType::Node,
        },
        kind: pattern.kind.clone(),
    }
}

fn resolve_field(
    reference: &FieldReference,
    entity_type: EntityType,
    where_context: bool,
) -> QueryResult<TypedFieldReference> {
    let Some(definition) = FIELD_REGISTRY
        .iter()
        .find(|field| field.entity_type == entity_type && field.name == reference.field)
    else {
        return Err(diagnostic(
            "query_field_unknown",
            QueryFailureClass::Type,
            if where_context { "where" } else { "projection" },
            "field",
            "field is not present in the closed field registry",
        ));
    };
    if where_context && !definition.where_allowed {
        return Err(diagnostic(
            "query_path_id_where_forbidden",
            QueryFailureClass::Type,
            "where",
            "field",
            "field is not available to WHERE predicates",
        ));
    }
    Ok(TypedFieldReference {
        binding: reference.binding.clone(),
        entity_type,
        field: reference.field.clone(),
        scalar_type: definition.scalar_type,
        nullable: definition.nullable,
    })
}

fn check_operator(
    field: &TypedFieldReference,
    operator: &ScalarOperator,
) -> QueryResult<(ScalarOperator, QueryType)> {
    match operator {
        ScalarOperator::Equal(literal) | ScalarOperator::NotEqual(literal) => {
            check_equality_literal(field, literal)?;
            Ok((operator.clone(), QueryType::Scalar(field.scalar_type)))
        }
        ScalarOperator::Less(literal)
        | ScalarOperator::LessOrEqual(literal)
        | ScalarOperator::Greater(literal)
        | ScalarOperator::GreaterOrEqual(literal) => {
            if !matches!(
                field.scalar_type,
                ScalarType::String | ScalarType::UnsignedInteger
            ) || literal_scalar_type(literal) != Some(field.scalar_type)
            {
                return Err(operator_type_error());
            }
            Ok((operator.clone(), QueryType::Scalar(field.scalar_type)))
        }
        ScalarOperator::StartsWith(literal) => {
            let Literal::String(prefix) = literal else {
                return Err(operator_type_error());
            };
            if field.scalar_type != ScalarType::String {
                return Err(operator_type_error());
            }
            if prefix.is_empty() {
                return Err(diagnostic(
                    "query_prefix_empty",
                    QueryFailureClass::Type,
                    "where",
                    "string",
                    "STARTS WITH requires a non-empty normalized prefix",
                ));
            }
            Ok((operator.clone(), QueryType::Scalar(ScalarType::String)))
        }
        ScalarOperator::In(literals) => {
            if literals.is_empty()
                || literals
                    .iter()
                    .any(|literal| literal_scalar_type(literal) != Some(field.scalar_type))
            {
                return Err(operator_type_error());
            }
            let mut canonical = literals.clone();
            canonical.sort();
            if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(diagnostic(
                    "query_duplicate_list_literal",
                    QueryFailureClass::Type,
                    "where",
                    "literal_list",
                    "IN list contains a duplicate literal",
                ));
            }
            Ok((
                ScalarOperator::In(canonical),
                QueryType::List(field.scalar_type),
            ))
        }
    }
}

fn check_equality_literal(field: &TypedFieldReference, literal: &Literal) -> QueryResult<()> {
    match literal {
        Literal::Null if field.nullable => Ok(()),
        Literal::Null => Err(operator_type_error()),
        _ if literal_scalar_type(literal) == Some(field.scalar_type) => Ok(()),
        _ => Err(operator_type_error()),
    }
}

fn literal_scalar_type(literal: &Literal) -> Option<ScalarType> {
    match literal {
        Literal::String(_) => Some(ScalarType::String),
        Literal::Unsigned(_) => Some(ScalarType::UnsignedInteger),
        Literal::Boolean(_) => Some(ScalarType::Boolean),
        Literal::Null => None,
    }
}

fn operator_type_error() -> QueryDiagnostic {
    diagnostic(
        "query_operator_type_invalid",
        QueryFailureClass::Type,
        "where",
        "scalar_operator",
        "operator and literal are incompatible with the field type",
    )
}

fn validate_binding_name(name: &str, clause: &'static str) -> QueryResult<()> {
    if RESERVED_BINDING_WORDS
        .iter()
        .any(|keyword| name.eq_ignore_ascii_case(keyword))
    {
        return Err(diagnostic(
            "query_binding_reserved",
            QueryFailureClass::Binding,
            clause,
            "identifier",
            "binding uses a reserved keyword",
        ));
    }
    Ok(())
}

fn diagnostic(
    code: &'static str,
    class: QueryFailureClass,
    clause: &'static str,
    token_class: &'static str,
    message: &'static str,
) -> QueryDiagnostic {
    QueryDiagnostic::semantic(code, class, clause, token_class, message)
}

fn canonical_expression_or(terms: Vec<TypedExpression>) -> TypedExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            TypedExpression::Or(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one typed expression")
    } else {
        TypedExpression::Or(flattened)
    }
}

fn canonical_expression_and(terms: Vec<TypedExpression>) -> TypedExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            TypedExpression::And(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one typed expression")
    } else {
        TypedExpression::And(flattened)
    }
}

fn canonical_entity_or(terms: Vec<TypedEntityExpression>) -> TypedEntityExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            TypedEntityExpression::Or(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one typed entity expression")
    } else {
        TypedEntityExpression::Or(flattened)
    }
}

fn canonical_entity_and(terms: Vec<TypedEntityExpression>) -> TypedEntityExpression {
    let mut flattened = Vec::new();
    for term in terms {
        match term {
            TypedEntityExpression::And(children) => flattened.extend(children),
            term => flattened.push(term),
        }
    }
    canonical_sort(&mut flattened);
    if flattened.len() == 1 {
        flattened.pop().expect("one typed entity expression")
    } else {
        TypedEntityExpression::And(flattened)
    }
}

fn canonical_sort<T: Serialize>(values: &mut [T]) {
    values.sort_by_cached_key(|value| {
        serde_json::to_vec(value).expect("typed bounded query AST serialization cannot fail")
    });
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{
        EntityType, FIELD_REGISTRY, QueryFailureClass, ScalarType, canonical_typed_query_ast_json,
        parse_and_type_check_bounded_query,
    };

    const QUERY_PREFIX: &str = r#"MATCH p = (source:"route")-["calls"*1..2]->(target:"external")"#;

    fn typed(where_clause: &str, return_clause: &str) -> super::TypedQuery {
        parse_and_type_check_bounded_query(&format!(
            "{QUERY_PREFIX}{where_clause} RETURN {return_clause} LIMIT 10"
        ))
        .unwrap()
    }

    fn rejected(where_clause: &str, return_clause: &str, code: &str) {
        let error = parse_and_type_check_bounded_query(&format!(
            "{QUERY_PREFIX}{where_clause} RETURN {return_clause} LIMIT 10"
        ))
        .unwrap_err();
        assert_eq!(error.code, code);
        assert!(matches!(
            error.class,
            QueryFailureClass::Binding | QueryFailureClass::Type
        ));
        let rendered = error.to_string();
        assert!(!rendered.contains("route:"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn field_registry_is_exact_closed_v1_table() {
        let fields = FIELD_REGISTRY
            .iter()
            .map(|field| {
                (
                    field.entity_type,
                    field.name,
                    field.scalar_type,
                    field.nullable,
                    field.where_allowed,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 34);
        assert!(fields.contains(&(EntityType::Path, "id", ScalarType::String, false, false)));
        assert!(fields.contains(&(
            EntityType::Edge,
            "generated",
            ScalarType::Boolean,
            false,
            true
        )));
        assert!(fields.contains(&(EntityType::Site, "reason", ScalarType::String, true, true)));
        assert!(fields.contains(&(
            EntityType::Evidence,
            "ordinal",
            ScalarType::UnsignedInteger,
            false,
            true
        )));
        assert!(!fields.iter().any(|(_, name, _, _, _)| {
            matches!(*name, "properties" | "detail" | "diagnostics" | "logs")
        }));
    }

    #[test]
    fn positive_field_operator_and_quantifier_matrix_is_admitted() {
        for predicate in [
            r#"source.id = "node:1""#,
            r#"source.kind != "file""#,
            r#"source.locator STARTS WITH "route""#,
            r#"source.display_name IN ["A","B"]"#,
            "p.depth >= 1",
            r#"p.direction = "forward""#,
            r#"EVERY edge IN EDGES(p) SATISFIES edge.generated = true"#,
            r#"EVERY edge IN EDGES(p) SATISFIES edge.phase IN ["build","runtime"]"#,
            r#"SOME site IN SITES(p) SATISFIES site.reason = null"#,
            r#"SOME site IN SITES(p) SATISFIES site.profile_id = "profile-a""#,
            r#"SOME evidence IN EVIDENCE(p) SATISFIES evidence.path STARTS WITH "apps/""#,
            "SOME evidence IN EVIDENCE(p) SATISFIES evidence.start_line > 0",
        ] {
            typed(&format!(" WHERE {predicate}"), "source.id, target.id, p");
        }
    }

    #[test]
    fn unknown_sensitive_and_incompatible_fields_are_rejected() {
        for (predicate, code) in [
            (r#"source.properties = "secret""#, "query_field_unknown"),
            (r#"source.detail = "secret""#, "query_field_unknown"),
            (r#"p.id = "path""#, "query_path_id_where_forbidden"),
            ("source.id = 1", "query_operator_type_invalid"),
            ("source.id = null", "query_operator_type_invalid"),
            ("p.depth = true", "query_operator_type_invalid"),
            ("p.depth STARTS WITH \"1\"", "query_operator_type_invalid"),
            ("source.id STARTS WITH \"\"", "query_prefix_empty"),
            ("source.id IN [\"a\",1]", "query_operator_type_invalid"),
            (
                "EVERY edge IN EDGES(p) SATISFIES edge.generated > true",
                "query_operator_type_invalid",
            ),
            (
                r#"SOME evidence IN EVIDENCE(p) SATISFIES evidence.detail = "secret""#,
                "query_field_unknown",
            ),
        ] {
            rejected(&format!(" WHERE {predicate}"), "source.id", code);
        }
    }

    #[test]
    fn binding_and_quantifier_scopes_are_closed() {
        rejected(
            r#" WHERE EVERY source IN EDGES(p) SATISFIES source.id = "edge""#,
            "source.id",
            "query_binding_shadowed",
        );
        rejected(
            r#" WHERE EVERY edge IN EDGES(p) SATISFIES source.id = "node""#,
            "source.id",
            "query_quantifier_binding_capture",
        );
        rejected(
            r#" WHERE EVERY edge IN EDGES(source) SATISFIES edge.id = "edge""#,
            "source.id",
            "query_quantifier_path_binding_invalid",
        );
        rejected(
            r#" WHERE EVERY edge IN EDGES(p) SATISFIES edge.id = "a" AND SOME edge IN SITES(p) SATISFIES edge.id = "b""#,
            "source.id",
            "query_binding_shadowed",
        );
        rejected("", "edge", "query_projection_binding_invalid");
    }

    #[test]
    fn top_level_bindings_cannot_shadow_or_use_keywords() {
        let duplicate =
            r#"MATCH p = (node:"route")-["calls"*1..1]->(node:"external") RETURN node.id LIMIT 1"#;
        assert_eq!(
            parse_and_type_check_bounded_query(duplicate)
                .unwrap_err()
                .code,
            "query_binding_shadowed"
        );
        let keyword = r#"MATCH p = (where:"route")-["calls"*1..1]->(target:"external") RETURN target.id LIMIT 1"#;
        assert_eq!(
            parse_and_type_check_bounded_query(keyword)
                .unwrap_err()
                .code,
            "query_binding_reserved"
        );
    }

    #[test]
    fn order_by_requires_an_exact_return_projection() {
        let accepted = parse_and_type_check_bounded_query(&format!(
            "{QUERY_PREFIX} RETURN source, target.id, p.id ORDER BY target.id DESC, p.id LIMIT 10"
        ))
        .unwrap();
        assert_eq!(accepted.ast.order_by.len(), 2);

        let rejected = parse_and_type_check_bounded_query(&format!(
            "{QUERY_PREFIX} RETURN source ORDER BY source.id LIMIT 10"
        ))
        .unwrap_err();
        assert_eq!(rejected.code, "query_order_projection_missing");
    }

    #[test]
    fn canonical_digest_ignores_keyword_case_and_commutative_input_order() {
        let first = parse_and_type_check_bounded_query(&format!(
            r#"{QUERY_PREFIX} WHERE source.kind IN ["route","service"] AND p.depth >= 1 RETURN source.id, p ORDER BY source.id LIMIT 10"#
        ))
        .unwrap();
        let second = parse_and_type_check_bounded_query(
            r#"match p = (source:"route")-["calls"*1..2]->(target:"external")
               where p.depth >= 1 and source.kind in ["service","route"]
               return source.id, p order by source.id limit 10"#,
        )
        .unwrap();
        assert_eq!(first.ast, second.ast);
        assert_eq!(first.digest, second.digest);
        assert_eq!(
            canonical_typed_query_ast_json(&first.ast),
            canonical_typed_query_ast_json(&second.ast)
        );
    }

    #[derive(Deserialize)]
    struct GoldenFixture {
        query: String,
        typed_ast_digest: String,
    }

    #[test]
    fn typed_ast_digest_matches_golden_fixture() {
        let fixture: GoldenFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/bounded_query_typed_ast_v1.json"
        ))
        .unwrap();
        let first = parse_and_type_check_bounded_query(&fixture.query).unwrap();
        let second = parse_and_type_check_bounded_query(&fixture.query).unwrap();
        assert_eq!(first.digest, fixture.typed_ast_digest);
        assert_eq!(first, second);
    }
}
