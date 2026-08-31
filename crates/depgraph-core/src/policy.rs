use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use depgraph_protocol::{
    Condition, EvidenceKind, Precision, ResolutionStatus, canonical_json, stable_id_from_value,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};

pub const POLICY_SCHEMA_VERSION: &str = "1.0";
pub const POLICY_RESULT_SCHEMA_VERSION: &str = "1.0";
pub const POLICY_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/depgraph-policy-v1.schema.json"
));

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub schema_version: String,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub suppressions: Vec<PolicySuppression>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION.to_owned(),
            rules: Vec::new(),
            suppressions: Vec::new(),
        }
    }
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            bail!(
                "unsupported policy schema_version {}; expected {POLICY_SCHEMA_VERSION}",
                self.schema_version
            );
        }

        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !rule_ids.insert(rule.id.as_str()) {
                bail!("policy rule ID {:?} is duplicated", rule.id);
            }
        }

        let mut suppression_ids = BTreeSet::new();
        for suppression in &self.suppressions {
            suppression.validate()?;
            if !suppression_ids.insert(suppression.id.as_str()) {
                bail!("policy suppression ID {:?} is duplicated", suppression.id);
            }
            if !rule_ids.contains(suppression.rule_id.as_str()) {
                bail!(
                    "policy suppression {:?} references unknown rule {:?}",
                    suppression.id,
                    suppression.rule_id
                );
            }
        }
        Ok(())
    }

    /// Returns the normalized semantic identity used to address policy results.
    ///
    /// Policy evaluation treats rules, suppressions, selector exclusions and
    /// filter operands as sets. Keep the source configuration intact for
    /// diagnostics and evaluation, but sort those set-like collections and
    /// canonicalize commutative conditions before hashing their identity.
    pub fn normalized_identity(&self) -> Result<Value> {
        self.validate()?;
        let mut rules = self
            .rules
            .iter()
            .map(normalized_rule_identity)
            .collect::<Result<Vec<_>>>()?;
        let mut suppressions = self
            .suppressions
            .iter()
            .map(normalized_suppression_identity)
            .collect::<Result<Vec<_>>>()?;
        sort_identity_values(&mut rules);
        sort_identity_values(&mut suppressions);
        Ok(json!({
            "schema_version": self.schema_version,
            "rules": rules,
            "suppressions": suppressions,
        }))
    }
}

fn normalized_rule_identity(rule: &PolicyRule) -> Result<Value> {
    let mut value = serde_json::to_value(rule)?;
    normalize_selector_identity(&mut value, "/source")?;
    normalize_selector_identity(&mut value, "/target")?;
    normalize_profile_filter_identity(&mut value, "/profiles")?;
    sort_identity_array(&mut value, "/precisions")?;
    sort_identity_array(&mut value, "/resolution_statuses")?;
    sort_identity_array(&mut value, "/evidence/kinds")?;
    value["condition"] = serde_json::to_value(rule.condition.canonicalized())?;
    Ok(value)
}

fn normalized_suppression_identity(suppression: &PolicySuppression) -> Result<Value> {
    let mut value = serde_json::to_value(suppression)?;
    if suppression.scope.source.is_some() {
        normalize_selector_identity(&mut value, "/scope/source")?;
    }
    if suppression.scope.target.is_some() {
        normalize_selector_identity(&mut value, "/scope/target")?;
    }
    normalize_profile_filter_identity(&mut value, "/scope/profiles")?;
    if let Some(condition) = &suppression.scope.condition {
        value["scope"]["condition"] = serde_json::to_value(condition.canonicalized())?;
    }
    Ok(value)
}

fn normalize_selector_identity(value: &mut Value, base: &str) -> Result<()> {
    sort_identity_array(value, &format!("{base}/exclude"))?;
    sort_identity_array(value, &format!("{base}/scope/paths"))?;
    sort_identity_array(value, &format!("{base}/scope/packages"))
}

fn normalize_profile_filter_identity(value: &mut Value, base: &str) -> Result<()> {
    sort_identity_array(value, &format!("{base}/include"))?;
    sort_identity_array(value, &format!("{base}/exclude"))
}

fn sort_identity_array(value: &mut Value, pointer: &str) -> Result<()> {
    let values = value
        .pointer_mut(pointer)
        .and_then(Value::as_array_mut)
        .with_context(|| format!("policy identity field {pointer} is not an array"))?;
    sort_identity_values(values);
    Ok(())
}

fn sort_identity_values(values: &mut [Value]) {
    values.sort_by_cached_key(canonical_json);
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleKind {
    LayerBoundary,
    ForbiddenDependency,
    Cycle,
    DependencyDepth,
    FanIn,
    FanOut,
    PublicApiChange,
    RuntimeBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySeverity {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub kind: PolicyRuleKind,
    pub severity: PolicySeverity,
    pub source: PolicySelector,
    pub target: PolicySelector,
    pub profiles: PolicyProfileFilter,
    pub condition: PolicyCondition,
    pub precisions: Vec<Precision>,
    pub resolution_statuses: Vec<ResolutionStatus>,
    pub evidence: PolicyEvidenceRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<PolicyThreshold>,
}

impl PolicyRule {
    fn validate(&self) -> Result<()> {
        validate_contract_id("policy rule", &self.id)?;
        self.source
            .validate()
            .map_err(|error| anyhow::anyhow!("rule {:?} source: {error}", self.id))?;
        self.target
            .validate()
            .map_err(|error| anyhow::anyhow!("rule {:?} target: {error}", self.id))?;
        self.profiles
            .validate()
            .map_err(|error| anyhow::anyhow!("rule {:?} profiles: {error}", self.id))?;
        self.condition
            .validate()
            .map_err(|error| anyhow::anyhow!("rule {:?} condition: {error}", self.id))?;
        validate_unique_nonempty("precisions", &self.precisions)
            .map_err(|error| anyhow::anyhow!("rule {:?}: {error}", self.id))?;
        validate_unique_nonempty("resolution_statuses", &self.resolution_statuses)
            .map_err(|error| anyhow::anyhow!("rule {:?}: {error}", self.id))?;
        self.evidence
            .validate()
            .map_err(|error| anyhow::anyhow!("rule {:?} evidence: {error}", self.id))?;

        let is_threshold_rule = matches!(
            self.kind,
            PolicyRuleKind::DependencyDepth | PolicyRuleKind::FanIn | PolicyRuleKind::FanOut
        );
        match (is_threshold_rule, self.threshold) {
            (true, None) => bail!("rule {:?} requires a threshold", self.id),
            (false, Some(_)) => bail!(
                "rule {:?} cannot set a threshold for kind {:?}",
                self.id,
                self.kind
            ),
            _ => {}
        }
        if self.kind == PolicyRuleKind::Cycle && self.source.kind != self.target.kind {
            bail!(
                "cycle rule {:?} requires source and target selectors of the same kind",
                self.id
            );
        }
        if self.kind == PolicyRuleKind::Cycle && self.source.kind == PolicySelectorKind::Component {
            bail!(
                "cycle rule {:?} does not support component selectors",
                self.id
            );
        }
        if self.kind == PolicyRuleKind::PublicApiChange
            && !matches!(
                self.target.kind,
                PolicySelectorKind::Symbol | PolicySelectorKind::Type | PolicySelectorKind::Route
            )
        {
            bail!(
                "public API change rule {:?} requires a symbol, type, or route target selector",
                self.id
            );
        }
        if self.kind == PolicyRuleKind::RuntimeBoundary
            && (!matches!(
                self.source.kind,
                PolicySelectorKind::Route | PolicySelectorKind::Component
            ) || self.target.kind != PolicySelectorKind::Component)
        {
            bail!(
                "runtime boundary rule {:?} requires a route/component source and component target",
                self.id
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySelectorKind {
    Package,
    File,
    Symbol,
    Type,
    Route,
    Component,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySelectorField {
    Id,
    Path,
    Locator,
    DisplayName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMatchKind {
    Exact,
    Prefix,
    Glob,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySelectorCardinality {
    One,
    Many,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelector {
    pub kind: PolicySelectorKind,
    pub field: PolicySelectorField,
    #[serde(rename = "match")]
    pub match_kind: PolicyMatchKind,
    pub value: String,
    pub cardinality: PolicySelectorCardinality,
    #[serde(default)]
    pub exclude: Vec<PolicySelectorPattern>,
    #[serde(default)]
    pub scope: PolicySelectorScope,
}

impl PolicySelector {
    fn validate(&self) -> Result<()> {
        validate_pattern(
            "selector",
            self.match_kind,
            &self.value,
            self.field == PolicySelectorField::Path,
        )?;
        if self.field == PolicySelectorField::Id
            && (self.match_kind != PolicyMatchKind::Exact
                || self.cardinality != PolicySelectorCardinality::One)
        {
            bail!("ID selectors must use exact matching and one cardinality");
        }
        if self.field == PolicySelectorField::Path && self.kind != PolicySelectorKind::File {
            bail!("path selectors may be used only with file nodes");
        }
        validate_unique("selector exclusions", &self.exclude)?;
        for exclusion in &self.exclude {
            exclusion.validate(self.kind)?;
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelectorPattern {
    pub field: PolicySelectorField,
    #[serde(rename = "match")]
    pub match_kind: PolicyMatchKind,
    pub value: String,
}

impl PolicySelectorPattern {
    fn validate(&self, selector_kind: PolicySelectorKind) -> Result<()> {
        validate_pattern(
            "selector exclusion",
            self.match_kind,
            &self.value,
            self.field == PolicySelectorField::Path,
        )?;
        if self.field == PolicySelectorField::Id && self.match_kind != PolicyMatchKind::Exact {
            bail!("ID exclusions must use exact matching");
        }
        if self.field == PolicySelectorField::Path && selector_kind != PolicySelectorKind::File {
            bail!("path exclusions may be used only with file nodes");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySelectorScope {
    #[serde(default)]
    pub paths: Vec<PolicyPattern>,
    #[serde(default)]
    pub packages: Vec<PolicyPattern>,
}

impl PolicySelectorScope {
    fn validate(&self) -> Result<()> {
        validate_unique("selector scope paths", &self.paths)?;
        validate_unique("selector scope packages", &self.packages)?;
        for pattern in &self.paths {
            pattern.validate("selector scope path", true)?;
        }
        for pattern in &self.packages {
            pattern.validate("selector scope package", false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPattern {
    #[serde(rename = "match")]
    pub match_kind: PolicyMatchKind,
    pub value: String,
}

impl PolicyPattern {
    fn validate(&self, name: &str, path: bool) -> Result<()> {
        validate_pattern(name, self.match_kind, &self.value, path)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProfileFilter {
    #[serde(default)]
    pub include: Vec<PolicyPattern>,
    #[serde(default)]
    pub exclude: Vec<PolicyPattern>,
}

impl PolicyProfileFilter {
    fn validate(&self) -> Result<()> {
        validate_unique("included profile patterns", &self.include)?;
        validate_unique("excluded profile patterns", &self.exclude)?;
        for pattern in self.include.iter().chain(&self.exclude) {
            pattern.validate("profile pattern", false)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyThreshold {
    pub max: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidenceRequirement {
    pub kinds: Vec<EvidenceKind>,
    pub minimum_spans: u32,
    pub primary_only: bool,
}

impl PolicyEvidenceRequirement {
    fn validate(&self) -> Result<()> {
        validate_unique_nonempty("evidence kinds", &self.kinds)?;
        if self.minimum_spans == 0 {
            bail!("minimum_spans must be at least 1");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySuppression {
    pub id: String,
    pub rule_id: String,
    pub reason: String,
    pub scope: PolicySuppressionScope,
}

impl PolicySuppression {
    fn validate(&self) -> Result<()> {
        validate_contract_id("policy suppression", &self.id)?;
        validate_contract_id("suppressed policy rule", &self.rule_id)?;
        validate_bounded_text("policy suppression reason", &self.reason, 1024)?;
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySuppressionScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PolicySelector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<PolicySelector>,
    #[serde(default)]
    pub profiles: PolicyProfileFilter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<PolicyCondition>,
}

impl PolicySuppressionScope {
    fn validate(&self) -> Result<()> {
        let condition_restricts_scope = self
            .condition
            .as_ref()
            .is_some_and(|condition| condition.constant_truth() != Some(true));
        if self.source.is_none()
            && self.target.is_none()
            && self.profiles == PolicyProfileFilter::default()
            && !condition_restricts_scope
        {
            bail!("suppression scope must restrict source, target, profile, or condition");
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        if let Some(target) = &self.target {
            target.validate()?;
        }
        self.profiles.validate()?;
        if let Some(condition) = &self.condition {
            condition.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PolicyCondition {
    All { conditions: Vec<PolicyCondition> },
    Any { conditions: Vec<PolicyCondition> },
    Not { condition: Box<PolicyCondition> },
    Eq { key: String, value: Value },
    In { key: String, values: Vec<Value> },
    Defined { key: String },
}

impl Default for PolicyCondition {
    fn default() -> Self {
        Self::All {
            conditions: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for PolicyCondition {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictPolicyCondition::deserialize(deserializer).map(Into::into)
    }
}

impl PolicyCondition {
    pub fn canonicalized(&self) -> Condition {
        self.to_protocol().canonicalized()
    }

    fn to_protocol(&self) -> Condition {
        match self {
            Self::All { conditions } => Condition::All {
                conditions: conditions.iter().map(Self::to_protocol).collect(),
            },
            Self::Any { conditions } => Condition::Any {
                conditions: conditions.iter().map(Self::to_protocol).collect(),
            },
            Self::Not { condition } => Condition::Not {
                condition: Box::new(condition.to_protocol()),
            },
            Self::Eq { key, value } => Condition::Eq {
                key: key.clone(),
                value: value.clone(),
            },
            Self::In { key, values } => Condition::In {
                key: key.clone(),
                values: values.clone(),
            },
            Self::Defined { key } => Condition::Defined { key: key.clone() },
        }
    }

    fn validate(&self) -> Result<()> {
        self.validate_inner(0, false)
    }

    fn validate_protocol_projection(&self) -> Result<()> {
        self.validate_inner(0, true)
    }

    fn constant_truth(&self) -> Option<bool> {
        match self {
            Self::All { conditions } => {
                let mut has_dynamic = false;
                for condition in conditions {
                    match condition.constant_truth() {
                        Some(false) => return Some(false),
                        Some(true) => {}
                        None => has_dynamic = true,
                    }
                }
                (!has_dynamic).then_some(true)
            }
            Self::Any { conditions } => {
                let mut has_dynamic = false;
                for condition in conditions {
                    match condition.constant_truth() {
                        Some(true) => return Some(true),
                        Some(false) => {}
                        None => has_dynamic = true,
                    }
                }
                (!has_dynamic).then_some(false)
            }
            Self::Not { condition } => condition.constant_truth().map(|value| !value),
            Self::Eq { .. } | Self::In { .. } | Self::Defined { .. } => None,
        }
    }

    fn validate_inner(&self, depth: u32, protocol_projection: bool) -> Result<()> {
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                if depth >= 16 {
                    bail!("condition operator nesting depth must not exceed 16");
                }
                if conditions.len() > 255 {
                    bail!("condition operators must not contain more than 255 children");
                }
                for condition in conditions {
                    condition.validate_inner(depth + 1, protocol_projection)?;
                }
            }
            Self::Not { condition } => {
                if depth >= 16 {
                    bail!("condition operator nesting depth must not exceed 16");
                }
                condition.validate_inner(depth + 1, protocol_projection)?;
            }
            Self::Eq { key, value } => {
                if protocol_projection {
                    validate_protocol_condition_key(key)?;
                    validate_protocol_condition_value(value)?;
                } else {
                    validate_condition_key(key)?;
                    validate_condition_value(value)?;
                }
            }
            Self::In { key, values } => {
                if protocol_projection {
                    validate_protocol_condition_key(key)?;
                } else {
                    validate_condition_key(key)?;
                }
                if !protocol_projection && values.is_empty() {
                    bail!("in condition values must not be empty");
                }
                if values.len() > 128 {
                    bail!("in condition values must not contain more than 128 entries");
                }
                for value in values {
                    if protocol_projection {
                        validate_protocol_condition_value(value)?;
                    } else {
                        validate_condition_value(value)?;
                    }
                }
                if !protocol_projection {
                    validate_unique_condition_values(values)?;
                }
            }
            Self::Defined { key } => {
                if protocol_projection {
                    validate_protocol_condition_key(key)?;
                } else {
                    validate_condition_key(key)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StrictPolicyCondition {
    All(StrictAllCondition),
    Any(StrictAnyCondition),
    Not(StrictNotCondition),
    Eq(StrictEqCondition),
    In(StrictInCondition),
    Defined(StrictDefinedCondition),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictAllCondition {
    op: AllOperator,
    conditions: Vec<PolicyCondition>,
}

#[derive(Deserialize)]
enum AllOperator {
    #[serde(rename = "all")]
    All,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictAnyCondition {
    op: AnyOperator,
    conditions: Vec<PolicyCondition>,
}

#[derive(Deserialize)]
enum AnyOperator {
    #[serde(rename = "any")]
    Any,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictNotCondition {
    op: NotOperator,
    condition: Box<PolicyCondition>,
}

#[derive(Deserialize)]
enum NotOperator {
    #[serde(rename = "not")]
    Not,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictEqCondition {
    op: EqOperator,
    key: String,
    value: Value,
}

#[derive(Deserialize)]
enum EqOperator {
    #[serde(rename = "eq")]
    Eq,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictInCondition {
    op: InOperator,
    key: String,
    values: Vec<Value>,
}

#[derive(Deserialize)]
enum InOperator {
    #[serde(rename = "in")]
    In,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDefinedCondition {
    op: DefinedOperator,
    key: String,
}

#[derive(Deserialize)]
enum DefinedOperator {
    #[serde(rename = "defined")]
    Defined,
}

impl From<StrictPolicyCondition> for PolicyCondition {
    fn from(condition: StrictPolicyCondition) -> Self {
        match condition {
            StrictPolicyCondition::All(value) => {
                let AllOperator::All = value.op;
                Self::All {
                    conditions: value.conditions,
                }
            }
            StrictPolicyCondition::Any(value) => {
                let AnyOperator::Any = value.op;
                Self::Any {
                    conditions: value.conditions,
                }
            }
            StrictPolicyCondition::Not(value) => {
                let NotOperator::Not = value.op;
                Self::Not {
                    condition: value.condition,
                }
            }
            StrictPolicyCondition::Eq(value) => {
                let EqOperator::Eq = value.op;
                Self::Eq {
                    key: value.key,
                    value: value.value,
                }
            }
            StrictPolicyCondition::In(value) => {
                let InOperator::In = value.op;
                Self::In {
                    key: value.key,
                    values: value.values,
                }
            }
            StrictPolicyCondition::Defined(value) => {
                let DefinedOperator::Defined = value.op;
                Self::Defined { key: value.key }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntity {
    pub id: String,
    pub kind: PolicySelectorKind,
    pub locator: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPathStep {
    pub source_id: String,
    pub edge_id: String,
    pub target_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidenceSpan {
    pub kind: EvidenceKind,
    pub path: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl PolicyEvidenceSpan {
    fn validate(&self) -> Result<()> {
        validate_bounded_text("policy evidence path", &self.path, 4096)?;
        validate_repository_path("policy evidence path", &self.path)?;
        if self.start_line == 0
            || self.start_column == 0
            || self.end_line == 0
            || self.end_column == 0
        {
            bail!("policy evidence positions are one-based and must be at least 1");
        }
        if (self.end_line, self.end_column) < (self.start_line, self.start_column) {
            bail!("policy evidence end must not precede its start");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedPolicySuppression {
    pub id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicApiChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicApiChange {
    pub id: String,
    pub rule_id: String,
    pub kind: PublicApiChangeKind,
    pub breaking: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<PolicyEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<PolicyEntity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub condition: PolicyCondition,
    pub evidence: Vec<PolicyEvidenceSpan>,
}

impl PublicApiChange {
    pub fn stable_id(
        rule_id: &str,
        kind: PublicApiChangeKind,
        before_id: Option<&str>,
        after_id: Option<&str>,
        profile_id: Option<&str>,
        changed_fields: &[String],
    ) -> String {
        stable_id_from_value(
            "policy-api-change",
            &json!({
                "schema_version": POLICY_RESULT_SCHEMA_VERSION,
                "rule_id": rule_id,
                "kind": kind,
                "before_id": before_id,
                "after_id": after_id,
                "profile_id": profile_id,
                "changed_fields": changed_fields,
            }),
        )
    }

    fn validate(&self) -> Result<()> {
        if !is_stable_id(&self.id, "policy-api-change") {
            bail!(
                "public API change ID {:?} must be policy-api-change:sha256:<64 lowercase hex>",
                self.id
            );
        }
        validate_contract_id("public API change rule", &self.rule_id)?;
        match self.kind {
            PublicApiChangeKind::Added if self.before.is_some() || self.after.is_none() => {
                bail!("added public API change must contain only an after entity")
            }
            PublicApiChangeKind::Removed if self.before.is_none() || self.after.is_some() => {
                bail!("removed public API change must contain only a before entity")
            }
            PublicApiChangeKind::Changed if self.before.is_none() || self.after.is_none() => {
                bail!("changed public API change must contain before and after entities")
            }
            _ => {}
        }
        if self.breaking != (self.kind != PublicApiChangeKind::Added) {
            bail!("only removed or changed public APIs are breaking in policy result v1");
        }
        if self.kind == PublicApiChangeKind::Changed && self.changed_fields.is_empty() {
            bail!("changed public API change must list changed_fields");
        }
        if self.kind != PublicApiChangeKind::Changed && !self.changed_fields.is_empty() {
            bail!("added or removed public API changes must not list changed_fields");
        }
        let mut canonical_fields = self.changed_fields.clone();
        canonical_fields.sort();
        canonical_fields.dedup();
        if canonical_fields != self.changed_fields {
            bail!("public API changed_fields must be unique and sorted");
        }
        for field in &self.changed_fields {
            validate_bounded_text("public API changed field", field, 256)?;
        }
        if let Some(before) = &self.before {
            validate_entity("public API before entity", before)?;
            if !matches!(
                before.kind,
                PolicySelectorKind::Symbol | PolicySelectorKind::Type | PolicySelectorKind::Route
            ) {
                bail!("public API before entity must be a symbol, type, or route");
            }
        }
        if let Some(after) = &self.after {
            validate_entity("public API after entity", after)?;
            if !matches!(
                after.kind,
                PolicySelectorKind::Symbol | PolicySelectorKind::Type | PolicySelectorKind::Route
            ) {
                bail!("public API after entity must be a symbol, type, or route");
            }
        }
        if let (Some(before), Some(after)) = (&self.before, &self.after)
            && before.kind != after.kind
        {
            bail!("changed public API before and after entities must have the same kind");
        }
        if let Some(profile_id) = &self.profile_id {
            validate_bounded_text("public API change profile ID", profile_id, 1024)?;
        }
        self.condition.validate()?;
        if self.evidence.is_empty() {
            bail!("public API change evidence must not be empty");
        }
        for span in &self.evidence {
            span.validate()?;
        }
        validate_unique("public API change evidence", &self.evidence)?;
        let expected_id = Self::stable_id(
            &self.rule_id,
            self.kind,
            self.before.as_ref().map(|entity| entity.id.as_str()),
            self.after.as_ref().map(|entity| entity.id.as_str()),
            self.profile_id.as_deref(),
            &self.changed_fields,
        );
        if self.id != expected_id {
            bail!("public API change ID does not match its canonical fields");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyViolation {
    pub id: String,
    pub rule_id: String,
    pub severity: PolicySeverity,
    pub message: String,
    pub source: PolicyEntity,
    pub target: PolicyEntity,
    pub dependency_path: Vec<PolicyPathStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub condition: PolicyCondition,
    pub evidence: Vec<PolicyEvidenceSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppression: Option<AppliedPolicySuppression>,
}

impl PolicyViolation {
    pub fn stable_id(
        rule_id: &str,
        source_id: &str,
        target_id: &str,
        profile_id: Option<&str>,
        dependency_path: &[PolicyPathStep],
    ) -> String {
        stable_id_from_value(
            "policy-violation",
            &json!({
                "schema_version": POLICY_RESULT_SCHEMA_VERSION,
                "rule_id": rule_id,
                "source_id": source_id,
                "target_id": target_id,
                "profile_id": profile_id,
                "dependency_path": dependency_path,
            }),
        )
    }

    fn validate(&self) -> Result<()> {
        if !is_stable_id(&self.id, "policy-violation") {
            bail!(
                "policy violation ID {:?} must be policy-violation:sha256:<64 lowercase hex>",
                self.id
            );
        }
        validate_contract_id("policy violation rule", &self.rule_id)?;
        validate_bounded_text("policy violation message", &self.message, 4096)?;
        validate_entity("policy violation source", &self.source)?;
        validate_entity("policy violation target", &self.target)?;
        if self.dependency_path.is_empty() {
            bail!("policy violation dependency_path must not be empty");
        }
        for step in &self.dependency_path {
            validate_bounded_text("policy path source ID", &step.source_id, 1024)?;
            validate_bounded_text("policy path edge ID", &step.edge_id, 1024)?;
            validate_bounded_text("policy path target ID", &step.target_id, 1024)?;
        }
        if self
            .dependency_path
            .first()
            .is_none_or(|step| step.source_id != self.source.id)
            || self
                .dependency_path
                .last()
                .is_none_or(|step| step.target_id != self.target.id)
        {
            bail!("policy violation dependency_path must connect its source and target");
        }
        if self
            .dependency_path
            .windows(2)
            .any(|steps| steps[0].target_id != steps[1].source_id)
        {
            bail!("policy violation dependency_path steps must form a connected path");
        }
        if let Some(profile_id) = &self.profile_id {
            validate_bounded_text("policy violation profile ID", profile_id, 1024)?;
        }
        self.condition.validate_protocol_projection()?;
        if self.evidence.is_empty() {
            bail!("policy violation evidence must not be empty");
        }
        for span in &self.evidence {
            span.validate()?;
        }
        validate_unique("policy violation evidence", &self.evidence)?;
        if let Some(change_id) = &self.change_id
            && !is_stable_id(change_id, "policy-api-change")
        {
            bail!(
                "policy violation change_id {:?} must be policy-api-change:sha256:<64 lowercase hex>",
                change_id
            );
        }
        if let Some(suppression) = &self.suppression {
            validate_contract_id("applied policy suppression", &suppression.id)?;
            validate_bounded_text(
                "applied policy suppression reason",
                &suppression.reason,
                1024,
            )?;
        }

        let expected_id = Self::stable_id(
            &self.rule_id,
            &self.source.id,
            &self.target.id,
            self.profile_id.as_deref(),
            &self.dependency_path,
        );
        if self.id != expected_id {
            bail!(
                "policy violation ID does not match its canonical rule/source/target/profile/path"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResultSummary {
    pub errors: u64,
    pub warnings: u64,
    pub suppressed: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyResult {
    pub schema_version: String,
    pub snapshot_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_changes: Vec<PublicApiChange>,
    pub violations: Vec<PolicyViolation>,
    pub summary: PolicyResultSummary,
    pub exit_code: u8,
}

impl PolicyResult {
    #[must_use]
    pub fn new(snapshot_id: impl Into<String>, violations: Vec<PolicyViolation>) -> Self {
        Self::with_api_changes(snapshot_id, Vec::new(), violations)
    }

    #[must_use]
    pub fn with_api_changes(
        snapshot_id: impl Into<String>,
        mut api_changes: Vec<PublicApiChange>,
        mut violations: Vec<PolicyViolation>,
    ) -> Self {
        api_changes.sort_by(|left, right| {
            (
                &left.rule_id,
                left.kind,
                left.before.as_ref().map(|entity| &entity.id),
                left.after.as_ref().map(|entity| &entity.id),
                &left.profile_id,
                &left.id,
            )
                .cmp(&(
                    &right.rule_id,
                    right.kind,
                    right.before.as_ref().map(|entity| &entity.id),
                    right.after.as_ref().map(|entity| &entity.id),
                    &right.profile_id,
                    &right.id,
                ))
        });
        violations.sort_by(|left, right| {
            (
                &left.rule_id,
                &left.source.id,
                &left.target.id,
                &left.profile_id,
                &left.id,
            )
                .cmp(&(
                    &right.rule_id,
                    &right.source.id,
                    &right.target.id,
                    &right.profile_id,
                    &right.id,
                ))
        });
        let summary = summarize_violations(&violations);
        let exit_code = u8::from(summary.errors > 0);
        Self {
            schema_version: POLICY_RESULT_SCHEMA_VERSION.to_owned(),
            snapshot_id: snapshot_id.into(),
            api_changes,
            violations,
            summary,
            exit_code,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != POLICY_RESULT_SCHEMA_VERSION {
            bail!(
                "unsupported policy result schema_version {}; expected {POLICY_RESULT_SCHEMA_VERSION}",
                self.schema_version
            );
        }
        validate_bounded_text("policy result snapshot ID", &self.snapshot_id, 1024)?;
        for change in &self.api_changes {
            change.validate()?;
        }
        let mut canonical_changes = self.api_changes.clone();
        canonical_changes.sort_by(|left, right| {
            (
                &left.rule_id,
                left.kind,
                left.before.as_ref().map(|entity| &entity.id),
                left.after.as_ref().map(|entity| &entity.id),
                &left.profile_id,
                &left.id,
            )
                .cmp(&(
                    &right.rule_id,
                    right.kind,
                    right.before.as_ref().map(|entity| &entity.id),
                    right.after.as_ref().map(|entity| &entity.id),
                    &right.profile_id,
                    &right.id,
                ))
        });
        if canonical_changes != self.api_changes {
            bail!("policy result public API changes are not in canonical order");
        }
        let changes_by_id: std::collections::BTreeMap<_, _> = self
            .api_changes
            .iter()
            .map(|change| (change.id.as_str(), change))
            .collect();
        if changes_by_id.len() != self.api_changes.len() {
            bail!("policy result contains duplicate public API change IDs");
        }
        for violation in &self.violations {
            violation.validate()?;
            if let Some(change_id) = violation.change_id.as_deref() {
                let change = changes_by_id
                    .get(change_id)
                    .context("policy violation references an unknown public API change")?;
                if change.rule_id != violation.rule_id {
                    bail!(
                        "policy violation and referenced public API change must use the same rule"
                    );
                }
                if !change.breaking {
                    bail!("policy violation cannot reference a compatible public API addition");
                }
            }
        }
        let mut canonical = self.violations.clone();
        canonical.sort_by(|left, right| {
            (
                &left.rule_id,
                &left.source.id,
                &left.target.id,
                &left.profile_id,
                &left.id,
            )
                .cmp(&(
                    &right.rule_id,
                    &right.source.id,
                    &right.target.id,
                    &right.profile_id,
                    &right.id,
                ))
        });
        if canonical != self.violations {
            bail!("policy result violations are not in canonical order");
        }
        let mut ids = BTreeSet::new();
        if self
            .violations
            .iter()
            .any(|violation| !ids.insert(violation.id.as_str()))
        {
            bail!("policy result contains duplicate violation IDs");
        }
        let expected_summary = summarize_violations(&self.violations);
        if self.summary != expected_summary {
            bail!("policy result summary does not match its violations");
        }
        let expected_exit_code = u8::from(expected_summary.errors > 0);
        if self.exit_code != expected_exit_code {
            bail!(
                "policy result exit_code must be {expected_exit_code} for its active error violations"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAnnotationLevel {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAnnotation {
    pub violation_id: String,
    pub rule_id: String,
    pub level: PolicyAnnotationLevel,
    pub path: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
    pub title: String,
    pub message: String,
}

pub fn policy_annotations(result: &PolicyResult) -> Result<Vec<PolicyAnnotation>> {
    result.validate()?;
    let mut annotations = Vec::new();
    for violation in result
        .violations
        .iter()
        .filter(|violation| violation.suppression.is_none())
    {
        let evidence = violation
            .evidence
            .first()
            .context("active policy violation has no annotation evidence")?;
        annotations.push(PolicyAnnotation {
            violation_id: violation.id.clone(),
            rule_id: violation.rule_id.clone(),
            level: match violation.severity {
                PolicySeverity::Warning => PolicyAnnotationLevel::Warning,
                PolicySeverity::Error => PolicyAnnotationLevel::Error,
            },
            path: evidence.path.clone(),
            start_line: evidence.start_line,
            start_column: evidence.start_column,
            end_line: evidence.end_line,
            end_column: evidence.end_column,
            title: format!("depgraph policy {}", violation.rule_id),
            message: format!(
                "rule {} violated ({}); inspect the depgraph policy report for details",
                violation.rule_id, violation.id
            ),
        });
    }
    annotations.sort_by(|left, right| {
        (
            &left.path,
            left.start_line,
            left.start_column,
            left.level,
            &left.rule_id,
            &left.violation_id,
        )
            .cmp(&(
                &right.path,
                right.start_line,
                right.start_column,
                right.level,
                &right.rule_id,
                &right.violation_id,
            ))
    });
    Ok(annotations)
}

#[must_use]
pub fn render_github_annotations(annotations: &[PolicyAnnotation]) -> String {
    let mut output = String::new();
    for annotation in annotations {
        let level = match annotation.level {
            PolicyAnnotationLevel::Warning => "warning",
            PolicyAnnotationLevel::Error => "error",
        };
        output.push_str(&format!(
            "::{level} file={},line={},col={},endLine={},endColumn={},title={}::{}\n",
            escape_workflow_property(&annotation.path),
            annotation.start_line,
            annotation.start_column,
            annotation.end_line,
            annotation.end_column,
            escape_workflow_property(&annotation.title),
            escape_workflow_data(&annotation.message),
        ));
    }
    output
}

fn escape_workflow_property(value: &str) -> String {
    escape_workflow_data(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn escape_workflow_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn summarize_violations(violations: &[PolicyViolation]) -> PolicyResultSummary {
    let mut summary = PolicyResultSummary::default();
    for violation in violations {
        if violation.suppression.is_some() {
            summary.suppressed += 1;
        } else {
            match violation.severity {
                PolicySeverity::Warning => summary.warnings += 1,
                PolicySeverity::Error => summary.errors += 1,
            }
        }
    }
    summary
}

fn validate_entity(name: &str, entity: &PolicyEntity) -> Result<()> {
    validate_bounded_text(&format!("{name} ID"), &entity.id, 1024)?;
    validate_bounded_text(&format!("{name} locator"), &entity.locator, 4096)
}

fn validate_contract_id(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "{name} ID {value:?} must be 1-128 ASCII letters, digits, dot, underscore, or hyphen and start with a letter or digit"
        );
    }
    Ok(())
}

fn validate_pattern(name: &str, kind: PolicyMatchKind, value: &str, path: bool) -> Result<()> {
    validate_bounded_text(name, value, 1024)?;
    if value.contains('\\') {
        bail!("{name} must use forward slashes");
    }
    match kind {
        PolicyMatchKind::Exact | PolicyMatchKind::Prefix
            if value.contains('*') || value.contains('?') =>
        {
            bail!("{name} may use wildcards only with glob matching");
        }
        PolicyMatchKind::Glob
            if value.contains('[')
                || value.contains(']')
                || value.contains('{')
                || value.contains('}') =>
        {
            bail!("{name} glob supports only *, **, and ? wildcards");
        }
        _ => {}
    }
    if path {
        validate_repository_path(name, value)?;
    }
    Ok(())
}

fn validate_repository_path(name: &str, value: &str) -> Result<()> {
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().nth(1) == Some(':')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{name} {value:?} must be a normalized repository-relative path or path pattern");
    }
    Ok(())
}

fn validate_bounded_text(name: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(|character| character.is_control())
    {
        bail!("{name} must contain 1-{maximum} non-control characters");
    }
    Ok(())
}

fn validate_condition_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || key.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '-'))
        })
    {
        bail!(
            "condition key {key:?} must contain 1-128 ASCII letters, digits, dot, colon, underscore, or hyphen"
        );
    }
    Ok(())
}

fn validate_condition_value(value: &Value) -> Result<()> {
    if !matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    ) {
        bail!("condition values must be JSON primitives");
    }
    if let Value::String(value) = value {
        validate_bounded_text("condition string value", value, 1024)?;
    }
    Ok(())
}

fn validate_protocol_condition_key(key: &str) -> Result<()> {
    if key.is_empty() {
        bail!("protocol condition key must not be empty");
    }
    if key.len() > 128 {
        bail!("protocol condition key must not exceed 128 UTF-8 bytes");
    }
    Ok(())
}

fn validate_protocol_condition_value(value: &Value) -> Result<()> {
    if !matches!(
        value,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
    ) {
        bail!("protocol condition values must be JSON primitives");
    }
    if let Value::String(value) = value
        && value.chars().count() > 1024
    {
        bail!("protocol condition string values must not exceed 1024 characters");
    }
    Ok(())
}

fn validate_unique_condition_values(values: &[Value]) -> Result<()> {
    for (index, value) in values.iter().enumerate() {
        if values[..index]
            .iter()
            .any(|existing| condition_values_equal(existing, value))
        {
            bail!("in condition values must not contain duplicates");
        }
    }
    Ok(())
}

fn condition_values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => match (left.as_i128(), right.as_i128()) {
            (Some(left), Some(right)) => left == right,
            (Some(integer), None) => right
                .as_f64()
                .is_some_and(|float| float.fract() == 0.0 && integer == float as i128),
            (None, Some(integer)) => left
                .as_f64()
                .is_some_and(|float| float.fract() == 0.0 && float as i128 == integer),
            (None, None) => left.as_f64() == right.as_f64(),
        },
        _ => left == right,
    }
}

fn validate_unique<T>(name: &str, values: &[T]) -> Result<()>
where
    T: Serialize,
{
    let mut seen = BTreeSet::new();
    for value in values {
        let encoded = serde_json::to_string(value)?;
        if !seen.insert(encoded) {
            bail!("{name} must not contain duplicates");
        }
    }
    Ok(())
}

fn validate_unique_nonempty<T>(name: &str, values: &[T]) -> Result<()>
where
    T: Serialize,
{
    if values.is_empty() {
        bail!("{name} must not be empty");
    }
    validate_unique(name, values)
}

fn is_stable_id(value: &str, namespace: &str) -> bool {
    value
        .strip_prefix(&format!("{namespace}:sha256:"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_POLICY: &str = include_str!("../tests/fixtures/policy-v1.golden.json");

    #[test]
    fn golden_policy_is_accepted_by_rust_and_json_schema() -> Result<()> {
        let value: Value = serde_json::from_str(GOLDEN_POLICY)?;
        let policy: PolicyConfig = serde_json::from_value(value.clone())?;
        policy.validate()?;

        let schema: Value = serde_json::from_str(POLICY_SCHEMA)?;
        jsonschema::validator_for(&schema)?
            .validate(&value)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(())
    }

    #[test]
    fn policy_rejects_unknown_fields_versions_and_unbounded_suppressions() -> Result<()> {
        let value: Value = serde_json::from_str(GOLDEN_POLICY)?;
        let mut unknown = value.clone();
        unknown["rules"][0]["sevverity"] = json!("error");
        assert!(serde_json::from_value::<PolicyConfig>(unknown).is_err());

        let mut version = value.clone();
        version["schema_version"] = json!("2.0");
        let version: PolicyConfig = serde_json::from_value(version)?;
        assert!(
            version
                .validate()
                .unwrap_err()
                .to_string()
                .contains("unsupported policy schema_version")
        );

        let mut unbounded = value.clone();
        unbounded["suppressions"][0]["scope"] = json!({});
        let unbounded: PolicyConfig = serde_json::from_value(unbounded)?;
        assert!(
            unbounded
                .validate()
                .unwrap_err()
                .to_string()
                .contains("suppression scope")
        );

        let schema: Value = serde_json::from_str(POLICY_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        for condition in [
            json!({"op": "all", "conditions": []}),
            json!({
                "op": "any",
                "conditions": [
                    {"op": "defined", "key": "target"},
                    {"op": "all", "conditions": []}
                ]
            }),
            json!({
                "op": "not",
                "condition": {"op": "any", "conditions": []}
            }),
        ] {
            let mut vacuous = value.clone();
            vacuous["suppressions"][0]["scope"] = json!({"condition": condition});
            let policy: PolicyConfig = serde_json::from_value(vacuous.clone())?;
            assert!(
                policy
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("suppression scope")
            );
            assert!(
                validator.validate(&vacuous).is_err(),
                "JSON Schema accepted a vacuous suppression condition"
            );
        }

        for invalid_path in [
            json!({"match": "glob", "value": "/src/**"}),
            json!({"match": "glob", "value": "src/../secret"}),
            json!({"match": "glob", "value": "src/[ab].ts"}),
            json!({"match": "exact", "value": "src/*.ts"}),
            json!({"match": "exact", "value": "src\\secret.ts"}),
            json!({"match": "exact", "value": "C:/src/app.ts"}),
            json!({"match": "exact", "value": "é:/src/app.ts"}),
        ] {
            let mut invalid = value.clone();
            invalid["rules"][0]["source"]["match"] = invalid_path["match"].clone();
            invalid["rules"][0]["source"]["value"] = invalid_path["value"].clone();
            let policy: PolicyConfig = serde_json::from_value(invalid.clone())?;
            assert!(policy.validate().is_err());
            assert!(
                validator.validate(&invalid).is_err(),
                "JSON Schema accepted invalid path pattern {invalid_path}"
            );
        }

        let mut mismatched_cycle = value.clone();
        mismatched_cycle["rules"][0]["kind"] = json!("cycle");
        mismatched_cycle["rules"][0]["target"]["kind"] = json!("route");
        mismatched_cycle["rules"][0]["target"]["field"] = json!("locator");
        let policy: PolicyConfig = serde_json::from_value(mismatched_cycle.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&mismatched_cycle).is_err(),
            "JSON Schema accepted mismatched cycle selector kinds"
        );

        let mut oversized_condition = value.clone();
        oversized_condition["rules"][0]["condition"] = json!({
            "op": "all",
            "conditions": (0..256)
                .map(|index| json!({"op": "eq", "key": "feature", "value": index}))
                .collect::<Vec<_>>()
        });
        let policy: PolicyConfig = serde_json::from_value(oversized_condition.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&oversized_condition).is_err(),
            "JSON Schema accepted 256 child conditions plus their parent"
        );

        let mut deeply_nested = value.clone();
        let mut condition = json!({"op": "eq", "key": "feature", "value": "stable"});
        for _ in 0..17 {
            condition = json!({"op": "not", "condition": condition});
        }
        deeply_nested["rules"][0]["condition"] = condition;
        let policy: PolicyConfig = serde_json::from_value(deeply_nested.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&deeply_nested).is_err(),
            "JSON Schema accepted a condition deeper than 16 operators"
        );

        let mut maximum_depth = value.clone();
        let mut condition = json!({"op": "eq", "key": "feature", "value": "stable"});
        for _ in 0..16 {
            condition = json!({"op": "not", "condition": condition});
        }
        maximum_depth["rules"][0]["condition"] = condition;
        let policy: PolicyConfig = serde_json::from_value(maximum_depth.clone())?;
        policy.validate()?;
        assert!(
            validator.validate(&maximum_depth).is_ok(),
            "JSON Schema rejected a condition at the 16-operator boundary"
        );

        for invalid_string in [
            String::new(),
            "x".repeat(1025),
            "annotation\nbreak".to_owned(),
        ] {
            let mut invalid = value.clone();
            invalid["rules"][0]["condition"] =
                json!({"op": "eq", "key": "feature", "value": invalid_string});
            let policy: PolicyConfig = serde_json::from_value(invalid.clone())?;
            assert!(policy.validate().is_err());
            assert!(
                validator.validate(&invalid).is_err(),
                "JSON Schema accepted an invalid condition string"
            );
        }

        let mut duplicate_numeric_values = value.clone();
        duplicate_numeric_values["rules"][0]["condition"] =
            json!({"op": "in", "key": "feature", "values": [1, 1.0]});
        let policy: PolicyConfig = serde_json::from_value(duplicate_numeric_values.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&duplicate_numeric_values).is_err(),
            "JSON Schema accepted mathematically equal numeric condition values"
        );

        let mut unsafe_reason = value.clone();
        unsafe_reason["suppressions"][0]["reason"] = json!("annotation\nbreak");
        let policy: PolicyConfig = serde_json::from_value(unsafe_reason.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&unsafe_reason).is_err(),
            "JSON Schema accepted a control-bearing suppression reason"
        );

        let mut unsafe_match = value;
        unsafe_match["rules"][0]["source"]["value"] = json!("src/ui/\n**");
        let policy: PolicyConfig = serde_json::from_value(unsafe_match.clone())?;
        assert!(policy.validate().is_err());
        assert!(
            validator.validate(&unsafe_match).is_err(),
            "JSON Schema accepted a control-bearing match value"
        );
        Ok(())
    }

    #[test]
    fn specialized_rule_selector_contracts_match_json_schema() -> Result<()> {
        let golden: Value = serde_json::from_str(GOLDEN_POLICY)?;
        let schema: Value = serde_json::from_str(POLICY_SCHEMA)?;
        let validator = jsonschema::validator_for(&schema)?;
        let policy_value = |rule: Value| {
            json!({
                "schema_version": POLICY_SCHEMA_VERSION,
                "rules": [rule],
                "suppressions": []
            })
        };

        let mut runtime = golden["rules"][0].clone();
        runtime["id"] = json!("runtime-boundary");
        runtime["kind"] = json!("runtime_boundary");
        runtime["source"] = json!({
            "kind": "route",
            "field": "locator",
            "match": "prefix",
            "value": "framework-route:",
            "cardinality": "many",
            "exclude": [],
            "scope": {}
        });
        runtime["target"] = json!({
            "kind": "component",
            "field": "locator",
            "match": "prefix",
            "value": "framework-component:",
            "cardinality": "many",
            "exclude": [],
            "scope": {}
        });
        let valid_runtime = policy_value(runtime.clone());
        let parsed: PolicyConfig = serde_json::from_value(valid_runtime.clone())?;
        parsed.validate()?;
        validator
            .validate(&valid_runtime)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        runtime["target"]["kind"] = json!("route");
        let invalid_runtime = policy_value(runtime);
        let parsed: PolicyConfig = serde_json::from_value(invalid_runtime.clone())?;
        assert!(parsed.validate().is_err());
        assert!(validator.validate(&invalid_runtime).is_err());

        let mut public_api = golden["rules"][0].clone();
        public_api["id"] = json!("public-api");
        public_api["kind"] = json!("public_api_change");
        public_api["target"] = json!({
            "kind": "symbol",
            "field": "locator",
            "match": "prefix",
            "value": "typescript-symbol:",
            "cardinality": "many",
            "exclude": [],
            "scope": {}
        });
        let valid_public_api = policy_value(public_api.clone());
        let parsed: PolicyConfig = serde_json::from_value(valid_public_api.clone())?;
        parsed.validate()?;
        validator
            .validate(&valid_public_api)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        public_api["target"]["kind"] = json!("file");
        public_api["target"]["field"] = json!("path");
        public_api["target"]["value"] = json!("src/**");
        let invalid_public_api = policy_value(public_api);
        let parsed: PolicyConfig = serde_json::from_value(invalid_public_api.clone())?;
        assert!(parsed.validate().is_err());
        assert!(validator.validate(&invalid_public_api).is_err());
        Ok(())
    }

    #[test]
    fn policy_result_is_canonical_and_error_exit_is_one() -> Result<()> {
        let path = vec![PolicyPathStep {
            source_id: "file:source".into(),
            edge_id: "edge:dependency".into(),
            target_id: "file:target".into(),
        }];
        let violation = PolicyViolation {
            id: PolicyViolation::stable_id(
                "no-ui-to-data",
                "file:source",
                "file:target",
                Some("profile:web"),
                &path,
            ),
            rule_id: "no-ui-to-data".into(),
            severity: PolicySeverity::Error,
            message: "UI must not depend directly on data internals".into(),
            source: PolicyEntity {
                id: "file:source".into(),
                kind: PolicySelectorKind::File,
                locator: "src/ui.ts".into(),
            },
            target: PolicyEntity {
                id: "file:target".into(),
                kind: PolicySelectorKind::File,
                locator: "src/data/internal.ts".into(),
            },
            dependency_path: path,
            profile_id: Some("profile:web".into()),
            condition: PolicyCondition::default(),
            evidence: vec![PolicyEvidenceSpan {
                kind: EvidenceKind::Source,
                path: "src/ui.ts".into(),
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 20,
            }],
            change_id: None,
            suppression: None,
        };

        let mut disconnected = violation.clone();
        disconnected.dependency_path[0].source_id = "file:other".into();
        disconnected.id = PolicyViolation::stable_id(
            &disconnected.rule_id,
            &disconnected.source.id,
            &disconnected.target.id,
            disconnected.profile_id.as_deref(),
            &disconnected.dependency_path,
        );
        assert!(
            disconnected
                .validate()
                .unwrap_err()
                .to_string()
                .contains("connect its source and target")
        );

        let mut broken_steps = violation.clone();
        broken_steps.dependency_path = vec![
            PolicyPathStep {
                source_id: "file:source".into(),
                edge_id: "edge:first".into(),
                target_id: "file:middle".into(),
            },
            PolicyPathStep {
                source_id: "file:other".into(),
                edge_id: "edge:second".into(),
                target_id: "file:target".into(),
            },
        ];
        broken_steps.id = PolicyViolation::stable_id(
            &broken_steps.rule_id,
            &broken_steps.source.id,
            &broken_steps.target.id,
            broken_steps.profile_id.as_deref(),
            &broken_steps.dependency_path,
        );
        assert!(
            broken_steps
                .validate()
                .unwrap_err()
                .to_string()
                .contains("steps must form a connected path")
        );

        let mut unsafe_evidence_path = violation.clone();
        unsafe_evidence_path.evidence[0].path = "src/\nannotation.rs".into();
        assert!(
            unsafe_evidence_path
                .validate()
                .unwrap_err()
                .to_string()
                .contains("policy evidence path")
        );

        let result = PolicyResult::new("snapshot:fixture", vec![violation]);
        assert_eq!(result.summary.errors, 1);
        assert_eq!(result.exit_code, 1);
        result.validate()
    }

    #[test]
    fn github_annotations_are_repository_relative_escaped_and_omit_suppressed() -> Result<()> {
        let path = vec![PolicyPathStep {
            source_id: "symbol:consumer".into(),
            edge_id: "edge:impact".into(),
            target_id: "symbol:api".into(),
        }];
        let active = PolicyViolation {
            id: PolicyViolation::stable_id(
                "stable-api",
                "symbol:consumer",
                "symbol:api",
                Some("profile:web"),
                &path,
            ),
            rule_id: "stable-api".into(),
            severity: PolicySeverity::Error,
            message: "policy 100%: public API changed at /Users/alice with super-secret-value"
                .into(),
            source: PolicyEntity {
                id: "symbol:consumer".into(),
                kind: PolicySelectorKind::Symbol,
                locator: "symbol:consumer".into(),
            },
            target: PolicyEntity {
                id: "symbol:api".into(),
                kind: PolicySelectorKind::Symbol,
                locator: "symbol:api".into(),
            },
            dependency_path: path,
            profile_id: Some("profile:web".into()),
            condition: PolicyCondition::default(),
            evidence: vec![PolicyEvidenceSpan {
                kind: EvidenceKind::Source,
                path: "src/api,client:entry.ts".into(),
                start_line: 7,
                start_column: 3,
                end_line: 7,
                end_column: 19,
            }],
            change_id: None,
            suppression: None,
        };
        let mut suppressed = active.clone();
        suppressed.rule_id = "suppressed-api".into();
        suppressed.id = PolicyViolation::stable_id(
            &suppressed.rule_id,
            &suppressed.source.id,
            &suppressed.target.id,
            suppressed.profile_id.as_deref(),
            &suppressed.dependency_path,
        );
        suppressed.suppression = Some(AppliedPolicySuppression {
            id: "reviewed-exception".into(),
            reason: "migration window".into(),
        });
        let result = PolicyResult::new("snapshot:fixture", vec![suppressed, active]);

        let mut annotations = policy_annotations(&result)?;
        assert_eq!(annotations.len(), 1);
        assert_eq!(annotations[0].path, "src/api,client:entry.ts");
        assert_eq!(annotations[0].start_line, 7);
        assert!(!annotations[0].message.contains("100%"));
        assert!(!annotations[0].message.contains("public API changed"));
        assert!(!annotations[0].message.contains("/Users/alice"));
        assert!(!annotations[0].message.contains("super-secret-value"));
        annotations[0].message = "policy 100%: public API changed, review required".into();
        let rendered = render_github_annotations(&annotations);
        assert!(rendered.starts_with(
            "::error file=src/api%2Cclient%3Aentry.ts,line=7,col=3,endLine=7,endColumn=19"
        ));
        assert!(rendered.contains("policy 100%25: public API changed, review required"));
        assert!(!rendered.contains("/Users/"));
        assert!(!rendered.contains("migration window"));
        Ok(())
    }
}
