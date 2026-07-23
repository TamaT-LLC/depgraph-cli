use std::collections::BTreeSet;

use anyhow::{Result, bail};
use depgraph_protocol::{
    Condition, EvidenceKind, Precision, ResolutionStatus, stable_id_from_value,
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
        let mut count = 0_u32;
        self.validate_inner(0, &mut count)
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

    fn validate_inner(&self, depth: u32, count: &mut u32) -> Result<()> {
        if depth > 16 {
            bail!("nesting depth must not exceed 16");
        }
        *count += 1;
        if *count > 256 {
            bail!("condition must not contain more than 256 expressions");
        }
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                for condition in conditions {
                    condition.validate_inner(depth + 1, count)?;
                }
            }
            Self::Not { condition } => condition.validate_inner(depth + 1, count)?,
            Self::Eq { key, value } => {
                validate_condition_key(key)?;
                validate_condition_value(value)?;
            }
            Self::In { key, values } => {
                validate_condition_key(key)?;
                if values.is_empty() {
                    bail!("in condition values must not be empty");
                }
                if values.len() > 128 {
                    bail!("in condition values must not contain more than 128 entries");
                }
                for value in values {
                    validate_condition_value(value)?;
                }
                validate_unique("in condition values", values)?;
            }
            Self::Defined { key } => validate_condition_key(key)?,
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
        if let Some(profile_id) = &self.profile_id {
            validate_bounded_text("policy violation profile ID", profile_id, 1024)?;
        }
        self.condition.validate()?;
        if self.evidence.is_empty() {
            bail!("policy violation evidence must not be empty");
        }
        for span in &self.evidence {
            span.validate()?;
        }
        validate_unique("policy violation evidence", &self.evidence)?;
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
    pub violations: Vec<PolicyViolation>,
    pub summary: PolicyResultSummary,
    pub exit_code: u8,
}

impl PolicyResult {
    #[must_use]
    pub fn new(snapshot_id: impl Into<String>, mut violations: Vec<PolicyViolation>) -> Self {
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
        for violation in &self.violations {
            violation.validate()?;
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
        || value.len() > maximum
        || value.chars().any(|character| character.is_control())
    {
        bail!("{name} must contain 1-{maximum} non-control UTF-8 bytes");
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
            suppression: None,
        };

        let result = PolicyResult::new("snapshot:fixture", vec![violation]);
        assert_eq!(result.summary.errors, 1);
        assert_eq!(result.exit_code, 1);
        result.validate()
    }
}
