use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    PublicReadinessDecision, PublicReadinessToolIdentity, canonical_public_readiness_digest,
};

pub const GITHUB_SETTINGS_DESIRED_SCHEMA_VERSION: &str = "github-settings-desired-v1";
pub const GITHUB_SETTINGS_EVALUATION_SCHEMA_VERSION: &str = "github-settings-evaluation-v1";
pub const GITHUB_SETTINGS_VERIFIER_MODE: &str = "read-only-no-settings-actuator";
pub const GITHUB_SETTINGS_REPOSITORY: &str = "TamaT-LLC/depgraph-cli";
pub const GITHUB_SETTINGS_VERIFIER_NAME: &str = "depgraph-github-settings-verifier";
pub const GITHUB_SETTINGS_VERIFIER_VERSION: &str = "1.0.0";
pub const GITHUB_SETTINGS_DESIRED_DIGEST: &str =
    "d0d2ad331c8519f72fabd34558f1e7d30affee34626bd0f0ce6fed63b964fa5b";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRulesetTarget {
    Branch,
    Tag,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubRulesetEnforcement {
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRequiredCheck {
    pub context: String,
    pub source_app_id: u64,
    pub source_app_slug: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRedactedPrincipal {
    pub identity: String,
    pub permission: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRuleset {
    pub name: String,
    pub target: GitHubRulesetTarget,
    pub enforcement: GitHubRulesetEnforcement,
    pub include: Vec<String>,
    pub required_checks: Vec<GitHubRequiredCheck>,
    pub required_approvals: u32,
    pub require_code_owner_review: bool,
    pub require_conversation_resolution: bool,
    pub allow_force_pushes: bool,
    pub allow_deletions: bool,
    pub bypass_actors: Vec<GitHubRedactedPrincipal>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRedactedSurface {
    pub apps: Vec<GitHubRedactedPrincipal>,
    pub webhook_digests: Vec<String>,
    pub deploy_key_fingerprints: Vec<String>,
    pub token_fingerprints: Vec<String>,
    pub teams: Vec<GitHubRedactedPrincipal>,
    pub environments: Vec<String>,
    pub runner_groups: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSecuritySettings {
    pub private_vulnerability_reporting: bool,
    pub security_advisories: bool,
    pub secret_scanning: bool,
    pub push_protection: bool,
    pub dependency_graph: bool,
    pub dependabot_alerts: bool,
    pub dependabot_security_updates: bool,
    pub code_scanning: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSettingsState {
    pub schema_version: String,
    pub repository: String,
    pub default_branch: String,
    pub rulesets: Vec<GitHubRuleset>,
    pub surface: GitHubRedactedSurface,
    pub security: GitHubSecuritySettings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubSettingsCollectionStatus {
    Complete,
    PermissionDenied,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSettingsApiSnapshot {
    pub collection_status: GitHubSettingsCollectionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<GitHubSettingsState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitHubSettingsDriftReason {
    BypassExpanded,
    CollectionPermissionDenied,
    DefaultBranchMismatch,
    ForceOrDeleteAllowed,
    MissingSetting,
    RequiredCheckSourceMismatch,
    RulesetDisabled,
    SecuritySettingDisabled,
    SettingMismatch,
    UnexpectedPublicSurface,
    UnexpectedSetting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSettingsDrift {
    pub path: String,
    pub reason: GitHubSettingsDriftReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubSettingsEvaluation {
    pub schema_version: String,
    pub verifier_mode: String,
    pub tool: PublicReadinessToolIdentity,
    pub desired_settings_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_settings_digest: Option<String>,
    pub drift: Vec<GitHubSettingsDrift>,
    pub decision: PublicReadinessDecision,
}

pub fn github_settings_verifier_identity() -> PublicReadinessToolIdentity {
    PublicReadinessToolIdentity {
        name: GITHUB_SETTINGS_VERIFIER_NAME.into(),
        version: GITHUB_SETTINGS_VERIFIER_VERSION.into(),
        acquisition_digest: digest_text(
            "depgraph-github-settings-verifier-v1\ntransport=github-api-read-only\nactuator=none\n",
        ),
        configuration_digest: digest_text(
            "github-settings-verifier-policy-v1\nsecret-values=never-requested\nunknown=reject\npartial=reject\n",
        ),
    }
}

pub fn parse_github_settings_desired(bytes: &[u8]) -> Result<GitHubSettingsState> {
    let desired = canonical_github_settings_state(serde_json::from_slice(bytes)?)?;
    validate_desired_identity(&desired)?;
    Ok(desired)
}

pub fn evaluate_github_settings(
    desired: &GitHubSettingsState,
    snapshot: &GitHubSettingsApiSnapshot,
) -> Result<GitHubSettingsEvaluation> {
    let desired = canonical_github_settings_state(desired.clone())?;
    validate_desired_identity(&desired)?;
    let desired_settings_digest = canonical_public_readiness_digest(&desired)?;
    let mut drift = Vec::new();
    if snapshot.collection_status != GitHubSettingsCollectionStatus::Complete {
        drift.push(GitHubSettingsDrift {
            path: "collection".into(),
            reason: GitHubSettingsDriftReason::CollectionPermissionDenied,
            expected_digest: None,
            actual_digest: None,
        });
    }
    let observed = snapshot
        .settings
        .clone()
        .map(canonical_github_settings_state)
        .transpose()?;
    let observed_settings_digest = observed
        .as_ref()
        .map(canonical_public_readiness_digest)
        .transpose()?;
    if let Some(observed) = &observed {
        compare_settings(&desired, observed, &mut drift)?;
    } else {
        drift.push(drift_entry(
            "settings",
            GitHubSettingsDriftReason::MissingSetting,
            Some(&desired),
            Option::<&GitHubSettingsState>::None,
        )?);
    }
    drift.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.reason.cmp(&right.reason))
    });
    drift.dedup();
    Ok(GitHubSettingsEvaluation {
        schema_version: GITHUB_SETTINGS_EVALUATION_SCHEMA_VERSION.into(),
        verifier_mode: GITHUB_SETTINGS_VERIFIER_MODE.into(),
        tool: github_settings_verifier_identity(),
        desired_settings_digest,
        observed_settings_digest,
        decision: if drift.is_empty() {
            PublicReadinessDecision::Allow
        } else {
            PublicReadinessDecision::Reject
        },
        drift,
    })
}

pub fn canonical_github_settings_digest(state: &GitHubSettingsState) -> Result<String> {
    canonical_public_readiness_digest(&canonical_github_settings_state(state.clone())?)
}

fn compare_settings(
    desired: &GitHubSettingsState,
    observed: &GitHubSettingsState,
    drift: &mut Vec<GitHubSettingsDrift>,
) -> Result<()> {
    if desired.repository != observed.repository {
        drift.push(drift_entry(
            "repository",
            GitHubSettingsDriftReason::SettingMismatch,
            Some(&desired.repository),
            Some(&observed.repository),
        )?);
    }
    if desired.default_branch != observed.default_branch {
        drift.push(drift_entry(
            "default_branch",
            GitHubSettingsDriftReason::DefaultBranchMismatch,
            Some(&desired.default_branch),
            Some(&observed.default_branch),
        )?);
    }
    let desired_rules = desired
        .rulesets
        .iter()
        .map(|ruleset| ((ruleset.target, ruleset.name.as_str()), ruleset))
        .collect::<BTreeMap<_, _>>();
    let observed_rules = observed
        .rulesets
        .iter()
        .map(|ruleset| ((ruleset.target, ruleset.name.as_str()), ruleset))
        .collect::<BTreeMap<_, _>>();
    for (key, expected) in &desired_rules {
        let path = format!("rulesets/{}/{}", target_name(key.0), key.1);
        let Some(actual) = observed_rules.get(key) else {
            drift.push(drift_entry(
                &path,
                GitHubSettingsDriftReason::MissingSetting,
                Some(*expected),
                Option::<&GitHubRuleset>::None,
            )?);
            continue;
        };
        if actual.enforcement != GitHubRulesetEnforcement::Enabled {
            drift.push(drift_entry(
                &format!("{path}/enforcement"),
                GitHubSettingsDriftReason::RulesetDisabled,
                Some(&expected.enforcement),
                Some(&actual.enforcement),
            )?);
        }
        if actual.allow_force_pushes || actual.allow_deletions {
            drift.push(drift_entry(
                &format!("{path}/history"),
                GitHubSettingsDriftReason::ForceOrDeleteAllowed,
                Some(&(expected.allow_force_pushes, expected.allow_deletions)),
                Some(&(actual.allow_force_pushes, actual.allow_deletions)),
            )?);
        }
        if actual.bypass_actors != expected.bypass_actors {
            drift.push(drift_entry(
                &format!("{path}/bypass_actors"),
                GitHubSettingsDriftReason::BypassExpanded,
                Some(&expected.bypass_actors),
                Some(&actual.bypass_actors),
            )?);
        }
        let expected_checks = expected
            .required_checks
            .iter()
            .map(|check| (check.context.as_str(), check))
            .collect::<BTreeMap<_, _>>();
        let actual_checks = actual
            .required_checks
            .iter()
            .map(|check| (check.context.as_str(), check))
            .collect::<BTreeMap<_, _>>();
        for (context, expected_check) in expected_checks {
            if actual_checks.get(context).is_some_and(|actual_check| {
                actual_check.source_app_id != expected_check.source_app_id
                    || actual_check.source_app_slug != expected_check.source_app_slug
            }) {
                drift.push(drift_entry(
                    &format!("{path}/required_checks/{context}/source"),
                    GitHubSettingsDriftReason::RequiredCheckSourceMismatch,
                    Some(expected_check),
                    actual_checks.get(context).copied(),
                )?);
            }
        }
        if *actual != *expected {
            drift.push(drift_entry(
                &path,
                GitHubSettingsDriftReason::SettingMismatch,
                Some(*expected),
                Some(*actual),
            )?);
        }
    }
    for (key, actual) in &observed_rules {
        if !desired_rules.contains_key(key) {
            let identity_digest = canonical_public_readiness_digest(&(target_name(key.0), key.1))?;
            drift.push(drift_entry(
                &format!("rulesets/unexpected/{identity_digest}"),
                GitHubSettingsDriftReason::UnexpectedSetting,
                Option::<&GitHubRuleset>::None,
                Some(*actual),
            )?);
        }
    }
    compare_surface(&desired.surface, &observed.surface, drift)?;
    compare_security(&desired.security, &observed.security, drift)?;
    Ok(())
}

fn compare_surface(
    expected: &GitHubRedactedSurface,
    actual: &GitHubRedactedSurface,
    drift: &mut Vec<GitHubSettingsDrift>,
) -> Result<()> {
    for (name, expected_value, actual_value) in [
        (
            "apps",
            canonical_public_readiness_digest(&expected.apps)?,
            canonical_public_readiness_digest(&actual.apps)?,
        ),
        (
            "webhooks",
            canonical_public_readiness_digest(&expected.webhook_digests)?,
            canonical_public_readiness_digest(&actual.webhook_digests)?,
        ),
        (
            "deploy_keys",
            canonical_public_readiness_digest(&expected.deploy_key_fingerprints)?,
            canonical_public_readiness_digest(&actual.deploy_key_fingerprints)?,
        ),
        (
            "tokens",
            canonical_public_readiness_digest(&expected.token_fingerprints)?,
            canonical_public_readiness_digest(&actual.token_fingerprints)?,
        ),
        (
            "teams",
            canonical_public_readiness_digest(&expected.teams)?,
            canonical_public_readiness_digest(&actual.teams)?,
        ),
        (
            "environments",
            canonical_public_readiness_digest(&expected.environments)?,
            canonical_public_readiness_digest(&actual.environments)?,
        ),
        (
            "runner_groups",
            canonical_public_readiness_digest(&expected.runner_groups)?,
            canonical_public_readiness_digest(&actual.runner_groups)?,
        ),
    ] {
        if expected_value != actual_value {
            drift.push(GitHubSettingsDrift {
                path: format!("surface/{name}"),
                reason: GitHubSettingsDriftReason::UnexpectedPublicSurface,
                expected_digest: Some(expected_value),
                actual_digest: Some(actual_value),
            });
        }
    }
    Ok(())
}

fn compare_security(
    expected: &GitHubSecuritySettings,
    actual: &GitHubSecuritySettings,
    drift: &mut Vec<GitHubSettingsDrift>,
) -> Result<()> {
    for (name, expected_value, actual_value) in [
        (
            "private_vulnerability_reporting",
            expected.private_vulnerability_reporting,
            actual.private_vulnerability_reporting,
        ),
        (
            "security_advisories",
            expected.security_advisories,
            actual.security_advisories,
        ),
        (
            "secret_scanning",
            expected.secret_scanning,
            actual.secret_scanning,
        ),
        (
            "push_protection",
            expected.push_protection,
            actual.push_protection,
        ),
        (
            "dependency_graph",
            expected.dependency_graph,
            actual.dependency_graph,
        ),
        (
            "dependabot_alerts",
            expected.dependabot_alerts,
            actual.dependabot_alerts,
        ),
        (
            "dependabot_security_updates",
            expected.dependabot_security_updates,
            actual.dependabot_security_updates,
        ),
        (
            "code_scanning",
            expected.code_scanning,
            actual.code_scanning,
        ),
    ] {
        if expected_value != actual_value {
            drift.push(drift_entry(
                &format!("security/{name}"),
                GitHubSettingsDriftReason::SecuritySettingDisabled,
                Some(&expected_value),
                Some(&actual_value),
            )?);
        }
    }
    Ok(())
}

fn canonical_github_settings_state(mut state: GitHubSettingsState) -> Result<GitHubSettingsState> {
    if state.schema_version != GITHUB_SETTINGS_DESIRED_SCHEMA_VERSION
        || !valid_repository_identifier(&state.repository)
        || !valid_branch_name(&state.default_branch)
        || state.rulesets.len() > 64
    {
        bail!("GitHub settings state identity or bounds are invalid");
    }
    for ruleset in &mut state.rulesets {
        if !valid_token(&ruleset.name)
            || ruleset.include.is_empty()
            || ruleset.include.len() > 64
            || ruleset.required_checks.len() > 64
            || ruleset.bypass_actors.len() > 64
            || ruleset.required_approvals > 6
        {
            bail!("GitHub ruleset is malformed or exceeds its bound");
        }
        ruleset.include.sort();
        if ruleset.include.windows(2).any(|pair| pair[0] == pair[1])
            || ruleset
                .include
                .iter()
                .any(|include| !valid_ref_pattern(include, ruleset.target))
        {
            bail!("GitHub ruleset refs are duplicate, unsafe, or target the wrong kind");
        }
        ruleset.required_checks.sort_by(|left, right| {
            left.context
                .cmp(&right.context)
                .then(left.source_app_id.cmp(&right.source_app_id))
                .then(left.source_app_slug.cmp(&right.source_app_slug))
        });
        if ruleset
            .required_checks
            .windows(2)
            .any(|pair| pair[0].context == pair[1].context)
            || ruleset.required_checks.iter().any(|check| {
                check.source_app_id == 0
                    || !valid_token(&check.context)
                    || !valid_token(&check.source_app_slug)
            })
        {
            bail!("GitHub required checks must be unique and source-bound");
        }
        sort_principals(&mut ruleset.bypass_actors)?;
    }
    state.rulesets.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.name.cmp(&right.name))
    });
    if state
        .rulesets
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target && pair[0].name == pair[1].name)
    {
        bail!("GitHub rulesets must have unique target/name identities");
    }
    canonicalize_surface(&mut state.surface)?;
    Ok(state)
}

fn validate_desired_identity(state: &GitHubSettingsState) -> Result<()> {
    if state.repository != GITHUB_SETTINGS_REPOSITORY
        || state.default_branch != "main"
        || state.rulesets.is_empty()
        || canonical_public_readiness_digest(state)? != GITHUB_SETTINGS_DESIRED_DIGEST
    {
        bail!("GitHub desired settings must match the build-pinned repository settings manifest");
    }
    Ok(())
}

fn canonicalize_surface(surface: &mut GitHubRedactedSurface) -> Result<()> {
    for count in [
        surface.apps.len(),
        surface.webhook_digests.len(),
        surface.deploy_key_fingerprints.len(),
        surface.token_fingerprints.len(),
        surface.teams.len(),
        surface.environments.len(),
        surface.runner_groups.len(),
    ] {
        if count > 256 {
            bail!("GitHub redacted surface inventory exceeds its bound");
        }
    }
    sort_principals(&mut surface.apps)?;
    sort_principals(&mut surface.teams)?;
    sort_unique_strings(&mut surface.webhook_digests, true)?;
    sort_unique_strings(&mut surface.deploy_key_fingerprints, true)?;
    sort_unique_strings(&mut surface.token_fingerprints, true)?;
    sort_unique_strings(&mut surface.environments, false)?;
    sort_unique_strings(&mut surface.runner_groups, false)?;
    Ok(())
}

fn sort_principals(principals: &mut [GitHubRedactedPrincipal]) -> Result<()> {
    principals.sort_by(|left, right| {
        left.identity
            .cmp(&right.identity)
            .then(left.permission.cmp(&right.permission))
    });
    if principals.windows(2).any(|pair| pair[0] == pair[1])
        || principals.iter().any(|principal| {
            !valid_token(&principal.identity) || !valid_token(&principal.permission)
        })
    {
        bail!("GitHub redacted principals are malformed or duplicate");
    }
    Ok(())
}

fn sort_unique_strings(values: &mut [String], digests: bool) -> Result<()> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1])
        || values.iter().any(|value| {
            if digests {
                !is_digest(value)
            } else {
                !valid_token(value)
            }
        })
    {
        bail!("GitHub settings string inventory is malformed or duplicate");
    }
    Ok(())
}

fn drift_entry<T: Serialize>(
    path: &str,
    reason: GitHubSettingsDriftReason,
    expected: Option<&T>,
    actual: Option<&T>,
) -> Result<GitHubSettingsDrift> {
    Ok(GitHubSettingsDrift {
        path: path.into(),
        reason,
        expected_digest: expected
            .map(canonical_public_readiness_digest)
            .transpose()?,
        actual_digest: actual.map(canonical_public_readiness_digest).transpose()?,
    })
}

fn target_name(target: GitHubRulesetTarget) -> &'static str {
    match target {
        GitHubRulesetTarget::Branch => "branch",
        GitHubRulesetTarget::Tag => "tag",
    }
}

fn valid_ref_pattern(value: &str, target: GitHubRulesetTarget) -> bool {
    let prefix = match target {
        GitHubRulesetTarget::Branch => "refs/heads/",
        GitHubRulesetTarget::Tag => "refs/tags/",
    };
    value.starts_with(prefix)
        && value.len() <= 256
        && !value.contains("..")
        && !value.contains('\\')
        && !value.contains('\0')
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'+' | b'*')
        })
}

fn valid_repository_identifier(value: &str) -> bool {
    let Some((owner, repository)) = value.split_once('/') else {
        return false;
    };
    !repository.contains('/') && valid_token(owner) && valid_token(repository)
}

fn valid_branch_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("..")
        && !value.contains('\\')
        && !value.contains('\0')
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_text(value: &str) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use serde_json::json;

    fn desired() -> GitHubSettingsState {
        parse_github_settings_desired(include_bytes!("../../../.github/settings-desired-v1.json"))
            .unwrap()
    }

    #[test]
    fn fixture_api_response_allows_and_canonical_digest_ignores_api_order() {
        let expected = desired();
        let mut reordered = expected.clone();
        reordered.rulesets.reverse();
        reordered.surface.teams.reverse();
        reordered.rulesets[0].include.reverse();
        let evaluation = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(reordered.clone()),
            },
        )
        .unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Allow);
        assert!(evaluation.drift.is_empty());
        assert_eq!(
            canonical_github_settings_digest(&expected).unwrap(),
            canonical_github_settings_digest(&reordered).unwrap()
        );
        assert_eq!(
            canonical_github_settings_digest(&expected).unwrap(),
            GITHUB_SETTINGS_DESIRED_DIGEST
        );
    }

    #[test]
    fn weakened_substitute_desired_state_is_rejected_even_when_observed_matches() {
        let mut weakened = desired();
        let main = weakened
            .rulesets
            .iter_mut()
            .find(|ruleset| ruleset.target == GitHubRulesetTarget::Branch)
            .unwrap();
        main.allow_force_pushes = true;
        main.bypass_actors.push(GitHubRedactedPrincipal {
            identity: "team:unexpected-admins".into(),
            permission: "bypass".into(),
        });
        weakened.security.secret_scanning = false;

        assert!(
            evaluate_github_settings(
                &weakened,
                &GitHubSettingsApiSnapshot {
                    collection_status: GitHubSettingsCollectionStatus::Complete,
                    settings: Some(weakened.clone()),
                },
            )
            .is_err()
        );
        assert!(canonical_github_settings_digest(&weakened).is_ok());
    }

    #[test]
    fn disabled_ruleset_force_delete_bypass_and_wrong_check_source_reject() {
        let expected = desired();
        let mut actual = expected.clone();
        let main = actual
            .rulesets
            .iter_mut()
            .find(|ruleset| ruleset.target == GitHubRulesetTarget::Branch)
            .unwrap();
        main.enforcement = GitHubRulesetEnforcement::Disabled;
        main.allow_force_pushes = true;
        main.allow_deletions = true;
        main.bypass_actors.push(GitHubRedactedPrincipal {
            identity: "team:unexpected-admins".into(),
            permission: "bypass".into(),
        });
        main.required_checks[0].source_app_id = 1;
        let evaluation = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(actual),
            },
        )
        .unwrap();
        let reasons = evaluation
            .drift
            .iter()
            .map(|drift| drift.reason)
            .collect::<BTreeSet<_>>();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(reasons.contains(&GitHubSettingsDriftReason::RulesetDisabled));
        assert!(reasons.contains(&GitHubSettingsDriftReason::ForceOrDeleteAllowed));
        assert!(reasons.contains(&GitHubSettingsDriftReason::BypassExpanded));
        assert!(reasons.contains(&GitHubSettingsDriftReason::RequiredCheckSourceMismatch));
    }

    #[test]
    fn observed_repository_and_default_branch_mismatches_are_reported_as_drift() {
        let expected = desired();
        let mut actual = expected.clone();
        actual.repository = "fork-owner/depgraph-cli".into();
        actual.default_branch = "trunk".into();
        let evaluation = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(actual),
            },
        )
        .unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert!(evaluation.drift.iter().any(|drift| {
            drift.path == "repository" && drift.reason == GitHubSettingsDriftReason::SettingMismatch
        }));
        assert!(evaluation.drift.iter().any(|drift| {
            drift.path == "default_branch"
                && drift.reason == GitHubSettingsDriftReason::DefaultBranchMismatch
        }));
    }

    #[test]
    fn missing_observed_rulesets_are_reported_as_drift() {
        let expected = desired();
        let mut actual = expected.clone();
        actual.rulesets.clear();
        let evaluation = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(actual),
            },
        )
        .unwrap();
        assert_eq!(evaluation.decision, PublicReadinessDecision::Reject);
        assert_eq!(
            evaluation
                .drift
                .iter()
                .filter(|drift| drift.reason == GitHubSettingsDriftReason::MissingSetting)
                .count(),
            expected.rulesets.len()
        );
    }

    #[test]
    fn permission_failure_and_unexpected_public_surface_are_redacted_rejections() {
        let expected = desired();
        let denied = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::PermissionDenied,
                settings: None,
            },
        )
        .unwrap();
        assert_eq!(denied.decision, PublicReadinessDecision::Reject);
        assert!(
            denied
                .drift
                .iter()
                .any(|drift| drift.reason == GitHubSettingsDriftReason::CollectionPermissionDenied)
        );

        let mut actual = expected.clone();
        actual.surface.webhook_digests.push("a".repeat(64));
        let drifted = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(actual),
            },
        )
        .unwrap();
        assert!(
            drifted
                .drift
                .iter()
                .any(|drift| drift.reason == GitHubSettingsDriftReason::UnexpectedPublicSurface)
        );
        assert!(
            !serde_json::to_string(&drifted)
                .unwrap()
                .contains("a".repeat(64).as_str())
        );

        let mut actual = expected.clone();
        let mut unexpected_ruleset = actual.rulesets[0].clone();
        unexpected_ruleset.name = "token-super-secret".into();
        actual.rulesets.push(unexpected_ruleset);
        let drifted = evaluate_github_settings(
            &expected,
            &GitHubSettingsApiSnapshot {
                collection_status: GitHubSettingsCollectionStatus::Complete,
                settings: Some(actual),
            },
        )
        .unwrap();
        assert_eq!(drifted.decision, PublicReadinessDecision::Reject);
        assert!(
            !serde_json::to_string(&drifted)
                .unwrap()
                .contains("token-super-secret")
        );
    }

    #[test]
    fn desired_schema_and_snapshot_types_reject_unknown_or_secret_fields() {
        let value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../.github/settings-desired-v1.json"))
                .unwrap();
        let schema: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../schemas/github-settings-desired-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&value));
        let mut unknown = value;
        unknown["secret_value"] = json!("must-never-exist");
        assert!(!validator.is_valid(&unknown));
        assert!(serde_json::from_value::<GitHubSettingsState>(unknown).is_err());
    }
}
