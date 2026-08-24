use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;

use super::{
    AGENT_DOGFOOD_REPORT_PATH, AGENT_DOGFOOD_REPORT_SHA256, MCP_OPERATION_CONTRACT_VERSION,
    MCP_TOOL_CONTRACT_VERSION, PROJECT_LICENSE_EXPRESSION, PROJECT_LICENSES, RELEASE_TARGETS,
    RUST_SOURCE_COPYRIGHT, RUST_SOURCE_COPYRIGHT_SHA256, RUST_SOURCE_LICENSE_MIT,
    RUST_SOURCE_LICENSE_MIT_SHA256, RUST_SYSROOT_TOOLCHAIN_VERSION, STABLE_RELEASE_BASELINE_STATUS,
    STABLE_RELEASE_GATE_SCHEMA_VERSION, STABLE_RELEASE_MAINTENANCE_BRANCH, STABLE_RELEASE_VERSION,
    STABLE_UPGRADE_SOURCE_FIXTURE_PATH, STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
    STABLE_UPGRADE_SOURCE_VERSION, V0_4_RC6_AARCH64_APPLE_ARCHIVE_SHA256,
    V0_4_RC6_AARCH64_APPLE_BINARY_SHA256, V0_4_RC6_TAG_COMMIT, V0_4_STABLE_RELEASE_BASELINE_COMMIT,
    V0_4_STABLE_RELEASE_BASELINE_DIGEST, V0_4_STABLE_RELEASE_BASELINE_TREE,
    V0_4_STABLE_RELEASE_MAINTENANCE_BRANCH, V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH,
    V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256, VERSION, mcp_package_smoke, read_lf_normalized_text,
    release_compatibility, sha256_file, v0_4_stable_release_baseline_digest,
    verify_stable_release_source_guard,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GithubActionsPolicy {
    schema_version: String,
    pub(crate) actions: Vec<GithubActionPin>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GithubActionPin {
    pub(crate) identity: String,
    pub(crate) sha: String,
    reviewed_upstream_ref: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDisclosureDryRun {
    schema_version: String,
    scenario_id: String,
    candidate_digest: String,
    private_route: String,
    raw_report_retained: bool,
    phases: Vec<SecurityDisclosurePhase>,
    fork_secret_access: bool,
    release_secret_access_before_verified_release: bool,
    completed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDisclosurePhase {
    id: String,
    owner_role: String,
    evidence_digest: String,
}

pub(crate) fn verify_github_actions_security(root: &Path) -> Result<()> {
    let policy_path = root.join(".github/actions-policy.json");
    let policy: GithubActionsPolicy = serde_json::from_slice(&fs::read(&policy_path)?)
        .context("GitHub Actions policy is not closed valid JSON")?;
    if policy.schema_version != "github-actions-policy-v1" || policy.actions.is_empty() {
        bail!("GitHub Actions policy version or action inventory is invalid");
    }
    let mut pins = BTreeMap::new();
    let mut prior_identity = None;
    for action in &policy.actions {
        if prior_identity.is_some_and(|prior| prior >= action.identity.as_str())
            || !valid_action_identity(&action.identity)
            || !is_lower_hex_len(&action.sha, 40)
            || !valid_reviewed_action_ref(&action.reviewed_upstream_ref)
            || pins
                .insert(action.identity.as_str(), action.sha.as_str())
                .is_some()
        {
            bail!("GitHub Actions policy pins must be canonical, unique, and immutable");
        }
        prior_identity = Some(action.identity.as_str());
    }

    let workflow_root = root.join(".github/workflows");
    let mut workflows = fs::read_dir(&workflow_root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    workflows.retain(|path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("yml" | "yaml")
        )
    });
    workflows.sort();
    if workflows.is_empty() {
        bail!("GitHub workflow inventory is empty");
    }
    let mut used_actions = BTreeSet::new();
    for path in workflows {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("GitHub workflow must be a regular non-symlink file");
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("GitHub workflow has a non-UTF-8 name")?;
        let workflow = fs::read_to_string(&path)?;
        verify_workflow_policy_text(name, &workflow, &pins, &mut used_actions)?;
    }
    if used_actions
        != pins
            .keys()
            .map(|identity| (*identity).to_owned())
            .collect::<BTreeSet<_>>()
    {
        bail!("GitHub Actions policy contains an unused or unlisted action identity");
    }

    let dry_run_bytes = fs::read(root.join("security/disclosure-dry-run-v1.json"))?;
    verify_security_disclosure_dry_run(&dry_run_bytes)?;
    let threat_model = fs::read_to_string(
        root.join("docs/40_arch_design/github-actions-security-threat-model.md"),
    )?
    .replace("\r\n", "\n")
    .replace('\r', "\n");
    for required in [
        "`github-actions-policy-v1`",
        "Pull requests, fork branches",
        "does not interpolate the `secrets` expression",
        "Only the final `publish` job receives job-scoped",
        "`release-post-publish-evidence-v1`",
        "Every one of the 51 pre-evidence public assets",
        "The stable source guard handles `workflow_run` metadata without checking out",
        "The v0.5.0 post-publish recovery workflow is an incident-specific read-only",
        "It cannot upload or replace an\nasset, move a tag, change a check conclusion, or delete a run.",
        "Only the npm publisher receives job-scoped `id-token: write`",
        "The OIDC-capable npm job performs no checkout\nand executes no repository script.",
        "Manual dispatches retain the same read-only and\nsecret-free boundary",
        "`.github/actions-policy.json` is the canonical allowlist",
        "A mutable tag or branch is never a temporary fallback.",
        "| Fork changes a workflow to print a secret |",
        "| `workflow_run` executes attacker code with write token |",
        "| Post-publish recovery rewrites release history |",
    ] {
        if !threat_model.contains(required) {
            bail!("GitHub Actions threat model is missing {required:?}");
        }
    }
    Ok(())
}

pub(crate) const RECOVERY_PINNED_NODE_SETUP_STEP: &str = concat!(
    "      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0\n",
    "        with:\n",
    "          node-version: 24.18.0\n",
);
const RECOVERY_PINNED_NODE_SETUP_HEADER: &str =
    "      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0";
const RECOVERY_VERIFIER_HEADER: &str =
    "      - name: Verify the immutable v0.5.0 public closure and recover its Agent host canary";
pub(crate) const RECOVERY_VERIFIER_RUN: &str =
    "        run: scripts/release-post-publish-recovery.sh";
pub(crate) const NPM_POST_PUBLISH_RETRY_BLOCK: &str = concat!(
    "            published=false\n",
    "            for attempt in {1..60}; do\n",
    "              if npm view \"${package}@${version}\" dist.integrity --json >\"$view_output\" 2>\"$view_error\"; then\n",
    "                actual_integrity=\"$(jq -er '.' \"$view_output\")\"\n",
    "                if test \"$actual_integrity\" != \"$expected_integrity\"; then\n",
    "                  echo \"published npm integrity differs for ${package}@${version}\" >&2\n",
    "                  exit 1\n",
    "                fi\n",
    "                published=true\n",
    "                break\n",
    "              fi\n",
    "              if ! grep -q 'E404' \"$view_error\"; then\n",
    "                cat \"$view_error\" >&2\n",
    "                exit 1\n",
    "              fi\n",
    "              if test \"$attempt\" -lt 60; then\n",
    "                echo \"waiting for npm registry visibility: ${package}@${version} (${attempt}/60)\" >&2\n",
    "                sleep 30\n",
    "              fi\n",
    "            done\n",
    "            if test \"$published\" != \"true\"; then\n",
    "              echo \"npm registry did not expose ${package}@${version} within 30 minutes\" >&2\n",
    "              exit 1\n",
    "            fi\n",
);

pub(crate) fn verify_workflow_policy_text(
    name: &str,
    workflow: &str,
    pins: &BTreeMap<&str, &str>,
    used_actions: &mut BTreeSet<String>,
) -> Result<()> {
    let normalized_workflow = workflow.replace("\r\n", "\n").replace('\r', "\n");
    let workflow = normalized_workflow.as_str();
    let write_permissions = write_permission_scopes(workflow);
    if workflow.contains("pull_request_target")
        || contains_yaml_hex_escape(workflow)
        || write_permissions.contains(&"write-all")
        || has_noncanonical_permissions_declaration(workflow)
    {
        bail!("{name} enables a forbidden trigger or broad credential");
    }
    let top_permissions = top_level_permissions(workflow)?;
    if !matches!(top_permissions.as_slice(), [] | ["contents: read"]) {
        bail!("{name} has broad workflow-level permissions");
    }
    if workflow.contains("\n  pull_request:") && contains_expression_context(workflow, "secrets") {
        bail!("{name} exposes repository secrets to pull request execution");
    }
    for line in workflow.lines() {
        let trimmed = line.trim_start();
        let specification = trimmed
            .strip_prefix("- uses:")
            .or_else(|| trimmed.strip_prefix("uses:"));
        if specification.is_none() && has_workflow_uses_key(trimmed) {
            bail!("{name} contains a noncanonical uses key");
        }
        let Some(specification) = specification else {
            continue;
        };
        let specification = specification
            .split_whitespace()
            .next()
            .context("workflow uses entry is empty")?;
        if specification.starts_with("./") {
            continue;
        }
        let (identity, sha) = specification
            .rsplit_once('@')
            .context("third-party Action is missing an immutable revision")?;
        if !is_lower_hex_len(sha, 40) || pins.get(identity) != Some(&sha) {
            bail!("{name} uses unreviewed or mutable Action {specification}");
        }
        used_actions.insert(identity.to_owned());
    }

    let setup_go_steps = workflow.matches("actions/setup-go@").count();
    let setup_go_cache_paths = workflow
        .matches("          cache-dependency-path: workers/go/go.sum\n")
        .count();
    if setup_go_steps != setup_go_cache_paths {
        bail!("{name} must bind every setup-go cache to the checked-in workers/go/go.sum");
    }

    match name {
        "ci.yml" => {
            if top_level_trigger_keys(workflow)? != ["pull_request", "push", "workflow_dispatch"]
                || !workflow.contains("\n  pull_request:")
                || !workflow.contains("\n  workflow_dispatch:")
                || ![
                    "\n  benchmark:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                    "\n  integration:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                    "\n  windows-smoke:\n    needs: [rust, go, web]\n    if: github.event_name == 'workflow_dispatch'\n",
                ]
                .iter()
                .all(|required| workflow.contains(required))
                || workflow.matches("\n      fail-fast: false\n").count() != 1
                || workflow
                    .matches("rustflags: -C linker-features=-lld")
                    .count()
                    != 1
                || workflow
                    .matches("RUSTFLAGS: ${{ matrix.rustflags }}")
                    .count()
                    != 1
                || workflow.matches("CARGO_INCREMENTAL: \"0\"").count() != 2
                || workflow.matches("CARGO_PROFILE_DEV_DEBUG: \"0\"").count() != 2
                || workflow.matches("CARGO_PROFILE_TEST_DEBUG: \"0\"").count() != 2
                || workflow
                    .matches(
                        "Reclaim integration build artifacts before the isolated Rust semantic gate",
                    )
                    .count()
                    != 1
                || top_permissions != ["contents: read"]
                || contains_expression_context(workflow, "secrets")
                || !write_permissions.is_empty()
            {
                bail!(
                    "CI pull requests must remain read-only, secret-free, and pinned to the full-CI linker/resource policy"
                );
            }
        }
        "release.yml" => {
            let stable_gate = workflow_job_block(workflow, "stable-gate")?;
            let stable_gate_permissions = job_permissions(stable_gate)?;
            let package = workflow_job_block(workflow, "package")?;
            let package_node_setup = package
                .find("actions/setup-node@")
                .context("release package job is missing setup-node")?;
            let package_pnpm_setup = package
                .find("pnpm/action-setup@")
                .context("release package job is missing pnpm/action-setup")?;
            let publish = workflow_job_block(workflow, "publish")?;
            let publish_permissions = job_permissions(publish)?;
            if top_level_trigger_keys(workflow)? != ["push"]
                || !workflow.contains("tags: [\"v*\"]")
                || workflow.contains("\n  pull_request:")
                || workflow.contains("\n  workflow_run:")
                || write_permissions != ["contents"]
                || stable_gate_permissions != ["actions: read", "contents: read"]
                || publish_permissions != ["actions: read", "contents: write"]
                || package_node_setup >= package_pnpm_setup
                || package.matches("standalone: false").count() != 1
                || package.contains("standalone: true")
                || workflow
                    .matches("rustflags: -C linker-features=-lld")
                    .count()
                    != 2
                || workflow
                    .matches("RUSTFLAGS: ${{ matrix.rustflags }}")
                    .count()
                    != 2
            {
                bail!(
                    "release gate permissions must remain read-only, publish permissions must remain actions-read/contents-write, the workflow must remain tag-only, native packages must use pinned Node-backed pnpm, and native x86_64 Linux builds must retain the pinned linker policy"
                );
            }
        }
        "release-post-publish-recovery.yml" => {
            let verification = workflow_job_block(workflow, "verify-v0-5-0")?;
            let verification_permissions = job_permissions(verification)?;
            let (node_setup_offset, node_setup) =
                workflow_step_block(verification, RECOVERY_PINNED_NODE_SETUP_HEADER)?;
            let (verifier_offset, verifier) =
                workflow_step_block(verification, RECOVERY_VERIFIER_HEADER)?;
            if top_level_trigger_keys(workflow)? != ["workflow_dispatch"]
                || !workflow.contains("\n  workflow_dispatch:\n\npermissions: {}\n")
                || !top_permissions.is_empty()
                || verification_permissions != ["actions: read", "contents: read"]
                || !write_permissions.is_empty()
                || contains_expression_context(workflow, "secrets")
                || workflow.matches("actions/checkout@").count() != 1
                || workflow.matches("actions/setup-node@").count() != 1
                || node_setup != RECOVERY_PINNED_NODE_SETUP_STEP
                || verifier.matches(RECOVERY_VERIFIER_RUN).count() != 1
                || node_setup_offset >= verifier_offset
                || workflow.contains("gh release upload")
                || workflow.contains("gh release create")
                || workflow.contains("gh release delete")
                || workflow.contains("gh api --method")
            {
                bail!(
                    "release post-publish recovery must remain input-free, main-checked, read-only, pinned to Node.js 24.18.0, and pinned to its reviewed verifier"
                );
            }
        }
        "npm-release.yml" => {
            let prepare = workflow_job_block(workflow, "prepare")?;
            let prepare_permissions = job_permissions(prepare)?;
            let publish = workflow_job_block(workflow, "publish")?;
            let publish_permissions = job_permissions(publish)?;
            let retry_order_is_closed = match (
                publish.find("npm publish \"./${file}\" --access public --tag latest --provenance"),
                publish.find(NPM_POST_PUBLISH_RETRY_BLOCK),
                publish.find("          done < <(jq -r '.packages[]"),
            ) {
                (Some(publish_offset), Some(retry_offset), Some(loop_end_offset)) => {
                    publish_offset < retry_offset && retry_offset < loop_end_offset
                }
                _ => false,
            };
            if top_level_trigger_keys(workflow)? != ["workflow_dispatch"]
                || !workflow.contains("\n  workflow_dispatch:\n")
                || !top_permissions.is_empty()
                || write_permissions != ["id-token"]
                || prepare_permissions != ["actions: read", "contents: read"]
                || publish_permissions != ["id-token: write"]
                || contains_expression_context(workflow, "secrets")
                || workflow.contains("NODE_AUTH_TOKEN")
                || workflow.contains("NPM_TOKEN")
                || workflow.matches("actions/checkout@").count() != 1
                || !prepare.contains("ref: ${{ github.sha }}")
                || !prepare.contains("test \"$RELEASE_REF\" = \"refs/tags/${RELEASE_TAG}\"")
                || !prepare.contains(".schema_version == \"release-post-publish-evidence-v1\"")
                || !prepare.contains(".conclusion == \"success\"")
                || !prepare.contains("cargo xtask verify-release-assets release-assets")
                || !prepare.contains("node npm/scripts/build-packages.mjs")
                || !prepare.contains("--ignore-scripts")
                || !publish.contains("if: startsWith(github.ref, 'refs/tags/v')")
                || !publish.contains("    environment: npm\n")
                || publish.matches("    timeout-minutes: 210\n").count() != 1
                || publish.contains("actions/checkout@")
                || publish.contains("run: cargo")
                || publish.contains("npm/scripts/")
                || publish.matches("npm publish").count() != 1
                || !publish.contains("--provenance")
                || publish.matches(NPM_POST_PUBLISH_RETRY_BLOCK).count() != 1
                || !retry_order_is_closed
                || publish.matches("grep -q 'E404'").count() != 2
                || !publish.contains("sleep 30")
                || !publish.contains("npm registry did not expose")
                || publish.contains("actual_integrity=\"$(npm view")
                || !publish.contains("needs: prepare")
            {
                bail!(
                    "npm release must dispatch against an evidence-bound stable tag, prepare without OIDC, publish provenance from a tag-guarded environment-protected no-checkout OIDC job, and tolerate bounded post-publish registry propagation"
                );
            }
        }
        "stable-release-source-guard.yml" => {
            if top_level_trigger_keys(workflow)? != ["workflow_run"]
                || !workflow.contains("\n  workflow_run:")
                || !top_permissions.is_empty()
                || workflow.contains("actions/checkout@")
                || contains_expression_context(workflow, "secrets")
                || workflow.contains("run: cargo")
                || workflow.contains("run: ./")
                || write_permissions != ["actions", "contents"]
                || !workflow.contains("permissions:\n      actions: write\n      contents: write")
            {
                bail!("stable release source guard must be metadata-only and job-scoped");
            }
        }
        _ => {
            if workflow.lines().any(has_write_permission) {
                bail!("{name} grants an unreviewed write permission");
            }
        }
    }
    Ok(())
}

fn workflow_job_block<'a>(workflow: &'a str, job_name: &str) -> Result<&'a str> {
    let header = format!("  {job_name}:");
    if workflow.lines().filter(|line| *line == header).count() != 1 {
        bail!("workflow must contain exactly one {job_name} job");
    }

    let mut offset = 0;
    let mut start = None;
    let mut end = workflow.len();
    for line in workflow.split_inclusive('\n') {
        let code = line.strip_suffix('\n').unwrap_or(line);
        if start.is_some()
            && code.starts_with("  ")
            && !code.starts_with("    ")
            && code.ends_with(':')
        {
            end = offset;
            break;
        }
        if code == header {
            start = Some(offset);
        }
        offset += line.len();
    }
    let start = start.context("workflow job disappeared while extracting its block")?;
    Ok(&workflow[start..end])
}

fn workflow_step_block<'a>(job: &'a str, step_header: &str) -> Result<(usize, &'a str)> {
    if !step_header.starts_with("      - ") || step_header.contains('\n') {
        bail!("workflow step header is not canonical");
    }
    if job.lines().filter(|line| *line == "    steps:").count() != 1 {
        bail!("workflow job must contain exactly one canonical steps sequence");
    }

    let mut offset = 0;
    let mut steps_start = None;
    let mut steps_end = job.len();
    for line in job.split_inclusive('\n') {
        let code = line.strip_suffix('\n').unwrap_or(line);
        if steps_start.is_some() && !code.is_empty() && !code.starts_with("      ") {
            steps_end = offset;
            break;
        }
        if code == "    steps:" {
            steps_start = Some(offset + line.len());
        }
        offset += line.len();
    }
    let steps_start = steps_start.context("workflow steps disappeared while extracting them")?;
    let steps = &job[steps_start..steps_end];

    let mut relative_offset = 0;
    let mut candidates = Vec::new();
    for line in steps.split_inclusive('\n') {
        let code = line.strip_suffix('\n').unwrap_or(line);
        if code == step_header {
            candidates.push(relative_offset);
        }
        relative_offset += line.len();
    }
    if candidates.len() != 1 {
        bail!("workflow steps must contain exactly one {step_header:?}");
    }

    let step_start = candidates[0];
    let first_line_len = steps[step_start..]
        .split_inclusive('\n')
        .next()
        .context("workflow step header disappeared")?
        .len();
    let mut step_end = steps.len();
    relative_offset = step_start + first_line_len;
    for line in steps[relative_offset..].split_inclusive('\n') {
        let code = line.strip_suffix('\n').unwrap_or(line);
        if code.starts_with("      - ") {
            step_end = relative_offset;
            break;
        }
        relative_offset += line.len();
    }

    let absolute_start = steps_start + step_start;
    let absolute_end = steps_start + step_end;
    Ok((absolute_start, &job[absolute_start..absolute_end]))
}

fn job_permissions(job: &str) -> Result<Vec<&str>> {
    let lines = job.lines().collect::<Vec<_>>();
    let declarations = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == "    permissions:")
        .collect::<Vec<_>>();
    if declarations.len() != 1 {
        bail!("workflow job must contain exactly one canonical permissions block");
    }

    let mut permissions = Vec::new();
    for line in &lines[declarations[0].0 + 1..] {
        let code = line.split('#').next().unwrap_or_default();
        if code.trim().is_empty() {
            continue;
        }
        let indentation = code.len() - code.trim_start_matches(' ').len();
        if indentation <= 4 {
            break;
        }
        if indentation != 6 {
            bail!("workflow job permissions nesting is malformed");
        }
        permissions.push(code.trim());
    }
    permissions.sort_unstable();
    if permissions.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("workflow job permissions contain a duplicate scope");
    }
    Ok(permissions)
}

fn contains_yaml_hex_escape(workflow: &str) -> bool {
    let bytes = workflow.as_bytes();
    (0..bytes.len()).any(|index| {
        if bytes[index] != b'\\' {
            return false;
        }
        let Some(kind) = bytes.get(index + 1).copied() else {
            return false;
        };
        let digits = match kind {
            b'x' => 2,
            b'u' => 4,
            b'U' => 8,
            _ => return false,
        };
        bytes
            .get(index + 2..index + 2 + digits)
            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    })
}

fn top_level_trigger_keys(workflow: &str) -> Result<Vec<&str>> {
    let lines = workflow.lines().collect::<Vec<_>>();
    let Some((index, declaration)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.starts_with("on:"))
    else {
        bail!("workflow is missing an explicit trigger policy");
    };
    if declaration.trim() != "on:" {
        bail!("workflow trigger declaration is malformed");
    }
    let mut triggers = Vec::new();
    for line in &lines[index + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        if line.starts_with("    ") {
            continue;
        }
        let (trigger, _) = line
            .trim()
            .split_once(':')
            .context("workflow trigger entry is malformed")?;
        if !trigger
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            bail!("workflow trigger key is noncanonical");
        }
        triggers.push(trigger);
    }
    triggers.sort_unstable();
    if triggers.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("workflow trigger policy contains a duplicate event");
    }
    Ok(triggers)
}

fn write_permission_scopes(workflow: &str) -> Vec<&str> {
    let mut scopes = workflow
        .lines()
        .filter_map(|line| {
            let code = line.split('#').next().unwrap_or_default().trim();
            let (scope, value) = code.split_once(':')?;
            let scope = scope.trim();
            let value = yaml_scalar(value);
            if scope == "permissions" && value == "write-all" {
                Some("write-all")
            } else if value == "write" {
                Some(scope)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes
}

fn yaml_scalar(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2
        && matches!(
            (value.as_bytes().first(), value.as_bytes().last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        )
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn has_noncanonical_permissions_declaration(workflow: &str) -> bool {
    let mut permissions_indent = None;
    for line in workflow.lines() {
        let code = line.split('#').next().unwrap_or_default().trim();
        if code.is_empty() {
            continue;
        }
        let indentation = line.len() - line.trim_start_matches(' ').len();
        if let Some(block_indent) = permissions_indent {
            if indentation > block_indent {
                let Some((scope, value)) = code.split_once(':') else {
                    return true;
                };
                if indentation != block_indent + 2
                    || scope.trim() != scope
                    || !scope
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                    || !matches!(value.trim(), "read" | "write" | "none")
                {
                    return true;
                }
                continue;
            }
            permissions_indent = None;
        }
        let Some((key, value)) = code.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if key.contains('\\') && (key.starts_with('"') || key.starts_with('\'')) {
            return true;
        }
        let normalized_key = key.trim_matches(|character| matches!(character, '"' | '\''));
        if normalized_key == "permissions" {
            if key != "permissions" || !matches!(value.trim(), "" | "{}") {
                return true;
            }
            if value.trim().is_empty() {
                permissions_indent = Some(indentation);
            }
        }
    }
    false
}

fn contains_expression_context(workflow: &str, context: &str) -> bool {
    workflow.split("${{").skip(1).any(|suffix| {
        suffix
            .split_once("}}")
            .is_some_and(|(expression, _)| contains_identifier(expression, context))
    })
}

fn contains_identifier(expression: &str, identifier: &str) -> bool {
    let expression = expression.as_bytes();
    let identifier = identifier.as_bytes();
    if identifier.is_empty() || identifier.len() > expression.len() {
        return false;
    }
    (0..=expression.len() - identifier.len()).any(|index| {
        let end = index + identifier.len();
        if !expression[index..end].eq_ignore_ascii_case(identifier) {
            return false;
        }
        let before = index
            .checked_sub(1)
            .and_then(|prior| expression.get(prior))
            .copied();
        let after = expression.get(end).copied();
        before.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
            && after.is_none_or(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    })
}

fn has_workflow_uses_key(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default();
    ["uses", "\"uses\"", "'uses'"].iter().any(|marker| {
        code.match_indices(marker).any(|(index, matched)| {
            let boundary = index == 0
                || !code.as_bytes()[index - 1].is_ascii_alphanumeric()
                    && code.as_bytes()[index - 1] != b'_';
            boundary && code[index + matched.len()..].trim_start().starts_with(':')
        })
    })
}

fn has_write_permission(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or_default().trim();
    code.contains("permissions:") && code.contains("write")
        || code
            .split_once(':')
            .is_some_and(|(_, value)| yaml_scalar(value) == "write")
}

fn top_level_permissions(workflow: &str) -> Result<Vec<&str>> {
    let lines = workflow.lines().collect::<Vec<_>>();
    let Some((index, declaration)) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.starts_with("permissions:"))
    else {
        bail!("workflow is missing an explicit top-level permissions policy");
    };
    if declaration.trim() == "permissions: {}" {
        return Ok(Vec::new());
    }
    if declaration.trim() != "permissions:" {
        bail!("workflow top-level permissions declaration is malformed");
    }
    let mut permissions = Vec::new();
    for line in &lines[index + 1..] {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        if line.starts_with("    ") {
            bail!("workflow top-level permissions nesting is malformed");
        }
        permissions.push(line.trim());
    }
    permissions.sort_unstable();
    Ok(permissions)
}

pub(crate) fn verify_security_disclosure_dry_run(bytes: &[u8]) -> Result<()> {
    let dry_run: SecurityDisclosureDryRun =
        serde_json::from_slice(bytes).context("security disclosure dry run is malformed")?;
    let expected_phases = [
        ("private-report", "security-maintainer"),
        ("triage", "security-maintainer"),
        ("private-advisory", "security-maintainer"),
        ("private-fix", "release-maintainer"),
        ("verified-release", "release-maintainer"),
        ("coordinated-disclosure", "security-maintainer"),
    ];
    if dry_run.schema_version != "security-disclosure-dry-run-v1"
        || !valid_policy_token(&dry_run.scenario_id)
        || !is_lower_hex_len(&dry_run.candidate_digest, 64)
        || dry_run.private_route != "github-security-advisory"
        || dry_run.raw_report_retained
        || dry_run.fork_secret_access
        || dry_run.release_secret_access_before_verified_release
        || !dry_run.completed
        || dry_run.phases.len() != expected_phases.len()
        || dry_run
            .phases
            .iter()
            .zip(expected_phases)
            .any(|(phase, expected)| {
                phase.id != expected.0
                    || phase.owner_role != expected.1
                    || !is_lower_hex_len(&phase.evidence_digest, 64)
            })
    {
        bail!("security disclosure dry run is incomplete, unsafe, or noncanonical");
    }
    Ok(())
}

fn valid_action_identity(value: &str) -> bool {
    let mut components = value.split('/');
    components.next().is_some_and(valid_policy_token)
        && components.next().is_some_and(valid_policy_token)
        && components.next().is_none()
}

fn valid_reviewed_action_ref(value: &str) -> bool {
    value
        .strip_prefix('v')
        .is_some_and(|major| !major.is_empty() && major.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_policy_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_lower_hex_len(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn readme_cli_examples(readme: &str) -> BTreeSet<&str> {
    readme
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("depgraph "))
        .collect()
}

pub(crate) fn verify_japanese_readme_contract(readme: &str, english_readme: &str) -> Result<()> {
    let release_note = format!("[`v{VERSION}`リリースノート](docs/releases/v{VERSION}.md)");
    let release_package = format!(
        "`v{VERSION}`は、Linux x86-64、Linux ARM64、macOS Intel、macOS Apple Silicon、Windows x86-64向けのネイティブパッケージを提供する。"
    );
    let release_version_assignment = format!("VERSION={VERSION}");
    let compatibility = format!(
        "v0.5のワーカープロトコルは`{}`、ストアスキーマは`{}`、操作ジャーナルスキーマは`{}`であり、`{}`と`{}`を使用する。",
        depgraph_protocol::PROTOCOL_VERSION,
        depgraph_store::STORE_SCHEMA_VERSION,
        depgraph_operation::JOURNAL_SCHEMA_VERSION,
        MCP_TOOL_CONTRACT_VERSION,
        MCP_OPERATION_CONTRACT_VERSION,
    );
    for required in [
        "日本語 | [English](README.en.md)",
        "Rust 1.93.1、Go 1.26.1、Node.js 24.18.0、pnpm 10.33.0",
        release_note.as_str(),
        release_package.as_str(),
        release_version_assignment.as_str(),
        "`npm i -g @tamat-llc/depgraph`",
        "すべてのv0.5アーカイブには、ネイティブMCPサーバー、永続的な操作ランナー、バージョン管理されたエージェント用ツール／操作スキーマが含まれる。",
        compatibility.as_str(),
        "`v0.4.0`は予約済みベースラインの履歴記録であり、正式版は公開されなかった。",
        "[`v0.4.0`の契約](docs/releases/v0.4.0.md)",
        "[`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md)",
        "[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md)",
        "[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)",
        "[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md)",
        "depgraph scan /path/to/repository --strict",
        "depgraph profiles plan /path/to/repository --profiles-file profiles.json --json",
        "depgraph resolve --build /path/to/repository --allow-project-code",
        "depgraph runtime validate --file runtime-trace.json --json",
        "depgraph export --format graphml --output graph.graphml",
        "`project_code_executed`は`false`",
        "[コンパイラーパックとリリース検証](README.en.md#compiler-pack-and-release-verification)",
        "[MIT](LICENSE-MIT)または[Apache-2.0](LICENSE-APACHE)",
    ] {
        if !readme.contains(required) {
            bail!("Japanese README shared contract metadata is missing {required:?}");
        }
    }
    for (target, _) in RELEASE_TARGETS {
        if !readme.contains(target) {
            bail!("Japanese README release target matrix is missing {target:?}");
        }
    }

    let japanese_examples = readme_cli_examples(readme);
    let english_examples = readme_cli_examples(english_readme);
    if japanese_examples.is_empty() {
        bail!("Japanese README must contain CLI examples");
    }
    if let Some(example) = japanese_examples.difference(&english_examples).next() {
        bail!("Japanese README CLI example is not synchronized with English README: {example:?}");
    }

    let exit_code_section = readme
        .split_once("## 厳格ポリシーと終了コード\n")
        .map(|(_, section)| section)
        .context("Japanese README is missing the strict policy and exit codes section")?;
    let exit_code_section = exit_code_section
        .split_once("\n## ")
        .map_or(exit_code_section, |(section, _)| section);
    let actual_exit_code_table = exit_code_section
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .collect::<Vec<_>>();
    let expected_exit_code_table = [
        "| コード | 意味 |",
        "| ---: | --- |",
        "| 0 | ポリシー違反なしで処理が完了した |",
        "| 1 | グラフまたはカバレッジのポリシー違反 |",
        "| 2 | CLIの使用方法、セレクター、設定のエラー |",
        "| 3 | ワーカー、ツールチェーン、グラフ検証、プロトコルの失敗 |",
        "| 4 | プロジェクトコード実行権限またはセキュリティポリシーの失敗 |",
    ];
    if actual_exit_code_table != expected_exit_code_table {
        bail!("Japanese README exit code table is not synchronized with the CLI contract");
    }
    Ok(())
}

pub(crate) fn verify_project_metadata(root: &Path) -> Result<()> {
    verify_github_actions_security(root)?;
    verify_mcp_tasks_architecture_decision(root)?;
    mcp_package_smoke::verify_documentation(root, VERSION)?;
    let mcp_operations_path = "docs/50_test/mcp-agent-host-operations.md";
    let mcp_operations = read_lf_normalized_text(&root.join(mcp_operations_path))?;
    verify_local_markdown_links(root, mcp_operations_path, &mcp_operations)?;
    let agent_dogfood_path = "docs/50_test/agent-dogfood-benchmark.md";
    let agent_dogfood = read_lf_normalized_text(&root.join(agent_dogfood_path))?;
    verify_local_markdown_links(root, agent_dogfood_path, &agent_dogfood)?;
    let npm_release_path = "docs/50_test/npm-release-procedure.md";
    let npm_release = read_lf_normalized_text(&root.join(npm_release_path))?;
    verify_local_markdown_links(root, npm_release_path, &npm_release)?;
    let cargo_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    if !cargo_manifest
        .lines()
        .any(|line| line.trim() == format!("version = \"{VERSION}\""))
    {
        bail!("Cargo workspace version does not match release version {VERSION}");
    }
    let web_package: Value =
        serde_json::from_slice(&fs::read(root.join("workers/web/package.json"))?)?;
    if web_package["name"] != "@depgraph/web-worker"
        || web_package["version"] != VERSION
        || web_package["packageManager"] != "pnpm@10.33.0"
        || web_package["engines"]["node"] != ">=24.0.0"
    {
        bail!("Web package version/runtime metadata is not synchronized with release {VERSION}");
    }
    let npm_package: Value =
        serde_json::from_slice(&fs::read(root.join("npm/depgraph/package.json"))?)?;
    if npm_package["name"] != "@tamat-llc/depgraph"
        || npm_package["version"] != VERSION
        || npm_package["private"] != true
        || npm_package["engines"]["node"] != ">=24.0.0"
        || npm_package["license"] != PROJECT_LICENSE_EXPRESSION
        || npm_package["repository"]["url"] != "git+https://github.com/TamaT-LLC/depgraph-cli.git"
        || npm_package["publishConfig"]["access"] != "public"
        || npm_package["publishConfig"]["provenance"] != true
        || npm_package["bin"]["depgraph"] != "bin/depgraph.js"
        || npm_package["bin"]["depgraph-cli"] != "bin/depgraph.js"
        || npm_package["bin"]["depgraph-mcp"] != "bin/depgraph-mcp.js"
        || !npm_package["scripts"].is_null()
    {
        bail!("npm CLI template metadata is not synchronized with release {VERSION}");
    }

    let go_model = fs::read_to_string(root.join("workers/go/internal/worker/model.go"))?;
    let web_types = fs::read_to_string(root.join("workers/web/src/types.ts"))?;
    if quoted_assignment(&go_model, "AdapterVersion").as_deref() != Some(VERSION)
        || quoted_assignment(&web_types, "ADAPTER_VERSION").as_deref() != Some(VERSION)
    {
        bail!("Go/Web adapter versions must match Cargo release version {VERSION}");
    }
    let framework_build_sources = [
        (
            "astro",
            "workers/web/src/astro-build-observer.ts",
            "ASTRO_BUILD_OBSERVER",
            "ASTRO_BUILD_OBSERVER_VERSION",
            "ASTRO_BUILD_OBSERVER_CAPABILITY",
            "ASTRO_BUILD_OBSERVATION_SCHEMA",
        ),
        (
            "next",
            "workers/web/src/next-build-observer.ts",
            "NEXT_BUILD_OBSERVER",
            "NEXT_BUILD_OBSERVER_VERSION",
            "NEXT_BUILD_OBSERVER_CAPABILITY",
            "NEXT_BUILD_OBSERVATION_SCHEMA",
        ),
        (
            "tanstack-router",
            "workers/web/src/tanstack-router-build-observer.ts",
            "TANSTACK_ROUTER_BUILD_OBSERVER",
            "TANSTACK_ROUTER_BUILD_OBSERVER_VERSION",
            "TANSTACK_ROUTER_BUILD_CAPABILITY",
            "TANSTACK_ROUTER_BUILD_SCHEMA",
        ),
        (
            "tanstack-start",
            "workers/web/src/tanstack-start-build-observer.ts",
            "TANSTACK_START_BUILD_OBSERVER",
            "TANSTACK_START_BUILD_OBSERVER_VERSION",
            "TANSTACK_START_BUILD_CAPABILITY",
            "TANSTACK_START_BUILD_SCHEMA",
        ),
    ];
    let web_build_script = fs::read_to_string(root.join("workers/web/scripts/build.mjs"))?;
    for (framework, source_path, observer, version, capability, schema) in framework_build_sources {
        let expected = depgraph_core::framework_build_capability_contract()
            .into_iter()
            .find(|entry| entry.framework == framework)
            .with_context(|| format!("core has no {framework} framework build capability"))?;
        let source = fs::read_to_string(root.join(source_path))?;
        if quoted_assignment(&source, observer).as_deref() != Some(expected.observer.as_str())
            || quoted_assignment(&source, version).as_deref()
                != Some(expected.observer_version.as_str())
            || quoted_assignment(&source, capability).as_deref()
                != Some(expected.capability.as_str())
            || quoted_assignment(&source, schema).as_deref()
                != Some(expected.observation_schema.as_str())
            || !web_build_script.contains(&format!("framework: \"{framework}\""))
            || !web_build_script.contains(&format!("version: \"{}\"", expected.observer_version))
            || !web_build_script.contains(&format!("capability: \"{}\"", expected.capability))
            || !web_build_script.contains(&format!(
                "observation_schema: \"{}\"",
                expected.observation_schema
            ))
        {
            bail!(
                "{framework} framework build capability is not synchronized across core, observer, and package inventory"
            );
        }
    }

    let go_mod = fs::read_to_string(root.join("workers/go/go.mod"))?;
    let rust_toolchain = fs::read_to_string(root.join("rust-toolchain.toml"))?;
    let rust_worker = fs::read_to_string(root.join("workers/rust/Cargo.toml"))?;
    let protocol_crate = fs::read_to_string(root.join("crates/depgraph-protocol/Cargo.toml"))?;
    if !go_mod.lines().any(|line| line.trim() == "go 1.26.1")
        || !rust_toolchain
            .lines()
            .any(|line| line.trim() == format!("channel = \"{RUST_SYSROOT_TOOLCHAIN_VERSION}\""))
        || !rust_worker
            .lines()
            .any(|line| line.trim() == "version.workspace = true")
        || !protocol_crate
            .lines()
            .any(|line| line.trim() == "version.workspace = true")
    {
        bail!("Rust/Go worker baseline or workspace version metadata is not synchronized");
    }
    if sha256_file(&root.join("third_party/rust-src/COPYRIGHT"))? != RUST_SOURCE_COPYRIGHT_SHA256
        || sha256_file(&root.join("third_party/rust-src/LICENSE-MIT"))?
            != RUST_SOURCE_LICENSE_MIT_SHA256
        || fs::read(root.join("third_party/rust-src/COPYRIGHT"))? != RUST_SOURCE_COPYRIGHT
        || fs::read(root.join("third_party/rust-src/LICENSE-MIT"))? != RUST_SOURCE_LICENSE_MIT
    {
        bail!(
            "pinned Rust {RUST_SYSROOT_TOOLCHAIN_VERSION} source license inputs are missing or modified"
        );
    }

    let english_readme = read_lf_normalized_text(&root.join("README.en.md"))?;
    let japanese_readme = read_lf_normalized_text(&root.join("README.md"))?;
    verify_japanese_readme_contract(&japanese_readme, &english_readme)?;
    let rc1_release = read_lf_normalized_text(&root.join("docs/releases/v0.4.0-rc.1.md"))?;
    let design = read_lf_normalized_text(
        &root.join("docs/40_arch_design/arch-dependency-graph-cli-system-design.md"),
    )?;
    let docs_index = read_lf_normalized_text(&root.join("docs/00_index/index.md"))?;
    let rust_compiler_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-rust-compiler-precise-backend.md"),
    )?;
    let rust_compiler_hostile =
        read_lf_normalized_text(&root.join("docs/50_test/compiler-precise-hostile-e2e.md"))?;
    let rust_compiler_release = read_lf_normalized_text(
        &root.join("docs/50_test/compiler-precise-five-target-release.md"),
    )?;
    let rust_compiler_hostile_gate =
        fs::read_to_string(root.join("scripts/compiler-precise-hostile-e2e.sh"))?;
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    let cross_language_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-cross-language-adapter-contract.md"),
    )?;
    let default_profile_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-default-profile-selection-budget.md"),
    )?;
    let graph_query_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-bounded-graph-query-language.md"),
    )?;
    let public_oss_adr = read_lf_normalized_text(
        &root.join("docs/40_arch_design/adr-public-oss-release-governance.md"),
    )?;
    let v0_5_release_adr =
        read_lf_normalized_text(&root.join("docs/40_arch_design/adr-v0.5-release-contract.md"))?;
    verify_public_community_surface(root)?;
    for required in [
        "Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0",
        "TypeScript/JavaScript symbol/type/import/re-export/type-use",
        "[the system design](docs/40_arch_design/arch-dependency-graph-cli-system-design.md)",
        "[`v0.4.0` contract](docs/releases/v0.4.0.md)",
        "[`v0.4.0-rc.6`](docs/releases/v0.4.0-rc.6.md)",
        "[`v0.4.0-rc.2`](docs/releases/v0.4.0-rc.2.md)",
        "[`v0.4.0-rc.1`](docs/releases/v0.4.0-rc.1.md)",
        "[`v0.2.0-rc.1`](docs/releases/v0.2.0-rc.1.md)",
        "dynamic-framework-evidence-release-gate-v1",
        "rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf",
        "[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)",
        "depgraph runtime validate --file runtime-trace.json --json",
        "## Compiler pack and release verification",
        "gh release download \"$release_tag\" \\\n  --repo TamaT-LLC/depgraph-cli",
        "Every v0.5 archive includes the native MCP server, durable\noperation runner, and versioned Agent tool/operation schema.",
        "binds the MCP server and runner digests to `rmcp 3.1.0`, MCP revision `2026-07-28`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v1`",
        "no `v0.4.0` stable GitHub",
        "Store\nschema `17`, operation journal schema `5`, `depgraph-mcp-tools-v1`, and\n`depgraph-operation-v1`",
    ] {
        if !english_readme.contains(required) {
            bail!("English README release metadata is missing {required:?}");
        }
    }
    if !rc1_release.contains("depgraph runtime validate --file runtime-trace.json --json") {
        bail!("v0.4.0-rc.1 runtime validate example is not synchronized with the CLI");
    }
    let release_note = format!("docs/releases/v{VERSION}.md");
    let release_link = format!("[`v{VERSION}` release notes]({release_note})");
    if !english_readme.contains(&release_link) || !root.join(&release_note).is_file() {
        bail!("English README release note link is not synchronized with {VERSION}");
    }
    for required in [
        "updated: 2026-08-25",
        "| Product / Rust / Go / Web adapter | `0.5.3` |",
        "| SQLite store / scan cache / impact query cache | `17` / `2` / `1` |",
        "| Operation journal / MCP tool / operation DTO | `5` / `depgraph-mcp-tools-v1` / `depgraph-operation-v1` |",
        "Milestone 4のrelease candidateは`v0.4.0-rc.1`",
        "stable GitHub Releaseは公開されなかった",
        "`stable-release-gate-v2`",
        "Issue #355として",
        "Issue #359のGA gate",
        "`maintenance-ref-pinned`",
        "Issue #55ではこのWeb semantic compatibility unitをrelease manifest",
        "Issue #145のrelease gate contractは`dynamic-framework-evidence-release-gate-v1`",
        "Issue #146でRust `1.93.1`",
        "`PROJ-ARC-001-ADR-002`",
        "`compiler-precise-rust-v1`",
        "Issue #149として`compiler-precise-rust-v1`",
        "`PROJ-ARC-001-ADR-003`",
        "`cross-language-contract-v1`",
        "Issue #150として`cross-language-contract-v1`",
        "`PROJ-ARC-001-ADR-004`",
        "`default-profile-selection-v1`",
        "Issue #151として`default-profile-selection-v1`",
        "`PROJ-ARC-001-ADR-005`",
        "`bounded-graph-query-v1`",
        "Issue #152として`bounded-graph-query-v1`",
        "Issue #178で`bounded-query-types-v1`のclosed type checker",
        "Issue #179で`bounded-query-statistics-v1`、`bounded-query-plan-v1`、`bounded-query-limits-v1`",
        "Issue #180で`bounded-query-result-v1`のstaged executor",
        "Issue #181でpublic `depgraph query`",
        "Issue #182で`bounded-query-release-smoke-v1`",
        "`PROJ-ARC-001-ADR-006`",
        "`public-readiness-v1`",
        "Issue #153として`public-readiness-v1`",
        "Issue #176でgreen確認済みのmain commit `d5ca92bae4b4fdbbedb2f3cabd4aa3ef731e7c9f`を`release-baseline-v1`",
        "### ADR-015: Exact Stable Baseline with a Separate Maintenance Line",
        "2026-07-26: Issue #176としてgreenなmain commit",
    ] {
        if !design.contains(required) {
            bail!("system design release metadata is missing {required:?}");
        }
    }
    for required in [
        "| PROJ-ARC-001-ADR-002 | PROJ-ARC-001 | [Opt-in Rust compiler-precise backend](../40_arch_design/adr-rust-compiler-precise-backend.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-002` を追加",
        "| PROJ-ARC-001-ADR-003 | PROJ-ARC-001 | [Cross-language adapter common contract](../40_arch_design/adr-cross-language-adapter-contract.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-003` を追加",
        "| PROJ-ARC-001-ADR-004 | PROJ-ARC-001 | [Default profile selection and exploration budget](../40_arch_design/adr-default-profile-selection-budget.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-004` を追加",
        "| PROJ-ARC-001-ADR-005 | PROJ-ARC-001 | [Bounded read-only graph query language](../40_arch_design/adr-bounded-graph-query-language.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-005` を追加",
        "| PROJ-ARC-001-ADR-006 | PROJ-ARC-001 | [Public OSS readiness and release governance](../40_arch_design/adr-public-oss-release-governance.md) | Accepted |",
        "2026-07-25: `PROJ-ARC-001-ADR-006` を追加",
        "| PROJ-ARC-001-ADR-007 | PROJ-ARC-001 | [v0.5 release, migration, and source contract](../40_arch_design/adr-v0.5-release-contract.md) | Accepted |",
        "2026-08-13: `PROJ-ARC-001-ADR-007` と v0.5 release contractを追加",
    ] {
        if !docs_index.contains(required) {
            bail!("documentation index is missing Rust compiler ADR metadata {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-002`",
        "- Contract: `compiler-precise-rust-v1`",
        "| Toolchain channel | `nightly-2026-07-17` |",
        "| rustc commit | `3d50c25bc66853bf0ad205529d0f305a1d841b5e` |",
        "depgraph resolve --build PATH --allow-project-code --rust-compiler-precise",
        "| wrapper process after rustc starts |",
        "There is no automatic retry with another toolchain",
        "## Options considered",
        "## Security review gates",
        "## Staged implementation and acceptance matrix",
        "`linux-bubblewrap-v1`",
        "`compiler-precise-hostile-e2e-v1`",
        "Hostile execution and rollback E2E (implemented in #248)",
        "every admitted Cargo unit invocation, including dependency, build-script, and proc-macro units",
        "Five-target release gate (implemented in #249)",
        "`compiler-pack-five-target-release-v1`",
        "| Safe invariant |",
    ] {
        if !rust_compiler_adr.contains(required) {
            bail!("Rust compiler-precise ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "Evidence contract: `compiler-precise-hostile-e2e-v1`",
        "filesystem isolation: enforced",
        "network isolation: enforced",
        "process isolation: enforced",
        "`rust-compiler-invocation-child-signalled`",
        "`repeated_promotion_is_byte_stable_and_failure_rolls_back`",
        "`mcp_security_matrix`",
        "| MCP security matrix |",
        "The hostile gate fails if",
    ] {
        if !rust_compiler_hostile.contains(required) {
            bail!("compiler-precise hostile evidence is missing {required:?}");
        }
    }
    for required in [
        "compiler-precise-hostile-e2e-v1",
        "enforced_hostile_boundary_denies_parent_secret_network_and_private_paths",
        "cargo test --offline -p depgraph-mcp --test process --locked issue_317_",
        "mcp-cli-capability-path-cancel-recovery-security-matrix",
        "mcp_security_matrix",
        "unsafe[[:space:]]*\\{",
        "previous_completed_build_layer_preserved",
    ] {
        if !rust_compiler_hostile_gate.contains(required) {
            bail!("compiler-precise hostile gate is missing {required:?}");
        }
    }
    for required in [
        "`compiler-pack-five-target-release-v1`",
        "`x86_64-unknown-linux-gnu`",
        "`aarch64-unknown-linux-gnu`",
        "`x86_64-apple-darwin`",
        "`aarch64-apple-darwin`",
        "`x86_64-pc-windows-msvc`",
        "`depgraph-compiler-component-handshake-v1`",
        "`compiler-pack-five-target-verification-v1`",
        "`unsupported-no-fallback`",
        "cargo xtask verify-compiler-pack-assets compiler-artifacts",
    ] {
        if !rust_compiler_release.contains(required) {
            bail!("compiler-pack release evidence is missing {required:?}");
        }
    }
    for required in [
        "compiler-precise-hostile:",
        "sudo apt-get install --yes --no-install-recommends bubblewrap",
        "scripts/compiler-precise-hostile-e2e.sh",
        "compiler-precise-hostile-${{ github.sha }}",
        "id: decide",
        "steps.decide.outputs.run",
        r#"github.event_name }}" = "workflow_dispatch""#,
        r#"github.event_name }}" = "push""#,
        "github.event.pull_request.base.sha",
        "github.event.pull_request.head.sha",
        r#"Cargo\.(toml|lock)"#,
        "crates/depgraph-core/",
        "crates/depgraph-rustc-wrapper/",
        "crates/depgraph-rustc-query/",
        "crates/depgraph-cli/",
        "crates/depgraph-store/",
        "scripts/compiler-precise-hostile",
        "docs/50_test/compiler-precise-hostile",
        r#"\.github/workflows/ci\.yml"#,
        "if: steps.decide.outputs.run == 'true'",
        "if: steps.decide.outputs.run != 'true'",
    ] {
        if !ci_workflow.contains(required) {
            bail!("CI is missing compiler-precise hostile gate {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-003`",
        "- Contract: `cross-language-contract-v1`",
        "1. OpenAPI;",
        "2. Protocol Buffers;",
        "3. GraphQL;",
        "4. HTTP runtime correlation;",
        "5. FFI.",
        "| `service` |",
        "| `schema` |",
        "| `operation` |",
        "| `message` |",
        "| `native_symbol` |",
        "`depgraph-cross-language-mapping-v1`",
        "A unique spelling is not format-aware proof.",
        "Items 1-2 may support a static `exact` edge",
        "Item 3 emits `phase=build`, `precision=observed`; item 4 emits",
        "never satisfies or promotes a static exact mapping by itself.",
        "## Format capability boundaries",
        "## Security boundary",
        "## Rollout order and issue-sized plan",
        "| 1 | Common node/site/edge DTO, validator, coverage ledger, and cross-format golden harness | Implemented in #191 |",
        "| 2 | OpenAPI 3.1 repository parser and contract graph | Implemented in #192 |",
        "| 3 | OpenAPI generated-client/provider repository mapping | Implemented in #193 |",
        "| 4 | Protobuf source/descriptor contract graph | Implemented in #194 |",
        "| 5 | Protobuf generated-code mapping | Implemented in #195 |",
        "| 6 | GraphQL SDL and executable-document graph | Implemented in #196 |",
        "| 7 | GraphQL client/resolver repository mapping | Implemented in #197 |",
        "| 8 | HTTP trace-to-operation correlation | Implemented in #198 |",
        "| 9 | Rust/Go/Web static FFI declaration inventory | Implemented in #199 |",
        "| 10 | FFI supervised link/export evidence | Implemented in #200 |",
        "| 11 | Five-target package/query/release gate | Implemented in #201 |",
        "## Acceptance matrix",
        "| Safe invariant |",
        "## Security and release gates",
    ] {
        if !cross_language_adr.contains(required) {
            bail!("cross-language adapter ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-004`",
        "- Contract: `default-profile-selection-v1`",
        "never enumerates a target × feature × mode × environment",
        "| `tiny` | `<= 1,000` | `<= 25` | `16` |",
        "| `small` | `<= 10,000` | `<= 100` | `10` |",
        "| `medium` | `<= 50,000` | `<= 500` | `6` |",
        "| `large` | otherwise within inventory limits | otherwise within inventory limits | `4` |",
        "The hard cap is `32` selected root profiles",
        "A set that exactly exhausts the admitted input at",
        "## Mandatory language baselines",
        "## Automatic candidate generation",
        "## Ranking and canonical selection",
        "depgraph profiles plan PATH [--profile-budget N] [--json]",
        "depgraph scan PATH --profiles-file FILE",
        "The core does not truncate it,",
        "`default_profile_budget_exhausted`",
        "`default_profile_candidate_limit_exceeded`",
        "profiles: 10 selected / 14 eligible; 4 omitted by small-repository budget 10",
        "`default_profile_matrix_complete=false`",
        "## Security and resource boundary",
        "## Staged implementation",
        "| 8 | Cache/incremental binding and five-target package/release gate | Implemented in #190 |",
        "## Acceptance matrix",
        "| Explicit set above 32 or with unsupported target |",
    ] {
        if !default_profile_adr.contains(required) {
            bail!("default profile ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-005`",
        "- Contract: `bounded-graph-query-v1`",
        "Existing dedicated commands remain stable and preferred.",
        "## Scope boundary",
        "## Query input and CLI",
        "depgraph query --query QUERY --explain [--json]",
        "## MVP grammar",
        "The parser accepts exactly one statement.",
        "Implemented in #178",
        "Implemented in #179",
        "Implemented in #180",
        "Implemented in #181",
        "## Type system",
        "`EVIDENCE(p)` contains canonical evidence owned by those edges",
        "## Traversal semantics",
        "emits at most one path for a `(source_id, target_id)` pair.",
        "satisfied_existential_predicate_bitset",
        "predicate bits or used-edge sets remain distinct",
        "## Planner and cost model",
        "1 * admitted source-node tests",
        "| Query bytes / tokens / AST nodes | `64 KiB` / `4,096` / `512` |",
        "| Minimum/maximum path depth | `1` / `8` |",
        "| Deterministic cost units | `1,000,000` |",
        "## Explain contract",
        "`query_plan_budget_exceeded`",
        "There is no partial-success mode in v1.",
        "## Security boundary",
        "## Staged implementation",
        "| 1 | Lexer/parser, bounded input reader, canonical AST, and malformed corpus | Implemented in #177 |",
        "| 3 | Snapshot cardinality statistics, fixed operator planner, cost admission, and explain schema | Implemented in #179 |",
        "| 4 | Canonical forward/reverse BFS executor, site/evidence filters, staging, and cancellation | Implemented in #180 |",
        "| 5 | CLI human/JSON output, read-only store integration, profile/phase/condition/evidence fixtures | Implemented in #181 |",
        "| 6 | Fuzz/property tests, hostile large-graph benchmark, and five-target package/release gate | Implemented in #182 |",
        "## Acceptance matrix",
        "| Plan above node/edge/evidence/cost cap despite `LIMIT 1` |",
    ] {
        if !graph_query_adr.contains(required) {
            bail!("bounded graph query ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-006`",
        "- Contract: `public-readiness-v1`",
        "| Current visibility | `private` |",
        "| Current public readiness | `reject` / no-go |",
        "| Accountable owner | TamaT-LLC organization owner |",
        "Passing the current `stable-release-gate-v2` is mandatory but insufficient.",
        "The readiness record is evidence, not an actuator.",
        "[`schemas/public-readiness-v1.schema.json`](../../schemas/public-readiness-v1.schema.json)",
        "`evidence-only-no-visibility-actuator`",
        "## Authority and separation of duties",
        "## Decision record",
        "1. `candidate-and-surface`;",
        "4. `incident-readiness`;",
        "9. `security-and-disclosure`.",
        "## Executable pre-publication checklist",
        "### Gate 2: history and secrets",
        "History rewriting alone never remediates a",
        "`public-history-audit-v1`",
        "Rotation or revocation, purge evidence, and a clean fresh-mirror rescan",
        "### Gate 3: legal, license, and provenance",
        "`public-provenance-review-v1`",
        "Missing assets or notices, unresolved provenance",
        "Developer Certificate of Origin",
        "### Gate 4: security and disclosure",
        "Pin every third-party GitHub Action to a reviewed full commit SHA.",
        "`github-actions-policy-v1`",
        "`security-disclosure-dry-run-v1`",
        "### Gate 5: governance and community",
        "### Gate 6: repository controls",
        "`github-settings-desired-v1`",
        "`read-only-no-settings-actuator`",
        "### Gate 7: release and support",
        "### Gate 8: migration dry run and change window",
        "`public-migration-rehearsal-input-v1`",
        "`temporary-repository-no-production-actuator`",
        "### Gate 9: incident readiness",
        "changing back to private cannot retract clones, forks,",
        "## Maintainer, review, release, support, and contribution policy",
        "## Staged implementation",
        "| 1 | Community/governance documents, issue forms, PR template, DCO/CLA decision | Implemented in #202 |",
        "| 2 | Closed readiness/evidence schemas and deterministic verifier | Implemented in #203 |",
        "| 3 | All-ref/history/collaboration secret audit tooling and redacted ledger | Implemented in #204 |",
        "| 4 | Dependency/license/provenance inventory and legal review package | Implemented in #205 |",
        "| 5 | Workflow SHA pinning, threat model, disclosure policy, and security dry run | Implemented in #206 |",
        "| 6 | Desired GitHub settings/rulesets manifest, access review, and verifier | Implemented in #207 |",
        "| 7 | Temporary-repository migration rehearsal and anonymous smoke suite | Implemented in #208 |",
        "| 8 | Candidate-bound final audit, owner decision, authorized change window, and observation | 2-3 days |",
        "## Acceptance matrix",
        "| Stable release gate passes but history audit is missing |",
        "| All gates pass but organization owner has not authorized visibility | remain private |",
        "### Preserved v0.4 baseline and v0.5 maintenance line",
        "`refs/heads/release/0.4`",
        "`refs/heads/release/0.5`",
        "`maintenance-ref-pinned`",
    ] {
        if !public_oss_adr.contains(required) {
            bail!("public OSS governance ADR is missing required contract {required:?}");
        }
    }
    for required in [
        "- Status: Accepted",
        "- Decision ID: `PROJ-ARC-001-ADR-007`",
        "- Issue: `PROJ-ARC-003-TASK-001` / #355",
        "- Contract: `stable-release-gate-v2`",
        "No `v0.4.0` stable GitHub Release was published",
        "| Product and adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Agent host configuration | `depgraph-agent-host-config-v1` |",
        "| Agent onboarding release evidence | `release-post-publish-evidence-v1` |",
        "| Packaged MCP smoke | `mcp-package-smoke-v2` |",
        STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        V0_4_RC6_TAG_COMMIT,
        V0_4_RC6_AARCH64_APPLE_ARCHIVE_SHA256,
        V0_4_RC6_AARCH64_APPLE_BINARY_SHA256,
        "The stable baseline status is `maintenance-ref-pinned`.",
    ] {
        if !v0_5_release_adr.contains(required) {
            bail!("v0.5 release ADR is missing required contract {required:?}");
        }
    }
    let migration_rehearsal =
        read_lf_normalized_text(&root.join("docs/50_test/public-migration-rehearsal.md"))?;
    for required in [
        "`temporary-repository-no-production-actuator`",
        "The production repository must retain its original visibility",
        "`freeze_writes`",
        "`verify_desired_settings`",
        "`run_anonymous_smoke`",
        "`reopen_writes`",
        "`cleanup_temporary_repository`",
        "`activity_after_no_go`",
        "schemas/public-migration-rehearsal-input-v1.schema.json",
    ] {
        if !migration_rehearsal.contains(required) {
            bail!("public migration rehearsal is missing required contract {required:?}");
        }
    }
    let v0_4_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.4.0.md"))?;
    if v0_4_stable_release_baseline_digest() != V0_4_STABLE_RELEASE_BASELINE_DIGEST {
        bail!("compiled v0.4 release baseline digest does not match its canonical record");
    }
    for required in [
        "## Release baseline and maintenance line",
        V0_4_STABLE_RELEASE_BASELINE_COMMIT,
        V0_4_STABLE_RELEASE_BASELINE_TREE,
        V0_4_STABLE_RELEASE_BASELINE_DIGEST,
        V0_4_STABLE_RELEASE_MAINTENANCE_BRANCH,
        "git cherry-pick -x",
        "default-disabled or explicitly opt-in",
        "Stable release source guard",
    ] {
        if !v0_4_release_note.contains(required) {
            bail!("v0.4 release note is missing preserved baseline contract {required:?}");
        }
    }
    let v0_5_0_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0.md"))?;
    for required in [
        "0.5.0",
        "stable-release-gate-v2",
        "maintenance-ref-pinned",
        "refs/heads/release/0.5",
        STABLE_UPGRADE_SOURCE_VERSION,
        STABLE_UPGRADE_SOURCE_FIXTURE_PATH,
        STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        "depgraph-mcp-tools-v1",
        "depgraph-operation-v1",
        "depgraph-agent-host-config-v1",
        "release-post-publish-evidence-v1",
        "mcp-package-smoke-v2",
        AGENT_DOGFOOD_REPORT_PATH,
        AGENT_DOGFOOD_REPORT_SHA256,
        "`flate2`, `tar`, `zip`",
        "operation journal schema `5`",
    ] {
        if !v0_5_0_release_note.contains(required) {
            bail!("v0.5.0 release note is missing historical contract {required:?}");
        }
    }
    let stable_release_note =
        read_lf_normalized_text(&root.join(format!("docs/releases/v{VERSION}.md")))?;
    for required in [
        STABLE_RELEASE_VERSION,
        STABLE_RELEASE_GATE_SCHEMA_VERSION,
        STABLE_RELEASE_BASELINE_STATUS,
        STABLE_RELEASE_MAINTENANCE_BRANCH,
        STABLE_UPGRADE_SOURCE_VERSION,
        STABLE_UPGRADE_SOURCE_FIXTURE_PATH,
        STABLE_UPGRADE_SOURCE_FIXTURE_SHA256,
        "`v0.5.2`, Store schema `17`",
        "@tamat-llc/depgraph",
        "@tamat-llc/depgraph-win32-x64",
        "npm Trusted Publishing",
        "release-post-publish-evidence-v0.5.3.json",
        "stable-v0.5.0-packaged-smoke-v1",
        "mcp-package-smoke-v2",
        "Node.js 24",
        "musl",
    ] {
        if !stable_release_note.contains(required) {
            bail!("v{VERSION} release note is missing contract {required:?}");
        }
    }
    let rc_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.1.md"))?;
    for required in [
        "first v0.5 release candidate",
        "signed annotated `v0.5.0-rc.1` tag",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.1.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc_release_note.contains(required) {
            bail!("v0.5.0-rc.1 release note is missing contract {required:?}");
        }
    }
    let rc2_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.2.md"))?;
    for required in [
        "second v0.5 release candidate",
        "signed annotated `v0.5.0-rc.2` tag",
        "`v0.5.0-rc.1` tag remains immutable and was not published",
        "canonicalizes the relative",
        "checkout-built CLI path before switching",
        "`x86_64-pc-windows-msvc` only receives the 15-minute semantic ceiling; all four supported Linux and macOS targets retain the 10-minute semantic ceiling.",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.2.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc2_release_note.contains(required) {
            bail!("v0.5.0-rc.2 release note is missing contract {required:?}");
        }
    }
    let rc3_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.3.md"))?;
    for required in [
        "third v0.5 release candidate",
        "signed annotated `v0.5.0-rc.3` tag",
        "`v0.5.0-rc.1` and `v0.5.0-rc.2` tags remain immutable",
        "validates each rollback failure by its exact typed",
        "removing only execution",
        "`/etc/alternatives/cc`",
        "canonical root-owned compiler executable",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.3.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc3_release_note.contains(required) {
            bail!("v0.5.0-rc.3 release note is missing contract {required:?}");
        }
    }
    let rc4_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.4.md"))?;
    for required in [
        "fourth v0.5 release candidate",
        "signed annotated `v0.5.0-rc.4` tag",
        "`v0.5.0-rc.1`, `v0.5.0-rc.2`, and `v0.5.0-rc.3` tags",
        "`/etc/alternatives/cc`",
        "root-owned, non-writable path",
        "actual C executable link and launch",
        "exact Linux compiler-pack semantic release smoke",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.4.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc4_release_note.contains(required) {
            bail!("v0.5.0-rc.4 release note is missing contract {required:?}");
        }
    }
    let rc5_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.5.md"))?;
    for required in [
        "fifth v0.5 release candidate",
        "signed annotated `v0.5.0-rc.5` tag",
        "`v0.5.0-rc.1` through `v0.5.0-rc.4` tags remain immutable",
        "GitHub Git Data API",
        "remote tag object type is `tag`",
        "shallow checkout",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.5.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc5_release_note.contains(required) {
            bail!("v0.5.0-rc.5 release note is missing contract {required:?}");
        }
    }
    let rc6_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.6.md"))?;
    for required in [
        "sixth v0.5 release candidate",
        "signed annotated `v0.5.0-rc.6` tag",
        "`v0.5.0-rc.1` through `v0.5.0-rc.5` tags remain immutable",
        "51 pre-evidence",
        "lacked `actions: read`",
        "`actions: write`",
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.6.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc6_release_note.contains(required) {
            bail!("v0.5.0-rc.6 release note is missing contract {required:?}");
        }
    }
    let rc7_release_note = read_lf_normalized_text(&root.join("docs/releases/v0.5.0-rc.7.md"))?;
    for required in [
        "seventh v0.5 release candidate",
        "signed annotated `v0.5.0-rc.7` tag",
        "`v0.5.0-rc.1` through `v0.5.0-rc.6` tags remain immutable",
        "Full CI run `31867648482`",
        "non-empty `rustflags` matrix value",
        V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH,
        V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256,
        "| Product and Rust/Go/Web adapters | `0.5.0` |",
        "| Worker protocol / graph schema | `1.0` |",
        "| SQLite Store | schema `17` |",
        "| Durable operation journal | schema `5` |",
        "| MCP tool DTO | `depgraph-mcp-tools-v1` |",
        "| Operation DTO | `depgraph-operation-v1` |",
        "| Post-publish evidence | `release-post-publish-evidence-v1` |",
        "release-post-publish-evidence-v0.5.0-rc.7.json",
        "all 51 pre-evidence asset sizes and SHA-256 digests",
        "does not substitute checkout-built product binaries",
        "Agent host operations runbook",
        "Downgrade-in-place is unsupported",
    ] {
        if !rc7_release_note.contains(required) {
            bail!("v0.5.0-rc.7 release note is missing contract {required:?}");
        }
    }
    let release_procedure =
        read_lf_normalized_text(&root.join("docs/50_test/release-procedure.md"))?;
    for required in [
        "git tag -s \"$release_tag\" \"$candidate\"",
        "git verify-tag \"$release_tag\"",
        "## 公開後の再取得検証",
        "`release-post-publish-evidence-v1`",
        "GitHub Git Data APIからremote",
        "local `git rev-parse <tag>^{tag}`",
        "計51点",
        "checkout内のproduct binaryや未公開package artifact",
        "non-empty matrix値をすべて含む",
        "`mcp-package-smoke-v2`",
        "`depgraph-agent-host-config-v1`",
        "`maintenance-ref-pinned`",
        AGENT_DOGFOOD_REPORT_SHA256,
        "release-post-publish-evidence-v0.5.0.json",
        "`tar`、`zip`とそのtransitive closure",
        V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH,
        "### v0.5.0のimmutable post-publish recovery",
        "Release post-publish recovery",
        "31928961757",
        "31923533506",
        "preflight input file paths must be absolute",
        "green recovery run",
    ] {
        if !release_procedure.contains(required) {
            bail!("release procedure is missing post-publish contract {required:?}");
        }
    }
    if sha256_file(&root.join(STABLE_UPGRADE_SOURCE_FIXTURE_PATH))?
        != STABLE_UPGRADE_SOURCE_FIXTURE_SHA256
    {
        bail!("official v0.4.0-rc.6 store fixture was modified");
    }
    if sha256_file(&root.join(V0_5_RC6_FULL_CI_RUN_FIXTURE_PATH))?
        != V0_5_RC6_FULL_CI_RUN_FIXTURE_SHA256
    {
        bail!("captured v0.5.0-rc.6 Full CI API fixture was modified");
    }
    let compatibility = release_compatibility();
    if compatibility.worker_protocol_version != depgraph_protocol::PROTOCOL_VERSION
        || compatibility.store_schema_version != depgraph_store::STORE_SCHEMA_VERSION
        || compatibility.operation_journal_schema_version
            != depgraph_operation::JOURNAL_SCHEMA_VERSION
        || compatibility.mcp_tool_contract_version != MCP_TOOL_CONTRACT_VERSION
        || compatibility.mcp_operation_contract_version != MCP_OPERATION_CONTRACT_VERSION
        || compatibility.stable_release_version != VERSION
        || compatibility.stable_upgrade_source_fixture_path != STABLE_UPGRADE_SOURCE_FIXTURE_PATH
        || compatibility.stable_upgrade_source_fixture_sha256
            != format!("sha256:{STABLE_UPGRADE_SOURCE_FIXTURE_SHA256}")
    {
        bail!("v0.5 release compatibility tuple is not synchronized");
    }
    verify_stable_release_source_guard(root)?;
    let git_attributes = fs::read_to_string(root.join(".gitattributes"))?;
    for readme_path in ["README.md", "README.en.md"] {
        let required_attribute = format!("{readme_path} text eol=lf");
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
        {
            bail!("{readme_path} is not pinned to LF in .gitattributes");
        }
    }
    for (path, expected) in PROJECT_LICENSES {
        let required_attribute = format!("{path} text eol=lf");
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
        {
            bail!("project license {path} is not pinned to LF in .gitattributes");
        }
        if expected.contains(&b'\r') {
            bail!("project license source {path} is not LF-normalized");
        }
        let actual = fs::read(root.join(path))?;
        if actual != *expected {
            bail!("project license source {path} differs from its compiled release input");
        }
    }
    for (path, expected) in [
        ("third_party/rust-src/COPYRIGHT", RUST_SOURCE_COPYRIGHT),
        ("third_party/rust-src/LICENSE-MIT", RUST_SOURCE_LICENSE_MIT),
    ] {
        let required_attribute = format!("{path} text eol=lf");
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
            || expected.contains(&b'\r')
        {
            bail!("Rust source legal input {path} is not pinned to LF");
        }
    }
    for required_attribute in [
        "fixtures/** text eol=lf",
        "xtask/fixtures/** text eol=lf",
        "queries/** text eol=lf",
        "schemas/** text eol=lf",
    ] {
        if !git_attributes
            .lines()
            .any(|line| line.trim() == required_attribute)
        {
            bail!("release contract text is missing checkout normalization {required_attribute}");
        }
    }
    for link in [
        "docs/40_arch_design/arch-dependency-graph-cli-system-design.md",
        "docs/40_arch_design/adr-rust-compiler-precise-backend.md",
        "docs/40_arch_design/adr-cross-language-adapter-contract.md",
        "docs/40_arch_design/adr-default-profile-selection-budget.md",
        "docs/40_arch_design/adr-bounded-graph-query-language.md",
        "docs/40_arch_design/adr-v0.5-release-contract.md",
        "docs/50_test/mcp-agent-host-operations.md",
        "docs/50_test/agent-dogfood-benchmark.md",
        "docs/releases/v0.4.0.md",
        "docs/releases/v0.5.3.md",
        "docs/releases/v0.5.2.md",
        "docs/releases/v0.5.1.md",
        "docs/releases/v0.5.0.md",
        "docs/releases/v0.5.0-rc.7.md",
        "docs/releases/v0.5.0-rc.6.md",
        "docs/releases/v0.5.0-rc.5.md",
        "docs/releases/v0.5.0-rc.4.md",
        "docs/releases/v0.5.0-rc.3.md",
        "docs/releases/v0.5.0-rc.2.md",
        "docs/releases/v0.5.0-rc.1.md",
        "docs/releases/v0.4.0-rc.6.md",
        "docs/releases/v0.4.0-rc.3.md",
        "docs/releases/v0.4.0-rc.2.md",
        "docs/releases/v0.4.0-rc.1.md",
        "docs/releases/v0.2.0-rc.1.md",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ] {
        if !root.join(link).is_file() {
            bail!("README local documentation link does not resolve: {link}");
        }
    }
    let schema: Value = serde_json::from_slice(&fs::read(
        root.join("schemas/depgraph-protocol-v1.schema.json"),
    )?)?;
    if schema["title"] != "depgraph worker protocol v1.0"
        || schema["$defs"]["common"]["properties"]["protocol_version"]["const"] != "1.0"
    {
        bail!("protocol schema compatibility reference is not synchronized with 1.0");
    }
    let release_workflow = read_lf_normalized_text(&root.join(".github/workflows/release.yml"))?;
    for (target, _) in RELEASE_TARGETS {
        if !release_workflow.contains(target) {
            bail!("release workflow is missing target {target}");
        }
    }
    for required in [
        "cargo xtask verify-release-assets artifacts",
        "docs/releases/${GITHUB_REF_NAME}.md",
        "artifacts/release-verification.json",
        "benchmark-report-${{ github.sha }}",
        "dist/*.query-smoke.json",
        "compiler-precise-hostile:",
        "sudo apt-get install --yes --no-install-recommends bubblewrap",
        "run: scripts/compiler-precise-hostile-e2e.sh",
        "needs: [quality, compiler-precise-hostile]",
        "DEPGRAPH_INCREMENTAL_LIMIT_MS: \"10000\"",
        "DEPGRAPH_QUERY_LIMIT_MS: \"4000\"",
        "DEPGRAPH_BOUNDED_QUERY_PLAN_LIMIT_MS: \"7000\"",
        "DEPGRAPH_BOUNDED_QUERY_EXECUTE_LIMIT_MS: \"10000\"",
        "DEPGRAPH_RUST_SCAN_LIMIT_MS: \"12000\"",
        "DEPGRAPH_RUST_NO_CACHE_SCAN_LIMIT_MS: \"12000\"",
        "node scripts/benchmark-report.mjs verify benchmark/benchmark-report.json",
        "node scripts/cache-hit-benchmark.mjs verify benchmark/cache-hit-benchmark-report.json",
        "compiler-pack:",
        "verify-compiler-packs:",
        "rustup toolchain install nightly-2026-07-17 --profile minimal --component rust-src,rustc-dev,llvm-tools-preview",
        "cargo xtask compiler-pack-package --channel-manifest channel-rust-nightly-2026-07-17.toml",
        "cargo xtask verify-compiler-pack-assets compiler-artifacts",
        "needs: [quality, compiler-precise-hostile, benchmark, package, verify-assets, compiler-pack, verify-compiler-packs]",
        "name: Bind the stable candidate to main, release/0.5, and exact Full CI",
        "if [[ \"$GITHUB_REF_NAME\" == \"v0.5.3\" ]]",
        "api_source_tree=\"$(gh api",
        "test \"$source_tree\" = \"$api_source_tree\"",
        "DEPGRAPH_RELEASE_SOURCE_TREE=$source_tree",
        "DEPGRAPH_RELEASE_MAIN_HEAD_SHA=$main_head_sha",
        "DEPGRAPH_RELEASE_MAINTENANCE_HEAD_SHA=$maintenance_head_sha",
        "cargo xtask stable-release-gate",
        AGENT_DOGFOOD_REPORT_PATH,
        "artifacts/full-ci.json",
        "DEPGRAPH_RELEASE_QUALITY_RESULT: ${{ needs.quality.result }}",
        "DEPGRAPH_RELEASE_COMPILER_PRECISE_HOSTILE_RESULT: ${{ needs.compiler-precise-hostile.result }}",
        "DEPGRAPH_RELEASE_BENCHMARK_RESULT: ${{ needs.benchmark.result }}",
        "DEPGRAPH_RELEASE_PACKAGE_RESULT: ${{ needs.package.result }}",
        "DEPGRAPH_RELEASE_VERIFY_ASSETS_RESULT: ${{ needs.verify-assets.result }}",
        "DEPGRAPH_RELEASE_COMPILER_PACK_RESULT: ${{ needs.compiler-pack.result }}",
        "DEPGRAPH_RELEASE_VERIFY_COMPILER_PACKS_RESULT: ${{ needs.verify-compiler-packs.result }}",
        "name: stable-release-gate",
        "needs: stable-gate",
        "name: Verify the signed annotated release tag",
        "gh api \"repos/${GITHUB_REPOSITORY}/git/ref/tags/${GITHUB_REF_NAME}\"",
        "test \"$(jq -r '.ref' <<<\"$tag_ref_payload\")\" = \"refs/tags/${GITHUB_REF_NAME}\"",
        "test \"$(jq -r '.object.type' <<<\"$tag_ref_payload\")\" = \"tag\"",
        "tag_object_sha=\"$(jq -r '.object.sha' <<<\"$tag_ref_payload\")\"",
        "git ls-remote origin refs/heads/main",
        ".verification.signature != null",
        "gh release download \"$GITHUB_REF_NAME\" --dir post-publish/public",
        "cargo xtask verify-release-assets post-publish/normal",
        "cargo xtask verify-compiler-pack-assets post-publish/compiler",
        "gh run list --workflow CI --event workflow_dispatch --commit \"$GITHUB_SHA\" --status success",
        "cargo xtask release-post-publish-evidence",
        "ci_run_id=\"$(jq -r '.workflow_results.full_ci_run_id // empty' artifacts/stable-release-gate.json)\"",
        "gh release upload \"$GITHUB_REF_NAME\" \"$evidence\"",
        "cmp --silent \"$evidence\"",
        "git ls-remote origin refs/heads/release/0.5",
        "trusted_evidence_sha256",
        "scripts/release-post-publish-canary.sh",
        "post-publish/canary",
    ] {
        if !release_workflow.contains(required) {
            bail!("release workflow is missing {required:?}");
        }
    }
    let repository_onboarding_extraction = r#"          if [[ "$RUNNER_OS" == "Windows" ]]; then
            DEPGRAPH_ARCHIVE_PATH="$release_root/$archive" \
              DEPGRAPH_RELEASE_ROOT="$release_root" \
              pwsh -NoLogo -NoProfile -NonInteractive -Command \
                'Expand-Archive -LiteralPath $env:DEPGRAPH_ARCHIVE_PATH -DestinationPath $env:DEPGRAPH_RELEASE_ROOT'
          else
            tar -xf "$release_root/$archive" -C "$release_root"
          fi"#;
    if !release_workflow.contains(repository_onboarding_extraction) {
        bail!(
            "release workflow does not bind ZIP extraction to Windows and tar extraction to non-Windows runners"
        );
    }
    let canary_script = fs::read_to_string(root.join("scripts/release-post-publish-canary.sh"))?;
    for required in [
        "canonical_file()",
        "canonical_directory()",
        "realpath \"$path\"",
        "sha256sum --check --strict --status",
        "canary_compiler_archive",
        "canary_compiler_checksum",
        "output_root/compiler",
        "compiler-pack-manifest.json",
        "agent-config",
        "--release-archive \"$canary_archive\"",
        "--release-checksum \"$canary_checksum\"",
        "--release-evidence \"$evidence\"",
        "--release-manifest \"$canary_manifest\"",
        "--compiler-pack-requirement \"$canary_requirement\"",
        "--host claude-desktop",
        "claude-desktop.json",
    ] {
        if !canary_script.contains(required) {
            bail!("release post-publish canary is missing {required:?}");
        }
    }
    let recovery_workflow =
        fs::read_to_string(root.join(".github/workflows/release-post-publish-recovery.yml"))?;
    for required in [
        "name: Release post-publish recovery",
        "workflow_dispatch:",
        "permissions: {}",
        "actions: read",
        "contents: read",
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
        "node-version: 24.18.0",
        "run: scripts/release-post-publish-recovery.sh",
    ] {
        if !recovery_workflow.contains(required) {
            bail!("release post-publish recovery workflow is missing {required:?}");
        }
    }
    let recovery_script =
        fs::read_to_string(root.join("scripts/release-post-publish-recovery.sh"))?;
    for required in [
        "v0.5.0 post-publish recovery accepts no mutable inputs",
        "f1071178d3888503b6e02d4aec5e058f0b87d035",
        "2e1825dda4493acf581dbad9ef66f8f3a44bb734",
        "dd81d5f108fb8fc3db1afcad62d422c9d9c34415",
        "31928961757",
        "31923533506",
        "13e253b3759a9729f43ff8dbe6f6a48191770681b02a57cb5197bc908ab77524",
        "original_job_set_sha256",
        "compare/${source_sha}...${GITHUB_SHA}",
        ".path == \".github/workflows/release.yml\"",
        ".run_attempt == 1",
        "--log-failed",
        "preflight input file paths must be absolute",
        "(.assets | length) == 52",
        "(.assets | length) == 51",
        "compiler_archive_name",
        "compiler_checksum_name",
        "= \"6\"",
        "release-post-publish-canary.sh",
    ] {
        if !recovery_script.contains(required) {
            bail!("release post-publish recovery script is missing {required:?}");
        }
    }
    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    for required in [
        "needs: [rust, go, web]",
        "node --test npm/test/*.test.mjs scripts/tests/agent-dogfood.test.mjs scripts/tests/release-post-publish-canary.test.mjs",
        "node --test scripts/tests/benchmark.test.mjs scripts/tests/cache-hit-benchmark.test.mjs scripts/tests/agent-dogfood.test.mjs",
        "scripts/benchmark-mvp.sh",
        "benchmark-report-${{ github.sha }}",
        "dist/cache-hit-benchmark-report.json",
        "DEPGRAPH_CACHE_HIT_MIN_IMPROVEMENT_PERCENT: \"5\"",
        "DEPGRAPH_INCREMENTAL_LIMIT_MS: \"10000\"",
        "DEPGRAPH_QUERY_LIMIT_MS: \"4000\"",
        "DEPGRAPH_BOUNDED_QUERY_PLAN_LIMIT_MS: \"7000\"",
        "DEPGRAPH_BOUNDED_QUERY_EXECUTE_LIMIT_MS: \"10000\"",
        "DEPGRAPH_RUST_SCAN_LIMIT_MS: \"12000\"",
        "DEPGRAPH_RUST_NO_CACHE_SCAN_LIMIT_MS: \"12000\"",
        "crates/depgraph-operation/|xtask/src/compiler_pack_release\\.rs|scripts/compiler-precise-hostile",
        "name: Exact Linux compiler-pack semantic release smoke",
        "cargo xtask compiler-pack-package --channel-manifest channel-rust-nightly-2026-07-17.toml",
    ] {
        if !ci_workflow.contains(required) {
            bail!("CI workflow is missing {required:?}");
        }
    }
    Ok(())
}

fn markdown_table_rows_between(
    document: &str,
    start: Option<&str>,
    end: &str,
) -> Result<Vec<Vec<String>>> {
    let section = match start {
        Some(heading) => {
            document
                .split_once(heading)
                .with_context(|| format!("missing markdown section {heading:?}"))?
                .1
        }
        None => document,
    };
    let section = section
        .split_once(end)
        .with_context(|| format!("missing markdown section boundary {end:?}"))?
        .0;
    Ok(section
        .lines()
        .filter(|line| line.starts_with('|') && !line.contains("---"))
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_owned())
                .collect()
        })
        .skip(1)
        .collect())
}

fn markdown_count_table(document: &str, start: &str, end: &str) -> Result<BTreeMap<String, usize>> {
    markdown_table_rows_between(document, Some(start), end)?
        .into_iter()
        .map(|row| {
            if row.len() != 2 {
                bail!("count table {start:?} contains a malformed row: {row:?}");
            }
            let count = row[1]
                .parse::<usize>()
                .with_context(|| format!("count table {start:?} has a nonnumeric count"))?;
            Ok((row[0].clone(), count))
        })
        .collect()
}

pub(crate) fn verify_mcp_tasks_architecture_decision(root: &Path) -> Result<()> {
    const DOCUMENT_PATH: &str = "docs/40_arch_design/arch-mcp-agent-tools.md";
    const EXPECTED_FRONTMATTER: &str = "---\n\
id: PROJ-ARC-002\n\
layer: L4\n\
feature: mcp-agent-tools\n\
scope: feature\n\
status: Active\n\
upstream: [PROJ-ARC-001]\n\
downstream: []\n\
owner: TakehiroT\n\
updated: 2026-08-24\n\
open_questions: 0\n\
---\n";

    let attributes = fs::read_to_string(root.join(".gitattributes"))?;
    if !attributes
        .lines()
        .any(|line| line == "docs/**/*.md text eol=lf")
    {
        bail!("repository documentation is not pinned to LF checkout bytes");
    }
    let decision = fs::read_to_string(root.join(DOCUMENT_PATH))?;
    if !decision.starts_with(EXPECTED_FRONTMATTER) || !decision.ends_with('\n') {
        bail!("MCP Agent Tools architecture frontmatter is missing, open, or noncanonical");
    }
    for required in [
        "# アーキテクチャ設計: MCP Agent Tools",
        "| `Q-002` | baseline handleへMCP Tasksを追加するか | **Resolved: Option Aを採用する** |",
        "**Option A（baseline operation handle + MCP Tasks）を採用する。**",
        "`rmcp 3.1.0`",
        "1f9358eddca42d3a510c70ae6446dd6548c7c856",
        "`io.modelcontextprotocol/tasks`",
        "`taskId == operation_id`",
        "## Portable baseline operation contract",
        "`operation_get`",
        "`operation_result`",
        "`operation_cancel`",
        "## MCP Tasks additive contract",
        "### Capability negotiation and legacy fallback",
        "`2025-11-25` experimental",
        "baseline `OperationAccepted`",
        "`-32021` Missing Required Client Capability",
        "CallToolResponse = Complete(CallToolResult<OperationAccepted>)",
        "| `queued` / `running` / `cancelling` | `working` |",
        "### `tasks/cancel` authorization",
        "不足時は`CAPABILITY_DENIED`",
        "journal digest、lease、runnerを\n   変更しない",
        "### Disconnect, restart, and reconnection",
        "再接続先がTasks非対応、extension未宣言、またはlegacy protocolでも",
        "## Compatibility and conformance tests",
        "| Legacy fallback |",
        "| Cancel authorization |",
        "| `Q-002` | **Resolved** | Option Aを採用する。",
        "`open_questions`は`0`である。",
        "| `#316` | resolve buildを共有project-exec serviceとdurable MCP operationへ接続する |",
        "## Issue #316 resolve-build project-exec evidence",
        "`source_non_mutation_guaranteed=true`",
        "### Issue #316 acceptance mapping",
        "| `#317` | 全CLI mapping、capability、path confinement、operation recovery、hostile project executionを横断検証する |",
        "## Issue #317 cross-cutting security E2E evidence",
        "baseline-only assertionには置き換えず",
        "### Issue #317 acceptance mapping",
        "| `#318` | MCP server、operation runner、schema、SDK/legal metadataを5 target release closureへ含める |",
        "## Issue #318 five-target MCP release closure",
        "`rmcp 3.1.0`とprotocol revision `2026-07-28`",
        "stable gate schema 9の`mcp-five-target` check",
        "### Issue #318 acceptance mapping",
        "| `#319` | 抽出済みarchiveのMCP stdio smokeと5 target digest gateを追加する |",
        "## Issue #319 packaged MCP smoke and digest gate",
        "`mcp-package-smoke-v1`",
        "handle受領を2,000 ms未満",
        "stdin close後5,000 ms以内",
        "### Issue #319 acceptance mapping",
        "| `#358` | verified release archiveからAgent host onboardingを自動化する |",
        "## Issue #358 verified Agent host onboarding",
        "`depgraph-agent-host-config-v1`",
        "`mcp-package-smoke-v2`",
        "`flate2`/`tar`/`zip`",
        "### Issue #358 acceptance mapping",
        "## Issue #292 acceptance mapping",
    ] {
        if !decision.contains(required) {
            bail!("MCP Tasks architecture decision is missing {required:?}");
        }
    }
    for forbidden in [
        "open_questions: 1",
        "| `Q-002` | Open |",
        "| `Q-002` | Pending |",
        "TODO",
        "TBD",
    ] {
        if decision.contains(forbidden) {
            bail!("MCP Tasks architecture decision contains unresolved marker {forbidden:?}");
        }
    }
    if decision.matches("```").count() % 2 != 0 {
        bail!("MCP Tasks architecture decision contains an unclosed code fence");
    }
    verify_local_markdown_links(root, DOCUMENT_PATH, &decision)?;

    let index = fs::read_to_string(root.join("docs/00_index/index.md"))?;
    let architecture_rows =
        markdown_table_rows_between(&index, None, "## Architecture Decision Records")?;
    let mut ids = BTreeSet::new();
    let mut layers = BTreeMap::from([
        ("L0".to_owned(), 0),
        ("L1".to_owned(), 0),
        ("L2".to_owned(), 0),
        ("L3".to_owned(), 0),
        ("L4".to_owned(), 0),
        ("L5".to_owned(), 0),
    ]);
    let mut statuses = BTreeMap::from([
        ("Draft".to_owned(), 0),
        ("Active".to_owned(), 0),
        ("Deprecated".to_owned(), 0),
    ]);
    let mut features = BTreeMap::new();
    let mut found_mcp_entry = false;
    for row in &architecture_rows {
        if row.len() != 6 {
            bail!("documentation index contains a malformed architecture row: {row:?}");
        }
        if !ids.insert(row[0].clone()) {
            bail!(
                "documentation index contains duplicate architecture ID {:?}",
                row[0]
            );
        }
        *layers
            .get_mut(&row[1])
            .with_context(|| format!("documentation index uses unknown layer {:?}", row[1]))? += 1;
        *statuses
            .get_mut(&row[5])
            .with_context(|| format!("documentation index uses unknown status {:?}", row[5]))? += 1;
        *features.entry(row[2].clone()).or_insert(0) += 1;
        found_mcp_entry |= row
            == &[
                "PROJ-ARC-002",
                "L4",
                "mcp-agent-tools",
                "feature",
                "[アーキテクチャ設計: MCP Agent Tools](../40_arch_design/arch-mcp-agent-tools.md)",
                "Active",
            ];
    }
    if !found_mcp_entry {
        bail!("documentation index is missing the canonical MCP Agent Tools entry");
    }

    let mut expected_layers = layers;
    expected_layers.insert("Total".to_owned(), architecture_rows.len());
    let indexed_layers = markdown_count_table(&index, "### レイヤー別", "### ステータス別")?;
    let indexed_statuses = markdown_count_table(&index, "### ステータス別", "### 機能別")?;
    let indexed_features = markdown_count_table(&index, "### 機能別", "## 更新履歴")?;
    if indexed_layers != expected_layers
        || indexed_statuses != statuses
        || indexed_features != features
    {
        bail!("documentation index statistics do not match its architecture entries");
    }
    verify_local_markdown_links(root, "docs/00_index/index.md", &index)?;
    Ok(())
}

pub(crate) fn verify_public_community_surface(root: &Path) -> Result<()> {
    let documents: &[(&str, &[&str])] = &[
        (
            "README.md",
            &[
                "日本語 | [English](README.en.md)",
                "## プロジェクトの状況と公開コラボレーション",
                "サポート対象は、検証済みの`v0.5.3`リリースを条件として確定する",
                "[SUPPORT.md](SUPPORT.md)",
                "[CONTRIBUTING.md](CONTRIBUTING.md)",
                "[GOVERNANCE.md](GOVERNANCE.md)",
                "[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)",
                "[SECURITY.md](SECURITY.md)",
            ],
        ),
        (
            "README.en.md",
            &[
                "[Japanese](README.md) | English",
                "## Project status and public collaboration",
                "The supported line is conditionally anchored by the verified `v0.5.3` Release",
                "[SUPPORT.md](SUPPORT.md)",
                "[CONTRIBUTING.md](CONTRIBUTING.md)",
                "[GOVERNANCE.md](GOVERNANCE.md)",
                "[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)",
                "[SECURITY.md](SECURITY.md)",
            ],
        ),
        (
            "CONTRIBUTING.md",
            &[
                "## Developer Certificate of Origin",
                "git commit -s",
                "Signed-off-by",
                "cargo xtask test",
                "[SECURITY.md](SECURITY.md)",
                "[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)",
            ],
        ),
        (
            "CODE_OF_CONDUCT.md",
            &[
                "## Scope and enforcement",
                "private route in [SECURITY.md](SECURITY.md)",
                "may appeal once",
                "The appeal reviewer must not be the sole person",
            ],
        ),
        (
            "SECURITY.md",
            &[
                "## Supported versions",
                "## Report a vulnerability privately",
                "https://github.com/TamaT-LLC/depgraph-cli/security/advisories/new",
                "Do not open a public issue",
                "best effort and does not create a response-time SLA",
            ],
        ),
        (
            "SUPPORT.md",
            &[
                "best-effort basis",
                "does not provide an SLA",
                "The supported stable line is the newest stable version whose official GitHub",
                "[SECURITY.md](SECURITY.md)",
                "There is no automatic stale deadline",
            ],
        ),
        (
            "GOVERNANCE.md",
            &[
                "## Maintainer lifecycle and owner boundary",
                "The `CODEOWNERS` principals are added only after",
                "The current owner pair is `@TakehiroT` and",
                "Authors do not normally approve their own work.",
                "Developer Certificate of Origin",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/config.yml",
            &[
                "blank_issues_enabled: false",
                "Private vulnerability report",
                "https://github.com/TamaT-LLC/depgraph-cli/security/advisories/new",
                "SUPPORT.md",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/bug_report.yml",
            &[
                "name: Bug report",
                "id: reproduction",
                "id: expected",
                "id: actual",
                "This is not a suspected security vulnerability.",
            ],
        ),
        (
            ".github/ISSUE_TEMPLATE/feature_request.yml",
            &[
                "name: Feature request",
                "id: problem",
                "id: proposal",
                "id: alternatives",
                "Security reports belong in the private",
            ],
        ),
        (
            ".github/PULL_REQUEST_TEMPLATE.md",
            &[
                "## Scope and compatibility",
                "cargo xtask test",
                "## Security and provenance",
                "DCO `Signed-off-by`",
                "the author is not the independent approver",
            ],
        ),
    ];
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalize community surface root {}", root.display()))?;
    for (path, markers) in documents {
        let document_path = root.join(path);
        let content = fs::read_to_string(&document_path)
            .with_context(|| format!("public community profile is missing {path}"))?;
        for marker in *markers {
            if !content.contains(marker) {
                bail!("public community document {path} is missing marker {marker:?}");
            }
        }
        for forbidden in ["TODO", "TBD", "CHANGEME", "<contact>", "@team-name"] {
            if content.contains(forbidden) {
                bail!("public community document {path} contains placeholder {forbidden:?}");
            }
        }
        verify_local_markdown_links(&root, path, &content)?;
    }
    verify_codeowners(&root.join(".github/CODEOWNERS"))
}

pub(crate) fn verify_codeowners(path: &Path) -> Result<()> {
    let codeowners = read_lf_normalized_text(path)
        .context("public community profile is missing .github/CODEOWNERS")?;
    if codeowners
        != "# Require an owner review for every change in this repository.\n* @TakehiroT @Fuelda\n"
    {
        bail!("CODEOWNERS must match the organization-approved owner pair");
    }
    Ok(())
}

pub(crate) fn verify_local_markdown_links(root: &Path, source: &str, content: &str) -> Result<()> {
    let mut remainder = content;
    while let Some(label_end) = remainder.find("](") {
        remainder = &remainder[label_end + 2..];
        let Some(target_end) = markdown_link_target_end(remainder) else {
            bail!("public community document {source} contains an unterminated Markdown link");
        };
        let target = remainder[..target_end].trim();
        remainder = &remainder[target_end + 1..];
        if target.is_empty()
            || target.starts_with('#')
            || target.starts_with("https://")
            || target.starts_with("http://")
            || target.starts_with("mailto:")
        {
            continue;
        }
        let target = target.split('#').next().unwrap_or_default();
        let source_parent = Path::new(source).parent().unwrap_or_else(|| Path::new(""));
        let resolved = root.join(source_parent).join(target);
        let resolved = resolved.canonicalize().with_context(|| {
            format!("public community document {source} has broken local link {target:?}")
        })?;
        if !resolved.is_file() || !path_is_within_directory_by_identity(root, &resolved)? {
            bail!("public community document {source} has unsafe local link {target:?}");
        }
    }
    Ok(())
}

fn path_is_within_directory_by_identity(root: &Path, path: &Path) -> Result<bool> {
    for ancestor in path.ancestors() {
        if same_file::is_same_file(root, ancestor).with_context(|| {
            format!(
                "compare community link ancestor {} with root {}",
                ancestor.display(),
                root.display()
            )
        })? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn markdown_link_target_end(input: &str) -> Option<usize> {
    let mut depth = 1_usize;
    let mut escaped = false;
    for (offset, character) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn quoted_assignment(source: &str, name: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let (left, right) = line.split_once('=')?;
        left.split_whitespace().any(|token| token == name).then(|| {
            right
                .trim()
                .trim_end_matches(';')
                .trim_end_matches("as const")
                .trim()
                .trim_matches('"')
                .to_owned()
        })
    })
}
