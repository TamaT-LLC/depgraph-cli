# ADR: Public OSS readiness and release governance

- Status: Accepted
- Date: 2026-07-25
- Decision ID: `PROJ-ARC-001-ADR-006`
- Issue: `PROJ-ARC-001-TASK-085` / #153
- Contract: `public-readiness-v1`

## Context

The repository is private at the time of this decision. It already has dual
MIT / Apache-2.0 project licenses, five-target release packaging, SBOM and
third-party license output, artifact checksums and attestations, and the
`stable-release-gate-v1` quality decision. Those controls establish whether a
specific product build is releasable. They do not establish whether the
repository, its history, collaboration records, GitHub Actions history, or
governance are safe and ready to become public.

The current repository also does not yet contain the complete public
community and security surface required by this ADR: `SECURITY.md`,
`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`, `GOVERNANCE.md`, issue
forms, a pull-request template, and an assigned team-backed `CODEOWNERS` file.
Adding placeholder contacts or naming an unconfirmed person would be worse
than keeping the repository private.

Changing a repository from private to public has a wider effect than exposing
the default branch:

- source and repository activity become public and anyone can fork the
  repository;
- GitHub Actions history and logs become public;
- existing push rulesets are disabled by the visibility transition and must
  be recreated and verified;
- content already copied, cloned, cached, forked, indexed, or downloaded
  cannot be recalled by changing the repository back to private.

Consequently, “make it private again” is only an incident-containment action.
It is not rollback in the transactional sense. Public visibility must be a
separate, explicitly authorized operation after an evidence-bound readiness
decision.

## Decision

Adopt `public-readiness-v1`.

The effective decision is:

| Field | Decision |
| --- | --- |
| Current visibility | `private` |
| Current public readiness | `reject` / no-go |
| Long-term direction | public OSS is permitted only after every mandatory gate passes |
| Accountable owner | TamaT-LLC organization owner |
| Execution owner | repository administrators designated by the organization owner |
| Visibility mutation | separate, explicitly authorized organization-owner action |

The repository remains private until a closed
`public-readiness-v1` decision record says `allow` for one exact candidate
commit and the TamaT-LLC organization owner gives an explicit go decision.
This ADR does not itself authorize or perform a GitHub visibility change.
Passing `stable-release-gate-v1` is mandatory but insufficient.

An `allow` decision expires when the candidate commit, audited reachable refs,
release inputs, governance documents, GitHub control snapshot, assigned role,
or material dependency/license inventory changes. The affected gates must be
rerun and a new decision record issued. There is no “mostly ready” public
state and no waiver field in v1.

## Options considered

### Publish immediately because the product release gate passes

Rejected. The product gate does not inspect all Git history, collaboration
records, Actions logs/artifacts, disclosure channels, maintainer authority,
or the post-transition GitHub configuration.

### Stay private permanently

Rejected as an irreversible policy choice. Public OSS can improve adoption,
review, and contribution, and the known blockers are measurable. The project
should preserve that option behind a strict gate.

### Stay private until a commit-bound readiness gate passes

Accepted. This gives the organization a reviewable no-go default, keeps the
visibility mutation separate from evidence production, and makes future
public migration repeatable.

## Authority and separation of duties

Roles are organization assignments, not personal names in this ADR.

| Role | Responsibility | May approve own work? |
| --- | --- | --- |
| TamaT-LLC organization owner | accountable for visibility, legal authority, role assignment, and final `allow` | no; consumes independent sign-offs |
| Repository administrator | freezes the candidate, gathers evidence, snapshots settings, executes an authorized migration | not for a gate they solely produced |
| Security maintainer | secret/history review, disclosure process, security settings, incident plan | no |
| Release maintainer | release identity, five-target artifacts, provenance, support window, rollback procedure | no |
| Legal/provenance reviewer | project license, inbound contribution terms, dependency and asset provenance, trademark/export review | no |
| Independent code reviewer | governance/control changes and protected-path review | no |
| Support/triage maintainer | support scope, issue/PR triage, moderation and response expectations | no |

The organization owner assigns at least one active person or organization team
to every role before the candidate freeze. A person may hold several
day-to-day roles, but one readiness bundle must record different authenticated
organization identities for evidence production, gate approval, and each final
approval. An identity used in one of those responsibility classes cannot
satisfy another class in the same bundle. The final visibility action requires
the organization owner plus the recorded security, legal, and release
sign-offs. Credentials and team membership use least privilege and are
reviewed at least quarterly and when a maintainer leaves.

## Decision record

The canonical JSON record has this closed top-level shape:

```json
{
  "schema_version": "public-readiness-v1",
  "repository": "TamaT-LLC/depgraph-cli",
  "candidate_commit": "<40 lowercase hex>",
  "audited_refs_digest": "<64 lowercase hex>",
  "github_settings_digest": "<64 lowercase hex>",
  "governance_tree_digest": "<64 lowercase hex>",
  "release_gate_digest": "<64 lowercase hex>",
  "evidence_manifest_digest": "<64 lowercase hex>",
  "gates": [
    {
      "id": "history-and-secrets",
      "decision": "allow",
      "evidence_digest": "<64 lowercase hex>",
      "producer_role": "repository-administrator",
      "producer_identity": "team:readiness-producers",
      "approver_role": "security-maintainer",
      "approver_identity": "team:readiness-gate-reviewers"
    }
  ],
  "decision": "allow",
  "decided_at": "<RFC 3339 UTC>",
  "accountable_role": "tamat-llc-organization-owner",
  "approvals": [
    {
      "role": "security-maintainer",
      "identity": "<organization-controlled identity>",
      "approved_at": "<RFC 3339 UTC>",
      "statement_digest": "<64 lowercase hex>"
    }
  ]
}
```

The complete record contains exactly one gate entry for each mandatory gate,
sorted by gate ID:

1. `candidate-and-surface`;
2. `governance-and-community`;
3. `history-and-secrets`;
4. `incident-readiness`;
5. `legal-and-provenance`;
6. `migration-dry-run`;
7. `release-and-support`;
8. `repository-controls`;
9. `security-and-disclosure`.

Each evidence digest is SHA-256 over the canonical evidence object with its
`evidence_digest` member omitted. The verifier recomputes it instead of
trusting a caller-supplied digest. Tool name, exact version, acquisition
digest, configuration digest, start/end time, input ref set, findings,
producer role and authenticated identity, and approver role and authenticated
identity are evidence, not unstructured comments. Raw secrets, scanner
matches, personal contact data, access tokens, and absolute workstation paths
must not enter the record or its public artifacts.

`decision` is `allow` only when every gate is `allow`, all required approvals
refer to the same immutable evidence manifest, and the candidate commit is
still the default-branch head. Otherwise it is exactly `reject`. A missing,
unknown, stale, unsigned, or malformed field is `reject`.

The readiness record is evidence, not an actuator. No workflow, bot, or CLI
may change repository visibility merely because a record says `allow`.

The closed record/evidence bundle is defined by
[`schemas/public-readiness-v1.schema.json`](../../schemas/public-readiness-v1.schema.json).
The core verifier canonicalizes both documents, binds every gate evidence
entry to the exact candidate/ref/settings/governance/release state, recomputes
canonical evidence digests, verifies independent authenticated identities and
role approvals, and emits only the deterministic
`evidence-only-no-visibility-actuator` decision.

## Executable pre-publication checklist

Every item below has a pass condition and retained evidence. A checked box
without the required evidence is not a pass.

### Gate 1: candidate and exposure surface

- [ ] Freeze one full 40-hex candidate commit on the default branch; pass when
  the working tree is clean, the remote head matches, and the commit is
  reviewed.
- [ ] Export the complete remote ref inventory for branches, tags, notes, and
  pull-request refs available to the auditor; canonical-sort ref name and
  object ID and retain its digest.
- [ ] Inventory repositories and surfaces affected by visibility: code and
  Git objects, Releases, packages, Actions runs/logs/artifacts/caches,
  environments, Pages, wiki, discussions, issues, pull requests, comments,
  attachments, webhooks, deploy keys, collaborators/teams, apps, secrets,
  variables, rulesets, branch/tag protections, and security settings.
- [ ] Record a redacted GitHub settings snapshot using an organization-owned
  credential; pass when the snapshot contains no secret values and a second
  administrator can reproduce its digest.
- [ ] Freeze or account for writes during the final audit window. Any new
  commit, tag, release asset, collaboration attachment, or Actions run after
  its relevant audit invalidates that gate.

Evidence: `candidate.json`, canonical `refs.json`, redacted
`github-surface.json`, their SHA-256 values, and independent review.

### Gate 2: history and secrets

- [ ] Scan the object closure reachable from every audited ref, including
  blobs, trees, commit messages, tag messages, LFS objects, and submodule
  pointers, with an exact-pinned secret scanner and repository-specific
  high-risk patterns.
- [ ] Independently review high-risk paths and history: environment files,
  key/certificate material, cloud configuration, release/signing scripts,
  registry credentials, internal hostnames, customer/employee data, dumps,
  generated fixtures, and binary archives.
- [ ] Scan issue/PR/discussion text, comments, attachments, wiki, Releases,
  packages, Actions logs/artifacts/caches, Pages, and any retained build output
  for credentials, private data, and confidential internal context.
- [ ] Classify every finding as false positive, public-safe, or confirmed
  exposure, with a non-secret remediation reference and independent security
  approval.
- [ ] Revoke or rotate every confirmed or plausibly exposed credential before
  rewriting or deleting content. History rewriting alone never remediates a
  credential.
- [ ] Purge affected refs, assets, logs, caches, attachments, or GitHub-hosted
  sensitive data through the supported GitHub process, then rerun the full
  scan over a fresh mirror.
- [ ] Perform an anonymous clone and source-archive inspection from the final
  candidate and confirm that no ignored local file or removed object is
  required by build/test/release.

Pass condition: zero unresolved secret/private-data findings, all confirmed
credentials rotated or revoked, purge verified, and both scanners/reviewers
sign the same final ref digest.

Evidence: tool identities and configurations, redacted finding ledger,
rotation/purge attestations without secret values, fresh-mirror digest, and
anonymous-clone result.

Issue #204 implements the bounded `public-history-audit-v1` scanner contract.
It binds canonical branch/tag/note/pull-request refs, Git object/LFS/submodule
inputs, and the issue/PR/discussion/wiki/release/Actions collaboration surface
to the compiled scanner/config identity. Its serialized ledger contains only
source/content digests, pattern IDs, counts, and remediation attestations.
Rotation or revocation, purge evidence, and a clean fresh-mirror rescan are all
required before a finding becomes resolved.

### Gate 3: legal, license, and provenance

- [ ] Confirm the project remains offered under `MIT OR Apache-2.0`, both
  license texts are intact, copyright notices are authorized, and README /
  package metadata / release manifests agree.
- [ ] Trace repository-authored, imported, generated, vendored, binary, model,
  font, image, fixture, and documentation assets to an authorized source and
  compatible redistribution terms.
- [ ] Decide and publish the inbound contribution rule. The v1 default is
  Developer Certificate of Origin sign-off unless the legal/provenance
  reviewer records an approved CLA alternative before public contributions.
- [ ] Reproduce dependency inventories and SBOMs for Rust, Go, Web, bundled
  runtimes, source data-trees, generated files, and all five native targets.
- [ ] Run exact-pinned license-policy and vulnerability scans; resolve every
  forbidden/unknown license, missing notice, critical/high vulnerability, and
  unreviewed source before `allow`.
- [ ] Verify `THIRD_PARTY_LICENSES.txt`, SBOM, package manifest, artifact
  contents, source/binary distribution obligations, and checksum closure
  against the exact candidate.
- [ ] Complete organization review for repository/product name, trademarks,
  patent/export concerns, privacy, and any customer or employment agreement
  that can restrict publication.

Pass condition: legal/provenance reviewer signs a zero-unresolved-finding
ledger for the candidate; “unknown” is not compatible with `allow`.

Evidence: provenance inventory, license report, vulnerability report, SBOM
digests, DCO/CLA decision, notices, and legal sign-off statement digest.

Issue #205 implements the deterministic `public-provenance-review-v1`
package. It aggregates project, generated, vendor, binary, font, image,
fixture, and document assets with Rust, Go, Web, bundled-runtime, and exact
five-target release evidence. Exact-pinned license and vulnerability policy
identities, SBOMs, license reports, `THIRD_PARTY_LICENSES.txt`, manifests,
archive checksums, the candidate commit, and release artifact closure are
digest-bound. Missing assets or notices, unresolved provenance,
unknown/forbidden licenses, and critical/high vulnerabilities reject the gate.

### Gate 4: security and disclosure

- [ ] Add `SECURITY.md` with supported versions, a private reporting route,
  expected acknowledgement, coordinated-disclosure behavior, scope, and a
  prohibition on reporting vulnerabilities through public issues.
- [ ] Assign at least two organization-controlled security managers or a
  documented continuity fallback; do not publish a personal secret or an
  unmonitored address.
- [ ] Dry-run a private report through triage, severity assessment,
  repository security advisory, private-fork remediation, CVE decision,
  release, credit, and disclosure.
- [ ] Prepare the exact post-public settings actions for private vulnerability
  reporting, security advisories, secret scanning, push protection, dependency
  alerts, automated dependency updates, and code scanning.
- [ ] Threat-model GitHub Actions triggers, forked pull requests, reusable
  workflows, environments, release credentials, OIDC trust, self-hosted
  runners, caches, artifacts, and untrusted build inputs.
- [ ] Remove long-lived release credentials where possible; protect remaining
  secrets with least privilege, environments, reviewers, and short lifetime.
- [ ] Pin every third-party GitHub Action to a reviewed full commit SHA. A
  mutable major tag such as `@v4` or `@v5` is a no-go.

Pass condition: security maintainer approves disclosure continuity and the
workflow threat model, with no unresolved critical/high finding or mutable
third-party Action reference.

Evidence: security-policy digest, dry-run record, workflow inventory and
pinning report, proposed settings manifest, and security sign-off.

Issue #206 implements `github-actions-policy-v1`: all third-party Actions are
pinned to reviewed full commit SHAs, workflow-wide permissions are read-only
or empty, and write permission is confined to the release publisher and
metadata-only stable-source guard. The executable policy verifier rejects
mutable refs, pin drift, broad top-level permissions, fork secret exposure,
and tampered disclosure exercises. The threat model and redacted
`security-disclosure-dry-run-v1` harness cover private report, advisory, fix,
verified release, and coordinated disclosure.

### Gate 5: governance and community

- [ ] Review `README.md` for a public audience: product status, installation,
  verified releases, supported platforms, compatibility, known limitations,
  license choice, documentation, support, contribution, and security links
  must be accurate and must not expose private context.
- [ ] Add and review `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`,
  `GOVERNANCE.md`, structured issue forms, pull-request template, and
  security-report routing.
- [ ] State project scope, roadmap authority, decision process, maintainer
  nomination/removal, conflict handling, code-of-conduct enforcement,
  moderation, and appeal path.
- [ ] State that support is best effort with no implied SLA, list supported
  release lines, and distinguish bugs/features/questions from private
  vulnerability reports.
- [ ] Define issue labels, duplicate/invalid handling, reproduction
  expectations, triage cadence, inactivity/stale policy, abuse/spam response,
  and who may close or lock a conversation.
- [ ] Define PR size/scope, tests, DCO/CLA attestation, review expectations,
  generated/dependency updates, security-sensitive changes, and release-note
  requirements.
- [ ] Assign organization teams before adding `CODEOWNERS`; every pattern must
  name an existing team with active members and least-privilege access.
- [ ] Verify the GitHub community profile and every document link through an
  anonymous session.

Pass condition: the public README and all mandatory documents exist at the
candidate commit, every contact and team is live, there are no placeholder
values, and governance/support owners approve the tree digest.

Evidence: governance-tree digest, team/role attestation, link/community-profile
report, and approvals.

### Gate 6: repository controls

- [ ] Define the post-transition default-branch and tag rulesets before the
  visibility change. The default branch requires pull requests, at least one
  independent approval, dismissal/reapproval for relevant new commits,
  resolved conversations, and exact required status checks with expected app
  sources.
- [ ] Require code-owner or designated security/release-team approval for
  `.github/workflows/**`, release/signing/security policy, dependency
  manifests/locks, schema/migration, and governance control paths.
- [ ] Prohibit direct push, force push, branch/tag deletion, and ruleset bypass
  except a minimal audited emergency role.
- [ ] Inventory GitHub Apps, webhooks, deploy keys, fine-grained tokens,
  collaborators, teams, environments, runners, Pages, and package permissions;
  remove stale, broad, personal, or unexplained access.
- [ ] Ensure required checks run on the candidate and cannot be satisfied by a
  same-named check from an untrusted source.
- [ ] Export a desired-state settings manifest and a read-only verifier that
  fails on a missing/disabled rule, wrong source, bypass expansion, or
  unexpected public surface.

Pass condition: two administrators approve the desired state and the verifier
passes in a dry-run repository with the same organization plan/features.

Evidence: desired-state manifest, access review, dry-run before/after settings
snapshot, verifier identity/output, and approvals.

### Gate 7: release and support

- [ ] Run the complete local and GitHub Actions quality suite for the exact
  candidate on all supported platforms.
- [ ] Produce `stable-release-gate-v1=allow` for the same candidate and retain
  all five archives, checksums, SBOMs, provenance/attestations, release notes,
  and gate record by digest.
- [ ] Use Semantic Versioning; create an immutable annotated and
  cryptographically verifiable release tag from the reviewed commit.
- [ ] Require two-person release approval, protected release environment,
  exact artifact-to-source identity, and verification after upload.
- [ ] Publish a support matrix, compatibility promise, known limitations,
  deprecation policy, and security-fix policy consistent with the release
  notes.
- [ ] Dry-run failed publish, withdrawn artifact, compromised credential,
  broken package, and urgent security release procedures.
- [ ] Confirm no release step depends on private-only source, local state,
  unpinned downloads, an individual workstation, or an unavailable
  maintainer.

Pass condition: release maintainer and independent reviewer approve one
reproducible release closure whose commit matches the readiness record.

Evidence: CI run identities, stable gate and artifact digests, signed tag
verification, support matrix, and release dry-run results.

### Stable baseline and maintenance line

The first stable release is anchored by `release-baseline-v1` at commit
`d5ca92bae4b4fdbbedb2f3cabd4aa3ef731e7c9f`. The canonical record and its
SHA-256 are defined in `docs/releases/v0.4.0.md`. The initial
`refs/heads/release/0.4` ref points to that exact commit, and the peeled
`v0.4.0` tag is valid only at the same commit.

`main` remains the next-version development line. A fix shared with 0.4.x
lands on `main` first and is cherry-picked with `-x` through a distinct pull
request to `release/0.4`. An urgent stable-first fix is forward-ported through
a distinct pull request to `main`. Wholesale merges from `main`, force-pushes,
history rewrites, and backports that narrow the 0.4.x compatibility promise
are forbidden. Pull requests record the source commit, issue, compatibility
assessment, and verification so both directions remain auditable.

Next-version work on `main` that could alter an existing default remains
default-disabled or explicitly opt-in while 0.4.x is supported. A breaking
default requires a new minor release and migration contract. It does not enter
the stable line as a patch.

The baseline source predates this decision and cannot contain a new source
check without changing the immutable commit. A `workflow_run(requested)`
guard therefore executes from the default branch for the `Release` workflow.
For `v0.4.0`, it compares `head_sha` with the recorded baseline; a mismatch
cancels the release run and deletes the invalid tag before the baseline
workflow can publish it. The baseline's existing `stable-release-gate-v1`
continues to close artifacts, compatibility, benchmarks, and release jobs.
Operators also reproduce the documented commit, tree, canonical digest,
remote maintenance ref, and signed annotated tag before publication. The
immutable anchor is not redefined when later approved patch commits advance
`release/0.4`.

### Gate 8: migration dry run and change window

- [ ] Back up a fresh mirror plus repository metadata/settings exports and
  record restore/containment ownership.
- [ ] Rehearse the documented sequence in a temporary organization repository
  with equivalent plan/features and non-sensitive fixtures.
- [ ] Confirm the GitHub visibility-change effects against current official
  documentation immediately before the window.
- [ ] Pre-stage desired rulesets/settings because visibility change disables
  existing push rulesets; record the exact operator and verifier steps.
- [ ] Obtain a final organization-owner `allow` tied to the candidate,
  evidence-manifest digest, settings digest, named role assignments, and
  maintenance window.
- [ ] During the authorized window only: stop writes, reconfirm the remote
  head/ref digest, change visibility, recreate and enable branch/tag rulesets,
  enable public security features and private vulnerability reporting, then
  run the desired-state verifier.
- [ ] From an anonymous account/network, verify clone and archive, README and
  community links, issue/PR templates, security routing, Actions logs,
  Releases/packages/Pages, artifact verification, and installation on every
  supported target.
- [ ] Reopen writes only after both the settings verifier and anonymous
  smoke-test report pass. Otherwise enter incident containment.

Pass condition: rehearsal passes, all final inputs are unchanged, explicit
owner authorization exists, and the runbook has deterministic stop/no-go
points. The actual production visibility mutation is not part of an ordinary
documentation PR.

Evidence: backup digests, rehearsal log, official-document review date,
authorization statement digest, change-window log, settings verification, and
anonymous smoke report.

### Gate 9: incident readiness

- [ ] Maintain an incident tree covering secret/private-data exposure,
  malicious contribution, compromised maintainer/app/action, package or tag
  compromise, legal takedown, code-of-conduct emergency, and support overload.
- [ ] Define 24-hour organization-owned escalation coverage for the change
  window and the initial public observation period; this is incident
  readiness, not a general product-support SLA.
- [ ] For exposure, immediately contain writes/automation, revoke and rotate
  credentials, remove affected releases/artifacts/runs where supported,
  preserve a non-public audit trail, and contact GitHub Support for sensitive
  data removal when required.
- [ ] Use repository security advisories and coordinated notification for a
  vulnerability; use legal/privacy escalation for regulated or third-party
  data.
- [ ] Record that changing back to private cannot retract clones, forks,
  downloads, logs, caches, mirrors, or indexes. Communications and credential
  response continue after containment.
- [ ] Define decision authority for making the repository private, suspending
  Releases/packages/Pages/Actions, rotating signing identity, and publishing
  an incident notice.

Pass condition: every scenario has an owner, contact path, containment
sequence, evidence-preservation rule, communication authority, and completed
tabletop exercise.

Evidence: redacted incident plan, call tree, tabletop result, and accountable
owner approval.

## Migration invariants

The production visibility transition must preserve these invariants:

1. the authorized candidate is still the default-branch head;
2. the audited ref set and evidence digests have not changed;
3. every required governance file and protected-path owner exists;
4. no secret value is printed into a command transcript or readiness record;
5. public Actions never expose private-repository secrets to forked code;
6. required checks identify their expected GitHub App source;
7. rulesets are active before normal writes resume;
8. private vulnerability reporting and the advertised contact work;
9. public archives equal the verified release closure;
10. any failed verification stops the migration and enters containment.

No automation may weaken an invariant to complete the window. A partial
transition is a failed transition.

## Maintainer, review, release, support, and contribution policy

The public governance documents implement these minimum rules:

- changes land through pull requests; authors do not provide their own
  independent approval;
- all required CI is green and all review conversations are resolved;
- security, workflow, release, schema/migration, and governance paths require
  their assigned owner review;
- maintainers disclose conflicts, use least privilege and strong
  authentication, and lose access promptly when inactive or removed;
- releases are built from immutable reviewed commits, pass the stable release
  gate, receive two-person approval, and publish verifiable artifacts;
- supported versions and known limitations are explicit; support is best
  effort and no response-time promise is inferred;
- bugs and features use public issue forms, while suspected vulnerabilities
  use the private security channel;
- contributions follow the published DCO or approved CLA, license/provenance
  rules, test requirements, and code of conduct;
- project direction and maintainer appointments follow `GOVERNANCE.md`, not
  repository access alone.

## Staged implementation

Each row is an independently reviewable one-to-three-day follow-up.

| Slice | Deliverable | Estimate |
| ---: | --- | --- |
| 1 | Community/governance documents, issue forms, PR template, DCO/CLA decision | Implemented in #202 |
| 2 | Closed readiness/evidence schemas and deterministic verifier | Implemented in #203 |
| 3 | All-ref/history/collaboration secret audit tooling and redacted ledger | Implemented in #204 |
| 4 | Dependency/license/provenance inventory and legal review package | Implemented in #205 |
| 5 | Workflow SHA pinning, threat model, disclosure policy, and security dry run | Implemented in #206 |
| 6 | Desired GitHub settings/rulesets manifest, access review, and verifier | 2-3 days |
| 7 | Temporary-repository migration rehearsal and anonymous smoke suite | 2-3 days |
| 8 | Candidate-bound final audit, owner decision, authorized change window, and observation | 2-3 days |

Slices 1-7 may proceed while the repository remains private. Slice 8 cannot
start until all earlier evidence is final and requires explicit organization
owner authorization for any production visibility change.

## Acceptance matrix

| Scenario | Required result |
| --- | --- |
| Current repository lacks mandatory governance/security documents | `reject`; remain private |
| Stable release gate passes but history audit is missing | `reject`; product readiness does not imply public readiness |
| Scanner reports a credential that was removed but not rotated | `reject` |
| One dependency or asset has unknown redistribution rights | `reject` |
| A third-party Action uses a mutable tag | `reject` |
| Candidate commit or audited refs change after approval | previous decision expires; rerun affected gates |
| One required role is unassigned or approves its own sole work | `reject` |
| Ruleset dry run cannot reproduce required controls | `reject` |
| All gates pass but organization owner has not authorized visibility | remain private |
| Visibility changes but rules/settings verification fails | stop writes and enter incident containment |
| Repository is made private after exposure | continue incident response; do not claim retraction |
| All gates and independent approvals match one unchanged candidate | readiness may be `allow`; visibility still requires the separate owner action |

## Consequences

Public OSS remains possible, but not by merging this ADR or passing product
CI. The immediate result is an explicit private/no-go state with named
organizational accountability and a finite path to `allow`.

The gate adds work before publication: community documents, history and
collaboration scanning, legal/provenance review, workflow hardening, GitHub
control rehearsal, and incident preparation. That cost is intentional because
the transition cannot be fully undone.

The contract also avoids false confidence:

- a clean current tree is not a clean history;
- a license file is not a complete provenance audit;
- green CI is not a safe public Actions configuration;
- a release gate is not a repository-publication gate;
- making a repository private is not data recall.

## References

- GitHub Docs, Setting repository visibility:
  https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility
- GitHub Docs, Configuring private vulnerability reporting:
  https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configuring-private-vulnerability-reporting-for-a-repository
- GitHub Docs, Repository security advisories:
  https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories
- GitHub Docs, Available rules for rulesets:
  https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets
- GitHub Docs, Best practices for repositories:
  https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories
- GitHub Docs, Status checks:
  https://docs.github.com/en/pull-requests/reference/status-checks
- Stable `v0.4.0` release contract: `../releases/v0.4.0.md`
