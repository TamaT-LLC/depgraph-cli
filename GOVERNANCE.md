# Governance

## Scope and authority

depgraph is an open-source project stewarded by TamaT-LLC. The project scope is
a local-first CLI that produces explainable, deterministic dependency evidence
without silently crossing its declared execution and trust boundaries.
TamaT-LLC's organization owner is accountable for legal authority, repository
visibility, role assignment, and final release/public-readiness decisions.

Organization-assigned maintainers guide the roadmap, triage, review, security,
releases, support, and moderation. Repository access alone does not grant
project authority. A maintainer acts only within the role and permissions
assigned by the organization owner.

## Decisions and changes

Routine changes are decided through reviewed pull requests. Maintainers seek
rough consensus based on user impact, correctness, security, compatibility,
maintainability, and project capacity. The responsible maintainer records the
decision and rationale when consensus is not reached. Durable architecture,
security-boundary, release, or governance changes require an ADR and an
independent reviewer.

Authors do not normally approve their own work. Required CI must be green and
review conversations resolved. Security, workflows, release controls,
dependency manifests, schemas/migrations, and governance paths require an
organization-assigned reviewer for that domain. Conflicted reviewers disclose
the conflict and recuse. The organization owner grants `@TakehiroT` a
pull-request-only code-owner bypass for an audited emergency; it does not bypass
required CI, non-fast-forward/deletion protection, or version-tag protection.

The issue tracker informs the roadmap but does not create a delivery promise.
Organization-assigned maintainers may prioritize, defer, or decline work based
on scope, risk, compatibility, and capacity. Material project direction is
recorded in issues, pull requests, release notes, or ADRs rather than private
individual preference.

## Maintainer lifecycle and owner boundary

The TamaT-LLC organization owner appoints maintainers after sustained,
constructive contributions and evidence that the candidate can apply the
project's security, review, provenance, and conduct policies. Appointments
record the role, scope, least-privilege access, and an independent approver.
Access and role assignments are reviewed at least quarterly and when a
maintainer becomes inactive, changes responsibility, or leaves.

A maintainer may resign at any time. The organization owner may remove or
limit a maintainer for inactivity, loss of trust, policy violations, unresolved
conflicts, security risk, or organizational need. Removal revokes access
promptly while preserving a restricted audit record and a continuity handoff.

The `CODEOWNERS` principals are added only after the organization owner confirms
that each account is an active TamaT-LLC maintainer with repository access and
the relevant role assignment. The current owner pair is `@TakehiroT` and
`@Fuelda`; both accounts have independently confirmed repository administration
access. Invented identities and placeholder contacts are not acceptable
substitutes. Access and role changes must update `CODEOWNERS` and the repository
access review in the same change.

## Releases and maintenance

Releases come from immutable reviewed commits and must pass the complete local
and GitHub Actions quality gates, five-target package verification, SBOM and
license closure, and the stable release gate. A release requires a release
maintainer plus an independent approver. The supported stable line is the
newest stable version whose official Release and matching post-publish evidence
exist. During the `v0.5.2` rollout, `v0.5.1` remains supported until that
condition is satisfied for `v0.5.2`. The existing `release/0.4` ref and v0.4
tags are preserved historical anchors, not a current maintenance promise.
For each stable v0.5 patch, the signed tag, remote `main`, and `release/0.5`
must identify the same reviewed, exact-Full-CI-green source at publication.
Compatible fixes land on `main` first. After Full CI fixes the release
candidate, `release/0.5` advances to that exact commit by fast-forward only.
Force-pushes, history rewrites, and breaking defaults are forbidden on the
maintenance line.

Release support is best effort and has no implied SLA. Security fixes follow
[SECURITY.md](SECURITY.md); other support follows [SUPPORT.md](SUPPORT.md).

## Moderation, conflicts, and appeals

Organization-assigned maintainers may label, close, transfer, edit, hide, or
lock project conversations for duplication, scope, safety, spam, abuse, or
code-of-conduct enforcement. They explain ordinary actions publicly when safe.
Confidential evidence and enforcement records remain restricted.

Conflicts of interest must be disclosed before review or enforcement.
Technical decisions may be appealed with new evidence in the original issue or
pull request. Conduct or confidential governance appeals follow
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The appeal reviewer must be
independent of the original sole decision. The TamaT-LLC organization owner is
the final escalation point for role, legal, visibility, and project-scope
decisions.

Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md), including the
Developer Certificate of Origin, and by
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
