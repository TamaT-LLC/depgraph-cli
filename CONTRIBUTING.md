# Contributing to depgraph

Thank you for helping improve depgraph. Contributions must keep the CLI
local-first, explainable, deterministic, and fail-closed at security and
compatibility boundaries.

## Choose the right route

- Search existing issues before filing a report.
- Use the structured bug form for reproducible defects.
- Use the feature form for scoped proposals and explain the user problem.
- Follow [SUPPORT.md](SUPPORT.md) for usage questions and supported versions.
- Do not disclose a suspected vulnerability in an issue, pull request,
  discussion, commit message, test fixture, or log. Follow
  [SECURITY.md](SECURITY.md) instead.
- Follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) in every project space.

Maintainers may close duplicates, reports without enough safe reproduction
information, out-of-scope requests, spam, or abusive conversations. A closed
report may be reopened when the missing information is supplied.

## Before opening a pull request

Keep one pull request focused on one reviewable change. Link its issue, explain
the behavior and compatibility impact, and avoid unrelated generated or
dependency churn. Large architectural changes should begin with an issue and,
when they alter a durable contract, an ADR.

Run the complete local gate with the pinned Rust, Go, Node.js, and pnpm
versions:

```sh
cargo xtask test
```

Add tests that fail before the fix and cover malformed, boundary, deterministic,
and tamper cases when relevant. Update documentation and release notes for
user-visible behavior. Generated files and dependency updates must identify
their source, exact version, reproduction command, license/provenance impact,
and resulting lockfile or artifact changes.

Security-sensitive changes, workflows, release code, schemas/migrations,
dependency manifests, and governance documents require an independent
organization-assigned reviewer. Authors cannot provide their own independent
approval. All required CI must be green and every review conversation resolved
before merge.

## Developer Certificate of Origin

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
for inbound contributions. Use `git commit -s` to add your own `Signed-off-by`
line to every commit. The sign-off certifies that you have the right to submit
the work under this repository's
[MIT OR Apache-2.0](README.md#license) terms. A GitHub-provided no-reply address
is acceptable. The DCO is the active policy; no CLA is required unless
TamaT-LLC completes a documented legal review and updates this file before
accepting contributions under a CLA.

Do not add code, generated output, media, data, or other assets whose origin or
redistribution rights are unknown. Disclose relevant third-party notices and
conflicts of interest in the pull request.

## Review and merge

Maintainers evaluate correctness, security, compatibility, test coverage,
documentation, provenance, and scope. Review does not guarantee acceptance.
Changes normally merge through a pull request after independent approval,
green required checks, resolved conversations, and DCO verification. Release
and maintenance-line changes follow [GOVERNANCE.md](GOVERNANCE.md).
