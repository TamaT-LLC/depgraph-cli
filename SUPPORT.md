# Support

depgraph is maintained on a best-effort basis. The project does not promise a
response or resolution time and does not provide an SLA through this
repository.

## Supported release line

The supported stable line is the newest stable version whose official GitHub
Release and matching `release-post-publish-evidence-<tag>.json` asset exist and
agree.
During the `v0.5.4` rollout, the
[`v0.5.3` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.3)
remains supported until the same condition is satisfied for
[`v0.5.4`](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.4).
Release candidates and older stable versions are unsupported.
Fixes land on `main` first.
For a stable patch release, `release/0.5` advances by fast-forward to the exact
reviewed `main` commit that passed Full CI; it is not advanced by cherry-pick.
The pinned toolchains, five native archive targets, compatibility contract,
known limitations, and verified release links are listed in the
[English README](README.en.md).

## Where to ask

- For a reproducible defect in a supported release, use the bug report form.
- For a scoped enhancement, use the feature request form.
- For usage help, first search the [English README](README.en.md), release
  notes, and existing issues. If the documentation is insufficient, file a bug
  when the documented behavior is wrong or a feature request when new behavior
  is needed.
- For suspected vulnerabilities, use the private route in
  [SECURITY.md](SECURITY.md). Never use a public issue.
- For conduct or moderation concerns, follow
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Include the depgraph version, operating system and architecture, command,
minimal repository shape, expected behavior, actual behavior, and redacted
diagnostics. Do not attach proprietary source, credentials, personal data, or
unreviewed logs.

Maintainers triage when capacity permits. They may label, transfer, close, or
lock duplicate, inactive, out-of-scope, unsafe, abusive, or spam reports.
There is no automatic stale deadline: inactivity is considered together with
reproducibility, impact, and maintainer capacity. Repository issues are not a
substitute for commercial support or incident response.
