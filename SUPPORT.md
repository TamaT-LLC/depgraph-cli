# Support

depgraph is maintained on a best-effort basis. The project does not promise a
response or resolution time and does not provide an SLA through this
repository.

## Supported release line

The supported stable line is `v0.5.0` once the official
[`v0.5.0` GitHub Release](https://github.com/TamaT-LLC/depgraph-cli/releases/tag/v0.5.0)
and its `release-post-publish-evidence-v0.5.0.json` asset exist and agree.
Before that condition is met there is no supported stable release. Release
candidates and historical versions are unsupported; fixes land on `main`
first and compatible stable fixes are cherry-picked with `-x` to
`release/0.5` through a separate pull request.
The pinned toolchains, five native archive targets, compatibility contract,
known limitations, and verified release links are listed in [README.md](README.md).

## Where to ask

- For a reproducible defect in a supported release, use the bug report form.
- For a scoped enhancement, use the feature request form.
- For usage help, first search [README.md](README.md), release notes, and
  existing issues. If the documentation is insufficient, file a bug when the
  documented behavior is wrong or a feature request when new behavior is
  needed.
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
