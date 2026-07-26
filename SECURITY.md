# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest `0.4.x` release | Supported |
| `main` and release candidates | Evaluation only; fixes land on `main` first |
| `< 0.4` | Unsupported |

The stable release and maintenance policy is documented in
[GOVERNANCE.md](GOVERNANCE.md). Unsupported versions may still receive a
public advisory, but are not promised a patch.

## Report a vulnerability privately

Do not open a public issue, pull request, discussion, or commit containing a
suspected vulnerability or exploit details. Submit a
[private vulnerability report](https://github.com/TamaT-LLC/depgraph-cli/security/advisories/new)
through GitHub Security Advisories. This is the organization-controlled route
for depgraph security reports; do not send credentials or secrets anywhere
else.

Include the affected version or commit, impact, minimal reproduction, and any
suggested mitigation. Remove credentials, personal data, customer data,
private repository contents, and unrelated secrets from evidence. If the
private reporting form is unavailable, do not publish the report: use
GitHub's organization contact surface to notify TamaT-LLC that the private
route needs restoration, without including vulnerability details.

## What to expect

Security handling is best effort and does not create a response-time SLA. An
organization-assigned security maintainer will acknowledge a usable report,
assess severity and affected versions, coordinate a fix in a private advisory
when appropriate, decide whether a CVE is needed, and agree on disclosure and
credit with the reporter. Public disclosure waits until users have a
reasonable remediation path unless active exploitation or another overriding
safety concern requires a different schedule.

Reports about the safe-scan boundary, worker isolation, release artifact
integrity, dependency confusion, path traversal, command execution, secret
exposure, or GitHub workflow/release compromise are in scope. General support,
feature requests, and dependency warnings without a depgraph impact belong in
the routes described by [SUPPORT.md](SUPPORT.md).

Never test against systems or data you do not own or have permission to use.
Avoid privacy violations, service disruption, destructive testing, and
exfiltration. Good-faith reports following this policy will be handled
confidentially to the extent practical.
