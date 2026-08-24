# Security Policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| `v0.5.2` | Supported after the official GitHub Release and matching post-publish evidence exist |
| `v0.5.1` | Supported until the verified `v0.5.2` publication; unsupported afterward |
| `v0.5.0` | Unsupported |
| `main` and release candidates | Evaluation only; fixes land on `main` first |
| v0.4 candidates and older versions | Unsupported |

At any time, only the newest stable version with a verified publication is
supported. The release and maintenance policy is documented in
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

## Compiler-precise validated cache

The opt-in Rust compiler-precise cache is a separate trust boundary from the
normal build cache. A hit still requires all three execution consent flags
because a miss or rejected entry may execute project build scripts or proc
macros in the same invocation.

The cache key binds the admitted repository tree and filesystem metadata,
manifest/lock/config inputs, safe base snapshot and profile plan, exact compiler
pack closed-tree attestation, rustc/wrapper/query/Cargo identities, validated
host linker tools, allowed non-secret environment inputs, and every relevant
contract version. Run IDs, timestamps, temporary paths, and secret values are
never cache identity or payload inputs. Inputs that cannot be represented by
this bounded contract are not cached.

Warm entries are treated as untrusted persisted data. depgraph re-verifies the
pack, key, payload digest, base and source snapshots, graph delta, Cargo unit
conservation, invocation ledger, and typed MIR ledger before creating a new
atomic build attempt. Corrupt or incompatible entries are never partially
promoted. A failed pre-commit source/pack check rolls back the new audit,
attempt, snapshot, cache event, and current pointer. Cache storage or eviction
failure does not invalidate an already completed cold compiler-precise result.

Each entry is limited to 64 MiB; the store retains at most 32 entries and 512
MiB of compiler-precise payloads using transactional LRU eviction. Eviction
removes cache references only and cannot delete a completed snapshot.

Maintainers exercise the private report → triage → private advisory → private
fix → verified release → coordinated disclosure handoff with the redacted
[security disclosure dry-run harness](docs/50_test/security-disclosure-dry-run.md).
The exercise never stores vulnerability details in the repository and never
gives forked code access to private-report or release credentials.

Never test against systems or data you do not own or have permission to use.
Avoid privacy violations, service disruption, destructive testing, and
exfiltration. Good-faith reports following this policy will be handled
confidentially to the extent practical.
