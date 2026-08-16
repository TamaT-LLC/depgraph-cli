# GitHub Actions security threat model

- Status: Active
- Contract: `github-actions-policy-v1`
- Owner: security maintainer
- Reviewers: repository administrator and release maintainer

## Trust boundaries

Pull requests, fork branches, issue text, artifact names, cache entries, and
repository files from an untrusted revision are attacker-controlled. Hosted
runner images, GitHub's OIDC issuer, environments, Actions artifacts/caches,
and every third-party Action are external dependencies. Organization secrets,
the repository token, release environments, tag deletion, advisory contents,
and published release artifacts are privileged surfaces.

The ordinary CI workflow has only `contents: read`, never uses
`pull_request_target`, and does not interpolate the `secrets` expression
context. Its exact trigger set is `pull_request`, `push`, and
`workflow_dispatch`. Manual dispatches retain the same read-only and
secret-free boundary as the other CI events. Pull requests and `main` pushes
run the Rust, Go, and Web checks. The compiler-precise hostile job always runs
on `main` push and `workflow_dispatch`; on pull requests it runs the expensive
steps only when relevant paths change (compiler crates, hostile scripts/docs,
or this CI workflow), and otherwise exits successfully without those steps so
required checks stay green. Benchmark,
Linux/macOS integration, and Windows smoke jobs run only on an explicit manual
dispatch. The verifier binds those expensive jobs to `workflow_dispatch`, so a
workflow edit cannot silently restore them on every merge. The verifier detects
the secrets context as an identifier regardless of
ASCII case, expression whitespace, or dot/bracket access syntax. Flow-style or
quoted `permissions` declarations are rejected so write scopes cannot bypass
the canonical block scanner. Permission scope keys and values must be
unescaped plain scalars; quoted, escaped, folded, aliased, or nested values fail
closed before checking for `write`. Hex and Unicode YAML escapes are forbidden
throughout a workflow, and every privileged workflow has an exact canonical
top-level trigger set, so escaped event or expression names cannot acquire
different GitHub semantics. It may compile and
test fork code, but that code receives no private-report, release, environment,
OIDC, organization, or write-capable repository credential. CI artifacts and
caches are untrusted inputs and cannot authorize a release.

The release workflow is triggered only by a pushed `v*` tag. Its quality,
benchmark, package, verification, and stable-gate jobs retain read-only
repository permissions. Only the final `publish` job receives job-scoped
`actions: read` and `contents: write`, after all exact-candidate verification
jobs succeed. `actions: read` is required only to bind the successful manual
full-CI run and its job conclusions into the post-publish evidence. The verifier
requires `contents` to be the complete write-scope set, so adding another write
permission to any release job fails the gate. It
downloads artifacts produced by the same run and verifies their manifests,
checksums, SBOMs, licenses, benchmark report, and stable release gate before
publication. The same final job requires a signed annotated tag object, creates
the GitHub Release, downloads the public assets into a fresh directory, and
repeats the package, compiler-pack, benchmark, and aggregate verification.
Every one of the 51 pre-evidence public assets must have the same filename,
size, and SHA-256 as its same-run workflow artifact. The resulting closed
`release-post-publish-evidence-v1` record binds the candidate commit/tree,
manual full-CI jobs, Release run, signed tag object, and public asset set; it is
uploaded and downloaded once more before the write-capable job succeeds. No
fork event can trigger this path.

The manual full CI run is a preflight for one candidate commit and cannot
authorize publication. The tag-triggered Release workflow rebuilds and verifies
its own artifacts from the tagged commit. A successful CI artifact is never
promoted into a release artifact.

The stable source guard handles `workflow_run` metadata without checking out or
executing the triggering revision. Its write token is restricted to cancelling
the release run and removing the protected release tag when the immutable
source identity is wrong; its complete write-scope set is exactly `actions` and
`contents`. It must never run repository scripts or consume an
artifact from the triggering run.

The v0.5.0 post-publish recovery workflow is an incident-specific read-only
closure verifier, not a second publisher. It has no dispatch inputs and only
job-scoped `actions: read` and `contents: read`. It pins the immutable source,
tree, signed tag object, exact Full CI run, failed Release run and job-set
digest, and public evidence digest in reviewed source. It accepts only a
`main` dispatch, verifies that the original failure occurred after publication
at the absolute-path Agent host canary boundary, compares all 52 GitHub Release
assets with the closed 51-asset evidence inventory, and runs the published
Linux binary with canonical absolute inputs. It cannot upload or replace an
asset, move a tag, change a check conclusion, or delete a run.

No current workflow requests `id-token: write` or an environment secret. If
OIDC or GitHub Environments are added, the policy must first bind the exact
workflow, protected tag, repository, audience, environment reviewers, and
subject claim, and must add negative fork and replay tests.

## Third-party Action review and update

`.github/actions-policy.json` is the canonical allowlist. Every non-local
`uses:` entry must match its action identity and reviewed 40-character commit
SHA exactly. The trailing major-version comment is documentation only.

To update an Action:

1. resolve the intended upstream ref through GitHub's commits API so annotated
   tags are peeled to their commit; never copy the tag-object SHA returned by
   the Git refs API. Fetch that immutable commit and review its release notes,
   source diff, runtime, transitive downloads, and permission changes;
2. verify the commit belongs to the documented upstream ref and record the
   exact identity, SHA, and reviewed ref in `.github/actions-policy.json`;
3. replace every workflow use atomically, run `cargo xtask test`, and inspect
   the workflow diff for new inputs, secret access, network publication, cache,
   artifact, runner, OIDC, or permission behavior;
4. require repository-administrator and security-maintainer review before
   merge. A mutable tag or branch is never a temporary fallback.

## Abuse cases and controls

| Threat | Required control |
| --- | --- |
| Fork changes a workflow to print a secret | no secrets and read-only token on pull requests; protected review for workflow changes |
| Mutable Action tag is retargeted | exact allowlisted full SHA and CI verifier |
| Cache or artifact is poisoned | never an authorization signal; release closure re-verifies exact digests |
| Runner image is compromised or persists data | ephemeral hosted runners, bounded credentials, no cross-job secret handoff |
| OIDC token is replayed | OIDC disabled until exact claims and environment review are implemented |
| Release tag points at another commit | immutable stable source guard cancels the run and removes the tag |
| `workflow_run` executes attacker code with write token | guard consumes metadata only and performs no checkout or repository execution |
| Post-publish recovery rewrites release history | no inputs or write scopes; exact immutable run/tag/evidence binding and published-binary canary only |
| Private advisory leaks into public CI | advisory data stays in GitHub Security Advisories and is represented publicly only by redacted dry-run digests |

## Evidence

The executable verifier covers action identity/SHA pinning, top-level
permissions, fork secret isolation, release trigger and publish permission
placement, the metadata-only source guard, and the redacted disclosure dry-run
ledger. Its output is evidence only; GitHub branch protection and environment
settings remain organization-admin controls.
