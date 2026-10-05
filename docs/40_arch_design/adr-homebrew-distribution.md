# Homebrew distribution of verified native packages

## Decision

Distribute the complete native CLI package through `TamaT-LLC/homebrew-tap`.
The first command is `brew install tamat-llc/tap/depgraph`; later commands can
use `brew install depgraph` and `brew upgrade depgraph`.
Status: proposed, pending independent organization-assigned review of this
release/workflow change. The [tap PR](https://github.com/TamaT-LLC/homebrew-tap/pull/3)
has merged after all four installation tests, required checks, and CodeRabbit review passed.

## Context

macOS and Linux users need a standard installer and update path. The stable
v0.6.1 Release has authenticated public evidence and native packages for all
four Homebrew targets, including Intel macOS. npm continues to serve four
platforms without Intel macOS; this decision does not change npm's target set.

## Package and verification

Keep the release tree byte-for-byte inside the Formula's `libexec` directory.
The CLI authenticates its manifest, workers, runtime components, and schemas
relative to its canonical executable. Moving individual workers or rewriting
packaged files would break that boundary. Small launchers expose `depgraph`
and `depgraph-mcp` and prepend Homebrew's `node@24` directory to `PATH`.
The Formula skips Homebrew shebang cleanup inside the release tree and supplies
separate prefix license copies so Homebrew does not move the verified originals.
Go/Rust project toolchains remain external. MCP/compiler-precise use continues
to require the matching separately verified compiler pack.

Generate the Formula from an immutable revision of the tap's release checker.
It binds public archive/checksum digests to authenticated post-publish evidence,
the signed annotated tag, and successful canonical full-CI/Release executions.
It rejects prereleases, missing targets, malformed identities, and downgrades.
The tap verifies the generated Formula again and tests native installation and
worker integrity on macOS/Linux ARM64/x86-64.

## Update credentials and execution

Run `Homebrew tap` on the protected main branch after a successful `Release`
workflow, or dispatch it manually against main. Never execute checkout code
from a triggering tag, fork, or `workflow_run.head_sha`. Verify the public
release before reading App credentials; bind automatic triggers to the Release
run recorded in the public evidence. Pin the separate checker checkout to a
full commit SHA and review that pin when updating its implementation.

Use the existing `tamat-homebrew-tap` App, installed only on homebrew-tap,
with Contents and Pull requests write permissions. depgraph-cli stores its own
App client ID variable and private-key secret. The action issues a short-lived
repository-scoped token and revokes it after the job. Git authentication is
passed through process environment, never a remote URL or persistent config.

The updater changes only `Formula/depgraph.rb` on a deterministic release
branch and opens/reuses a PR. Same-version byte changes and unrelated branch
changes fail closed. Reruns do not force-push. Formula-update PRs require a
maintainer merge after every platform check succeeds; automatic merging is
not enabled by this change.

## Alternatives

- Installing only the main binary loses packaged workers and evidence.
- A Homebrew/core submission requires a separate source-build Formula and
  upstream acceptance; it is a later route to installation without an initial tap.
- A custom installer duplicates Homebrew's dependency and upgrade handling.

## Consequences

The Formula adds Node.js 24 as a dependency. Homebrew patch versions may differ
from depgraph's verified toolchain baseline and produce best-effort diagnostics.
An absent native target blocks an update rather than silently installing the
wrong package. Target-set changes need an explicit Formula/template review.
The Homebrew workflow is independent of Release publication, so a tap update
failure does not unpublish a successful Release.
