# Homebrew publication and validation

## Bootstrap

The [initial tap Formula PR](https://github.com/TamaT-LLC/homebrew-tap/pull/3)
was followed by the [v0.6.2 platform update](https://github.com/TamaT-LLC/homebrew-tap/pull/6).
For current releases, require successful installation on the three supported
targets, expected rejection on Intel macOS, and passing `brew audit` /
`release check` jobs. Before merging depgraph's workflow change, obtain
independent organization-assigned review under CONTRIBUTING.md/GOVERNANCE.md
and update its pinned tap-tools revision to the reviewed commit if needed.

Configure `HOMEBREW_TAP_APP_CLIENT_ID` and `HOMEBREW_TAP_APP_PRIVATE_KEY` in
TamaT-LLC/depgraph-cli using the existing `tamat-homebrew-tap` App. The App's
installation stays limited to homebrew-tap. Generate a dedicated private key,
register its contents as a repository secret, and delete the downloaded file.
No App installation on depgraph-cli is needed. Never put the key in logs,
source, PR bodies, or command arguments.

After the reviewed workflow is on main, dispatch `Homebrew tap` with
`tag=v0.6.2` and `dry_run=true`. It authenticates the public release before
issuing the token, clones the tap, and reports no change when the Formula
already matches. It does not push or open a PR in dry-run mode.

## Public installation

```sh
brew install tamat-llc/tap/depgraph
brew test tamat-llc/tap/depgraph
brew install depgraph
```

The first fully qualified command adds the tap and trusts this Formula. If
already tapped without trust, run `brew trust --formula tamat-llc/tap/depgraph`.
`brew test` uses a temporary repository/store; it performs a Web scan, checks
that the scan completed, and authenticates the release and all three workers
through `doctor`. Go/Rust toolchains and the optional compiler pack are
configured separately as described in the README. Test macOS ARM64 and Ubuntu 24.04 ARM64/x86-64 before claiming Homebrew support
for its three installation targets. On Intel macOS, verify that installation
is rejected by the ARM64 requirement.

## Stable updates

A successful stable `Release` triggers `Homebrew tap` on trusted main code.
Its immutable verifier rejects any release without matching signed-tag,
full-CI, Release, public evidence, and three native archive/checksum identities.
The App then pushes a Formula-only update branch and opens/reuses a tap PR.
Merge it only after all platform checks are green and review is complete.
An identical Formula produces no PR; newer tap versions cannot be downgraded.

Retry with a main-branch manual dispatch for the same stable tag. Start with
`dry_run=true`, then use `false` to create a PR. Existing same-version Formula
changes or unrelated files on an update branch require manual investigation;
the workflow never force-pushes them. Missing targets require a reviewed
Formula/template change, not a checksum exception.

If the immutable checker changes, review and update the tap-tools SHA in the
workflow and run both the updater regression tests and the repository gate:

```sh
node --test scripts/tests/homebrew-tap.test.mjs
cargo xtask test
```

The App token has no depgraph-cli write permissions. Tap-update failures are
reported in the separate workflow and do not remove published releases.
