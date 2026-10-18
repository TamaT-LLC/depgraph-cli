# Installation guide

[日本語](install.md) | English

The [README](../../README.en.md) shows the shortest install commands. This
guide covers each distribution channel, archive verification, and building from
source.

`v0.6.4` is being prepared. Until its official Release and matching evidence
are published, use the published `v0.6.3` package in the versioned examples.

## Supported targets

`v0.6.4` targets Linux x86-64, Linux ARM64, macOS Apple Silicon, and Windows
x86-64. Intel macOS is not supported.
Use a version with its official Release and public post-publish evidence.

## Homebrew (macOS Apple Silicon / Linux)

```sh
brew install tamat-llc/tap/depgraph
```

After the first installation, the tap name can be omitted:

```sh
brew install depgraph
brew upgrade depgraph
```

If the tap was already added without trusting the formula, first run
`brew trust --formula tamat-llc/tap/depgraph`.
Homebrew installs Node.js 24 and the complete native package, including workers,
schemas, and license inventories. A Homebrew Node.js version different from the
verified `24.18.0` baseline produces a best-effort Web analysis diagnostic.
Go/Rust analysis needs the project's existing toolchains and offline dependencies.
Starting `depgraph-mcp` additionally requires the matching compiler pack below.
See the [Homebrew release procedure](../50_test/homebrew-release-procedure.md).

## npm / GitHub Release

`v0.5.0` was distributed only through GitHub Releases; npm distribution
starts with `v0.5.1`
under TamaT LLC's `@tamat-llc` organization scope.

`npm i -g @tamat-llc/depgraph` installs verified native packages for macOS Apple
Silicon, Linux x86-64 / ARM64, and Windows x86-64 without an install-time
external download. Intel macOS
packages are not provided for `v0.6.4`. The npm launcher
requires Node.js 24 or later. The `depgraph` CLI runs entirely from the npm
package. `depgraph-mcp` is included as well, but starting the MCP server also
requires the compiler pack for the same version and target from the GitHub
Release to be verified and extracted, with its requirement file supplied.

See the [npm release procedure](../50_test/npm-release-procedure.md) for
publication status and initial bootstrap details. Choose the `TARGET` for your
environment below.

| Environment | `TARGET` |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

Use GitHub CLI on macOS or Linux to download the archive and checksum.

```sh
VERSION=0.6.4
TARGET=aarch64-apple-darwin
ARCHIVE="depgraph-${VERSION}-${TARGET}.tar.gz"

gh release download "v${VERSION}" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "${ARCHIVE}" \
  --pattern "${ARCHIVE}.sha256"
```

Verify the checksum before extracting the archive. Use `shasum` on macOS and
`sha256sum` on Linux.

```sh
# macOS
shasum -a 256 --check "${ARCHIVE}.sha256"

# Linux
sha256sum --check "${ARCHIVE}.sha256"

tar -xzf "${ARCHIVE}"
"./depgraph-${VERSION}-${TARGET}/bin/depgraph" --version
```

From the repository root, one command verifies that the package works on the current host.
It reads the checksum automatically from `<archive>.sha256`.

```sh
cargo xtask verify-release-archive --archive "/absolute/path/to/${ARCHIVE}"
```

The command accepts only a native archive for the checkout's version.
It verifies the integrity of required artifacts declared by the manifest, `doctor`, Web / Rust / Go scans, query / export, MCP onboarding, and operations in temporary directories.
It does not change tracked source files or the regular Store.
It runs the complete native package gate, so it can take more than 30 minutes depending on the environment.
This command checks only the regular archive; post-publish verification separately authenticates the RC tag, public evidence, and compiler-pack archive.

On Windows, download `.zip` and `.zip.sha256` from the same Release, verify
them with `Get-FileHash -Algorithm SHA256`, and extract with `Expand-Archive`.
The release SBOM, license inventory, and compatibility information are included
in the archive.

## Compiler pack for `depgraph-mcp`

`depgraph-mcp` and the opt-in Rust compiler-precise mode need the compiler pack
published with the same release and target. Most users get it automatically
through `depgraph mcp setup`. To download and verify it by hand, see
[Compiler pack and release verification](../reference/compiler-pack-and-release-verification.md).

## Build from source

The pinned development toolchains are Rust 1.93.1, Go 1.26.1, Node.js 24.18.0, and pnpm 10.33.0.
From the repository root, build the CLI and the Rust, Go, and Web workers with:

```sh
cargo xtask build
target/debug/depgraph --version
```

Use `cargo xtask test` to run formatting, lint, contract, worker, and fixture
tests together. Development workflow and command details are in
[CONTRIBUTING.md](../../CONTRIBUTING.md).
