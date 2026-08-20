# ADR: npm distribution for the native CLI

- ID: `PROJ-ARC-001-ADR-008`
- Status: Accepted
- Date: 2026-08-19
- Updated: 2026-08-20
- Parent: `PROJ-ARC-001`

## Context

The stable v0.5.0 contract distributes five native archives through GitHub
Releases.
The repository also contains `@depgraph/web-worker`, but that package has been
private since its first commit and is an internal release component rather than
a supported JavaScript API.

An npm installation path must preserve the native archive layout because the
CLI verifies `release-manifest.json`, its own executable, sibling workers,
runtime components, schemas, licenses, and SBOM before using packaged workers.
A lifecycle script that downloads an executable from GitHub would introduce a
second network trust boundary, fail under `--ignore-scripts`, and make offline
or registry-proxied installation unreliable.

The public package set must belong to the npm organization `tamat-llc` instead
of an individual maintainer account.
npm organizations can manage scoped packages but cannot own unscoped package
names, so every supported package uses the `@tamat-llc` scope.

## Decision

Publish one root package and five exact-version native packages.

| npm package | Native target | Constraint |
| --- | --- | --- |
| `@tamat-llc/depgraph` | Platform selector and launch shim | Node.js 24 or later |
| `@tamat-llc/depgraph-darwin-arm64` | `aarch64-apple-darwin` | macOS ARM64 |
| `@tamat-llc/depgraph-darwin-x64` | `x86_64-apple-darwin` | macOS x64 |
| `@tamat-llc/depgraph-linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | Linux ARM64 with glibc |
| `@tamat-llc/depgraph-linux-x64-gnu` | `x86_64-unknown-linux-gnu` | Linux x64 with glibc |
| `@tamat-llc/depgraph-win32-x64` | `x86_64-pc-windows-msvc` | Windows x64 |

The root package exposes `depgraph`, `depgraph-cli`, and `depgraph-mcp` through
its `bin` map.
It declares the five native packages as exact-version
`optionalDependencies`; npm selects the matching `os`, `cpu`, and `libc`
package.
Neither the root package nor a native package defines an install or publish
lifecycle script.

Each native npm package contains the complete extracted, already verified
GitHub Release package.
The launcher resolves only the expected native package, requires its version
and target to match the root package, rejects symlinked metadata and
executables, and checks the selected executable against the SHA-256 in
`release-manifest.json` before spawning it.
The native binary then applies the existing release-manifest verification to
its remaining package closure.

The checked-in root package template remains `private: true`.
The release packager removes that field only in an isolated staging directory,
adds exact optional dependencies, generates native metadata, runs `npm pack`,
and records the six tarballs in `depgraph-npm-package-set-v1`.
Source directories, tests, and fixtures outside the verified native release
are not included.

## Publication boundary

The npm workflow is dispatched manually against the exact stable tag after the
GitHub `Release` run succeeds.
Its prepare job verifies the exact `main` commit, signed annotated tag, public
Release, post-publish evidence and the successful Release run named by that
evidence, five native archives, and generated npm package set without OIDC
permission.
It installs the Linux root/native tarball pair with lifecycle scripts disabled
and runs a packaged scan.

The publish job uses the protected GitHub Environment `npm` and has only
`id-token: write`.
It performs no checkout and executes no repository script.
It verifies the downloaded same-run tarballs, publishes native packages before
the root package, and requires npm provenance through Trusted Publishing.
No `NPM_TOKEN` or `NODE_AUTH_TOKEN` secret is stored.

npm requires a package to exist before a Trusted Publisher can be configured.
The six names therefore receive an inert `0.0.0-bootstrap.0` version under the
`bootstrap` dist-tag through one interactive, 2FA-protected publication before
the first supported npm release.
Bootstrap packages contain no executable, dependency, or lifecycle script.
The npm registry may also point `latest` at the only published version even
when the publish requested another tag.
The bootstrap version is therefore deprecated immediately, and the first
supported stable publication replaces `latest` through OIDC.
The root package is not bootstrapped until all five platform names exist.
Immediately afterward, each package is bound to repository
`TamaT-LLC/depgraph-cli`, workflow `npm-release.yml`, environment `npm`, and
publish-only permission; traditional token publication is then disabled and
the first supported stable version is published through OIDC.

Four unscoped native bootstrap packages were published before organization
ownership was selected.
They remain deprecated placeholders and never receive a supported stable
version; the supported package set is exclusively under `@tamat-llc`.

## Compatibility

The npm version always equals the stable native release version.
Release candidates are not published to npm by this workflow.
Published npm versions are immutable and are never rebuilt from a later commit.
The existing v0.5.0 GitHub Release predates this decision and remains a
GitHub-Release-only distribution. npm publication begins with `v0.5.1`, the
first stable tag that contains this contract.

Linux musl, Windows ARM64, and other targets fail with an explicit unsupported
platform error.
Adding a target requires a native GitHub Release archive, a new constrained npm
package, launcher mapping, package-set verification, installation smoke test,
and documentation update in the same release.

## Consequences

- `npm install --global @tamat-llc/depgraph` does not execute a lifecycle script or
  fetch executable bytes outside the npm registry.
- npm registry integrity, npm provenance, the package-set SHA-256 inventory,
  and the native release manifest form layered verification.
- A release publishes six immutable names and must tolerate safe retry after a
  partial registry failure; the root package is always published last.
- The private Web Worker remains an implementation detail and is not a public
  npm API.
