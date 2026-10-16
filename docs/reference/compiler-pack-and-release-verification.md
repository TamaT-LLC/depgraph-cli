# Compiler pack and release verification

[Back to the README](../../README.en.md) · [Installation guide](../guide/install.en.md)

The opt-in Rust compiler-precise toolchain is distributed separately from the
normal archive. `cargo xtask compiler-pack SOURCE OUTPUT --spec SPEC.json`
builds one target-specific, closed-tree pack from pre-extracted official
components and their sorted file ownership inventory. The resulting manifest
digest must be published through the referenced release checksum set; the core
requires that external digest and verifies the pack before project staging and
again after the supervised process tree has stopped. It never downloads through
rustup or falls back to PATH, system, or project toolchains.

Release tags build separate compiler packs for Linux x86-64/ARM64, macOS
Apple Silicon, and Windows x86-64 with `cargo xtask
compiler-pack-package`. Intel macOS packs are no longer built. Each native job verifies archive extraction,
closed-tree attestation, wrapper/query handshakes, typed MIR and monomorphized
call semantics, cross-checkout determinism, resource budgets, legal/provenance
metadata, tamper rejection, and rollback. `cargo xtask
verify-compiler-pack-assets` requires every pack to share
`compiler-pack-five-target-release-v1`, the pinned toolchain/rustc/schema/query
identity, and the canonical semantic shape before the stable release gate can
publish them. Release metadata and `doctor --json` expose this separate
distribution and its `unsupported-no-fallback` policy.

Download the four assets for the depgraph version and host target from the
same [GitHub release](https://github.com/TamaT-LLC/depgraph-cli/releases). The
release tag may be the stable tag or its matching release candidate. The example
below uses the published v0.6.3 stable release. The normal depgraph archive and
compiler pack must come from one release run.

```bash
version=0.6.3
release_tag=v0.6.3
target=x86_64-unknown-linux-gnu # doctor --json reports compiler_pack.host_target
name="depgraph-compiler-pack-${version}-${target}"

gh release download "$release_tag" \
  --repo TamaT-LLC/depgraph-cli \
  --pattern "$name.tar.gz" \
  --pattern "$name.tar.gz.sha256" \
  --pattern "$name.requirement.json" \
  --pattern "$name.smoke.json" \
  --dir "$name"
(cd "$name" && sha256sum --check "$name.tar.gz.sha256" && tar -xzf "$name.tar.gz")
depgraph doctor --compiler-pack-requirement "$name/$name.requirement.json"
```

Use `shasum -a 256 --check` on macOS. On Windows, download the `.zip` and
`.zip.sha256` assets, verify the SHA-256 with `Get-FileHash`, and extract with
`Expand-Archive` into the directory containing the requirement JSON. The
requirement's relative `root` then resolves to the extracted pack. A missing,
wrong-version, wrong-target, or modified pack remains unavailable; `doctor`
prints the exact expected asset names and depgraph never falls back to another
compiler.

The first compiler-precise execution stage is explicitly selected with all
three invocation gates and a release-bound requirement document:

```text
depgraph resolve --build PATH --allow-project-code --rust-compiler-precise \
  --compiler-pack-requirement compiler-pack-requirement.json
```

The requirement JSON contains `root`, `expected_manifest_sha256`,
`release_checksum_reference`, `host`, and `target`; a relative `root` is
resolved beside the requirement document. This stage replaces project Cargo
configuration with a deterministic offline projection after rejecting compiler,
wrapper, runner, linker, credential-provider, alias, environment, and unsafe
rustflag injection. It runs only the attested Cargo with `--frozen --offline
--unit-graph -Z unstable-options`, validates and canonicalizes unit graph v1,
and does not start rustc, build scripts, or proc macros. Registry and Git
dependencies are copied from an existing host Cargo cache into a bounded,
run-owned, credentials-free subset before Cargo starts; their source paths are
accepted only inside that staged Cargo home and normalized as
`cargo-home://...`. No network lookup or direct host-cache path is exposed to
the child or persisted DTO. A second supervised stage starts a fresh target,
fixes the attested wrapper as the only `RUSTC_WRAPPER`, verifies the exact
rustc path, executable digest, and `-vV` identity, and conserves one bounded
start/terminal ledger pair for every admitted target, dependency, build-script,
and proc-macro compiler unit. Nested wrappers, response/path escape,
extra/missing/duplicate units, partial terminals, or compiler substitution fail
the whole attempt. The canonical ledger contains staged logical paths and
digests rather than host paths or raw process streams. Later compiler-precise
stages add compiler query output; the ledger stage still does not promote graph
evidence.

Run `rustup component add rust-src --toolchain 1.93.1` once, then `cargo xtask package` to create a native archive under `dist/`. Release archives place `depgraph` and `depgraph-mcp` under `bin/`, compatible workers and `depgraph-operation-runner` under `libexec/`, and include the project's complete `LICENSE-MIT` and `LICENSE-APACHE` texts, checksum-verified protocol and `depgraph-mcp-tools-v1` schemas, an SPDX SBOM, and a separate third-party license inventory. The release manifest declares `MIT OR Apache-2.0`, attests both project license files independently from `THIRD_PARTY_LICENSES.txt`, and binds the MCP server and runner digests to `rmcp 3.1.0`, MCP revision `2026-07-28`, `depgraph-mcp-tools-v1`, and `depgraph-operation-v2`. The SBOM and license inventory include the complete shipped rmcp dependency closure and an Apache-2.0 notice. The release gate fixes Rust/Cargo `1.93.1`; the Rust worker manifest records the linked backend unit, rust-analyzer `0.0.330` at revision `8954b66d43225e62c92e8bbcc8500191b5cceb1e` with Salsa `0.26.1`. It also carries `rust-stdlib-source@1.93.1+rustc.01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf` under `libexec/rust-sysroot` as a licensed, SBOM-recorded `data-tree` copied only from that pinned toolchain's `rust-src` and independently matched to the known normalized digest `cc5465ef70b933d2a80c30472468abb9f8ab297fc767bd6433b2f6f554f4f0e7`. The Web worker manifest records the exact TypeScript version, the complete Web semantic capability set, and its Astro and TypeScript runtime components.

The package verifier extracts the archive and validates the manifest, both project licenses, every artifact and runtime component, MCP/Rust/Web handshakes, per-framework scan/query/export E2E, dynamic framework build query/diff/impact/policy/JSON/GraphML E2E, cross-checkout determinism, rollback, and the complete runtime SBOM and third-party license closure. Missing, added, modified, symlinked, or version-mismatched license, MCP server/runner/schema/SDK metadata, Web worker, build observer/converter, Astro parser, TypeScript compiler, Rust sysroot source, or schema input fails before worker launch. Runtime components distinguish an `executable-tree` with an executable entrypoint from a `data-tree` whose entrypoint is optional. The aggregate release verifier requires every target archive to attest identical MCP schema and Rust sysroot source bytes. After core verifies that data tree, it hands the canonical root to the packaged Rust worker; the worker rechecks the pinned source identity, builds separate library VFS roots for `core`, `alloc`, and `std`, and emits exact standard-library import, type-use, and direct-call edges. Development, mismatched, missing, unsupported-target, and tampered inputs preserve syntax output without `semantic-complete`, and neither packaging nor scanning falls back implicitly to project or system `rust-src` or backend bytes. Tier 1 Linux/macOS package gates and Windows safety/determinism smoke cover the MCP, Web semantic, dynamic framework, and Rust sysroot archive contracts.

`mcp-package-smoke-v3` also runs `depgraph agent-config` for all three host
formats from a clean temporary home, verifies the complete package/root/Store/
compiler-pack tuple against a separately pinned `release-post-publish-evidence-v1`
digest, connects through the generated read-only launch arguments, and rejects
any repository, private Store, host-config, or journal mutation. Its report
records `agent_host_release_evidence_contract_version` and requires
`agent_host_release_trust_verified=true`.
The CLI runtime closure for this archive preflight (`flate2`, `tar`, `zip`, and
their transitive dependencies) is included in the SBOM and third-party license
inventory.
