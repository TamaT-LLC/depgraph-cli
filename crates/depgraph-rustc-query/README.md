# depgraph rustc query child

This crate is the pinned compiler-side boundary for
`compiler-precise-rust-v1`. It is intentionally excluded from the stable Cargo
workspace: it must be built only with `nightly-2026-07-17`, rustc commit
`3d50c25bc66853bf0ad205529d0f305a1d841b5e`, and that toolchain's `rustc-dev`
and `llvm-tools` components.

The child enters the compiler with `rustc_public::run!`, converts local typed
MIR to the bounded `depgraph-rust-compiler-precise-v1` DTO, and then allows the
normal compiler pipeline to continue. It never serializes rustc's `DefId`,
`TyCtxt`, allocation identity, `Debug` representation, or host path.

For a pack build, link against the pinned sysroot and copy the resulting
executable to the build spec's `query_path`:

```sh
sysroot="$(rustc +nightly-2026-07-17 --print sysroot)"
RUSTFLAGS="-L native=$sysroot/lib" \
  cargo +nightly-2026-07-17 build \
  --manifest-path crates/depgraph-rustc-query/Cargo.toml \
  --release --locked
```

The attested wrapper supplies the exact compiler-library search path when it
starts this executable. The stable parent treats every emitted DTO as
compromised-capable child output and validates it independently before keeping
the result as audit-only evidence.
