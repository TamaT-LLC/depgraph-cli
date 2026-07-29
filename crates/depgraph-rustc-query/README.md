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

## Reviewed internal API inventory

`src/rustc_private_bridge.rs` is the complete private compiler surface. For the
pinned rustc commit it uses only:

- `rustc_middle::ty::tls::with` to access the callback's active `TyCtxt`;
- `TyCtxt::collect_and_partition_mono_items(())` and
  `CodegenUnit::items()` to obtain compiler-selected mono items;
- `rustc_middle::mono::MonoItem` plus exhaustive
  `rustc_middle::ty::{InstanceKind, ShimKind}` matches to classify every
  supported private variant; and
- `rustc_public::rustc_internal::stable` to convert each value immediately to
  `rustc_public::mir::mono::{Instance, StaticDef}`.

The bridge contains no `unsafe` block. It returns only public values and the
small reviewed classification enums declared in that file; no `TyCtxt`,
`DefId`, internal `Ty`, lifetime tied to the compiler context, or debug string
leaves the module. Global assembly is counted and rejected because this DTO has
no typed call-graph representation for it. Exhaustive matches and the exact
nightly build make new or changed compiler variants fail closed at build time.
