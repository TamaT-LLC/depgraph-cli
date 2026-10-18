# Analysis health

`depgraph doctor` reports worker, toolchain, coverage, cache and protocol health for the Store's latest attempt, and `depgraph unresolved` lists dependency sites the analysis could not resolve, with reason and source span.

## Sub-features

- `doctor-summary` prints the bounded text summary.
- `doctor-json` returns `workers`, `toolchains`, `latest_successful_scan_id`, `store_schema_version` and more.
- `doctor-no-store` fails when the Store does not exist yet.
- `unresolved-list` lists unresolved sites with reasons.

## How to get to it (user POV)

- Run `depgraph doctor` (add `--json` or `--details`) and `depgraph unresolved` after a scan.

## Driving it with vdg

Preconditions:

- Baseline launch; doctor (the `vdg` one) passes.

- **Summary.** Run `$V run doctor-summary --expect-exit 0 -- doctor`. stdout starts with `doctor report: summary`, `protocol: 1.0`, `latest attempt: completed`.
- **JSON.** Run `$V run doctor-json --expect-exit 0 -- doctor --json`. `jq '.store_schema_version'` is `19`, the `rust` entry of `.workers` has `available: true` and `integrity: "development-unverified"`, and `go`/`web` have `available: false` (unless `--all-workers`).
- **No Store.** `eval "$($V env)"`, then `(cd "$VDG_FIXTURE" && HOME="$VDG_HOME" "$VDG_BIN" --store "$VDG_SCRATCH/none/graph.db" doctor --json)`. Exit `3` with `read-only store is unavailable`; `$VDG_SCRATCH/none` is not created. Record it with `vdg note`.
- **Unresolved.** Run `$V run unresolved-list --expect-exit 0 -- unresolved --json`. `jq '.total_items'` is `2`; text form (`unresolved`) shows `call sum` and `call iter` at `src/cart.rs:1` with reason `rust-analyzer could not resolve the method call`.

## Gotchas

- `vdg doctor` (the helper) and `depgraph doctor` (the feature) are different things; the helper calls the feature as one of its checks.
- `doctor --json` `toolchains` reports the ambient `rustc` (for example 1.97.x), not the pinned 1.93.1 that the Rust worker probes.
- The 2 unresolved sites come from the unloaded sysroot in dev builds; a release build with a verified sysroot would resolve them.
