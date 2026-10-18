# Why

`depgraph why <FROM> <TO>` explains the deterministic shortest dependency path between two nodes, with each step's edge kind, status and source evidence, or states that no path exists.

## Sub-features

- `why-symbol-path` explains a call path between two symbols.
- `why-json` returns `.data.path_found` and `.data.steps`.
- `why-no-path` reports a missing path without failing.

## How to get to it (user POV)

- Run `depgraph why path:src/app/checkout/page.tsx path:src/lib/cart.ts` (README example) or with `symbol:` selectors after a scan.

## Driving it with vdg

Preconditions:

- Baseline launch; doctor passes.

- **Symbol path.** Run `$V run why-symbol-path --expect-exit 0 -- why symbol:checkout::pay symbol:cart::total`. stdout names `crate::checkout::pay`, a `--calls [semantic; resolved; exact; ...]` step, and evidence `src/checkout.rs:2:36-2:48 via rust-analyzer-hir`.
- **JSON path.** Run `$V run why-json --expect-exit 0 -- why symbol:checkout::pay symbol:cart::total --json`. `jq '.data.path_found'` is `true` and `.data.steps | length` is `1`.
- **No path.** Run `$V run why-no-path --expect-exit 0 -- why path:src/checkout.rs path:src/cart.rs`. stdout is `no dependency path exists from file:src/checkout.rs to file:src/cart.rs`; with `--json`, `.data.path_found` is `false`.
- **File via lib.** Run `$V run why-lib-cart --expect-exit 0 -- why path:src/lib.rs path:src/cart.rs`. stdout shows `file:src/lib.rs --imports [...]` to the cart file.

## Gotchas

- "No path" exits `0`. Assert on `path_found`, not on the exit code.
- `checkout.rs -> cart.rs` has no file-level path because the import targets the `cart` module node; use symbols for call questions.
