# Dependencies and dependents

`depgraph deps` lists what a selected node uses and `depgraph dependents` lists what uses it, each edge with its kind, status (`resolved`, `candidates`, `external`, `unresolved`), condition and source evidence.

## Sub-features

- `deps-direct` lists outgoing edges of a file.
- `deps-json` returns the bounded page contract (`items`, `returned_items`, `total_items`, `complete`).
- `dependents-transitive` lists all incoming edges transitively.
- `deps-bad-selector` rejects a selector that matches nothing.

## How to get to it (user POV)

- Run `depgraph deps path:src/checkout.rs` or `depgraph dependents path:src/cart.rs --transitive` after a scan.
- Add `--json`, `--max-items N`, `--cursor TOKEN` for paging, `--all` for the full result.

## Driving it with vdg

Preconditions:

- Baseline launch; doctor passes.

- **Direct deps.** Run `$V run deps-direct --expect-exit 0 -- deps path:src/checkout.rs`. stdout starts with `deps: returned 1/1 items; complete=true` and shows `--imports [source; resolved; exact; ...]` with `evidence source src/checkout.rs:1:5-1:23`.
- **JSON page.** Run `$V run deps-json --expect-exit 0 -- deps path:src/checkout.rs --json`. `jq '.total_items'` is `1`, `.complete` is `true`, `.items[0].target.locator` is `rust-module:vdg-fixture:lib:vdg_fixture::cart`.
- **Transitive dependents.** Run `$V run dependents-transitive --expect-exit 0 -- dependents path:src/cart.rs --transitive`. stdout starts with `dependents: returned 6/6 items; complete=true` and the `summary kind:` line reads `contains=4, declares=1, imports=1`.
- **Bad selector.** Run `$V run deps-bad-selector --expect-exit 2 -- deps path:src/missing.rs`. Usage and selector errors exit `2`.

## Gotchas

- `checkout.rs` imports the module `crate::cart`, not the file, so its deps target is a `module` node. File-to-file questions often go through module nodes.
- Text output shows sha256 node ids; assert on `--json` `locator` fields instead.
