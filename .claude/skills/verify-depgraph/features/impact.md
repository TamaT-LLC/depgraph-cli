# Impact

`depgraph impact <SELECTOR>` shows which nodes are affected, via reverse dependency paths, when the selected node changes. With `--changed <GIT_REF>` it instead maps the committed and dirty changes since `merge-base(GIT_REF, HEAD)` to graph nodes and reports whether the selected node is affected by them.

## Sub-features

- `impact-selector` lists reverse-impacted nodes of a file.
- `impact-json` returns `.data.root_impacted`, `.data.impacts[]` and `.data.complete`.
- `impact-changed-hit` reports a selector that depends on a changed file as impacted.
- `impact-changed-miss` reports the changed file itself as not affected.

## How to get to it (user POV)

- Run `depgraph impact path:src/lib/cart.ts --changed main` (README example) inside the repository after a scan, or without `--changed` for the pure reverse graph.

## Driving it with vdg

Preconditions:

- Baseline launch; doctor passes.
- `--changed` steps additionally need `$V fixture-change` followed by a rescan, so the Store snapshot matches `HEAD`.

- **Selector impact.** Run `$V run impact-selector --expect-exit 0 -- impact path:src/cart.rs`. stdout contains `impact focus: file:src/cart.rs` and `result: impacted=true complete=true impacts=6`.
- **JSON impact.** Run `$V run impact-json --expect-exit 0 -- impact path:src/cart.rs --json`. `jq '.data.root_impacted'` is `true`, `.data.complete` is `true`, `.data.impacts | length` is `6`, and `[.data.impacts[].node.locator]` contains `file:src/lib.rs`.
- **Make a change.** Run `$V fixture-change`. `fixture-change.git-log` shows `vdg: change cart` on top of `vdg fixture`.
- **Rescan.** Run `$V run impact-rescan --expect-exit 0 -- scan .`. stdout `status: completed`.
- **Changed set hit.** Run `$V run impact-changed-hit --expect-exit 0 -- impact path:src/checkout.rs --changed main`. stdout contains `git changed set: ref=main`, `modified src/cart.rs sources=committed`, and `result: impacted=true`.
- **Changed set miss.** Run `$V run impact-changed-miss --expect-exit 0 -- impact path:src/cart.rs --changed main`. stdout contains `result: impacted=false` and `selected node is not affected by the mapped changed set`.

## Gotchas

- `--changed` reads Git from the current directory. Run from anywhere other than the fixture root (for example `/`) and it fails with exit 2, `PATH contains no safe absolute directories outside the scan root`. `vdg run` always runs in the fixture; manual calls must `cd "$VDG_FIXTURE"`. An exported `GIT_DIR` / `GIT_WORK_TREE` would make depgraph's `git` read another repository; `vdg` unsets them, a manual call must too.
- `--changed` answers "is the selected node affected by the change", so selecting the changed file itself yields `impacted=false`. Select a dependent (`src/checkout.rs`) to see a hit.
- File-level `impact path:src/cart.rs` does not list `src/checkout.rs`, because checkout imports the `cart` module node; it lists `file:src/lib.rs`, the module, the crate target, package and workspace.
- After `fixture-change` the fixture is no longer at baseline; relaunch before running other features' recipes.
