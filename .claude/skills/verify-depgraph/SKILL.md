---
name: verify-depgraph
description: Drive the locally built `depgraph` CLI (scan, deps/dependents, why, impact, doctor/unresolved) against a disposable Rust fixture repository in an isolated HOME and Store, and capture command/stdout/stderr/exit evidence. Use when a change to depgraph-cli, depgraph-core, depgraph-store or the Rust worker must be proven in the real binary rather than only by cargo tests, or when asked to "run depgraph and show it works".
---

# verify-depgraph

depgraph's primary user surface is the `depgraph` CLI (`crates/depgraph-cli`, binary `target/debug/depgraph`). A user runs `depgraph scan` inside a repository and then asks graph questions (`deps`, `dependents`, `why`, `impact`, `unresolved`, `doctor`). Other surfaces exist but are not the default target of this skill:

- `depgraph-mcp` (stdio MCP server, `crates/depgraph-mcp`) requires a verified compiler pack (`--compiler-pack-requirement`); a dev build has none. Its end-to-end coverage lives in `cargo test -p depgraph-mcp --test process`.
- `depgraph mcp setup|update` downloads and verifies an official release from GitHub and writes host config (`.mcp.json` etc.). Do not drive it from this skill: it hits the network and edits real config.
- Go and Web (TS/JS, Next.js, Astro, TanStack) adapters need `workers/go/bin/depgraph-go-worker` and `workers/web/dist/`, built by `vdg launch --all-workers` (`cargo xtask build`, needs Go 1.26.1 and pnpm 10.33.0). The seeded fixture is Rust-only.

The CLI is short-lived: there is no server to keep alive. "Launch" builds the binary once and creates a sandbox with a fixture repo plus a baseline scan; each drive is one `depgraph` process.

All commands below run from the repository (or worktree) root. The helper is `.claude/skills/verify-depgraph/scripts/vdg`; abbreviate it as `V=.claude/skills/verify-depgraph/scripts/vdg`.

## Launch

```sh
V=.claude/skills/verify-depgraph/scripts/vdg
$V launch            # cargo build --locked -p depgraph-cli -p depgraph-rust-worker, then sandbox + baseline scan
$V launch --no-build # reuse an existing target/debug/depgraph (doctor still checks staleness)
$V launch --all-workers  # cargo xtask build: also Go + Web workers (slow, needs go/pnpm)
```

What launch does:

1. Builds the CLI and the Rust worker (`target/debug/depgraph`, `target/debug/depgraph-rust-worker`). A warm incremental build takes about a minute; a cold one is several minutes, so run it with a long timeout or in the background.
2. Creates the sandbox `$TMPDIR/verify-depgraph.<run>.XXXXXX/` with `home/` (fake `HOME`), `state/graph.db` (the Store) and `repo/` (a git repo, branch `main`, one commit) holding the fixture crate `vdg-fixture`:
   - `src/lib.rs`: `pub mod cart; pub mod checkout;`
   - `src/cart.rs`: `pub fn total(items: &[u32]) -> u32`
   - `src/checkout.rs`: `use crate::cart::total;` and `pub fn pay` calling `total`
3. Runs the baseline `depgraph --store <store> scan . --json` and requires exit 0. This is what makes the instance usable: query commands and `doctor` fail with exit 3 (`read-only store is unavailable`) until a Store exists.

Ready means launch printed `vdg: ready run=<id> fixture=<path> evidence=<path>` and printed the run id as its last stdout line. The id is written to `target/verify-depgraph/current`; every later `vdg` call uses that run unless `VDG_RUN=<id>` is set.

Isolation: every `depgraph` call made through `vdg` gets an explicit `--store` inside the sandbox, `HOME` and `XDG_CACHE_HOME` inside the sandbox, and runs with cwd = fixture repo. `RUSTUP_HOME`/`CARGO_HOME` keep pointing at the real toolchain because a fake `HOME` otherwise hides rustup and silently disables HIR analysis.

- Git: `vdg` unsets every inherited `GIT_*` variable at startup (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_COMMON_DIR`, `GIT_NAMESPACE`, `GIT_CEILING_DIRECTORIES`, `GIT_CONFIG_*`, ...), so running it from a git hook or `git rebase --exec` cannot redirect fixture commits into the real repository. Fixture git commands and `depgraph` runs get `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `core.hooksPath=/dev/null`, `commit.gpgsign=false`, `tag.gpgsign=false` and the fixed identity `vdg <vdg@example.invalid>`.
- Workers: inherited `DEPGRAPH_<ADAPTER>_WORKER` overrides (`DEPGRAPH_RUST_WORKER`, `DEPGRAPH_GO_WORKER`, `DEPGRAPH_WEB_WORKER`) are unset because the CLI prefers them over the local build. Every `depgraph` run then gets `DEPGRAPH_RUST_WORKER=<checkout>/target/debug/depgraph-rust-worker`, plus `DEPGRAPH_GO_WORKER` / `DEPGRAPH_WEB_WORKER` pointing at `workers/go/bin/depgraph-go-worker` / `workers/web/dist/worker.mjs` when those were built in this checkout. `NOTES.md` records the pinned workers and the names of the scrubbed variables.
- State: `target/verify-depgraph/runs/<id>.env` is written with `printf %q`, so paths with spaces, `$` or quotes (for example in `TMPDIR` or `VDG_EVIDENCE_ROOT`) round-trip exactly and are never executed when sourced. Several runs can coexist (distinct run ids, sandboxes and Stores). Never point `--store` at the default OS cache (`~/Library/Caches/com.TamaT.depgraph/` on macOS, `~/.cache/depgraph/` on Linux): that is the user's real data.

Teardown is `vdg cleanup` (see Cleanup).

## Doctor

```sh
$V doctor
```

Read-only. It checks, and exits non-zero with `FAIL` lines if any fails:

- the run's sandbox and fixture git repo exist;
- `target/debug/depgraph --version` equals `[workspace.package] version` in `Cargo.toml`;
- `target/debug/depgraph` is newer than every `.rs` / `Cargo.toml` of the crates it is built from (`crates/depgraph-{cli,core,store,protocol,operation,mcp-tools}`);
- the pinned Rust worker `target/debug/depgraph-rust-worker` exists and is newer than every `.rs` / `Cargo.toml` under `workers/rust` and `crates/depgraph-protocol`. Each binary is compared against its own sources, so a fresh CLI does not hide a stale worker. If either check fails you are driving a stale build: rerun `$V launch` (without `--no-build`);
- the Store file is inside the sandbox;
- the real OS cache has no `repositories/<sha256(fixture path)>` entry (proof that nothing leaked into the user's Store);
- `depgraph --store <store> doctor --json` exits 0, its Rust worker is `available: true` (integrity `development-unverified` is expected for dev builds), and `latest_successful_scan_id` is set.

It also prints `info workers: [...]`; `go`/`web` are `available:true` only when this checkout has their builds (`workers/go/bin/depgraph-go-worker`, `workers/web/dist/worker.mjs`, for example after `--all-workers`), which `vdg` then pins; otherwise `available:false`. Run doctor first, and again whenever anything looks off. Do not drive a run whose doctor fails.

## Drive

Drive the CLI only through `vdg run`, which injects the isolated env and `--store`, runs in the fixture, and records evidence:

```sh
$V run <label> [--expect-exit N] -- <depgraph subcommand and args>
```

`<label>` matches `[A-Za-z0-9._-]+` and names the evidence files. The command's stdout is echoed; `vdg` fails (and prints stderr) unless the command exits with `--expect-exit N`, which defaults to `0`. Real recipes, all verified against the seeded fixture:

```sh
$V run deps -- deps path:src/checkout.rs                 # "deps: returned 1/1 items; complete=true"
$V run dependents -- dependents path:src/cart.rs --transitive   # "dependents: returned 6/6 items"
$V run why -- why symbol:checkout::pay symbol:cart::total --json  # .data.path_found == true
$V run impact -- impact path:src/cart.rs                 # "result: impacted=true complete=true impacts=6"
$V fixture-change                                         # branch feat: cart.rs gains fn tax, committed
$V run rescan --expect-exit 0 -- scan .
$V run impact-changed -- impact path:src/checkout.rs --changed main   # impacted=true
$V run unresolved -- unresolved --json                    # .total_items == 2
$V run strict --expect-exit 1 -- scan . --strict         # exit 1, "strict policy failed: unresolved=2"
```

Stable handles: selectors (`path:`, `symbol:`, `id:`, `package:`, `route:`, `type:`), `--json` output fields, and the first summary line of text output (`<cmd>: returned N/M items; complete=...`, `result: impacted=...`). Prefer `--json` plus `jq` for assertions; text output contains sha256 node ids that change with content.

Exit codes (from `docs/guide/usage.md`): `0` ok, `1` graph/coverage policy violation, `2` usage/selector/config error, `3` worker/toolchain/protocol/Store failure, `4` project-code consent or security policy failure.

The feature map in `features/` holds the per-feature recipes and proof criteria. Read `features/README.md` before driving.

## Evidence

Evidence for run `<id>` lives in `target/verify-depgraph/evidence/<id>/` (gitignored via `/target/`; override the root with `VDG_EVIDENCE_ROOT=/abs/path`). Print it with `$V evidence-dir`. Per `vdg run <label>`:

- `<label>.cmd` (cwd and exact argv), `<label>.stdout`, `<label>.stderr`, `<label>.exit`;
- a line appended to `NOTES.md` (which also records repo HEAD, uncommitted path count, binary version, fixture and Store paths).

`vdg note <label> <text>` appends your own observation (for example the jq assertion you ran and its result) to `NOTES.md`. `fixture-change` writes `fixture-change.git-log`.

Proof standards:

- Exercise the real user path: the built `depgraph` binary with real subcommands against a real git repo. No internal setters, no test-only fixtures from `crates/*/tests`.
- Capture the action and the resulting state: the scan that produced the snapshot, the query, and its output. For mutations (`fixture-change`, rescans) keep the before and after queries.
- Verify side effects alongside output: the Store moving (`latest_successful_scan_id` changes after a passing rescan, but not after `scan --strict` fails), and the doctor isolation check showing the real cache was not touched.
- Assert on `--json` fields with `jq`, and record the assertion with `vdg note`.
- `scan --plan` / `--split-plan` are the "dry run" entry points. They are documented to not launch workers or write a Store; verify that by observing (Store mtime / `doctor` scan id unchanged), not by trusting the name.
- A path you could not reach (Go/Web adapters without their worker builds, MCP without a compiler pack) is reported as unverified, never as passed through another path.

Note: `cargo clean` deletes `target/` and with it the evidence. Copy evidence elsewhere (or set `VDG_EVIDENCE_ROOT`) before cleaning.

## Cleanup

```sh
$V cleanup              # current run
$V cleanup --run <id>   # a specific run
```

Removes only the sandbox directory that run created (refuses any path not matching `verify-depgraph.<id>.*`) and the run's state file. The evidence directory is kept and gets a `cleanup: removed <path>` line. After cleanup `vdg evidence-dir` no longer resolves that run; use the `evidence kept at <path>` path that cleanup prints, or `ls target/verify-depgraph/evidence/`. `depgraph` processes are short-lived, so there is nothing to kill; the one exception is `depgraph daemon start`, which a recipe must stop with `$V run daemon-stop -- daemon stop` before cleanup. Never kill by process name. Run cleanup after every failed attempt too.

## Helpers

- `.claude/skills/verify-depgraph/scripts/vdg` (executable bash; needs `git`, `jq`, `shasum`). `vdg --help` prints:
  - `vdg launch [--all-workers] [--no-build]`
  - `vdg doctor`
  - `vdg run <label> [--expect-exit N] -- <depgraph args...>`
  - `vdg fixture-change`
  - `vdg note <label> <text...>`
  - `vdg env` (prints `export VDG_*=...` lines, shell-quoted; `eval "$($V env)"` gives `$VDG_FIXTURE`, `$VDG_STORE`, `$VDG_EVIDENCE`, `$VDG_HOME`, `$VDG_BIN`, `$VDG_RUST_WORKER` for manual inspection)
  - `vdg evidence-dir`
  - `vdg cleanup [--run ID]`

If you must run something `vdg run` cannot express (for example `sqlite3` on the Store), `eval "$($V env)"` first and keep `HOME=$VDG_HOME`, `--store "$VDG_STORE"`, cwd `$VDG_FIXTURE` and `DEPGRAPH_RUST_WORKER="$VDG_RUST_WORKER"`, with no `GIT_DIR`/`GIT_WORK_TREE` exported in your shell. Run cleanup before relaunching a run created by an older `vdg` (its state file has no `VDG_RUST_WORKER`; `vdg run` refuses it).
