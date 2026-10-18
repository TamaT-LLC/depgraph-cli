# Safe scan

`depgraph scan` reads a repository's sources and manifests without executing project code, stores a snapshot in the Store, and reports coverage and diagnostics. A completed scan that passes policy becomes the `latest successful` snapshot that every query reads.

## Sub-features

- `scan-json` scans the repository and prints a JSON report with `status`, `coverage` and `diagnostics`.
- `scan-text` prints the human summary (`scan: <id>`, `status:`, `files:`, `sites:`, `cache ...:`, `store:`).
- `scan-rescan` reruns on the same Store, reusing validated cache entries.
- `scan-strict` fails with exit 1 when the strict policy (unresolved/skipped/unsupported = 0) is violated.
- `scan-plan` (`--plan`, `--split-plan`) shows the analysis plan without launching workers or writing a Store.

## How to get to it (user POV)

- Run `depgraph scan .` (or `depgraph scan /path/to/repo`) inside the repository.
- Add `--json` for machine output, `--strict` for CI, `--plan` / `--split-plan` for a dry plan.

## Driving it with vdg

Preconditions:

- Baseline launch (the baseline scan already exists as evidence `00-baseline-scan.*`).

- **JSON scan.** Run `$V run scan-json --expect-exit 0 -- scan . --json`. `jq -r .status` is `completed`, `.coverage.project_code_executed` is `false`, `.coverage.files_analyzed` is `4`, and `.diagnostics[].code` contains `SAFE_SCAN`.
- **Text scan.** Run `$V run scan-text --expect-exit 0 -- scan .`. stdout contains `status: completed`, `files: 4/4 analyzed (0 skipped)` and a `store:` line inside the sandbox.
- **Rescan reuse.** Run the text scan again as `scan-rescan`. stdout contains `cache syntax: hit` and `cache semantic: hit (validated)`.
- **Strict failure.** Run `$V run scan-strict --expect-exit 1 -- scan . --strict`. stderr contains `strict policy failed: unresolved=2 (max 0)`; stdout `status: policy_failed`. Then `$V run doctor-after-strict -- doctor --json` and confirm `latest_successful_scan_id` still equals the one before the strict scan.
- **Plan only.** Record the Store mtime (`eval "$($V env)"; stat -f %m "$VDG_STORE"` on macOS, `stat -c %Y` on Linux), run `$V run scan-plan --expect-exit 0 -- scan . --plan`, then stat again. stdout starts with `analysis plan: sha256:` and lists `rust .: 3 files, 1 dependencies`; the mtime is unchanged.

## Gotchas

- With a fake `HOME` and no `RUSTUP_HOME`, the Rust probe fails and the scan silently degrades (`RUST_HIR_TOOLCHAIN_UNSUPPORTED`, `rust-hir-unsupported`). `vdg` sets `RUSTUP_HOME`/`CARGO_HOME`; if you see that code, the env leaked.
- Dev builds never reach `semantic-complete` for Rust: `RUST_HIR_SYSROOT_UNAVAILABLE` ("not handed off by a verified release") is expected. Completeness is `syntax-complete`.
- The fixture has 2 unresolved method calls (`iter`, `sum`) because the sysroot is not loaded. That is why `--strict` fails; do not "fix" the fixture to make strict pass.
- The Store writes a `.depgraph/` directory and `graph.db.writer-lock` next to `graph.db`; both are inside the sandbox.
