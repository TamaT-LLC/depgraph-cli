# Analysis completeness

[Back to the README](../../README.en.md) · [Usage guide](../guide/usage.en.md)

**`semantic-complete`** means that a profile's semantic analysis met the
defined completeness requirements. It does not mean that missing dependencies
were guessed. The marker is emitted only when syntax analysis completes, a
compatible validated semantic backend produces a graph, and the counts for
semantic issues, skipped input, unsupported input, and unresolved sites are all
zero. Explicit `candidates` and `external` sites do not prevent the marker.

The Rust semantic backend uses confined Cargo metadata, a ready project model,
and the verified Rust `1.93.1` toolchain. `depgraph` sets
`RUSTUP_AUTO_INSTALL=0`; if the toolchain is absent, it reports installation
instructions instead of installing it implicitly. Source builds report
`rust_hir_enable_gate=release-gate-pending`; only a worker launched from a
verified Release Archive can report `release-gate-verified`.

Web `semantic-complete` requires the bundled isolated TypeScript compiler, an
emitted v2 graph, and zero skipped, unsupported, unresolved, semantic-issue,
and compiler-diagnostic counts. Detected Next.js, Astro, TanStack Router, and
TanStack Start projects must also complete the matching Framework Capability
Ledger.

Beyond the static graph, depgraph supports architecture policy, GitHub
annotations, runtime traces, immutable snapshots, snapshot diff, Git
changed-set impact, GraphML, and a watcher daemon. Build observation is a
separate permission boundary; only an explicitly consented invocation may run
code from the target project.
