# ADR: Confined external TypeScript declarations

- Status: Implemented
- Date: 2026-10-08
- Issue: #520

## Decision

Web semantic analysis copies a bounded closure of installed declaration files
into its isolated virtual filesystem. A resolved signature in that closure
identifies an external package boundary, including calls through returned
objects, hooks, and generic chains. External declarations do not become project
source files, local definitions, or executable inputs.

The resolver uses the nearest confined package installation and existing
package export selection. Import and require type entries must select the same
file. Package versions and pnpm importer proofs retain their existing candidate
rules. Conflicting global mappings are withheld. If a package exposes runtime
code without declarations, a matching installed `@types` package can supply its
types while retaining the original runtime package boundary.

## Isolation and limits

The compiler receives declaration text under a synthetic directory whose path
has no `node_modules` components. Only explicit, verified path mappings expose
bare modules. This prevents native fallback resolution from bypassing a blocked
export or a conflicting importer. Relative declaration references remain inside
the package root. Symlinks may resolve inside the repository; outside targets
are rejected.

Each compiler context admits at most 1,024 declaration files, 16 MiB of text,
1 MiB per file, and 8,192 module requests. The loader reads declarations and
package metadata only. It never runs package JavaScript, project TypeScript,
compiler plugins, package-manager commands, or installation/build scripts.

Missing references, conflicting identities, and limit exhaustion produce
`web.external_declaration_incomplete` diagnostics and withhold semantic
completeness. Missing packages retain the isolated compiler's module diagnostics;
absence of an installed package alone does not invalidate a repository-provided
ambient declaration. Unresolved and dynamic calls retain their existing status.
A proven external signature is `external`, not a local `resolved` definition.

## Cache and resumable analysis

Installed declarations and package manifests participate in scan input proofs,
cache keys, and every Web analysis unit's configuration fingerprint. The witness
also records absent lookup directories, directory entries, and confined symlink
identities. Adding, changing, deleting, or redirecting a declaration therefore
invalidates reuse, even when project source text is unchanged.

The core witness scans installed trees reachable from source-directory lookup
boundaries. Its independent ceilings are 250,000 entries, depth 128, 256 MiB of
manifest/declaration bytes, and 16 MiB per input file. Exceeding these bounds or
observing a read race fails the input proof explicitly; no cached graph is
published from an incomplete proof. Runtime file contents are not read. This
conservative witness can invalidate more Web units than the declaration loader
actually affects, in exchange for avoiding stale package typing across units.

## Validation and compatibility

Fixtures compare declaration absence with returned-object, hook, and generic
chain calls. They cover `types` exports, relative `.js` references to `.d.ts`,
installed `@types`, pnpm links, outside-root links, missing references, byte and
file limits, and blocked exports despite another subpath loading the same file.
Rust tests verify both scan/cache input proofs and Web unit invalidation after a
declaration-only change.

The compiler remains bundled TypeScript 7.0.2. The profile's module-resolution
property becomes `inventory-and-confined-declarations`. Protocol node and edge
kinds and the persistent schema remain unchanged. Consumers continue to use
external-system nodes for TypeChecker package boundaries.
