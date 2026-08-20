# @tamat-llc/depgraph

`@tamat-llc/depgraph` is the organization-owned npm distribution of
[`TamaT-LLC/depgraph-cli`](https://github.com/TamaT-LLC/depgraph-cli).
It installs the `depgraph` CLI and the `depgraph-mcp` stdio server.

```sh
npm i -g @tamat-llc/depgraph
depgraph --version
```

The package requires Node.js 24 or later and supports Linux glibc on x64 and
ARM64, macOS on Intel and Apple Silicon, and Windows on x64. npm selects one
exact-version native package through `optionalDependencies`. Installation does
not run a lifecycle script and does not download executable code from an
unrelated host.

Each native package retains the complete verified GitHub Release layout,
including `release-manifest.json`, project licenses, third-party notices, and
the SPDX SBOM. Before launch, the JavaScript shim checks the package identity,
target, native executable path, and SHA-256 recorded in the release manifest.

See the [project README](https://github.com/TamaT-LLC/depgraph-cli#readme) for
usage, safety boundaries, MCP configuration, and release verification.
