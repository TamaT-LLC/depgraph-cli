#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the depgraph polyglot workspace.
#
# The full local gate (`cargo xtask test`) drives four toolchains that must
# match the versions pinned by the repository and CI:
#   - Rust    : rust-toolchain.toml (rustup installs it automatically)
#   - Go       : workers/go/go.mod (GOTOOLCHAIN=local, so the exact version must exist)
#   - Node.js  : workers/web/package.json engines (>=24)
#   - pnpm     : workers/web/package.json packageManager (Corepack activates it)
#
# Toolchains are installed under /usr/local and exposed through
# /usr/local/cargo/bin, which is first on the Cloud Agent PATH, so they win over
# any older interpreter that appears earlier than /usr/local/bin.
set -euo pipefail

GO_VERSION="1.26.1"
NODE_VERSION="24.18.0"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIORITY_BIN="/usr/local/cargo/bin"

log() { printf '\n=== %s ===\n' "$1"; }

# Prefer sudo only when we are not already root.
as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

link_priority() {
  # Expose a /usr/local/bin tool ahead of any earlier PATH entry.
  local name="$1"
  if [ -e "/usr/local/bin/$name" ] && [ -w "$PRIORITY_BIN" ]; then
    ln -sf "/usr/local/bin/$name" "$PRIORITY_BIN/$name"
  fi
}

ensure_go() {
  if command -v go >/dev/null 2>&1 && [ "$(go env GOVERSION 2>/dev/null)" = "go${GO_VERSION}" ]; then
    log "Go ${GO_VERSION} already present"
  else
    log "Installing Go ${GO_VERSION}"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/go.tar.gz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    as_root rm -rf /usr/local/go
    as_root tar -C /usr/local -xzf "$tmp/go.tar.gz"
    as_root ln -sf /usr/local/go/bin/go /usr/local/bin/go
    as_root ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -rf "$tmp"
  fi
  link_priority go
  link_priority gofmt
}

ensure_node() {
  if command -v node >/dev/null 2>&1 && [ "$(node --version 2>/dev/null)" = "v${NODE_VERSION}" ]; then
    log "Node.js ${NODE_VERSION} already present"
  else
    log "Installing Node.js ${NODE_VERSION}"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/node.tar.xz" "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
    as_root rm -rf /usr/local/nodejs
    as_root mkdir -p /usr/local/nodejs
    as_root tar -C /usr/local/nodejs --strip-components=1 -xf "$tmp/node.tar.xz"
    as_root ln -sf /usr/local/nodejs/bin/node /usr/local/bin/node
    as_root ln -sf /usr/local/nodejs/bin/npm /usr/local/bin/npm
    as_root ln -sf /usr/local/nodejs/bin/npx /usr/local/bin/npx
    as_root /usr/local/nodejs/bin/corepack enable --install-directory /usr/local/bin
    rm -rf "$tmp"
  fi
  link_priority node
  link_priority npm
  link_priority npx
  link_priority corepack
  link_priority pnpm
}

log "Toolchain versions before bootstrap"
rustc --version || true
go version 2>/dev/null || echo "go: missing"
node --version 2>/dev/null || echo "node: missing"

ensure_go
ensure_node

# Corepack activates the pnpm version pinned in workers/web/package.json.
log "Activating pnpm via Corepack"
corepack prepare --activate 2>/dev/null || true

# Warm the Rust toolchain (rust-toolchain.toml pins the channel + components).
log "Fetching Rust dependencies (locked)"
(cd "$REPO_ROOT" && cargo fetch --locked)

log "Downloading Go module dependencies"
(cd "$REPO_ROOT/workers/go" && GOTOOLCHAIN=local GOFLAGS=-mod=readonly go mod download)

log "Installing web worker dependencies (frozen lockfile)"
(cd "$REPO_ROOT/workers/web" && pnpm install --frozen-lockfile)

log "Bootstrap complete"
rustc --version
go version
node --version
echo "pnpm $(cd "$REPO_ROOT/workers/web" && pnpm --version)"
