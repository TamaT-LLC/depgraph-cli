#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the depgraph polyglot workspace.
#
# The full local gate (`cargo xtask test`) drives four toolchains that must
# match the versions pinned by the repository and CI:
#   - Rust     : rust-toolchain.toml (rustup installs it automatically)
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

# Official upstream SHA-256 checksums for the exact release archives below.
# Downloads are verified against these before any root-owned extraction so a
# corrupted or tampered artifact can never be unpacked or executed.
GO_SHA256="031f088e5d955bab8657ede27ad4e3bc5b7c1ba281f05f245bcc304f327c987a"
NODE_SHA256="55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742"

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

verify_sha256() {
  # Abort unless $1 hashes to the expected $2.
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [ "$actual" != "$expected" ]; then
    echo "integrity check failed for $file: expected $expected, got $actual" >&2
    return 1
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
    verify_sha256 "$tmp/go.tar.gz" "$GO_SHA256"
    as_root rm -rf /usr/local/go
    as_root tar -C /usr/local -xzf "$tmp/go.tar.gz"
    as_root ln -sf /usr/local/go/bin/go /usr/local/bin/go
    as_root ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -rf "$tmp"
  fi
  link_priority go
  link_priority gofmt
  # Drop any cached older `go`/`gofmt` location the shell resolved earlier so
  # later commands use the freshly linked priority binary.
  hash -r
}

ensure_node() {
  local corepack_bin
  if command -v node >/dev/null 2>&1 && [ "$(node --version 2>/dev/null)" = "v${NODE_VERSION}" ]; then
    log "Node.js ${NODE_VERSION} already present"
    # Use the Corepack that ships next to the already-present Node, wherever it
    # lives, rather than assuming an /usr/local/nodejs layout we did not create.
    local node_path
    node_path="$(readlink -f "$(command -v node)")"
    corepack_bin="$(dirname "$node_path")/corepack"
  else
    log "Installing Node.js ${NODE_VERSION}"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/node.tar.xz" "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
    verify_sha256 "$tmp/node.tar.xz" "$NODE_SHA256"
    as_root rm -rf /usr/local/nodejs
    as_root mkdir -p /usr/local/nodejs
    as_root tar -C /usr/local/nodejs --strip-components=1 -xf "$tmp/node.tar.xz"
    as_root ln -sf /usr/local/nodejs/bin/node /usr/local/bin/node
    as_root ln -sf /usr/local/nodejs/bin/npm /usr/local/bin/npm
    as_root ln -sf /usr/local/nodejs/bin/npx /usr/local/bin/npx
    corepack_bin="/usr/local/nodejs/bin/corepack"
    rm -rf "$tmp"
  fi
  # Always (re)generate the Corepack shims regardless of whether Node was
  # already present: a correct Node runtime can still ship a missing or broken
  # Corepack/pnpm shim, and the pnpm gate below depends on them. Fall back to a
  # Corepack already on PATH if none sits next to the resolved Node.
  if [ ! -x "$corepack_bin" ]; then
    corepack_bin="corepack"
  fi
  as_root "$corepack_bin" enable --install-directory /usr/local/bin
  link_priority node
  link_priority npm
  link_priority npx
  link_priority corepack
  link_priority pnpm
  hash -r
}

ensure_bubblewrap() {
  # The supervised build feature enforces a root-owned, non-writable bubblewrap
  # namespace boundary; several depgraph-core/CLI tests require it. CI installs
  # it before `cargo test --workspace`.
  if [ -x /usr/bin/bwrap ] || [ -x /bin/bwrap ]; then
    log "bubblewrap already present"
  else
    log "Installing bubblewrap"
    as_root apt-get update -qq
    as_root apt-get install -y --no-install-recommends bubblewrap
  fi
}

log "Toolchain versions before bootstrap"
rustc --version || true
go version 2>/dev/null || echo "go: missing"
node --version 2>/dev/null || echo "node: missing"

ensure_go
ensure_node
ensure_bubblewrap

# Corepack activates and pins the pnpm version from workers/web/package.json.
# Failures must propagate: a wrong or missing pnpm breaks the frozen install.
log "Activating pnpm via Corepack"
(cd "$REPO_ROOT/workers/web" && corepack install)
ACTUAL_PNPM="$(cd "$REPO_ROOT/workers/web" && pnpm --version)"
EXPECTED_PNPM="$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"pnpm@\([^"]*\)".*/\1/p' "$REPO_ROOT/workers/web/package.json")"
if [ -n "$EXPECTED_PNPM" ] && [ "$ACTUAL_PNPM" != "$EXPECTED_PNPM" ]; then
  echo "pnpm version mismatch: expected $EXPECTED_PNPM, got $ACTUAL_PNPM" >&2
  exit 1
fi

# Make the repo-pinned Rust the global default. rust-toolchain.toml already
# overrides the channel inside the repo, but the supervised build feature stages
# fixtures into temporary directories outside the repo, where only the rustup
# default applies. CI sets `rustup default 1.93.1` for the same reason.
RUST_CHANNEL="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$REPO_ROOT/rust-toolchain.toml")"
if [ -n "$RUST_CHANNEL" ] && command -v rustup >/dev/null 2>&1; then
  log "Setting Rust ${RUST_CHANNEL} as the rustup default"
  # clippy and rustfmt are required by rust-toolchain.toml and cargo xtask test,
  # so a failed install must abort rather than surface later as a missing
  # component.
  rustup toolchain install "$RUST_CHANNEL" --profile minimal --component clippy,rustfmt
  rustup default "$RUST_CHANNEL"
fi

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
