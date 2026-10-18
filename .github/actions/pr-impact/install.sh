#!/usr/bin/env bash
# Download a released depgraph archive, verify its SHA-256 sidecar, and print
# the path of the extracted binary. Inputs arrive through the environment so
# the composite action never interpolates workflow expressions into a script.
#
#   DEPGRAPH_VERSION  release version without the leading "v" (e.g. 0.6.4)
#   GH_TOKEN          token for `gh release download`
#   RUNNER_TEMP       scratch root (falls back to TMPDIR)
#   GITHUB_OUTPUT     optional; receives `depgraph-path=<binary>`
set -euo pipefail

readonly RELEASE_REPOSITORY="TamaT-LLC/depgraph-cli"
readonly VERSION_PATTERN='^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'

fail() {
  echo "depgraph install: $*" >&2
  exit 1
}

version="${DEPGRAPH_VERSION:-}"
[[ "$version" =~ $VERSION_PATTERN ]] || fail "version must match ${VERSION_PATTERN}: ${version:-<empty>}"

os="$(uname -s)"
arch="$(uname -m)"
case "${os}/${arch}" in
  Linux/x86_64 | Linux/amd64) target="x86_64-unknown-linux-gnu" ;;
  Linux/aarch64 | Linux/arm64) target="aarch64-unknown-linux-gnu" ;;
  Darwin/arm64 | Darwin/aarch64) target="aarch64-apple-darwin" ;;
  *) fail "unsupported runner platform ${os}/${arch}" ;;
esac

stem="depgraph-${version}-${target}"
archive="${stem}.tar.gz"
checksum="${archive}.sha256"

scratch_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work="$(mktemp -d "${scratch_root%/}/depgraph-install.XXXXXX")"
download="${work}/download"
extract="${work}/extract"
mkdir -p "$download" "$extract"

gh release download "v${version}" -R "$RELEASE_REPOSITORY" \
  --pattern "$archive" --pattern "$checksum" -D "$download" >&2

[[ -f "${download}/${archive}" && -f "${download}/${checksum}" ]] || fail "release v${version} is missing ${archive} or its checksum"

# The sidecar must name exactly the archive we asked for; otherwise a valid
# checksum for some other file would pass `--check`.
read -r expected_hex expected_name extra <"${download}/${checksum}" || true
[[ -z "${extra:-}" ]] || fail "checksum sidecar has unexpected fields"
[[ "$expected_hex" =~ ^[0-9a-f]{64}$ ]] || fail "checksum sidecar digest is malformed"
[[ "${expected_name#\*}" == "$archive" ]] || fail "checksum sidecar names ${expected_name}, expected ${archive}"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$download" && sha256sum --check --strict "$checksum") >&2
else
  (cd "$download" && shasum -a 256 --check "$checksum") >&2
fi

tar -xzf "${download}/${archive}" -C "$extract"
binary="${extract}/${stem}/bin/depgraph"
[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || fail "archive does not contain ${stem}/bin/depgraph"

"$binary" --version >&2

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "depgraph-path=${binary}" >>"$GITHUB_OUTPUT"
fi
echo "$binary"
