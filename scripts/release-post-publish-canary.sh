#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
  echo "usage: $0 RELEASE_TAG PUBLIC_ASSET_DIRECTORY EVIDENCE TRUSTED_EVIDENCE_SHA256 REPOSITORY OUTPUT_DIRECTORY" >&2
  exit 2
fi

release_tag="$1"
public_input="$2"
evidence_input="$3"
trusted_evidence_sha256="$4"
repository_input="$5"
output_input="$6"

if [[ ! "$release_tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)(-rc\.[1-9][0-9]*)?$ ]]; then
  echo "release post-publish canary requires a canonical release tag" >&2
  exit 1
fi
version="${BASH_REMATCH[1]}"
if [[ ! "$trusted_evidence_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "release post-publish canary requires a lowercase trusted evidence SHA-256" >&2
  exit 1
fi

canonical_directory() {
  local path="$1"
  if [[ ! -d "$path" || -L "$path" ]]; then
    echo "release post-publish canary directory is missing or symlinked: $path" >&2
    return 1
  fi
  realpath "$path"
}

canonical_file() {
  local path="$1"
  if [[ ! -f "$path" || -L "$path" ]]; then
    echo "release post-publish canary file is missing or symlinked: $path" >&2
    return 1
  fi
  realpath "$path"
}

public_root="$(canonical_directory "$public_input")"
evidence="$(canonical_file "$evidence_input")"
canary_repository="$(canonical_directory "$repository_input")"
if [[ -L "$output_input" ]]; then
  echo "release post-publish canary output directory must not be a symlink" >&2
  exit 1
fi
mkdir -p "$output_input"
output_root="$(canonical_directory "$output_input")"
if [[ -n "$(find "$output_root" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "release post-publish canary output directory must start empty" >&2
  exit 1
fi
case "$output_root/" in
  "$canary_repository/"*)
    echo "release post-publish canary output must be outside the scanned repository" >&2
    exit 1
    ;;
esac

canary_target="x86_64-unknown-linux-gnu"
archive_name="depgraph-${version}-${canary_target}.tar.gz"
compiler_pack_name="depgraph-compiler-pack-${version}-${canary_target}"
compiler_archive_name="${compiler_pack_name}.tar.gz"
canary_archive="$(canonical_file "${public_root}/${archive_name}")"
canary_checksum="$(canonical_file "${public_root}/${archive_name}.sha256")"
canary_compiler_archive="$(canonical_file "${public_root}/${compiler_archive_name}")"
canary_compiler_checksum="$(canonical_file "${public_root}/${compiler_archive_name}.sha256")"
public_requirement="$(canonical_file "${public_root}/${compiler_pack_name}.requirement.json")"

printf '%s  %s\n' "$trusted_evidence_sha256" "$evidence" \
  | sha256sum --check --strict --status -
(
  cd "$public_root"
  sha256sum --check --strict --status "$(basename "$canary_checksum")"
  sha256sum --check --strict --status "$(basename "$canary_compiler_checksum")"
)

mkdir -p "$output_root/extracted" "$output_root/compiler" "$output_root/state"
tar --extract --gzip --file "$canary_archive" --directory "$output_root/extracted" --no-same-owner
cp "$public_requirement" "$output_root/compiler/$(basename "$public_requirement")"
tar --extract --gzip --file "$canary_compiler_archive" --directory "$output_root/compiler" --no-same-owner
canary_package="$(canonical_directory "$output_root/extracted/depgraph-${version}-${canary_target}")"
canary_compiler_package="$(canonical_directory "$output_root/compiler/${compiler_pack_name}")"
canonical_file "$canary_compiler_package/compiler-pack-manifest.json" >/dev/null
canary_requirement="$(canonical_file "$output_root/compiler/$(basename "$public_requirement")")"
if [[ "$(find "$output_root/compiler" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" != "2" ]]; then
  echo "release post-publish canary compiler-pack extraction has an unexpected top-level closure" >&2
  exit 1
fi
canary_binary="$(canonical_file "$canary_package/bin/depgraph")"
canary_mcp_binary="$(canonical_file "$canary_package/bin/depgraph-mcp")"
canary_manifest="$(canonical_file "$canary_package/release-manifest.json")"
if [[ ! -x "$canary_binary" || ! -x "$canary_mcp_binary" ]]; then
  echo "release post-publish canary package binaries are not executable" >&2
  exit 1
fi
canary_store="$output_root/state/depgraph.sqlite"

"$canary_binary" --store "$canary_store" scan "$canary_repository" --no-cache --json \
  > "$output_root/scan.json"
"$canary_binary" --store "$canary_store" agent-config \
  --root "$canary_repository" \
  --release-archive "$canary_archive" \
  --release-checksum "$canary_checksum" \
  --release-evidence "$evidence" \
  --trusted-release-evidence-sha256 "$trusted_evidence_sha256" \
  --release-manifest "$canary_manifest" \
  --compiler-pack-requirement "$canary_requirement" \
  --host claude-desktop \
  > "$output_root/claude-desktop.json"

jq -e --arg command "$canary_mcp_binary" '
  type == "object" and
  (.mcpServers | type == "object") and
  (.mcpServers.depgraph.command == $command) and
  (.mcpServers.depgraph.args | type == "array")
' "$output_root/claude-desktop.json" >/dev/null

printf 'verified public %s Agent host canary; config=%s\n' \
  "$release_tag" "$output_root/claude-desktop.json"
