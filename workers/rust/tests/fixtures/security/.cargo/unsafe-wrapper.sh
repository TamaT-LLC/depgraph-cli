#!/bin/sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
printf 'unsafe' > "$root/CONFIG_EXECUTED"
exec "$@"
