#!/bin/sh
printf 'unsafe' > CONFIG_EXECUTED
exec rustc "$@"
