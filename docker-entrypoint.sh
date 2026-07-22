#!/bin/sh
# Entrypoint for the one-shot pipeline container (see Dockerfile).
#
# "pipeline" (the default CMD) runs fetch all -> unify -> tar the unified/
# tree into /out. Any other argument list is passed through to wisteria
# verbatim so debug subcommands can inspect the cache volume.
set -eu

CACHE_DIR="${WISTERIA_CACHE_DIR:-/cache}"

if [ "${1:-pipeline}" != "pipeline" ]; then
    exec wisteria "$@"
fi

# Fail before hours of fetching, not after, if the host forgot -v .../out.
if [ ! -d /out ] || [ ! -w /out ]; then
    echo "error: /out is not a writable directory; run with -v \"\$(pwd)/out:/out\"" >&2
    exit 1
fi

wisteria fetch all
wisteria unify

# tar only runs if fetch and unify both succeeded (set -e), so /out never
# receives a tarball built from a half-finished pipeline.
tar -czf /out/unified.tar.gz.tmp -C "$CACHE_DIR" unified
mv /out/unified.tar.gz.tmp /out/unified.tar.gz
echo "wrote /out/unified.tar.gz"
