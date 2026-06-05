#!/usr/bin/env bash

set -euo pipefail

if [[ $# != 3 ]]; then
    echo "Usage: $0 <leftovers jar> <aot cache path> <custom jdk root path>"
    exit 1
fi

JAR="$1"
CACHE_FILE="$2"
JAVA="$3/bin/java"
OUTER_CACHE_FILE="$(dirname "$CACHE_FILE")/outer-$(basename "$CACHE_FILE")"
AOT_COMPAT_FLAGS=(
    -XX:+UseG1GC
    -XX:+UseCompressedOops
    -Xmx3g
)

echo "====== Serving stage 1 ======"
"$JAVA" "${AOT_COMPAT_FLAGS[@]}" -XX:AOTCache="$OUTER_CACHE_FILE" -cp "$JAR" de.kitctf.gpn24.leftovers2.OuterServer serve "/tmp/cache.aot" "$CACHE_FILE"

echo "====== Serving stage 2 ======"
"$JAVA" "${AOT_COMPAT_FLAGS[@]}" -XX:AOTCache="/tmp/cache.aot" -jar "$JAR"
