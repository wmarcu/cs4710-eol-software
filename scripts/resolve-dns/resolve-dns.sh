#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_INPUT="$SCRIPT_DIR/domains.txt"
DEFAULT_UNIQUE_OUTPUT="$SCRIPT_DIR/resolved-ips.txt"
DEFAULT_MAPPING_OUTPUT="$SCRIPT_DIR/resolved-ips-mapping.txt"


INPUT="${1:-$DEFAULT_INPUT}"
UNIQUE_OUTPUT="${2:-$DEFAULT_UNIQUE_OUTPUT}"
MAPPING_OUTPUT="${3:-$DEFAULT_MAPPING_OUTPUT}"


echo "Resolving domains from $INPUT..."

> "$UNIQUE_OUTPUT"
> "$MAPPING_OUTPUT"

while IFS= read -r line; do
    domain=$(echo "$line" | sed 's|https\?://||')
    while IFS= read -r ip; do
        echo "$ip,$domain"
    done < <(dig +short "$domain" A | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u)
done < "$INPUT" | awk -F',' '{
    if (ip[$1]) ip[$1] = ip[$1] ";" $2
    else ip[$1] = $2
} END {
    for (i in ip) print i "," ip[i]
}' | sort > "$MAPPING_OUTPUT"

cut -d',' -f1 "$MAPPING_OUTPUT" > "$UNIQUE_OUTPUT"

echo "Done! Resolved IPs saved to $UNIQUE_OUTPUT"