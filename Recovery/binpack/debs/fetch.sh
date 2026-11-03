#!/bin/sh
# downloads the extra binpack packages listed in PACKAGES (sha256, pool path) and checks them
set -e
cd "$(dirname "$0")"
repo=https://roothide.github.io/procursus
while read -r sum path; do
    [ -n "$path" ] || continue
    name=$(basename "$path")
    if [ ! -f "$name" ] || ! echo "$sum  $name" | shasum -a 256 -c - >/dev/null 2>&1; then
        echo "fetching $name"
        curl -fsSL -o "$name" "$repo/$(echo "$path" | sed 's/+/%2B/g')"
    fi
    echo "$sum  $name" | shasum -a 256 -c -
done < PACKAGES
