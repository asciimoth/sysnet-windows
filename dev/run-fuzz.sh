#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

found=0
while IFS= read -r package; do
    while IFS= read -r target; do
        [[ $target == Fuzz* ]] || continue
        found=1
        printf 'Running %s in %s.\n' "$target" "$package"
        go test -run '^$' -fuzz "^${target}$" -fuzztime 5s "$package"
    done < <(go test -list '^Fuzz' "$package")
done < <(go list ./...)

if ((found == 0)); then
    printf 'No fuzz targets are present; compiling all test packages.\n'
    go test -run '^$' ./...
fi
