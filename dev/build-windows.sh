#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$root"

tmp=$(mktemp -d)
trap 'find "$tmp" -depth -delete' EXIT

for architecture in amd64 arm64; do
    printf 'Building Windows/%s packages.\n' "$architecture"
    GOOS=windows GOARCH="$architecture" CGO_ENABLED=0 go build ./...

    while IFS=$'\t' read -r import_path package_name; do
        [[ -n $import_path && -n $package_name ]] || continue
        output="$tmp/${architecture}-${package_name}.test.exe"
        GOOS=windows GOARCH="$architecture" CGO_ENABLED=0 \
            go test -c -o "$output" "$import_path"
    done < <(
        go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{"\t"}}{{.Name}}{{"\n"}}{{end}}' ./...
    )
done
