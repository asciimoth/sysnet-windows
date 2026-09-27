#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$script_dir/../.." && pwd -P)
output=${1:?usage: package-worktree.sh OUTPUT.tar}
[[ $output = /* ]] || output="$PWD/$output"
mkdir -p -- "$(dirname -- "$output")"
list=$(mktemp)
trap 'rm -f -- "$list"' EXIT
cd -- "$root"
git ls-files --deduplicate --cached --modified --others --exclude-standard -z | while IFS= read -r -d '' path; do
    [[ -f $path || -L $path ]] || continue
    case $path in .git/* | .artifacts/winvm/* | dev/winvm/env | dev/winvm/*.qcow2 | dev/winvm/*.sock | dev/winvm/*.iso | dev/winvm/tools/__pycache__/*) continue ;; esac
    printf '%s\0' "$path"
done >"$list"
tar --null --no-recursion --format=posix -cf "$output" -T "$list"
