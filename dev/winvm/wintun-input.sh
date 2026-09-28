#!/usr/bin/env bash
# shellcheck disable=SC2154 # Set by common.sh before this file is sourced.

# prepare_wintun_archive validates and downloads the Wintun archive that
# the live and flow gates use. It sets wintun_archive to the verified cache path.
prepare_wintun_archive() {
    local lock_file=$1 version file source expected partial fd
    jq -e '
        type == "object" and
        keys == ["schemaVersion", "wintun"] and
        .schemaVersion == 1 and
        (.wintun | type == "object" and
            keys == ["file", "sha256", "source", "version"] and
            (.version | type == "string") and
            (.file | type == "string") and
            (.source | type == "string") and
            (.sha256 | type == "string"))
    ' "$lock_file" >/dev/null || die 'invalid Wintun input lock'
    version=$(jq -er .wintun.version "$lock_file")
    file=$(jq -er .wintun.file "$lock_file")
    source=$(jq -er .wintun.source "$lock_file")
    expected=$(jq -er .wintun.sha256 "$lock_file")
    [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'invalid locked Wintun version'
    [[ $file == "wintun-$version.zip" ]] || die 'invalid locked Wintun file name'
    [[ $source == "https://www.wintun.net/builds/$file" ]] || die 'invalid locked Wintun source'
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die 'invalid locked Wintun SHA-256'

    ensure_cache_dir
    mkdir -p "$winvm_cache_dir/inputs" "$winvm_cache_dir/locks"
    wintun_archive="$winvm_cache_dir/inputs/$file"
    [[ -f $wintun_archive && $(sha256_file "$wintun_archive") == "$expected" ]] && return
    exec {fd}>"$winvm_cache_dir/locks/download-wintun.lock"
    flock "$fd"
    [[ -f $wintun_archive && $(sha256_file "$wintun_archive") == "$expected" ]] && return
    partial="$wintun_archive.partial.$$"
    if ! curl --fail --location --proto '=https' --tlsv1.2 --output "$partial" "$source"; then
        find "$partial" -maxdepth 0 -type f -delete 2>/dev/null || true
        die 'cannot download locked Wintun archive'
    fi
    if [[ $(sha256_file "$partial") != "$expected" ]]; then
        find "$partial" -maxdepth 0 -type f -delete
        die 'Wintun download SHA-256 mismatch'
    fi
    chmod 0600 "$partial"
    mv -- "$partial" "$wintun_archive"
}
