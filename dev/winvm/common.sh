#!/usr/bin/env bash
set -euo pipefail

winvm_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$winvm_dir/../.." && pwd -P)
config_file="$winvm_dir/config.json"
lock_file="$winvm_dir/image-lock.json"
if [[ -f ${WINVM_ENV_FILE:-$winvm_dir/env} ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${WINVM_ENV_FILE:-$winvm_dir/env}"
    set +a
fi
winvm_cache_dir=${WINVM_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sysnet-windows/winvm}

die() {
    printf 'winvm: %s\n' "$*" >&2
    exit 1
}
require_command() { command -v "$1" >/dev/null 2>&1 || die "missing command '$1'; enter 'nix develop'"; }
ensure_cache_dir() {
    mkdir -p -- "$winvm_cache_dir"
    chmod 0700 "$winvm_cache_dir"
}
sha256_file() { sha256sum -- "$1" | awk '{print $1}'; }
locked_value() { jq -er "$1" "$lock_file"; }
ssh_private_key() { printf '%s/ssh/id_ed25519\n' "$winvm_cache_dir"; }
ssh_public_key() { printf '%s/ssh/id_ed25519.pub\n' "$winvm_cache_dir"; }
ensure_ssh_key() {
    ensure_cache_dir
    local ssh_dir="$winvm_cache_dir/ssh" private public candidate derived fd
    private=$(ssh_private_key)
    public=$(ssh_public_key)
    mkdir -p -- "$ssh_dir" "$winvm_cache_dir/locks"
    chmod 0700 "$ssh_dir"
    exec {fd}>"$winvm_cache_dir/locks/ssh-key.lock"
    flock "$fd"
    if [[ ! -f $private ]]; then
        candidate="$ssh_dir/id_ed25519.new.$$"
        ssh-keygen -q -t ed25519 -N '' -C 'sysnet-windows winvm' -f "$candidate"
        chmod 0600 "$candidate"
        mv -- "$candidate" "$private"
        find "$candidate.pub" -maxdepth 0 -type f -delete
    fi
    chmod 0600 "$private"
    derived="$ssh_dir/id_ed25519.pub.new.$$"
    ssh-keygen -y -f "$private" >"$derived"
    chmod 0644 "$derived"
    mv -- "$derived" "$public"
    exec {fd}>&-
}
input_path() {
    local section=$1 name value
    name=$(locked_value ".${section}.environment")
    value=${!name:-}
    [[ -n $value ]] || die "$name is not set; copy dev/winvm/env.example to dev/winvm/env"
    [[ $value = /* ]] || die "$name must be an absolute path"
    printf '%s\n' "$value"
}
package_path() { printf '%s/inputs/%s\n' "$winvm_cache_dir" "$(locked_value ".${1}.file")"; }
verify_hash() {
    local label=$1 path=$2 expected=$3 actual
    [[ -f $path ]] || die "$label is absent: $path"
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "$label has no valid locked SHA-256"
    actual=$(sha256_file "$path")
    [[ $actual == "$expected" ]] || die "$label SHA-256 mismatch: expected $expected, got $actual"
}
download_packages() {
    ensure_cache_dir
    mkdir -p -- "$winvm_cache_dir/inputs" "$winvm_cache_dir/locks"
    local section path partial expected
    for section in go openssh; do
        path=$(package_path "$section")
        expected=$(locked_value ".${section}.sha256")
        [[ -f $path && $(sha256_file "$path") == "$expected" ]] && continue
        exec 7>"$winvm_cache_dir/locks/download-$section.lock"
        flock 7
        [[ -f $path && $(sha256_file "$path") == "$expected" ]] && continue
        partial="$path.partial.$$"
        trap 'rm -f -- "${partial:-}"' RETURN
        curl --fail --location --proto '=https' --tlsv1.2 --output "$partial" "$(locked_value ".${section}.source")"
        verify_hash "$section download" "$partial" "$expected"
        chmod 0600 "$partial"
        mv -- "$partial" "$path"
        trap - RETURN
    done
}
find_ovmf() {
    local kind=$1 override candidate
    local -a candidates
    if [[ $kind == code ]]; then
        override=${WINVM_OVMF_CODE:-}
        candidates=(/run/current-system/sw/share/qemu/edk2-x86_64-code.fd /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd)
    else
        override=${WINVM_OVMF_VARS:-}
        candidates=(/run/current-system/sw/share/qemu/edk2-i386-vars.fd /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd)
    fi
    [[ -n $override && -f $override ]] && {
        printf '%s\n' "$override"
        return
    }
    for candidate in "${candidates[@]}"; do [[ -f $candidate ]] && {
        printf '%s\n' "$candidate"
        return
    }; done
    return 1
}
base_key() {
    local input public
    local -a files=("$config_file" "$lock_file" "$winvm_dir/Autounattend.xml" "$winvm_dir/provision.ps1" "$winvm_dir/common.sh" "$winvm_dir/build-image.sh" "$repo_root/flake.lock" "$repo_root/flake.nix")
    public=$(ssh_public_key)
    [[ -r $public ]] || die "SSH public key is absent: $public; run just winvm-image"
    {
        qemu-system-x86_64 --version | head -n 1
        printf '%s\n' 'machine=q35,accel=kvm;disk=ahci;net=e1000e;firmware=ovmf'
        sha256_file "$(find_ovmf code)"
        sha256_file "$(find_ovmf vars)"
        sha256_file "$public"
        for input in "${files[@]}"; do
            [[ -f $input ]] || die "base-key input is absent: $input"
            sha256_file "$input"
        done
        printf '%s\n' "$(locked_value .windows.sha256)" "$(locked_value .virtio.sha256)"
        locked_value '.driver.files | to_entries | sort_by(.key)[] | .value'
    } | sha256sum | awk '{print $1}'
}
prepare_driver() {
    local output
    output=$(nix build --no-link --print-out-paths "$repo_root#windows-test-drivers")
    winvm_driver_dir="$output/amd64"
    local file
    for file in mullvad-split-tunnel.sys mullvad-split-tunnel.inf mullvad-split-tunnel.cat; do
        verify_hash "driver $file" "$winvm_driver_dir/$file" "$(locked_value ".driver.files[\"$file\"]")"
    done
}
prepare_wintun() {
    local output
    output=$(nix build --no-link --print-out-paths "$repo_root#windows-test-wintun")
    winvm_wintun_dir="$output"
    [[ -s $winvm_wintun_dir/amd64/wintun.dll ]] || die 'amd64 Wintun DLL is absent'
    [[ -s $winvm_wintun_dir/arm64/wintun.dll ]] || die 'arm64 Wintun DLL is absent'
}
allocate_locked_port() {
    local min max port fd attempt
    min=$(jq -r '.ssh.portMinimum' "$config_file")
    max=$(jq -r '.ssh.portMaximum' "$config_file")
    mkdir -p -- "$winvm_cache_dir/locks/ports"
    for ((attempt = 0; attempt <= max - min; attempt++)); do
        port=$((min + (RANDOM + attempt) % (max - min + 1)))
        exec {fd}>"$winvm_cache_dir/locks/ports/$port.lock"
        if flock -n "$fd" && python3 - "$port" <<'PY'
import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", int(sys.argv[1]))); s.close()
PY
        then
            # Callers read these globals, and the descriptor keeps the lock.
            # shellcheck disable=SC2034
            winvm_ssh_port=$port
            # shellcheck disable=SC2034
            winvm_port_lock_fd=$fd
            return
        fi
        exec {fd}>&-
    done
    die 'no free locked SSH port is available'
}
wait_for_pid() {
    local pid=$1 deadline=$((SECONDS + $2)) state
    while kill -0 "$pid" 2>/dev/null; do
        state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
        [[ $state == Z ]] && return
        ((SECONDS < deadline)) || return 1
        sleep 1
    done
}
stop_and_reap_pid() {
    local pid=$1
    if wait_for_pid "$pid" "$2"; then
        wait "$pid" 2>/dev/null || true
        return
    fi
    kill -TERM "$pid" 2>/dev/null || true
    if wait_for_pid "$pid" "$3"; then
        wait "$pid" 2>/dev/null || true
        return
    fi
    kill -KILL "$pid" 2>/dev/null || true
    if wait_for_pid "$pid" "$4"; then
        wait "$pid" 2>/dev/null || true
        return
    fi
    return 1
}
qemu_orphan_marker() { printf '%s/locks/qemu-orphan\n' "$winvm_cache_dir"; }
process_start_time() { awk '{print $22}' "/proc/$1/stat" 2>/dev/null; }
record_qemu_orphan() {
    local pid=$1 marker start
    marker=$(qemu_orphan_marker)
    start=$(process_start_time "$pid")
    [[ $start =~ ^[0-9]+$ ]] || start=unknown
    printf '%s %s\n' "$pid" "$start" >"$marker"
    chmod 0600 "$marker"
}
reject_live_qemu_orphan() {
    local marker pid start actual
    marker=$(qemu_orphan_marker)
    [[ -f $marker ]] || return 0
    read -r pid start <"$marker" || die "invalid QEMU orphan marker: $marker"
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        actual=$(process_start_time "$pid")
        if [[ $start == unknown || $actual == "$start" ]]; then
            die "QEMU process $pid survived cleanup; stop it before another VM run"
        fi
    fi
    find "$marker" -maxdepth 0 -type f -delete
}
cached_image_valid() {
    local image_dir=$1 key=$2 key_type key_data
    [[ -r $image_dir/base.qcow2 && -s $image_dir/OVMF_VARS.fd &&
        -r $image_dir/manifest.json && -s $image_dir/host-key.pub ]] || return 1
    [[ $(jq -r .baseImageKey "$image_dir/manifest.json" 2>/dev/null) == "$key" ]] || return 1
    [[ $(qemu-img info --output=json "$image_dir/base.qcow2" 2>/dev/null | jq -r .format) == qcow2 ]] || return 1
    read -r key_type key_data <"$image_dir/host-key.pub" || return 1
    [[ $key_type == ssh-* && -n $key_data ]] || return 1
    ssh-keygen -l -f "$image_dir/host-key.pub" >/dev/null 2>&1
}
make_socket_dir() {
    local root=${XDG_RUNTIME_DIR:-/tmp} path
    [[ $root = /* && -d $root && -w $root ]] || root=/tmp
    path=$(mktemp -d "$root/sysnet-winvm.XXXXXX")
    if ((${#path} + 10 >= 108)); then
        find "$path" -depth -delete
        path=$(mktemp -d /tmp/sysnet-winvm.XXXXXX)
    fi
    ((${#path} + 10 < 108)) || die 'cannot create a short QEMU socket path'
    chmod 0700 "$path"
    printf '%s\n' "$path"
}
remove_socket_dir() {
    local path=$1
    [[ ${path##*/} == sysnet-winvm.* ]] || die "unsafe socket path: $path"
    [[ ! -e $path ]] || find "$path" -depth -delete
}
