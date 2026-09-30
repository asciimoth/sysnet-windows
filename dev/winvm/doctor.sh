#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"
validate() {
    jq -e '.schemaVersion==1 and .architecture=="amd64" and .machine.cpus>=2 and .machine.memoryMiB>=4096 and .machine.diskGiB>=40 and .machine.bootTimeoutSeconds>0 and .machine.installTimeoutSeconds>0 and .machine.testTimeoutSeconds>0 and .ssh.user=="winvm" and .ssh.portMinimum>=1024 and .ssh.portMaximum>=.ssh.portMinimum and .artifacts.directory==".artifacts/winvm"' "$config_file" >/dev/null || die 'invalid config.json'
    jq -e '.schemaVersion==1 and .go.version=="1.25.14" and .driver.version=="1.3.0.0" and .driver.upstreamCommit=="0a0eb97f67d1dbcb3d08bda66d3b24f465d95475" and ([.windows.sha256,.virtio.sha256,.go.sha256,.openssh.sha256,.driver.files[]]|all(test("^[0-9a-f]{64}$")))' "$lock_file" >/dev/null || die 'invalid image-lock.json'
}
case ${1:-check} in
    --validate)
        validate
        printf 'Windows VM configuration is valid.\n'
        exit
        ;;
    --print-input-hashes)
        validate
        for section in windows virtio; do
            name=$(locked_value ".${section}.environment")
            path=${!name:-}
            [[ -f ${path:-} ]] && printf '%s %s %s\n' "$(sha256_file "$path")" "$name" "$path" || printf '%s: not set or absent\n' "$name"
        done
        exit
        ;;
    --base-key)
        validate
        base_key
        exit
        ;;
    check) ;;
    *) die "unknown option: $1" ;;
esac
for command in qemu-system-x86_64 qemu-img xorriso ssh scp ssh-keygen jq python3 curl sha256sum flock git tar nix; do require_command "$command"; done
validate
[[ $(uname -s) == Linux ]] || die 'the VM harness needs Linux'
[[ -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is not accessible; enable KVM and add this user to its device group'
find_ovmf code >/dev/null || die 'OVMF code firmware is absent'
find_ovmf vars >/dev/null || die 'OVMF variable firmware is absent'
for section in windows virtio; do verify_hash "$section ISO" "$(input_path "$section")" "$(locked_value ".${section}.sha256")"; done
for section in go openssh; do
    path=$(package_path "$section")
    if [[ -f $path ]]; then verify_hash "$section package" "$path" "$(locked_value ".${section}.sha256")"; else printf 'Windows VM %s package is not cached; winvm-image will download it.\n' "$section"; fi
done
prepare_driver
prepare_wintun
available=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
required=$(jq -r .machine.memoryMiB "$config_file")
((available >= required)) || die "VM needs $required MiB available memory"
ensure_cache_dir
free=$(df -Pk "$winvm_cache_dir" | awk 'NR==2{print $4}')
disk=$(jq -r .machine.diskGiB "$config_file")
((free >= (disk + 10) * 1024 * 1024)) || die "VM cache needs $((disk + 10)) GiB free"
allocate_locked_port
printf 'Windows VM host checks passed. Locked port %s is available.\n' "$winvm_ssh_port"
