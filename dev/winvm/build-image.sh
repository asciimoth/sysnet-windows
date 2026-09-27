#!/usr/bin/env bash
# shellcheck disable=SC2054
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"
download_packages
prepare_driver
"$script_dir/doctor.sh"
ensure_ssh_key
key=$(base_key)
image_dir="$winvm_cache_dir/images/$key"
ssh_dir="$winvm_cache_dir/ssh"
mkdir -p "$winvm_cache_dir/images" "$winvm_cache_dir/locks" "$ssh_dir"
chmod 0700 "$winvm_cache_dir" "$ssh_dir"
# Use the same lock as test runs. Windows installation is memory-intensive and
# must not race another guest on this host.
exec 6>"$winvm_cache_dir/locks/vm-run.lock"
flock -w 1800 6 || die 'another VM held the host lock for 30 minutes'
reject_live_qemu_orphan
exec 9>"$winvm_cache_dir/locks/image-$key.lock"
printf 'Waiting for image lock %s...\n' "$key"
flock 9
if cached_image_valid "$image_dir" "$key"; then
    printf 'Reusing Windows base image %s\n' "$key"
    exit
fi
ssh_key=$(ssh_private_key)
work=$(mktemp -d "$winvm_cache_dir/build-$key.XXXXXX")
sockets=$(make_socket_dir)
qga="$sockets/qga.sock"
qmp="$sockets/qmp.sock"
pid=''
cleanup() {
    status=$?
    trap - EXIT INT TERM
    stopped=1
    if [[ -n $pid ]]; then
        "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 shutdown >/dev/null 2>&1 || true
        if ! stop_and_reap_pid "$pid" 20 10 10; then
            record_qemu_orphan "$pid"
            stopped=0
            status=1
        fi
    fi
    if ((stopped)); then remove_socket_dir "$sockets"; else printf 'winvm: QEMU survived cleanup; retaining image files and sockets\n' >&2; fi
    ((status == 0)) || printf 'winvm: failed image files remain in %s\n' "$work" >&2
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp "$script_dir/Autounattend.xml" "$work/Autounattend.xml"
cp "$script_dir/provision.ps1" "$work/provision.ps1"
cp "$ssh_key.pub" "$work/authorized_key.pub"
password=$(python3 -c 'import secrets; print(secrets.token_hex(24)+"aA!")')
sed -i -e "s|@@WINDOWS_IMAGE_NAME@@|$(jq -r .windowsImageName "$config_file")|g" -e "s|@@ADMIN_PASSWORD@@|$password|g" "$work/Autounattend.xml"
unset password
sed -i \
    -e "s|@@GO_FILE@@|$(locked_value .go.file)|g" -e "s|@@GO_VERSION@@|$(locked_value .go.version)|g" \
    -e "s|@@OPENSSH_FILE@@|$(locked_value .openssh.file)|g" -e "s|@@DRIVER_SERVICE@@|$(locked_value .driver.serviceName)|g" \
    -e "s|@@DRIVER_VERSION@@|$(locked_value .driver.version)|g" -e "s|@@UPSTREAM_COMMIT@@|$(locked_value .driver.upstreamCommit)|g" \
    -e "s|@@DRIVER_SYS_SHA256@@|$(locked_value '.driver.files["mullvad-split-tunnel.sys"]')|g" \
    -e "s|@@DRIVER_INF_SHA256@@|$(locked_value '.driver.files["mullvad-split-tunnel.inf"]')|g" \
    -e "s|@@DRIVER_CAT_SHA256@@|$(locked_value '.driver.files["mullvad-split-tunnel.cat"]')|g" "$work/provision.ps1"
cp "$(package_path go)" "$(package_path openssh)" "$work/"
mkdir "$work/driver"
cp "$winvm_driver_dir"/* "$work/driver/"
printf 'Creating the Windows provisioning ISO...\n'
xorriso -as mkisofs -quiet -J -R -V WINVM_PROVISION -o "$work/provision.iso" "$work/Autounattend.xml" "$work/provision.ps1" "$work/authorized_key.pub" "$work/$(locked_value .go.file)" "$work/$(locked_value .openssh.file)" "$work/driver"
qemu-img create -q -f qcow2 "$work/base.qcow2" "$(jq -r .machine.diskGiB "$config_file")G"
cp "$(find_ovmf vars)" "$work/OVMF_VARS.fd"
chmod 0600 "$work/OVMF_VARS.fd"
allocate_locked_port
port=$winvm_ssh_port
qemu=(qemu-system-x86_64 -name sysnet-winvm-build -machine "$(jq -r .machine.type "$config_file")" -cpu host -smp "$(jq -r .machine.cpus "$config_file")" -m "$(jq -r .machine.memoryMiB "$config_file")" -display none -chardev "file,id=serial0,path=$work/serial.log" -serial chardev:serial0 -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)" -drive "if=pflash,format=raw,file=$work/OVMF_VARS.fd" -device ich9-ahci,id=sata -drive "if=none,id=osdisk,format=qcow2,file=$work/base.qcow2" -device ide-hd,drive=osdisk,bus=sata.0 -drive "if=none,id=windows,media=cdrom,readonly=on,file=$(input_path windows)" -device ide-cd,drive=windows,bus=sata.1 -drive "if=none,id=virtio,media=cdrom,readonly=on,file=$(input_path virtio)" -device ide-cd,drive=virtio,bus=sata.2 -drive "if=none,id=provision,media=cdrom,readonly=on,file=$work/provision.iso" -device ide-cd,drive=provision,bus=sata.3 -device e1000e,netdev=net0 -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-serial-pci -chardev "socket,path=$qga,server=on,wait=off,id=qga0" -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 -qmp "unix:$qmp,server=on,wait=off" -boot once=d,menu=off)
printf 'Starting the unattended Windows installation. This usually takes several minutes.\n'
printf 'Detailed logs: %s\n' "$work"
printf '%q ' "${qemu[@]}" >"$work/qemu-command.log"
"${qemu[@]}" >>"$work/qemu.log" 2>&1 &
pid=$!
deadline=$((SECONDS + 20))
while [[ ! -S $qmp && $SECONDS -lt $deadline ]]; do
    kill -0 "$pid" || die 'QEMU exited before QMP readiness'
    sleep .1
done
[[ -S $qmp ]] || die 'QMP readiness timeout'
# Firmware and optical-media timing varies across cold boots. Send a harmless
# key until setup starts writing to the disk, then stop immediately. This avoids
# both a fixed early window and stray input after Windows Setup has started.
disk_size_before_boot=$(stat -c %s "$work/base.qcow2")
setup_started=0
for _ in {1..60}; do
    kill -0 "$pid" || die 'QEMU exited during the installation boot window'
    "$script_dir/tools/qga.py" --socket "$qmp" --timeout 3 qmp send-key \
        --arguments '{"keys":[{"type":"qcode","data":"spc"}]}' >/dev/null
    sleep 1
    disk_size=$(stat -c %s "$work/base.qcow2")
    if ((disk_size >= disk_size_before_boot + 16 * 1024 * 1024)); then
        setup_started=1
        break
    fi
done
((setup_started)) || die 'Windows Setup did not start writing to the guest disk'
install_started=$SECONDS
install_timeout=$(jq -r .machine.installTimeoutSeconds "$config_file")
deadline=$((SECONDS + install_timeout))
next_progress=$((SECONDS + 30))
token=''
printf 'Windows Setup is writing the system disk. Waiting for guest provisioning...\n'
while ((SECONDS < deadline)); do
    kill -0 "$pid" || die 'QEMU exited during installation'
    if "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 ping >/dev/null 2>&1; then
        token=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 10 exec powershell.exe -NoProfile -Command "if(Test-Path C:\\winvm\\ready){Get-Content -Raw C:\\winvm\\ready}else{exit 1}" 2>/dev/null || true)
        [[ -n $token ]] && break
    fi
    if ((SECONDS >= next_progress)); then
        printf 'Still provisioning Windows: %d seconds elapsed, about %d minutes remain.\n' "$((SECONDS - install_started))" "$(((deadline - SECONDS + 59) / 60))"
        next_progress=$((SECONDS + 30))
    fi
    sleep 5
done
[[ -n $token ]] || die 'Windows provisioning timeout'
printf 'Guest provisioning completed. Verifying readiness and SSH identity...\n'
# Require the same atomic readiness generation after a quiet period. This prevents
# a transient QGA response or a reboot boundary from publishing an incomplete image.
sleep 5
token2=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 15 exec powershell.exe -NoProfile -Command "Get-Content -Raw C:\\winvm\\ready")
[[ $token2 == "$token" ]] || die 'guest readiness generation changed'
"$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec powershell.exe -NoProfile -Command 'Get-Content -Raw C:\winvm\manifest.json' >"$work/guest.json"
jq -e . "$work/guest.json" >/dev/null
scan="$work/known_hosts"
for _ in {1..60}; do
    ssh-keyscan -T 3 -p "$port" 127.0.0.1 >"$scan" 2>/dev/null && [[ -s $scan ]] && break
    sleep 2
done
awk '$2=="ssh-ed25519"{print $2,$3;exit}' "$scan" >"$work/host-key.pub"
[[ -s $work/host-key.pub ]] || die 'SSH host key unavailable'
"$script_dir/tools/qga.py" --socket "$qga" --timeout 10 shutdown || true
wait_for_pid "$pid" "$(jq -r .machine.shutdownTimeoutSeconds "$config_file")" || die 'provisioned guest did not stop'
wait "$pid" || true
pid=''
jq -n --arg key "$key" --argjson guest "$(cat "$work/guest.json")" '{baseImageKey:$key}+$guest' >"$work/manifest.json"
publish="$winvm_cache_dir/images/.publish-$key-$$"
mkdir "$publish"
mv "$work/base.qcow2" "$work/OVMF_VARS.fd" "$work/manifest.json" "$work/host-key.pub" "$publish/"
chmod 0444 "$publish"/*
if [[ -e $image_dir ]]; then
    [[ $image_dir == "$winvm_cache_dir/images/$key" ]] || die 'unsafe image directory'
    find "$image_dir" -depth -delete
fi
mv "$publish" "$image_dir"
find "$work" -depth -delete
printf 'Built Windows base image %s\n' "$key"
