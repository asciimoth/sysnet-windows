#!/usr/bin/env bash
# Remote PowerShell paths intentionally expand on the client.
# shellcheck disable=SC2029,SC2054
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"
# shellcheck source=dev/winvm/wintun-input.sh
source "$script_dir/wintun-input.sh"
mode=${1:-baseline}
shell_path=''
case $mode in baseline | e2e | flow) ;; --shell)
    mode=shell
    shell_path=${2:?usage: run.sh --shell RUN}
    ;;
--clean) mode=clean ;; *) die "unknown mode: $mode" ;; esac
artifact_root=$(realpath -m "$repo_root/$(jq -r .artifacts.directory "$config_file")")
[[ $artifact_root == "$repo_root/.artifacts/winvm" ]] || die "unsafe artifact root: $artifact_root"
if [[ $mode == clean ]]; then
    [[ -d $artifact_root ]] || {
        printf 'No Windows VM artifacts exist.\n'
        exit
    }
    ensure_cache_dir
    mkdir -p "$winvm_cache_dir/locks"
    exec 6>"$winvm_cache_dir/locks/vm-run.lock"
    flock -w 1800 6 || die 'an active VM held the host lock for 30 minutes'
    reject_live_qemu_orphan
    while IFS= read -r -d '' path; do
        resolved=$(realpath -e "$path")
        [[ $resolved == "$artifact_root"/run-* ]] || die "unsafe cleanup target: $resolved"
        find "$resolved" -depth -delete
    done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d -name 'run-*' -print0)
    printf 'Removed validated VM runs. The base image was kept.\n'
    exit
fi
for command in qemu-system-x86_64 qemu-img ssh scp jq python3 timeout flock git tar curl; do require_command "$command"; done
[[ -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is not accessible; run just winvm-doctor'
ensure_cache_dir
mkdir -p "$artifact_root" "$winvm_cache_dir/locks"
chmod 0700 "$artifact_root"
if [[ $mode == e2e || $mode == flow ]]; then
    wintun_lock="$script_dir/wintun-lock.json"
    prepare_wintun_archive "$wintun_lock"
fi
# One active VM per host prevents memory and CPU oversubscription from making
# boot and driver timing nondeterministic. The bounded flock also avoids hangs.
exec 6>"$winvm_cache_dir/locks/vm-run.lock"
flock -w 1800 6 || die 'another VM run held the host lock for 30 minutes'
reject_live_qemu_orphan
if [[ $mode == shell ]]; then
    run_dir=$(realpath -e "$shell_path")
    [[ $run_dir == "$artifact_root"/run-* ]] || die 'retained run is outside artifact root'
    key=$(jq -er .baseImageKey "$run_dir/run.json")
else key=$(base_key); fi
image_dir="$winvm_cache_dir/images/$key"
base="$image_dir/base.qcow2"
vars_base="$image_dir/OVMF_VARS.fd"
manifest="$image_dir/manifest.json"
host_key="$image_dir/host-key.pub"
ssh_key=$(ssh_private_key)
exec 8>"$winvm_cache_dir/locks/image-$key.lock"
flock -s 8
for path in "$base" "$vars_base" "$manifest" "$host_key" "$ssh_key"; do [[ -r $path ]] || die "base-image input is absent: $path; run just winvm-image"; done
[[ $(jq -r .baseImageKey "$manifest") == "$key" ]] || die 'base-image manifest key mismatch'
if [[ $mode != shell ]]; then
    allocated=0
    for _ in {1..20}; do
        run_id="run-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
        run_dir="$artifact_root/$run_id"
        if mkdir -m 0700 "$run_dir" 2>/dev/null; then
            allocated=1
            break
        fi
    done
    ((allocated)) || die 'cannot allocate a unique run directory'
fi
exec 5>"$run_dir/run.lock"
flock -n 5 || die 'this run is already active'
overlay="$run_dir/overlay.qcow2"
vars="$run_dir/OVMF_VARS.fd"
sockets=$(make_socket_dir)
qga="$sockets/qga.sock"
qmp="$sockets/qmp.sock"
pid=''
endpoint_pid=''
endpoint_overlay="$run_dir/endpoint-overlay.qcow2"
endpoint_vars="$run_dir/endpoint-OVMF_VARS.fd"
endpoint_sockets=''
success=0
stage=setup
test_status=1
safe_remove() {
    [[ $overlay == "$artifact_root"/run-*/overlay.qcow2 ]] || die "unsafe overlay: $overlay"
    if [[ -e $overlay ]]; then
        backing=$(qemu-img info --output=json "$overlay" | jq -r '."full-backing-filename" // ."backing-filename" // empty')
        [[ -n $backing && $(realpath -e "$backing") == "$(realpath -e "$base")" ]] || die 'refusing overlay with unexpected backing file'
        find "$overlay" -maxdepth 0 -type f -delete
    fi
}
safe_remove_endpoint() {
    [[ $endpoint_overlay == "$artifact_root"/run-*/endpoint-overlay.qcow2 ]] || die "unsafe endpoint overlay: $endpoint_overlay"
    if [[ -e $endpoint_overlay ]]; then
        backing=$(qemu-img info --output=json "$endpoint_overlay" | jq -r '."full-backing-filename" // ."backing-filename" // empty')
        [[ -n $backing && $(realpath -e "$backing") == "$(realpath -e "$base")" ]] || die 'refusing endpoint overlay with unexpected backing file'
        find "$endpoint_overlay" -maxdepth 0 -type f -delete
    fi
}
stop_vm() {
    [[ -n $pid ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 shutdown >>"$run_dir/guest-agent.log" 2>&1 || true
        wait_for_pid "$pid" "$(jq -r .machine.shutdownTimeoutSeconds "$config_file")" || "$script_dir/tools/qga.py" --socket "$qmp" --timeout 5 qmp quit >>"$run_dir/guest-agent.log" 2>&1 || true
        if ! stop_and_reap_pid "$pid" 10 10 10; then
            record_qemu_orphan "$pid"
            return 1
        fi
    else
        wait "$pid" 2>/dev/null || true
    fi
    pid=''
}
stop_endpoint_vm() {
    [[ -n $endpoint_pid ]] || return 0
    endpoint_qga="$endpoint_sockets/qga.sock"
    endpoint_qmp="$endpoint_sockets/qmp.sock"
    if kill -0 "$endpoint_pid" 2>/dev/null; then
        "$script_dir/tools/qga.py" --socket "$endpoint_qga" --timeout 5 shutdown >>"$run_dir/endpoint-agent.log" 2>&1 || true
        wait_for_pid "$endpoint_pid" "$(jq -r .machine.shutdownTimeoutSeconds "$config_file")" || "$script_dir/tools/qga.py" --socket "$endpoint_qmp" --timeout 5 qmp quit >>"$run_dir/endpoint-agent.log" 2>&1 || true
        if ! stop_and_reap_pid "$endpoint_pid" 10 10 10; then
            record_qemu_orphan "$endpoint_pid"
            return 1
        fi
    else
        wait "$endpoint_pid" 2>/dev/null || true
    fi
    endpoint_pid=''
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    vm_stopped=1
    if ((status != 0)) && [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null && [[ -S $qga ]]; then
        diagnostics='Get-Process | Sort-Object ProcessName | Format-Table -AutoSize; Get-Service | Where-Object Name -Match "mullvad|qemu|ssh" | Format-Table -AutoSize; Get-WinEvent -FilterHashtable @{LogName="Application","System"; StartTime=(Get-Date).AddMinutes(-30)} -ErrorAction SilentlyContinue | Select-Object -First 100 | Format-List'
        "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec powershell.exe -NoProfile -Command "$diagnostics" >"$run_dir/diagnostics.log" 2>&1 || true
        if [[ -n ${remote:-} ]]; then
            guest_remote=${remote//\//\\}
            "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec tar.exe -cf "$guest_remote\\artifacts.tar" -C "$guest_remote" artifacts >/dev/null 2>&1 || true
            "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 read "$guest_remote\\artifacts.tar" --limit 67108864 >"$run_dir/guest-artifacts.tar" 2>/dev/null || true
        fi
    fi
    cleanup_failed=0
    stop_vm || cleanup_failed=1
    stop_endpoint_vm || cleanup_failed=1
    if ((cleanup_failed)); then
        vm_stopped=0
        status=1
        stage=cleanup-qemu
        printf 'winvm: QEMU survived cleanup; retaining VM disks and sockets\n' >&2
    fi
    if ((vm_stopped)); then
        remove_socket_dir "$sockets"
        [[ -z $endpoint_sockets ]] || remove_socket_dir "$endpoint_sockets"
    fi
    if [[ $mode != shell && -f $run_dir/run.json ]]; then
        if jq --argjson exit "$status" --arg stage "$stage" --arg finished "$(date -u +%FT%TZ)" '.exitStatus=$exit|.status=(if $exit==0 then "passed" else "failed" end)|.stage=$stage|.finishedAt=$finished' "$run_dir/run.json" >"$run_dir/run.json.new"; then
            mv "$run_dir/run.json.new" "$run_dir/run.json"
        fi
    fi
    if ((success && vm_stopped)); then
        safe_remove
        [[ $mode != flow ]] || safe_remove_endpoint
        find "$vars" -maxdepth 0 -type f -delete
        [[ ! -e $endpoint_vars ]] || find "$endpoint_vars" -maxdepth 0 -type f -delete
    elif [[ $mode != shell ]]; then
        printf '%s\n' "$stage" >"$run_dir/failure-stage.txt"
        if ((vm_stopped)) && [[ $(jq -r .artifacts.retainFailedOverlay "$config_file") != true ]]; then
            safe_remove
            [[ $mode != flow ]] || safe_remove_endpoint
        else printf 'Retained failed overlay. Diagnose with: just winvm-shell %q\n' "$run_dir" >&2; fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ $mode != shell ]]; then
    revision=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || printf unknown)
    dirty=false
    [[ -n $(git -C "$repo_root" status --porcelain) ]] && dirty=true
    wintun_lock_hash=''
    if [[ $mode == e2e || $mode == flow ]]; then wintun_lock_hash=$(sha256_file "$wintun_lock"); fi
    jq -n --arg revision "$revision" --argjson dirty "$dirty" --arg key "$key" --arg mode "$mode" --arg started "$(date -u +%FT%TZ)" --arg testHash "$(sha256_file "$script_dir/test.ps1")" --arg e2eHash "$(sha256_file "$script_dir/e2e.ps1")" --arg runnerHash "$(sha256_file "$script_dir/run.sh")" --arg wintunLockHash "$wintun_lock_hash" '{revision:$revision,dirty:$dirty,baseImageKey:$key,mode:$mode,startedAt:$started,status:"running",stage:"setup",scriptHashes:{test:$testHash,e2e:$e2eHash,runner:$runnerHash,wintunLock:$wintunLockHash}}' >"$run_dir/run.json"
    cp "$manifest" "$run_dir/image-manifest.json"
    qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$overlay"
    if [[ $mode == flow ]]; then qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$endpoint_overlay"; fi
fi
actual=$(qemu-img info --output=json "$overlay" | jq -r '."full-backing-filename" // ."backing-filename" // empty')
[[ -n $actual && $(realpath -e "$actual") == "$(realpath -e "$base")" ]] || die 'overlay backing file mismatch'
if [[ $mode == shell ]]; then
    [[ -r $vars ]] || die 'retained OVMF variable store is absent'
else
    cp "$vars_base" "$vars"
    chmod 0600 "$vars"
    if [[ $mode == flow ]]; then
        cp "$vars_base" "$endpoint_vars"
        chmod 0600 "$endpoint_vars"
    fi
fi
allocate_locked_port
port=$winvm_ssh_port
if [[ $mode == flow ]]; then
    allocate_locked_port
    endpoint_port=$winvm_ssh_port
    endpoint_sockets=$(make_socket_dir)
fi
read -r key_type key_data <"$host_key"
printf '[127.0.0.1]:%s %s %s\n' "$port" "$key_type" "$key_data" >"$run_dir/known_hosts"
qemu=(qemu-system-x86_64 -name "sysnet-winvm-$mode" -machine "$(jq -r .machine.type "$config_file")" -cpu host -smp "$(jq -r .machine.cpus "$config_file")" -m "$(jq -r .machine.memoryMiB "$config_file")" -no-reboot -display none -chardev "file,id=serial0,path=$run_dir/serial.log" -serial chardev:serial0 -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)" -drive "if=pflash,format=raw,file=$vars" -device ich9-ahci,id=sata -drive "if=none,id=osdisk,format=qcow2,file=$overlay,cache=writeback" -device ide-hd,drive=osdisk,bus=sata.0 -device e1000e,netdev=net0 -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-serial-pci -chardev "socket,path=$qga,server=on,wait=off,id=qga0" -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 -qmp "unix:$qmp,server=on,wait=off")
if [[ $mode == flow ]]; then
    tunnel_socket="$endpoint_sockets/tunnel.sock"
    underlay_socket="$endpoint_sockets/underlay.sock"
    endpoint_qga="$endpoint_sockets/qga.sock"
    endpoint_qmp="$endpoint_sockets/qmp.sock"
    endpoint_qemu=(qemu-system-x86_64 -name sysnet-winvm-flow-endpoint -machine "$(jq -r .machine.type "$config_file")" -cpu host -smp 2 -m 4096 -no-reboot -display none -chardev "file,id=serial0,path=$run_dir/endpoint-serial.log" -serial chardev:serial0 -drive "if=pflash,format=raw,readonly=on,file=$(find_ovmf code)" -drive "if=pflash,format=raw,file=$endpoint_vars" -device ich9-ahci,id=sata -drive "if=none,id=osdisk,format=qcow2,file=$endpoint_overlay,cache=writeback" -device ide-hd,drive=osdisk,bus=sata.0 -device e1000e,netdev=net0 -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$endpoint_port-:22" -device e1000e,mac=52:54:00:12:34:20,netdev=tunnel -netdev "stream,id=tunnel,server=on,addr.type=unix,addr.path=$tunnel_socket" -device e1000e,mac=52:54:00:12:34:21,netdev=underlay -netdev "stream,id=underlay,server=on,addr.type=unix,addr.path=$underlay_socket" -device virtio-serial-pci -chardev "socket,path=$endpoint_qga,server=on,wait=off,id=qga0" -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 -qmp "unix:$endpoint_qmp,server=on,wait=off")
    printf '%q ' "${endpoint_qemu[@]}" >"$run_dir/endpoint-qemu-command.log"
    "${endpoint_qemu[@]}" >>"$run_dir/endpoint-qemu.log" 2>&1 &
    endpoint_pid=$!
    for _ in {1..100}; do
        [[ -S $tunnel_socket && -S $underlay_socket ]] && break
        kill -0 "$endpoint_pid" 2>/dev/null || die 'endpoint QEMU exited during setup'
        sleep .1
    done
    [[ -S $tunnel_socket && -S $underlay_socket ]] || die 'endpoint network sockets were not created'
    qemu+=(-device e1000e,mac=52:54:00:12:34:10,netdev=tunnel -netdev "stream,id=tunnel,server=off,addr.type=unix,addr.path=$tunnel_socket" -object "filter-dump,id=tunnel-capture,netdev=tunnel,file=$run_dir/tunnel.pcap" -device e1000e,mac=52:54:00:12:34:11,netdev=underlay -netdev "stream,id=underlay,server=off,addr.type=unix,addr.path=$underlay_socket" -object "filter-dump,id=underlay-capture,netdev=underlay,file=$run_dir/underlay.pcap")
    printf '[127.0.0.1]:%s %s %s\n' "$endpoint_port" "$key_type" "$key_data" >"$run_dir/endpoint-known_hosts"
fi
printf '%q ' "${qemu[@]}" >"$run_dir/qemu-command.log"
"${qemu[@]}" >>"$run_dir/qemu.log" 2>&1 &
pid=$!
ssh_opts=(-i "$ssh_key" -p "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/known_hosts" -o ConnectTimeout=5)
scp_opts=(-i "$ssh_key" -P "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/known_hosts" -o ConnectTimeout=5)
target=winvm@127.0.0.1
stage=boot
boot_started=$SECONDS
deadline=$((SECONDS + $(jq -r .machine.bootTimeoutSeconds "$config_file")))
next_progress=$((SECONDS + 30))
qga_ok=0
ssh_ok=0
ready_token=''
printf 'Starting the disposable Windows %s guest. Logs: %s\n' "$mode" "$run_dir"
while ((SECONDS < deadline)); do
    kill -0 "$pid" 2>/dev/null || die 'QEMU exited during boot'
    if ((qga_ok == 0)) && "$script_dir/tools/qga.py" --socket "$qga" --timeout 5 ping >>"$run_dir/guest-agent.log" 2>&1; then
        ready_token=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 10 exec powershell.exe -NoProfile -Command 'if(Test-Path C:\winvm\ready){Get-Content -Raw C:\winvm\ready}else{exit 1}' 2>/dev/null || true)
        [[ -n $ready_token ]] && qga_ok=1
    fi
    if ((ssh_ok == 0)) && ssh "${ssh_opts[@]}" "$target" 'powershell.exe -NoProfile -Command "if(Test-Path C:\winvm\ready){exit 0}else{exit 1}"' >/dev/null 2>&1; then ssh_ok=1; fi
    ((qga_ok && ssh_ok)) && break
    sleep 2
    if ((SECONDS >= next_progress)); then
        printf 'Still booting Windows: %d seconds elapsed.\n' "$((SECONDS - boot_started))"
        next_progress=$((SECONDS + 30))
    fi
done
((qga_ok && ssh_ok)) || die 'guest readiness timeout'
sleep 2
stable=$("$script_dir/tools/qga.py" --socket "$qga" --timeout 10 exec powershell.exe -NoProfile -Command 'Get-Content -Raw C:\winvm\ready')
[[ $stable == "$ready_token" ]] || die 'guest restarted across readiness check'
printf 'Windows guest is ready. Packaging and transferring the source tree...\n'
if [[ $mode == flow ]]; then
    endpoint_ssh_opts=(-i "$ssh_key" -p "$endpoint_port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/endpoint-known_hosts" -o ConnectTimeout=5)
    endpoint_scp_opts=(-i "$ssh_key" -P "$endpoint_port" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$run_dir/endpoint-known_hosts" -o ConnectTimeout=5)
    endpoint_target=winvm@127.0.0.1
    endpoint_deadline=$((SECONDS + $(jq -r .machine.bootTimeoutSeconds "$config_file")))
    until "$script_dir/tools/qga.py" --socket "$endpoint_qga" --timeout 5 ping >/dev/null 2>&1 && ssh "${endpoint_ssh_opts[@]}" "$endpoint_target" 'powershell.exe -NoProfile -Command "if(Test-Path C:\winvm\ready){exit 0}else{exit 1}"' >/dev/null 2>&1; do
        kill -0 "$endpoint_pid" 2>/dev/null || die 'endpoint QEMU exited during boot'
        ((SECONDS < endpoint_deadline)) || die 'endpoint readiness timeout'
        sleep 2
    done
fi
if [[ $mode == shell ]]; then
    stage=shell
    ssh "${ssh_opts[@]}" -t "$target" powershell.exe
    exit
fi
stage=package
payload="$run_dir/worktree.tar"
"$script_dir/package-worktree.sh" "$payload"
remote="C:/winvm/runs/${run_id//[^A-Za-z0-9-]/}"
payload_hash=$(sha256_file "$payload")
jq --arg hash "$payload_hash" '.sourceArchive={file:"worktree.tar",sha256:$hash}' "$run_dir/run.json" >"$run_dir/run.json.new"
mv "$run_dir/run.json.new" "$run_dir/run.json"
stage=transfer
ssh "${ssh_opts[@]}" "$target" "powershell.exe -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$remote/source','$remote/artifacts'|Out-Null\""
scp "${scp_opts[@]}" "$payload" "$target:$remote/worktree.tar" >/dev/null
ssh "${ssh_opts[@]}" "$target" "tar.exe -xf \"$remote/worktree.tar\" -C \"$remote/source\""
if [[ $mode == e2e || $mode == flow ]]; then
    wintun_architecture=$(jq -er .architecture "$manifest")
    python3 "$script_dir/tools/wintun-input.py" --lock "$wintun_lock" --archive "$wintun_archive" --architecture "$wintun_architecture" --output "$run_dir/wintun.dll"
    [[ -s $run_dir/wintun.dll ]] || die "Wintun $wintun_architecture DLL is absent from the locked archive"
    scp "${scp_opts[@]}" "$run_dir/wintun.dll" "$target:$remote/" >/dev/null
fi
if [[ $mode == flow ]]; then
    stage=flow-setup
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$run_dir/flowecho.exe" "$repo_root/cmd/flowecho"
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$run_dir/tunnelpeer.exe" "$repo_root/cmd/tunnelpeer"
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$run_dir/sysnetflow.exe" "$repo_root/cmd/sysnetflow"
    endpoint_remote="C:/winvm/runs/${run_id//[^A-Za-z0-9-]/}"
    ssh "${endpoint_ssh_opts[@]}" "$endpoint_target" "powershell.exe -NoProfile -Command \"New-Item -ItemType Directory -Force -Path '$endpoint_remote'|Out-Null\""
    scp "${endpoint_scp_opts[@]}" "$run_dir/flowecho.exe" "$run_dir/tunnelpeer.exe" "$script_dir/flow-network.ps1" "$endpoint_target:$endpoint_remote/" >/dev/null
    endpoint_windows=${endpoint_remote//\//\\}
    "$script_dir/tools/qga.py" --socket "$endpoint_qga" --timeout 60 exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$endpoint_windows\\flow-network.ps1" -Role Endpoint >"$run_dir/endpoint-network.json"
    "$script_dir/tools/qga.py" --socket "$endpoint_qga" --timeout 30 exec powershell.exe -NoProfile -Command "Set-NetFirewallProfile -All -Enabled False; Start-Sleep -Seconds 3; \$action=New-ScheduledTaskAction -Execute '$endpoint_windows\\flowecho.exe'; Register-ScheduledTask -TaskName SysnetFlowEndpoint -Action \$action -User SYSTEM -RunLevel Highest -Force | Out-Null; Start-ScheduledTask -TaskName SysnetFlowEndpoint; \$peer=New-ScheduledTaskAction -Execute '$endpoint_windows\\tunnelpeer.exe' -Argument '-listen 198.18.0.1:51900'; Register-ScheduledTask -TaskName SysnetFlowPeer -Action \$peer -User SYSTEM -RunLevel Highest -Force | Out-Null; Start-ScheduledTask -TaskName SysnetFlowPeer; Start-Sleep -Seconds 2; \$listeners=@(Get-NetTCPConnection -State Listen | Where-Object LocalPort -in 53,47823); if (@(\$listeners | Where-Object LocalPort -eq 53).Count -ne 2 -or @(\$listeners | Where-Object LocalPort -eq 47823).Count -ne 2) { throw 'Expected two IPv4/IPv6 listeners on ports 53 and 47823' }; if (-not (Get-NetUDPEndpoint -LocalAddress 198.18.0.1 -LocalPort 51900)) { throw 'Tunnel peer is not listening' }; \$listeners | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json" >"$run_dir/endpoint-service.json"
    guest_remote=${remote//\//\\}
    "$script_dir/tools/qga.py" --socket "$qga" --timeout 60 exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$guest_remote\\source\\dev\\winvm\\flow-network.ps1" -Role Client >"$run_dir/client-network.json"
    scp "${scp_opts[@]}" "$run_dir/sysnetflow.exe" "$target:$remote/" >/dev/null
fi
stage='test'
test_timeout=$(jq -r .machine.testTimeoutSeconds "$config_file")
set +e
printf 'Running the Windows %s gate with a %d-minute timeout...\n' "$mode" "$((test_timeout / 60))"
if [[ $mode == baseline ]]; then
    tree_state=clean
    [[ $dirty == false ]] || tree_state=dirty
    command="Set-Location '$remote/source'; & './dev/winvm/test.ps1' -ArtifactDir '$remote/artifacts' -ImageManifest 'C:/winvm/manifest.json' -SysnetWindowsRevision '$revision' -SysnetWindowsTreeState '$tree_state' -SourceArchiveSHA256 '$payload_hash' -RequireStandardUser"
    timeout --foreground --kill-after=30 "${test_timeout}s" ssh "${ssh_opts[@]}" "$target" "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command \"$command\"" 2>&1 | tee "$run_dir/windows-console.log"
    test_status=${PIPESTATUS[0]}
else
    flow_argument=''
    [[ $mode == flow ]] && flow_argument=' -Flow'
    tree_state=clean
    [[ $dirty == false ]] || tree_state=dirty
    command="& '$remote/source/dev/winvm/e2e.ps1' -SourceDir '$remote/source' -ArtifactDir '$remote/artifacts' -SysnetWindowsRevision '$revision' -SysnetWindowsTreeState '$tree_state' -SourceArchiveSHA256 '$payload_hash'$flow_argument"
    timeout --foreground --kill-after=30 "${test_timeout}s" "$script_dir/tools/qga.py" --socket "$qga" --timeout "$test_timeout" exec powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$command" 2>&1 | tee "$run_dir/windows-console.log"
    test_status=${PIPESTATUS[0]}
fi
set -e
((test_status == 0)) || {
    ((test_status == 124)) && stage=test-timeout
    exit "$test_status"
}
stage=artifacts
artifact="$run_dir/guest-artifacts.tar"
if ssh "${ssh_opts[@]}" "$target" "tar.exe -cf \"$remote/artifacts.tar\" -C \"$remote\" artifacts" >/dev/null 2>&1 && scp "${scp_opts[@]}" "$target:$remote/artifacts.tar" "$artifact" >/dev/null 2>&1; then
    :
else
    guest_remote=${remote//\//\\}
    "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 exec tar.exe -cf "$guest_remote\\artifacts.tar" -C "$guest_remote" artifacts >/dev/null
    "$script_dir/tools/qga.py" --socket "$qga" --timeout 30 read "$guest_remote\\artifacts.tar" --limit 67108864 >"$artifact"
fi
[[ -s $artifact ]] || die 'guest artifact archive is empty'
if [[ $mode == flow ]]; then
    stage=packet-evidence
    tar -xf "$artifact" -C "$run_dir" artifacts/packet-flow-observations.jsonl
    python3 "$script_dir/tools/flow-pcap.py" --observations "$run_dir/artifacts/packet-flow-observations.jsonl" --tunnel "$run_dir/tunnel.pcap" --underlay "$run_dir/underlay.pcap" --output "$run_dir/packet-flow-evidence.json"
fi
stage=shutdown
success=1
printf 'Windows %s gate passed. Artifacts: %s\n' "$mode" "$run_dir"
