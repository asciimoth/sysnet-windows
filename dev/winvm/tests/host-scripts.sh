#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
root=$(cd -- "$script_dir/../.." && pwd -P)
# shellcheck source=dev/winvm/common.sh
source "$script_dir/common.sh"
tmp=$(mktemp -d)
trap 'find "$tmp" -depth -delete' EXIT
export PYTHONPYCACHEPREFIX="$tmp/pycache"
"$script_dir/doctor.sh" --validate >/dev/null
jq -e '.schemaVersion==1 and (.suites | keys==["live-driver","native-unit","packet-flow"]) and ([.suites[].requiredTests[]]|all(type=="string" and length>0))' "$script_dir/test-manifest.json" >/dev/null
python3 -m py_compile "$script_dir/tools/qga.py"
python3 -m py_compile "$script_dir/tools/flow-pcap.py"
python3 -m py_compile "$script_dir/tools/wintun-input.py"
python3 -m py_compile "$script_dir/tools/qualify.py"
python3 "$script_dir/tests/test_flow_pcap.py"
python3 "$script_dir/tests/test_wintun_input.py"
python3 "$script_dir/tests/test_qualify.py"
shellcheck "$script_dir"/*.sh "$script_dir/tests"/*.sh

# Test commands retain JSON events while formatting their console output.
grep -Fq 'Tee-Object -FilePath' "$script_dir/test.ps1"
grep -Fq 'Tee-Object -FilePath' "$script_dir/e2e.ps1"
grep -Fq '        Format-GoTestOutput' "$script_dir/test.ps1"
grep -Fq '        Format-GoTestOutput' "$script_dir/e2e.ps1"
grep -Fq "'-coverpkg=github.com/asciimoth/sysnet-windows'" "$script_dir/e2e.ps1"
grep -Fq "if (-not \$Flow)" "$script_dir/e2e.ps1"
grep -Fq "'e2e-coverage.txt'" "$script_dir/e2e.ps1"
grep -Fq 'Expected two IPv4/IPv6 listeners on ports 53 and 47823' "$script_dir/run.sh"
grep -Fq "'test-manifest.json'" "$script_dir/test.ps1"
grep -Fq "'test-manifest.json'" "$script_dir/e2e.ps1"
grep -Fq 'SYSNET_FLOW_EXE' "$script_dir/e2e.ps1"
grep -Fq 'wintun-input.py' "$script_dir/run.sh"
grep -Fq 'wintunLockHash' "$script_dir/run.sh"

# Hash checks fail closed.
printf data >"$tmp/input"
if WINVM_CACHE_DIR="$tmp/cache" bash -c "source '$script_dir/common.sh'; verify_hash fixture '$tmp/input' '0000000000000000000000000000000000000000000000000000000000000000'" 2>/dev/null; then
    printf 'invalid hash was accepted\n' >&2
    exit 1
fi

# The Wintun downloader validates its lock, replaces corrupt cache data,
# reuses valid data without a network call, and never publishes a bad download.
download_source="$tmp/wintun-source.zip"
printf wintun-fixture >"$download_source"
download_hash=$(sha256_file "$download_source")
download_lock="$tmp/wintun-lock.json"
jq -n --arg hash "$download_hash" '{schemaVersion:1,wintun:{version:"0.14.1",file:"wintun-0.14.1.zip",source:"https://www.wintun.net/builds/wintun-0.14.1.zip",sha256:$hash}}' >"$download_lock"
mkdir "$tmp/fake-bin"
printf '#!%s\n' "$(command -v bash)" >"$tmp/fake-bin/curl"
cat >>"$tmp/fake-bin/curl" <<'SH'
set -euo pipefail
[[ ${FAKE_CURL_FAIL:-0} == 0 ]] || exit 90
output=''
while (($#)); do
    if [[ $1 == --output ]]; then output=$2; shift 2; else shift; fi
done
[[ -n $output ]]
cp -- "$FAKE_CURL_SOURCE" "$output"
SH
chmod +x "$tmp/fake-bin/curl"
download_cache="$tmp/download-cache"
download_command="source '$script_dir/common.sh'; source '$script_dir/wintun-input.sh'; prepare_wintun_archive '$download_lock'; printf '%s' \"\$wintun_archive\""
archive=$(PATH="$tmp/fake-bin:$PATH" WINVM_CACHE_DIR="$download_cache" FAKE_CURL_SOURCE="$download_source" bash -c "$download_command")
cmp "$download_source" "$archive"
PATH="$tmp/fake-bin:$PATH" WINVM_CACHE_DIR="$download_cache" FAKE_CURL_FAIL=1 bash -c "$download_command" >/dev/null
printf corrupt >"$archive"
archive=$(PATH="$tmp/fake-bin:$PATH" WINVM_CACHE_DIR="$download_cache" FAKE_CURL_SOURCE="$download_source" bash -c "$download_command")
cmp "$download_source" "$archive"
printf different >"$tmp/wrong-download.zip"
find "$archive" -maxdepth 0 -type f -delete
if PATH="$tmp/fake-bin:$PATH" WINVM_CACHE_DIR="$download_cache" FAKE_CURL_SOURCE="$tmp/wrong-download.zip" bash -c "$download_command" >/dev/null 2>&1; then
    printf 'invalid Wintun download was accepted\n' >&2
    exit 1
fi
[[ ! -e $archive ]]
if find "$download_cache/inputs" -maxdepth 1 -name '*.partial.*' -print -quit | grep -q .; then
    printf 'failed Wintun download left a partial file\n' >&2
    exit 1
fi

# Dirty worktrees contain each eligible file once and omit private files.
fixture="$tmp/repo"
mkdir -p "$fixture/dev/winvm"
cp "$script_dir/package-worktree.sh" "$fixture/dev/winvm/"
git -C "$fixture" init -q
git -C "$fixture" config user.email test@example.invalid
git -C "$fixture" config user.name test
printf 'dev/winvm/env\n.artifacts/\n' >"$fixture/.gitignore"
printf old >"$fixture/tracked"
git -C "$fixture" add .
git -C "$fixture" commit -qm initial
printf new >"$fixture/tracked"
printf source >"$fixture/untracked"
printf secret >"$fixture/dev/winvm/env"
(cd "$fixture" && dev/winvm/package-worktree.sh "$tmp/tree.tar")
tar -tf "$tmp/tree.tar" >"$tmp/list"
[[ $(grep -cx tracked "$tmp/list") == 1 ]]
grep -qx untracked "$tmp/list"
if grep -q 'env\|artifacts' "$tmp/list"; then
    printf 'private file was packaged\n' >&2
    exit 1
fi

# Image keys are path-independent. Provisioning changes affect the key, but
# test-only changes do not. Fake firmware and QEMU keep this test portable.
mkdir "$tmp/bin"
printf '#!/bin/sh\necho QEMU-fake\n' >"$tmp/bin/qemu-system-x86_64"
chmod +x "$tmp/bin/qemu-system-x86_64"
printf code >"$tmp/code.fd"
printf vars >"$tmp/vars.fd"
key_copy="$tmp/key-repo"
mkdir -p "$key_copy/dev"
cp -R "$script_dir" "$key_copy/dev/winvm"
cp "$root/flake.lock" "$root/flake.nix" "$key_copy/"
key_cache="$tmp/key-cache"
mkdir -p "$key_cache/ssh"
printf 'ssh-ed25519 fixture-one\n' >"$key_cache/ssh/id_ed25519.pub"
key_env=(PATH="$tmp/bin:$PATH" WINVM_CACHE_DIR="$key_cache" WINVM_OVMF_CODE="$tmp/code.fd" WINVM_OVMF_VARS="$tmp/vars.fd")
first=$(env "${key_env[@]}" "$key_copy/dev/winvm/doctor.sh" --base-key)
printf '\n' >>"$key_copy/dev/winvm/wintun-lock.json"
runtime_only=$(env "${key_env[@]}" "$key_copy/dev/winvm/doctor.sh" --base-key)
[[ $first == "$runtime_only" ]]
printf '\n# test-only\n' >>"$key_copy/dev/winvm/test.ps1"
second=$(env "${key_env[@]}" "$key_copy/dev/winvm/doctor.sh" --base-key)
[[ $first == "$second" ]]
printf '\n# image input\n' >>"$key_copy/dev/winvm/provision.ps1"
third=$(env "${key_env[@]}" "$key_copy/dev/winvm/doctor.sh" --base-key)
[[ $first != "$third" ]]
printf 'ssh-ed25519 fixture-two\n' >"$key_cache/ssh/id_ed25519.pub"
fourth=$(env "${key_env[@]}" "$key_copy/dev/winvm/doctor.sh" --base-key)
[[ $third != "$fourth" ]]

# A missing private key is regenerated, and a stale public key is repaired.
ssh_cache="$tmp/ssh-cache"
WINVM_CACHE_DIR="$ssh_cache" bash -c "source '$script_dir/common.sh'; ensure_ssh_key"
private="$ssh_cache/ssh/id_ed25519"
public="$private.pub"
[[ -s $private && -s $public ]]
printf stale >"$public"
WINVM_CACHE_DIR="$ssh_cache" bash -c "source '$script_dir/common.sh'; ensure_ssh_key"
ssh-keygen -y -f "$private" >"$tmp/derived.pub"
cmp "$tmp/derived.pub" "$public"

# Concurrent port allocators retain different advisory locks.
WINVM_CACHE_DIR="$tmp/ports" bash -c "source '$script_dir/common.sh'; allocate_locked_port; echo \$winvm_ssh_port; sleep 1" >"$tmp/p1" &
one=$!
WINVM_CACHE_DIR="$tmp/ports" bash -c "source '$script_dir/common.sh'; allocate_locked_port; echo \$winvm_ssh_port; sleep 1" >"$tmp/p2" &
two=$!
wait "$one" "$two"
[[ $(cat "$tmp/p1") != "$(cat "$tmp/p2")" ]]

# Overlay identity and cleanup stay exact.
qemu-img create -q -f qcow2 "$tmp/base.qcow2" 1M
qemu-img create -q -f qcow2 -F qcow2 -b "$tmp/base.qcow2" "$tmp/overlay.qcow2"
backing=$(qemu-img info --output=json "$tmp/overlay.qcow2" | jq -r '."full-backing-filename" // ."backing-filename"')
[[ $(realpath -e "$backing") == "$(realpath -e "$tmp/base.qcow2")" ]]
socket_dir=$(XDG_RUNTIME_DIR="$tmp" bash -c "source '$script_dir/common.sh'; make_socket_dir")
[[ ${#socket_dir} -lt 98 ]]
bash -c "source '$script_dir/common.sh'; remove_socket_dir '$socket_dir'"

# A child that ignores SIGTERM is killed and reaped within the bound.
ready="$tmp/ready"
python3 -c 'import signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open(sys.argv[1],"w").close(); time.sleep(60)' "$ready" &
stubborn=$!
for _ in {1..100}; do
    [[ -f $ready ]] && break
    sleep .01
done
stop_and_reap_pid "$stubborn" 0 1 2
if kill -0 "$stubborn" 2>/dev/null; then
    printf 'stubborn process survived cleanup\n' >&2
    exit 1
fi

# The final deadline does not fall through to an unbounded wait.
marker="$tmp/unbounded-wait"
if MARKER="$marker" COMMON="$script_dir/common.sh" bash -c '
    source "$COMMON"
    wait_for_pid() { return 1; }
    kill() { return 0; }
    wait() { touch "$MARKER"; return 0; }
    stop_and_reap_pid 42 0 0 0
'; then
    printf 'an unkillable process was reported as reaped\n' >&2
    exit 1
fi
[[ ! -e $marker ]] || {
    printf 'cleanup used an unbounded wait\n' >&2
    exit 1
}

# A QEMU process that survives cleanup blocks runs and artifact deletion. The
# marker clears only after the exact process identity is gone.
orphan_cache="$tmp/orphan-cache"
mkdir -p "$orphan_cache/locks"
sleep 60 &
orphan_pid=$!
WINVM_CACHE_DIR="$orphan_cache" bash -c "source '$script_dir/common.sh'; record_qemu_orphan '$orphan_pid'"
if WINVM_CACHE_DIR="$orphan_cache" bash -c "source '$script_dir/common.sh'; reject_live_qemu_orphan" 2>/dev/null; then
    printf 'a live QEMU orphan did not block a new run\n' >&2
    exit 1
fi
kill "$orphan_pid"
wait "$orphan_pid" 2>/dev/null || true
WINVM_CACHE_DIR="$orphan_cache" bash -c "source '$script_dir/common.sh'; reject_live_qemu_orphan"
[[ ! -e $orphan_cache/locks/qemu-orphan ]]

# Cached images need every published component, including a valid host key.
cached="$tmp/cached-image"
mkdir "$cached"
qemu-img create -q -f qcow2 "$cached/base.qcow2" 1M
printf vars >"$cached/OVMF_VARS.fd"
printf '{"baseImageKey":"fixture"}\n' >"$cached/manifest.json"
ssh-keygen -q -t ed25519 -N '' -f "$tmp/cached-host-key"
cp "$tmp/cached-host-key.pub" "$cached/host-key.pub"
cached_image_valid "$cached" fixture
find "$cached/host-key.pub" -maxdepth 0 -type f -delete
if cached_image_valid "$cached" fixture; then
    printf 'cached image without a host key was accepted\n' >&2
    exit 1
fi

# Exercise the real cleanup command with a stale lock file. It removes only
# run directories and does not follow links to data outside the artifact root.
clean_repo="$tmp/clean-repo"
mkdir -p "$clean_repo/dev"
cp -R "$script_dir" "$clean_repo/dev/winvm"
mkdir -p "$clean_repo/.artifacts/winvm/run-old/nested" "$clean_repo/.artifacts/winvm/keep" "$tmp/outside"
printf retained >"$tmp/outside/data"
ln -s "$tmp/outside" "$clean_repo/.artifacts/winvm/run-old/outside"
clean_cache="$tmp/clean-cache"
mkdir -p "$clean_cache/locks"
printf stale >"$clean_cache/locks/vm-run.lock"
WINVM_CACHE_DIR="$clean_cache" "$clean_repo/dev/winvm/run.sh" --clean >/dev/null
[[ ! -e $clean_repo/.artifacts/winvm/run-old && -d $clean_repo/.artifacts/winvm/keep && -f $tmp/outside/data ]]

# Fake sockets cover QGA ping, guest exit propagation, QMP, and timeout.
cat >"$tmp/fake.py" <<'PY'
import base64, json, os, socket, sys
path, mode = sys.argv[1:]
try: os.unlink(path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(path); s.listen()
while True:
 c,_=s.accept()
 with c:
  if mode=='qmp': c.sendall(b'{"QMP":{"version":{}}}\n')
  line=c.makefile('rb').readline()
  if not line: continue
  cmd=json.loads(line)['execute']
  if mode=='qmp':
   c.sendall(b'{"return":{}}\n')
   if cmd=='qmp_capabilities':
    c.makefile('rb').readline(); c.sendall(b'{"return":{}}\n'); break
  elif cmd=='guest-ping': c.sendall(b'{"return":{}}\n'); break
  elif cmd=='guest-exec': c.sendall(b'{"return":{"pid":7}}\n')
  elif cmd=='guest-exec-status':
   if mode=='timeout': c.sendall(b'{"return":{"exited":false}}\n')
   else: c.sendall(b'{"return":{"exited":true,"exitcode":7}}\n'); break
  elif cmd=='guest-file-open': c.sendall(b'{"return":5}\n')
  elif cmd=='guest-file-read': c.sendall(json.dumps({'return':{'buf-b64':base64.b64encode(b'hello').decode(),'eof':True}}).encode()+b'\n')
  elif cmd=='guest-file-close': c.sendall(b'{"return":{}}\n'); break
PY
start_fake() {
    python3 "$tmp/fake.py" "$1" "$2" &
    fake_pid=$!
    for _ in {1..100}; do
        [[ -S $1 ]] && return
        sleep .01
    done
    return 1
}
start_fake "$tmp/ping.sock" ping
"$script_dir/tools/qga.py" --socket "$tmp/ping.sock" ping
wait "$fake_pid"
start_fake "$tmp/qmp.sock" qmp
"$script_dir/tools/qga.py" --socket "$tmp/qmp.sock" qmp query-status >/dev/null
wait "$fake_pid"
start_fake "$tmp/exit.sock" exit
set +e
"$script_dir/tools/qga.py" --socket "$tmp/exit.sock" --timeout 2 exec cmd.exe
status=$?
set -e
wait "$fake_pid"
[[ $status == 7 ]]
start_fake "$tmp/timeout.sock" timeout
set +e
"$script_dir/tools/qga.py" --socket "$tmp/timeout.sock" --timeout .3 exec cmd.exe >/dev/null 2>&1
status=$?
set -e
kill "$fake_pid" 2>/dev/null || true
wait "$fake_pid" 2>/dev/null || true
[[ $status != 0 ]]
start_fake "$tmp/read.sock" read
[[ $("$script_dir/tools/qga.py" --socket "$tmp/read.sock" read C:\\fixture) == hello ]]
wait "$fake_pid"
start_fake "$tmp/bounded.sock" read
set +e
"$script_dir/tools/qga.py" --socket "$tmp/bounded.sock" read C:\\fixture --limit 4 >/dev/null 2>&1
status=$?
set -e
wait "$fake_pid"
[[ $status != 0 ]]
printf 'Windows VM host-script tests passed.\n'
