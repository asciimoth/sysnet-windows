# Native Windows VM tests

This harness runs the current working tree in a disposable Windows Server 2022
amd64 QEMU/KVM virtual machine. The baseline uses the standard `winvm` account.
The live-driver gate uses QEMU Guest Agent to run only tagged integration tests
as `SYSTEM`.

The developer must supply licensed Windows Server installation media and the
locked VirtIO ISO. The repository does not contain Windows media, product keys,
VM disks, or private keys. The Windows evaluation license and expiry terms still
apply.

## First-time setup

Enter `nix develop`. Copy `env.example` to `dev/winvm/env` and set the two
absolute ISO paths. If the sibling `tor-driver` project is configured on the
same host, its `dev/winvm/env` uses the same variable names and the paths can be
copied. This repository still validates both files against its own
`image-lock.json`. Review their hashes with:

```console
just winvm-input-hashes
just winvm-doctor
just winvm-image
```

The image command downloads only the locked Go and OpenSSH archives. It obtains
the signed amd64 driver from the `windows-test-drivers` Nix output. It validates
all hashes and Windows signatures, stages the driver, and creates a demand-start
service. It does not start the driver in the base image.

The content-addressed base is stored under
`${XDG_CACHE_HOME:-$HOME/.cache}/sysnet-windows/winvm`. Set `WINVM_CACHE_DIR` in
`dev/winvm/env` to use another private absolute path. The SSH public key is part
of the base-image identity. If its private key is lost, the image command
creates a new key and builds a matching base image.

## Daily use

```console
just check
just test-windows-vm
just test-windows-e2e
just test-windows-flow
just test-total
```

The baseline runs module verification, tidy, vet, tests, and build as the
standard user. The live gate starts the verified driver, runs only the
`windows && winintegration` package serially as `SYSTEM`, checks cleanup, and
stops the service. The flow gate adds a second disposable endpoint guest and two
isolated links. It validates packet markers in a capture from each link. The
live and flow gates require named tests and fail if a test is absent or skipped.
They cannot pass until the related implementation milestones are complete.
`just test-total` runs the local Go and fuzz tests, then builds or reuses the
base image and runs all three VM gates. `just check` adds all formatting,
linting, vetting, builds, and host-harness checks around `test-total`.
Linux-only VM recipes skip on Windows.

The harness serializes VM processes on one host. Image creation has an exclusive
content-key lock. Test runs hold a shared image lock and use a unique overlay,
OVMF variable store, run directory, socket directory, and locked SSH port. Guest
readiness uses an atomic generation token and must stay stable before a test can
start. These rules prevent an early Guest Agent or SSH response from racing the
final provisioning reboot.

The live-driver gate writes `e2e-cover.out` and `e2e-coverage.txt` to its guest
artifact archive. These files report native project-package coverage. The flow
gate does not enable Go coverage because it re-executes test binaries as
packet-flow helpers.

## Artifacts and recovery

Runs write `.artifacts/winvm/run-ID/`. Successful runs remove their overlay and
OVMF state. Failed runs keep the overlay by default and print a command like:

```console
just winvm-shell .artifacts/winvm/run-ID
```

The diagnostic shell verifies the recorded SSH host key. `just winvm-clean`
removes only validated run directories and keeps the cached base image. Inspect
`run.json`, `failure-stage.txt`, `qemu.log`, `serial.log`, `guest-agent.log`,
`worktree.tar`, and the guest test artifacts after a failure. The live-driver
artifacts include the coverage profile and per-function report. `run.json`
records the SHA-256 of `worktree.tar`, so the retained source can be matched to
the test evidence.

Native runs also write suite evidence with the exact Windows build,
architecture, sysnet-windows revision, Go version, required tests, and driver
identity. Use `just qualify-windows MATRIX EVIDENCE_DIR` to combine the
native-unit, live-driver, packet-flow, and independent capture results. The
matrix names are in `qualification-matrix.json`. The qualifier rejects dirty or
mismatched revisions.

The diagnostic shell starts with the retained disk overlay and OVMF variable
store. It does not replace either file with base-image state.

Do not upload or commit Windows media, base images, overlays, OVMF variable
stores, provisioning media, or SSH private keys.

## Lock updates

Update `image-lock.json` as a reviewed change. Update versions, provenance URLs,
and hashes together. The base key covers image configuration, provisioning,
firmware, QEMU, the Nix driver definition, and all locked content hashes. Test
script changes do not rebuild Windows. Each run records its script and source
state through the packaged working tree and run metadata. A successful gate also
requires retrieval of the guest artifact archive.

Native arm64 packet-flow execution is outside this QEMU appliance. Native CI can
run the ordinary suite on Windows amd64 and arm64 hosts. Run the signed driver
suite only on a disposable native host:

```powershell
./dev/winvm/test.ps1
./dev/winvm/host-e2e.ps1 -AllowDisposableHost
```

The second command stages a kernel driver and must not run on a workstation or a
host where the driver is in use.
