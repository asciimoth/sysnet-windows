# sysnet-windows

Windows network integration for `github.com/asciimoth/gonnect`.

The implementation is not present yet. The repository contains the locked
development environment and Windows test harness for the work in
[`docs/sysnet-windows-implementation-testing-plan.md`](docs/sysnet-windows-implementation-testing-plan.md).

## Development

Enter the pinned shell, then run the portable gate:

```console
nix develop
just check-fast
```

The shell pins Go 1.25.5, installs the Go, documentation, Nix, shell, and CI
tools, and exposes verified split-driver and Wintun inputs for both supported
architectures. `just check-fast` does not start a guest or change networking.
Use `just` to list all commands.

Windows cross-builds include production packages and each package that has Go
tests. Native Windows tests use `dev/winvm/test.ps1` and do not need Nix.

## Disposable Windows tests

The QEMU/KVM harness needs a Linux amd64 host and developer-supplied Windows
Server and VirtIO media. See [`dev/winvm/README.md`](dev/winvm/README.md) for
setup and safety requirements.

```console
cp dev/winvm/env.example dev/winvm/env
just winvm-input-hashes
just winvm-doctor
just winvm-image
just test-windows-vm
```

The live-driver and packet-flow entry points are wired into the harness. They
intentionally fail until their required `winintegration` and `winflow` tests,
and the `cmd/sysnetflow` helper, are implemented. A missing required test is not
reported as a successful qualification. Update `dev/winvm/test-manifest.json` as
milestone tests become required.
