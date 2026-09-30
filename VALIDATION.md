# Validation status

Date: 2026-09-29

## Result

The initial sysnet-windows release scope is implemented and qualified.
Maintainers report that `just check-release` passes and that native
qualification was completed manually for all declared matrix entries:

| Matrix entry              | Result |
| ------------------------- | ------ |
| Windows Server 2022 amd64 | Passed |
| Windows 11 amd64          | Passed |
| Windows 11 arm64          | Passed |

The authoritative entry constraints, dependency locks, required cases, resource
workload, and code-integrity requirements are in
`dev/winvm/qualification-matrix.json` and `dev/winvm/test-manifest.json`.
Qualification artifacts contain the exact Windows build and source archive
identity. They are retained as test artifacts and are not committed because they
can contain large captures and disposable-machine diagnostics.

## Gate scope

`just check-release` includes:

- portable formatting, lint, vet, race, fuzz, cross-build, and harness checks;
- native Windows baseline tests;
- privileged Wintun, NetIO, DNS, WFP, and split-driver integration tests;
- the resource gate with warm-up, lifecycle batches, cancellation cycles, and a
  30-minute transfer and reconfiguration soak;
- independent packet-flow validation for OutNet, managed DNS, underlay loss, and
  executable exclusions.

The packet-flow gate runs the pinned split-controller address-mode conformance
suite before the sysnet-windows public API cases. It uses separate tunnel and
underlay captures and requires positive controls for absence assertions.

## Routine checks

`just check` is the routine development gate. It intentionally omits the slow
resource and packet-flow suites. `just check-release` is required for release
qualification and for changes to native routing, DNS, WFP, split-driver, or
packet-path behavior.

GitHub Actions intentionally runs lightweight portable tests, including the fuzz
seed corpora, plus Windows cross-build and native baseline jobs. The local
`just check` gate keeps race detection and timed fuzzing. Privileged and
long-running release gates run manually on disposable systems because adding
them to routine CI would make CI unacceptably slow.

## Unsupported scope

Unsupported capabilities are validated for rejection before host mutation. They
are not failed qualification cases. The remaining optional work is listed in
`docs/sysnet-windows-implementation-testing-plan.md`, and current user-visible
restrictions are listed in `docs/limitations.md`.
