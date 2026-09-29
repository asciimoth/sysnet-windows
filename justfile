set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# This gate does not change host networking or start a Windows guest.
check-fast: verify tidy-check fmt-check typos lint vet test fuzz build-windows winvm-check

# This gate needs the licensed media and KVM setup described in dev/winvm/README.md.
check: check-fast test-total

# This future release gate also includes planned packet-flow coverage.
check-release: check-fast test-release

verify:
    go mod verify

tidy:
    go mod tidy

tidy-check:
    go mod tidy -diff

fmt:
    golangci-lint fmt ./...
    mdformat --wrap 80 README.md THIRD_PARTY_NOTICES.md dev/winvm/README.md docs/dependencies.md docs/gonnect-contract.md
    nixfmt flake.nix
    shfmt -w -i 4 -ci $(find dev -type f -name '*.sh' | sort)

fmt-check:
    test -z "$(gofmt -l .)"
    mdformat --check --wrap 80 README.md THIRD_PARTY_NOTICES.md dev/winvm/README.md docs/dependencies.md docs/gonnect-contract.md
    nixfmt --check flake.nix
    shfmt -d -i 4 -ci $(find dev -type f -name '*.sh' | sort)

typos:
    typos .

lint:
    golangci-lint run ./...
    actionlint .github/workflows/*.yml
    deadnix --fail flake.nix
    markdownlint README.md THIRD_PARTY_NOTICES.md dev/winvm/README.md docs/*.md
    shellcheck -x $(find dev -type f -name '*.sh' | sort)
    statix check .

vet:
    go vet ./...

test:
    go test -race -count=1 -timeout 2m ./...

fuzz:
    dev/run-fuzz.sh

build:
    go build ./...

build-windows:
    dev/build-windows.sh

vulncheck:
    govulncheck ./...

test-total: test fuzz test-windows-vm test-windows-e2e

test-release: test-total test-windows-resource test-windows-flow

winvm-doctor:
    dev/winvm/doctor.sh

winvm-input-hashes:
    dev/winvm/doctor.sh --print-input-hashes

winvm-image:
    dev/winvm/build-image.sh

test-windows-vm:
    dev/winvm/run.sh baseline

test-windows-e2e:
    dev/winvm/run.sh e2e

test-windows-flow:
    dev/winvm/run.sh flow

test-windows-resource:
    dev/winvm/run.sh resource

qualify-windows entry evidence:
    python3 dev/winvm/tools/qualify.py --matrix dev/winvm/qualification-matrix.json --entry "{{entry}}" --native-unit "{{evidence}}/native-unit-evidence.json" --live-driver "{{evidence}}/live-driver-evidence.json" --packet-flow "{{evidence}}/packet-flow-suite-evidence.json" --packet-evidence "{{evidence}}/packet-flow-evidence.json" --output "{{evidence}}/qualification.json"

winvm-shell run:
    dev/winvm/run.sh --shell "{{run}}"

winvm-clean:
    dev/winvm/run.sh --clean

winvm-check:
    if [[ "${OS:-}" == "Windows_NT" || "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]]; then printf 'Skipping Linux-only Windows VM host checks.\n'; else dev/winvm/tests/host-scripts.sh; fi
