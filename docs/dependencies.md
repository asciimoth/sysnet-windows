# Dependency baseline

This file records the direct implementation inputs selected for the initial
development scaffold. `go.mod`, `go.sum`, and the Nix module-proxy hash are the
build locks. Update them together.

| Input                                          | Version or revision                                    | Purpose                                                |
| ---------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------ |
| `github.com/asciimoth/gonnect`                 | `v0.55.0` (`823c6fe6c55755880ec217d5643134a89d339f03`) | Public `sysnet`, DNS, network, and ownership contracts |
| `github.com/asciimoth/tuntap`                  | `v0.4.3` (`05f95572b8997c78a0f6b8a561e8d5f8dc6e6e4a`)  | Wintun-backed TUN implementation                       |
| `github.com/asciimoth/mullvad-split-tunnel-go` | `f5db35e093d7be835882cbf68911f83be1cdacff`             | Split-driver controller and ABI                        |
| `github.com/tailscale/wf`                      | `6fbb0a674ee6`                                         | WFP object management                                  |
| `golang.zx2c4.com/wireguard/windows`           | `v1.1.1`                                               | NetIO and `winipcfg` operations                        |
| `golang.org/x/sys`                             | `v0.47.0` (`9e7e939dcafac07e8ab4cffa6e5fc74908413f00`) | Windows system calls                                   |

The direct module set requires Go 1.25.5. `gonnect` and `tuntap` set that
minimum; no selected direct or transitive module requires a later version. The
flake obtains Go 1.25.5 from the separate `toolchain-nixpkgs` input because the
main Nixpkgs input no longer supplies this end-of-life toolchain.

Native binary inputs have separate provenance locks:

- `dev/winvm/native-driver-lock.json` pins the signed split driver for amd64 and
  arm64.
- `dev/winvm/wintun-lock.json` pins the Wintun 0.14.1 archive.
- `dev/winvm/image-lock.json` pins the Windows VM media identity, guest Go
  archive, OpenSSH archive, VirtIO media, and amd64 split driver.
