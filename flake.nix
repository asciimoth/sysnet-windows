{
  description = "Windows network integration for gonnect";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Keep the minimum toolchain required by gonnect and tuntap even after the
    # main Nixpkgs input removes it at end of life.
    toolchain-nixpkgs.url = "github:nixos/nixpkgs/72a867531d4e5bb044424b89d4bc84c731bf9579";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      pre-commit-hooks,
      toolchain-nixpkgs,
      ...
    }:
    flake-utils.lib.eachSystem
      [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ]
      (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          toolchainPkgs = import toolchain-nixpkgs { inherit system; };
          go = toolchainPkgs.go_1_25;

          markdownFormatter = pkgs.python3.withPackages (
            pythonPackages: with pythonPackages; [
              mdformat
              mdformat-gfm
              mdformat-gfm-alerts
            ]
          );

          driverRevision = "5b6f46cde692acb77ee74b37b9fd3f1678c45a52";

          fetchDriverFile =
            architecture: file: hash:
            pkgs.fetchurl {
              url = "https://raw.githubusercontent.com/mullvad/mullvadvpn-app-binaries/${driverRevision}/${architecture}-pc-windows-msvc/split-tunnel/${file}";
              inherit hash;
            };

          windowsTestDrivers = pkgs.runCommand "sysnet-windows-split-driver-1.3.0.0" { } ''
            install -Dm0444 ${
              fetchDriverFile "x86_64" "mullvad-split-tunnel.sys"
                "sha256-EM8lu8/lH9Zjof7IipjpuFjzpXlYm7LsSWtm5P3RsgE="
            } $out/amd64/mullvad-split-tunnel.sys
            install -Dm0444 ${
              fetchDriverFile "x86_64" "mullvad-split-tunnel.inf"
                "sha256-PdWQXl+5jWGpQqM+jJpboHw6LeHk8xnh/sPlTfZZFgg="
            } $out/amd64/mullvad-split-tunnel.inf
            install -Dm0444 ${
              fetchDriverFile "x86_64" "mullvad-split-tunnel.cat"
                "sha256-xZmSagMn164GtTT0zQOdswOS4Yl7udA+T+w2MXRKTm0="
            } $out/amd64/mullvad-split-tunnel.cat

            install -Dm0444 ${
              fetchDriverFile "aarch64" "mullvad-split-tunnel.sys"
                "sha256-avizv+WqCV1Sdhh1WMfH06PgwXSzRAbNbEs/jm/6ZTQ="
            } $out/arm64/mullvad-split-tunnel.sys
            install -Dm0444 ${
              fetchDriverFile "aarch64" "mullvad-split-tunnel.inf"
                "sha256-C/2wROQFNdq76zYgtlXBVjcUs6bzIx00kslyxujepvE="
            } $out/arm64/mullvad-split-tunnel.inf
            install -Dm0444 ${
              fetchDriverFile "aarch64" "mullvad-split-tunnel.cat"
                "sha256-w9J2NnOeuqfd42nREzR96D4+IXO4pRK7iGPRGxSN584="
            } $out/arm64/mullvad-split-tunnel.cat
          '';

          wintunArchive = pkgs.fetchurl {
            url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
            hash = "sha256-B8JWGF1u42UuCfpVwLZz4mJLVl4CxLkJHHnKfS8k71E=";
          };

          windowsTestWintun =
            pkgs.runCommand "sysnet-windows-wintun-0.14.1" { nativeBuildInputs = [ pkgs.unzip ]; }
              ''
                unzip -q ${wintunArchive} -d unpacked
                install -Dm0444 unpacked/wintun/bin/amd64/wintun.dll $out/amd64/wintun.dll
                install -Dm0444 unpacked/wintun/bin/arm64/wintun.dll $out/arm64/wintun.dll
                install -Dm0444 ${wintunArchive} $out/wintun-0.14.1.zip
              '';

          goModuleProxy =
            (toolchainPkgs.buildGo125Module {
              pname = "sysnet-windows-dependencies";
              version = "0";
              src = ./.;
              proxyVendor = true;
              modPostBuild = "go mod tidy";
              vendorHash = "sha256-F5rFINkKghFJsywJMCELCKsGQ1yLiqJKJaTohRmghZQ=";
            }).goModules;

          goCheck =
            name: command:
            pkgs.runCommand name
              {
                nativeBuildInputs = [
                  go
                  pkgs.gcc
                ];
                src = ./.;
              }
              ''
                cp -R "$src" source
                chmod -R u+w source
                cd source
                export GOCACHE="$TMPDIR/go-build"
                export GOPATH="$TMPDIR/go"
                export GOTOOLCHAIN=local
                export GOPROXY=file://${goModuleProxy}
                ${command}
                touch "$out"
              '';

          checks = {
            go-version = pkgs.runCommand "sysnet-windows-go-version" { nativeBuildInputs = [ go ]; } ''
              test "$(go env GOVERSION)" = go1.25.14
              touch "$out"
            '';

            go-test = goCheck "sysnet-windows-go-test" "go test -race -count=1 -timeout 2m ./...";
            go-tidy = goCheck "sysnet-windows-go-tidy" "go mod tidy -diff";
            go-vet = goCheck "sysnet-windows-go-vet" "go vet ./...";

            pre-commit-check = pre-commit-hooks.lib.${system}.run {
              src = ./.;
              hooks = {
                actionlint.enable = true;
                deadnix.enable = true;
                gofmt.enable = true;
                markdownlint = {
                  enable = true;
                  settings.configuration = {
                    default = true;
                    MD013 = {
                      code_blocks = false;
                      line_length = 80;
                      tables = false;
                    };
                  };
                };
                nixfmt.enable = true;
                shellcheck = {
                  enable = true;
                  args = [ "-x" ];
                };
                shfmt = {
                  enable = true;
                  settings = {
                    case-indent = true;
                    indent = 4;
                    simplify = false;
                  };
                };
                statix.enable = true;
                typos.enable = true;
              };
            };
          }
          // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            winvm-host =
              pkgs.runCommand "sysnet-windows-winvm-host-tests"
                {
                  nativeBuildInputs = with pkgs; [
                    coreutils
                    git
                    jq
                    openssh
                    python3
                    powershell
                    qemu-utils
                    shellcheck
                    util-linux
                  ];
                }
                ''
                  cp -R ${./.} source
                  chmod -R u+w source
                  cd source
                  patchShebangs dev/winvm
                  dev/winvm/tests/host-scripts.sh
                  touch "$out"
                '';
          };
        in
        {
          inherit checks;

          packages = {
            go-module-proxy = goModuleProxy;
            windows-test-drivers = windowsTestDrivers;
            windows-test-wintun = windowsTestWintun;
            windows-test-inputs = pkgs.symlinkJoin {
              name = "sysnet-windows-test-inputs";
              paths = [
                windowsTestDrivers
                windowsTestWintun
              ];
            };
          };

          devShells.default = pkgs.mkShell {
            SYSNET_WINDOWS_DRIVER_DIR = windowsTestDrivers;
            SYSNET_WINDOWS_WINTUN_DIR = windowsTestWintun;
            WINVM_OVMF_CODE = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "${pkgs.OVMF.fd}/FV/OVMF_CODE.fd";
            WINVM_OVMF_VARS = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux "${pkgs.OVMF.fd}/FV/OVMF_VARS.fd";

            packages =
              with pkgs;
              [
                go
                gcc
                golangci-lint
                gopls
                govulncheck

                actionlint
                commitizen
                deadnix
                just
                markdownFormatter
                markdownlint-cli
                nixfmt
                shellcheck
                shfmt
                statix
                typos
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                curl
                jq
                openssh
                OVMF
                python3
                powershell
                qemu
                util-linux
                xorriso
              ];

            shellHook = ''
              ${checks.pre-commit-check.shellHook}
              export GOTOOLCHAIN=local
              actual_go=$(go env GOVERSION)
              if test "$actual_go" != go1.25.14; then
                printf 'Expected Go 1.25.14, got %s\n' "$actual_go" >&2
                return 1
              fi
            '';
          };
        }
      );
}
