//go:build tools

package windows

// Keep planned direct dependencies in go.mod before their implementation
// packages are added. The tools tag is not used for production builds.
import (
	_ "github.com/asciimoth/gonnect/dns"
	_ "github.com/asciimoth/gonnect/sysnet"
	_ "github.com/asciimoth/mullvad-split-tunnel-go"
	_ "github.com/asciimoth/tuntap"
	_ "github.com/tailscale/wf"
	_ "golang.org/x/sys/windows"
	_ "golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)
