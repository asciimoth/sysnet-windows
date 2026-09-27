# Third-party notices

## Windows VM test harness and packet helpers

The files under `dev/winvm`, `cmd/flowecho`, `cmd/tunnelpeer`, and
`internal/testtunnel` were adapted from the Windows test harness in
`github.com/asciimoth/mullvad-split-tunnel-go` at revision
`f5db35e093d7be835882cbf68911f83be1cdacff`.

That repository and this repository use the GNU General Public License, version
3\. See `LICENSE`.

The harness downloads or stages separate third-party test inputs. Their
versions, sources, and hashes are in `dev/winvm/image-lock.json`,
`dev/winvm/native-driver-lock.json`, and `dev/winvm/wintun-lock.json`. These
inputs keep their own licenses and signatures.
