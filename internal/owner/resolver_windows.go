//go:build windows

package owner

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
	"golang.org/x/sys/windows"
)

// NewNative creates the Windows owner resolver. GetSockOwner supplies the
// socket-table lookup. Resolver retries ERROR_INSUFFICIENT_BUFFER because a
// table can grow between the sizing and data calls. The pinned gonnect API
// matches UDP by an exact local address and port. A wildcard-only UDP row is
// therefore reported as unknown; competing exact rows are ambiguous.
func NewNative(config Config) (*Resolver, error) {
	return newResolver(config, sockowner.GetSockOwner, nativeProcessSource{}, time.Now)
}

type nativeProcessSource struct{}

func (nativeProcessSource) Identity(ctx context.Context, pid int) (time.Time, error) {
	handle, err := openProcess(ctx, pid)
	if err != nil {
		return time.Time{}, err
	}
	defer windows.CloseHandle(handle) //nolint:errcheck
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, creation.Nanoseconds()), nil
}

func (nativeProcessSource) ExecutablePath(ctx context.Context, pid int) (string, error) {
	handle, err := openProcess(ctx, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle) //nolint:errcheck
	for size := uint32(windows.MAX_PATH); size <= 32768; size *= 2 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		buffer := make([]uint16, size)
		length := size
		err = windows.QueryFullProcessImageName(handle, 0, &buffer[0], &length)
		if err == nil {
			return filepath.Clean(windows.UTF16ToString(buffer[:length])), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
	}
	return "", windows.ERROR_INSUFFICIENT_BUFFER
}

func openProcess(ctx context.Context, pid int) (windows.Handle, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if pid < 0 || uint64(pid) > uint64(^uint32(0)) {
		return 0, windows.ERROR_INVALID_PARAMETER
	}
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec
}

func isSizeRace(err error) bool {
	return errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER)
}
