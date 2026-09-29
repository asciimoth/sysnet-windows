//go:build windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/asciimoth/tuntap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// NativeFactory creates adapters through tuntap.CreateTUNWithRequestedGUID.
// It checks for an existing name before creation and verifies the resulting
// GUID before it returns the adapter to its caller.
type NativeFactory struct{}

// Create creates one Wintun adapter. Any Wintun driver acquisition occurs only
// as part of this explicit device operation, never during System construction.
func (NativeFactory) Create(ctx context.Context, config Config) (ManagedTun, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ValidateName(config.Name); err != nil {
		return nil, fmt.Errorf("validate Wintun name: %w", err)
	}
	guidText, err := NormalizeGUID(config.GUID)
	if err != nil {
		return nil, fmt.Errorf("validate requested Wintun GUID: %w", err)
	}
	var requested windows.GUID
	if guidText == "" {
		requested, err = windows.GenerateGUID()
		if err != nil {
			return nil, fmt.Errorf("generate Wintun GUID: %w", err)
		}
		guidText = canonicalGUID(requested)
	} else {
		requested, err = windows.GUIDFromString(guidText)
		if err != nil {
			return nil, fmt.Errorf("parse requested Wintun GUID: %w", err)
		}
	}
	name := config.Name
	if name == "" {
		name = defaultName(config.NamePrefix, guidText)
	}
	if err := rejectExistingName(ctx, name); err != nil {
		return nil, err
	}

	native, err := tuntap.CreateTUNWithRequestedGUID(name, &requested, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter %q: %w", name, err)
	}
	closeOnError := func(primary error) (ManagedTun, error) {
		return nil, errors.Join(primary, native.Close())
	}
	if err := ctx.Err(); err != nil {
		return closeOnError(err)
	}
	wintunDevice, ok := native.(*tuntap.NativeTun)
	if !ok {
		return closeOnError(fmt.Errorf("created TUN has type %T, want *tuntap.NativeTun", native))
	}
	luid := wintunDevice.LUID()
	if luid == 0 {
		return closeOnError(errors.New("created Wintun adapter has a zero LUID"))
	}
	row, err := winipcfg.LUID(luid).Interface()
	if err != nil {
		return closeOnError(fmt.Errorf("read created Wintun identity: %w", err))
	}
	actualGUID := canonicalGUID(row.InterfaceGUID)
	if actualGUID != guidText {
		return closeOnError(fmt.Errorf("%w: got %s, want %s", ErrIdentityMismatch, actualGUID, guidText))
	}
	adapter, err := Wrap(native, Metadata{GUID: actualGUID, LUID: luid, Index: row.InterfaceIndex})
	if err != nil {
		return closeOnError(err)
	}
	return adapter, nil
}

func rejectExistingName(ctx context.Context, name string) error {
	return retryNameInspection(ctx, func() error {
		existing, err := wintun.OpenAdapter(name)
		if err == nil {
			closeErr := existing.Close()
			return errors.Join(fmt.Errorf("%w: %q", ErrNameCollision, name), closeErr)
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_NOT_FOUND) {
			return nil
		}
		return fmt.Errorf("inspect Wintun adapter name %q: %w", name, err)
	}, func(err error) bool {
		return errors.Is(err, windows.WAIT_TIMEOUT)
	})
}

func canonicalGUID(guid windows.GUID) string {
	return strings.ToLower(guid.String())
}

func defaultName(prefix, guid string) string {
	if prefix == "" {
		prefix = DefaultNamePrefix
	}
	compact := strings.NewReplacer("{", "", "}", "", "-", "").Replace(guid)
	return prefix + "-" + compact[:12]
}
