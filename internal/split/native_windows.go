//go:build windows && (amd64 || arm64)

package split

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	nativeServiceName = "mullvad-split-tunnel"
	nativeDriverName  = "mullvad-split-tunnel.sys"
	amd64DriverSHA256 = "10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201"
	arm64DriverSHA256 = "6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534"
)

// NativeVerifier verifies the exact signed driver input pinned by this module.
// It is read-only and does not install, start, stop, or reconfigure a service.
type NativeVerifier struct{}

func (NativeVerifier) Verify(ctx context.Context) (Deployment, error) {
	if ctx == nil {
		return Deployment{}, errors.New("verify split driver: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Deployment{}, err
	}
	serviceManager, err := mgr.Connect()
	if err != nil {
		return Deployment{}, fmt.Errorf("connect to service manager: %w", err)
	}
	defer serviceManager.Disconnect()
	service, err := serviceManager.OpenService(nativeServiceName)
	if err != nil {
		return Deployment{}, fmt.Errorf("open service %q: %w", nativeServiceName, err)
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return Deployment{}, fmt.Errorf("read service %q configuration: %w", nativeServiceName, err)
	}
	if config.ServiceType&windows.SERVICE_KERNEL_DRIVER == 0 {
		return Deployment{}, fmt.Errorf("service %q is not a kernel driver", nativeServiceName)
	}
	if config.StartType != windows.SERVICE_DEMAND_START {
		return Deployment{}, fmt.Errorf("service %q is not demand-start", nativeServiceName)
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return Deployment{}, errors.New("SystemRoot is not set")
	}
	driverPath := filepath.Join(systemRoot, "System32", "drivers", nativeDriverName)
	if !validServicePath(config.BinaryPathName, driverPath) {
		return Deployment{}, fmt.Errorf("service %q has unexpected binary path %q", nativeServiceName, config.BinaryPathName)
	}
	if err := ctx.Err(); err != nil {
		return Deployment{}, err
	}
	digest, err := fileSHA256(driverPath)
	if err != nil {
		return Deployment{}, fmt.Errorf("hash installed split driver: %w", err)
	}
	wantDigest := amd64DriverSHA256
	if runtime.GOARCH == "arm64" {
		wantDigest = arm64DriverSHA256
	}
	if !strings.EqualFold(digest, wantDigest) {
		return Deployment{}, fmt.Errorf("installed split driver digest %s does not match pinned package", digest)
	}
	version, err := fileVersion(driverPath)
	if err != nil {
		return Deployment{}, fmt.Errorf("read installed split driver version: %w", err)
	}
	if version != splittunnel.TargetDriverVersion {
		return Deployment{}, fmt.Errorf("installed split driver version %s, want %s", version, splittunnel.TargetDriverVersion)
	}
	if err := verifySignature(driverPath); err != nil {
		return Deployment{}, fmt.Errorf("verify installed split driver signature: %w", err)
	}
	return Deployment{
		ServiceName: nativeServiceName, BinaryPath: driverPath,
		Signer: "trusted Windows driver signature and pinned package digest",
		SHA256: digest, Version: version, ABI: splittunnel.TargetDriverVersion,
	}, nil
}

// NativeOpener opens the pinned controller's global exclusive device.
type NativeOpener struct{}

func (NativeOpener) Open() (Controller, error) {
	controller, err := splittunnel.Open()
	if err != nil {
		// The pinned device uses share mode zero. Windows has returned both a
		// sharing violation and access denied for a second otherwise-authorized
		// opener, depending on the driver and OS build.
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, errors.Join(ErrBusy, err)
		}
		return nil, err
	}
	return nativeController{controller}, nil
}

type nativeController struct{ controller *splittunnel.Controller }

func (c nativeController) State(ctx context.Context) (State, error) {
	state, err := c.controller.State(ctx)
	return State(state), err
}

func (c nativeController) Initialize(ctx context.Context, sublayers Sublayers) error {
	baseline, err := splittunnel.ParseGUID(sublayers.Baseline)
	if err != nil {
		return fmt.Errorf("parse baseline sublayer GUID: %w", err)
	}
	dns, err := splittunnel.ParseGUID(sublayers.DNS)
	if err != nil {
		return fmt.Errorf("parse DNS sublayer GUID: %w", err)
	}
	return c.controller.Initialize(ctx, splittunnel.Sublayers{Baseline: baseline, DNS: dns})
}

func (c nativeController) RegisterProcesses(ctx context.Context, input []Process) error {
	processes := make([]splittunnel.Process, len(input))
	for index, process := range input {
		processes[index] = splittunnel.Process(process)
	}
	return c.controller.RegisterProcesses(ctx, processes)
}

func (c nativeController) SetAddresses(ctx context.Context, addresses Addresses) error {
	return c.controller.SetAddresses(ctx, splittunnel.Addresses(addresses))
}

func (c nativeController) SetExcludedDevicePaths(ctx context.Context, paths []string) error {
	return c.controller.SetExcludedDevicePaths(ctx, paths)
}

func (c nativeController) ReadEvent(ctx context.Context) (Event, error) {
	event, err := c.controller.ReadEvent(ctx)
	return Event{ID: uint32(event.ID), PID: event.PID, Reason: uint32(event.Reason), ImagePath: event.ImagePath,
		NTStatus: event.NTStatus, Message: event.Message, Raw: append([]byte(nil), event.Raw...)}, err
}

func (c nativeController) Reset(ctx context.Context) error { return c.controller.Reset(ctx) }

func (c nativeController) Close() error { return c.controller.Close() }

// NativeProcessSnapshotter reads the Toolhelp snapshot after initialization.
type NativeProcessSnapshotter struct{}

func (NativeProcessSnapshotter) Snapshot(ctx context.Context) (ProcessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProcessSnapshot{}, err
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		return ProcessSnapshot{}, err
	}
	result := ProcessSnapshot{Processes: make([]Process, len(snapshot.Processes)), Warnings: make([]ProcessWarning, len(snapshot.Warnings))}
	for index, process := range snapshot.Processes {
		result.Processes[index] = Process(process)
	}
	for index, warning := range snapshot.Warnings {
		result.Warnings[index] = ProcessWarning(warning)
	}
	if err := ctx.Err(); err != nil {
		return ProcessSnapshot{}, err
	}
	return result, nil
}

// NativePathResolver resolves junctions and volume mappings with a file handle.
type NativePathResolver struct{}

func (NativePathResolver) Resolve(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	resolved, err := splittunnel.ResolveDevicePath(path)
	if err == nil {
		err = ctx.Err()
	}
	return resolved, err
}

func validServicePath(configured, absolute string) bool {
	configured = strings.Trim(strings.TrimSpace(configured), `"`)
	systemRootPath := `\SystemRoot\System32\drivers\` + nativeDriverName
	return strings.EqualFold(configured, systemRootPath) || strings.EqualFold(filepath.Clean(configured), filepath.Clean(absolute))
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fileVersion(path string) (string, error) {
	var ignored windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &ignored)
	if err != nil {
		return "", err
	}
	if size == 0 {
		return "", errors.New("version resource is empty")
	}
	buffer := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buffer[0])); err != nil {
		return "", err
	}
	var info *windows.VS_FIXEDFILEINFO
	var infoSize uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), `\`, unsafe.Pointer(&info), &infoSize); err != nil {
		return "", err
	}
	if info == nil || infoSize < uint32(unsafe.Sizeof(*info)) {
		return "", errors.New("fixed version information is truncated")
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		info.FileVersionMS>>16, info.FileVersionMS&0xffff,
		info.FileVersionLS>>16, info.FileVersionLS&0xffff,
	), nil
}

func verifySignature(path string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: pathPointer,
	}
	data := &windows.WinTrustData{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return errors.Join(verifyErr, closeErr)
}
