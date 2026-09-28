//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gtun "github.com/asciimoth/gonnect/tun"
	internaltun "github.com/asciimoth/sysnet-windows/internal/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestMain(m *testing.M) {
	if err := stageWintunDLL(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stage Wintun DLL: %v\n", err)
		os.Exit(1)
	}
	// Wintun remains loaded until this process exits. The go command removes
	// its test work directory after the process releases the DLL.
	os.Exit(m.Run())
}

func TestT01T03NativeWintunIdentityAndCollision(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Fatalf("native Wintun test architecture = %s, want amd64 or arm64", runtime.GOARCH)
	}
	factory := internaltun.NativeFactory{}
	requested, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID() error = %v", err)
	}
	name := testAdapterName("identity", requested)
	device, err := factory.Create(context.Background(), internaltun.Config{
		Name: name, GUID: requested.String(), MTU: 1420,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { closeTun(t, device) })

	wantGUID, err := internaltun.NormalizeGUID(requested.String())
	if err != nil {
		t.Fatalf("NormalizeGUID() error = %v", err)
	}
	metadata := device.Metadata()
	if metadata.GUID != wantGUID || metadata.LUID == 0 || metadata.Index == 0 {
		t.Fatalf("Metadata() = %+v, want GUID %s and nonzero current identifiers", metadata, wantGUID)
	}
	if got, err := device.Name(); err != nil || got != name {
		t.Fatalf("Name() = %q, %v, want %q", got, err, name)
	}
	if device.File() != nil || !device.IsNative() || device.BatchSize() != 1 || device.MRO() != 16 || device.MWO() != 16 {
		t.Fatalf("packet contract = native %t, file %v, batch %d, MRO %d, MWO %d", device.IsNative(), device.File(), device.BatchSize(), device.MRO(), device.MWO())
	}

	otherGUID, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID() error = %v", err)
	}
	if collision, err := factory.Create(context.Background(), internaltun.Config{
		Name: name, GUID: otherGUID.String(), MTU: 1420,
	}); err == nil || collision != nil || !errors.Is(err, internaltun.ErrNameCollision) {
		if collision != nil {
			_ = collision.Close()
		}
		t.Fatalf("same-name Create() = %v, %v, want ErrNameCollision", collision, err)
	}
	if collision, err := factory.Create(context.Background(), internaltun.Config{
		Name: testAdapterName("guid-collision", otherGUID), GUID: requested.String(), MTU: 1420,
	}); err == nil || collision != nil {
		if collision != nil {
			_ = collision.Close()
		}
		t.Fatalf("same-GUID Create() = %v, %v, want rejection", collision, err)
	}
	if got := device.Metadata(); got != metadata {
		t.Fatalf("first adapter metadata changed after collisions: got %+v, want %+v", got, metadata)
	}

	generated, err := factory.Create(context.Background(), internaltun.Config{})
	if err != nil {
		t.Fatalf("Create(default config) error = %v", err)
	}
	if got, err := generated.Name(); err != nil || !strings.HasPrefix(got, internaltun.DefaultNamePrefix+"-") {
		_ = generated.Close()
		t.Fatalf("generated Name() = %q, %v", got, err)
	}
	if got, err := generated.MTU(); err != nil || got != 1420 {
		_ = generated.Close()
		t.Fatalf("default MTU() = %d, %v, want 1420", got, err)
	}
	closeTun(t, generated)
}

func TestT10T12NativeWintunPacketContractAndMTUReport(t *testing.T) {
	device := createNativeTun(t, "packet")
	metadata := device.Metadata()
	rowBefore, err := winipcfg.LUID(metadata.LUID).Interface()
	if err != nil {
		t.Fatalf("read interface before MTU report update: %v", err)
	}
	reportedMTU := 1280
	if int(rowBefore.MTU) == reportedMTU {
		reportedMTU = 1290
	}
	if err := device.UpdateReportedMTU(reportedMTU); err != nil {
		t.Fatalf("UpdateReportedMTU() error = %v", err)
	}
	if got, err := device.MTU(); err != nil || got != reportedMTU {
		t.Fatalf("MTU() = %d, %v, want %d", got, err, reportedMTU)
	}
	select {
	case event := <-device.Events():
		if event&gtun.EventMTUUpdate == 0 {
			t.Fatalf("event = %v, want EventMTUUpdate", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MTU report event was not delivered")
	}
	rowAfter, err := winipcfg.LUID(metadata.LUID).Interface()
	if err != nil {
		t.Fatalf("read interface after MTU report update: %v", err)
	}
	if rowAfter.MTU != rowBefore.MTU {
		t.Fatalf("native MTU changed from %d to %d during report-only update", rowBefore.MTU, rowAfter.MTU)
	}

	packets := [][]byte{
		{0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 8, 0, 0, 0, 1, 2, 3, 4},
		{0x60, 0, 0, 0, 0, 8, 58, 64, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 0, 0, 0, 1, 2, 3, 4},
	}
	for _, packet := range packets {
		buffer := append(make([]byte, device.MWO()), packet...)
		if written, err := device.Write([][]byte{buffer}, device.MWO()); err != nil || written != 1 {
			t.Fatalf("Write(%x) = %d, %v", packet[:1], written, err)
		}
	}
}

func TestT13T15NativeWintunCloseContract(t *testing.T) {
	device := createNativeTun(t, "close")
	readStarted := make(chan struct{})
	readResult := make(chan error, 1)
	go func() {
		close(readStarted)
		buffer := make([]byte, device.MRO()+65535)
		_, err := device.Read([][]byte{buffer}, []int{0}, device.MRO())
		readResult <- err
	}()
	<-readStarted
	time.Sleep(100 * time.Millisecond)

	const closers = 16
	closeResults := make(chan error, closers)
	var group sync.WaitGroup
	group.Add(closers)
	for range closers {
		go func() {
			defer group.Done()
			closeResults <- device.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close calls did not return")
	}
	close(closeResults)
	for err := range closeResults {
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("blocked Read error = %v, want os.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	if _, err := device.Read([][]byte{{0}}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close error = %v, want os.ErrClosed", err)
	}
	if _, err := device.Write([][]byte{{0}}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close error = %v, want os.ErrClosed", err)
	}
	select {
	case _, ok := <-device.Events():
		if ok {
			t.Fatal("Events remained open after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Events did not close")
	}
}

func createNativeTun(t *testing.T, label string) internaltun.ManagedTun {
	t.Helper()
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID() error = %v", err)
	}
	device, err := (internaltun.NativeFactory{}).Create(context.Background(), internaltun.Config{
		Name: testAdapterName(label, guid), GUID: guid.String(), MTU: 1420,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	t.Cleanup(func() { closeTun(t, device) })
	return device
}

func testAdapterName(label string, guid windows.GUID) string {
	compact := strings.NewReplacer("{", "", "}", "", "-", "").Replace(guid.String())
	return "sysnet-test-" + label + "-" + compact[:8]
}

func closeTun(t *testing.T, device internaltun.ManagedTun) {
	t.Helper()
	if err := device.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func stageWintunDLL() error {
	source := os.Getenv("SYSNET_WINDOWS_WINTUN_DLL")
	if source == "" {
		return errors.New("SYSNET_WINDOWS_WINTUN_DLL is not set")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	target := filepath.Join(filepath.Dir(executable), "wintun.dll")
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}
