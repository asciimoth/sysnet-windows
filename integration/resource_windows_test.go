//go:build windows && winintegration && winresource

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/asciimoth/gonnect/sysnet"
	sysnetwindows "github.com/asciimoth/sysnet-windows"
	"github.com/asciimoth/sysnet-windows/internal/netio"
	internalsplit "github.com/asciimoth/sysnet-windows/internal/split"
	"github.com/asciimoth/sysnet-windows/internal/underlay"
	internalwfp "github.com/asciimoth/sysnet-windows/internal/wfp"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	resourceWarmupCycles      = 10
	resourceBatchCount        = 4
	resourceCyclesPerBatch    = 25
	resourceCancellationCount = 100
)

var (
	kernel32Resource = windows.NewLazySystemDLL("kernel32.dll")
	psapiResource    = windows.NewLazySystemDLL("psapi.dll")
	getHandleCount   = kernel32Resource.NewProc("GetProcessHandleCount")
	getMemoryInfo    = psapiResource.NewProc("GetProcessMemoryInfo")
)

// processMemoryCounters is PROCESS_MEMORY_COUNTERS_EX. Keep the complete
// layout because GetProcessMemoryInfo validates the structure size.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

type resourceSample struct {
	Phase        string `json:"phase"`
	Cycles       int    `json:"cycles"`
	Handles      uint32 `json:"handles"`
	Goroutines   int    `json:"goroutines"`
	PrivateBytes uint64 `json:"privateBytes"`
}

type resourceReport struct {
	SchemaVersion  int              `json:"schemaVersion"`
	WarmupCycles   int              `json:"warmupCycles"`
	BatchCount     int              `json:"batchCount"`
	CyclesPerBatch int              `json:"cyclesPerBatch"`
	Samples        []resourceSample `json:"samples"`
}

// TestM6ResourceLifecycleBatches looks for persistent process-resource growth
// only after allocator and DLL warm-up. Native adapter absence is checked after
// every cycle, so a flat process trend cannot hide an owned network leak.
func TestM6ResourceLifecycleBatches(t *testing.T) {
	report := resourceReport{
		SchemaVersion: 1, WarmupCycles: resourceWarmupCycles,
		BatchCount: resourceBatchCount, CyclesPerBatch: resourceCyclesPerBatch,
	}
	completed := 0
	for cycle := range resourceWarmupCycles {
		runNativeResourceCycle(t, cycle)
		completed++
	}
	report.Samples = append(report.Samples, sampleProcessResources(t, "post-warm-up", completed))

	for batch := range resourceBatchCount {
		for cycle := range resourceCyclesPerBatch {
			runNativeResourceCycle(t, resourceWarmupCycles+batch*resourceCyclesPerBatch+cycle)
			completed++
		}
		report.Samples = append(report.Samples, sampleProcessResources(t, fmt.Sprintf("batch-%d", batch+1), completed))
	}
	writeResourceReport(t, report)
	assertNoPersistentResourceTrend(t, report.Samples)
}

// TestM6CancellationCycles cancels native queries while change callbacks are
// registered. Each cycle must join the System worker and unregister callbacks;
// otherwise the process counters in the lifecycle gate show a persistent trend.
func TestM6CancellationCycles(t *testing.T) {
	reader := netio.NativeReader{}
	for cycle := range resourceCancellationCount {
		system, err := sysnetwindows.New(sysnetwindows.SystemConfig{})
		if err != nil {
			t.Fatalf("cycle %d New() error = %v", cycle, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		var group sync.WaitGroup
		group.Add(2)
		results := make(chan error, 2)
		started := make(chan struct{}, 2)
		go func() {
			defer group.Done()
			started <- struct{}{}
			_, queryErr := reader.ReadHostState(ctx)
			results <- queryErr
		}()
		go func() {
			defer group.Done()
			started <- struct{}{}
			_, queryErr := (underlay.NativeSource{}).ReadCandidates(ctx)
			results <- queryErr
		}()
		<-started
		<-started
		cancel()
		group.Wait()
		close(results)
		for queryErr := range results {
			if queryErr != nil && !errors.Is(queryErr, context.Canceled) {
				t.Fatalf("cycle %d cancelled query error = %v", cycle, queryErr)
			}
		}
		if err := system.Close(); err != nil {
			t.Fatalf("cycle %d Close() error = %v", cycle, err)
		}
	}
}

// TestM6NativeTransferReconfigurationSoak keeps one adapter open while packet
// writes, address replacement, route replacement, and MTU changes run together.
// SYSNET_WINDOWS_SOAK_DURATION can shorten diagnostic runs; the resource VM
// gate does not set it and therefore always runs the required 30 minutes.
func TestM6NativeTransferReconfigurationSoak(t *testing.T) {
	duration := 30 * time.Minute
	if value := os.Getenv("SYSNET_WINDOWS_SOAK_DURATION"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			t.Fatalf("SYSNET_WINDOWS_SOAK_DURATION = %q, want a positive duration", value)
		}
		duration = parsed
	}
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("GenerateGUID() error = %v", err)
	}
	name := testAdapterName("m6-soak", guid)
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{StableGUID: guid.String()})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = system.Close() })
	device, err := system.BuildTun(sysnet.TunOpts{
		Name: name, TunAddrs: []string{"198.18.220.1/32"},
		TunRoutes: []string{"203.0.113.220/32"}, MTU: 1400,
	})
	if err != nil {
		t.Fatalf("BuildTun() error = %v", err)
	}

	packets := make(chan []byte, 256)
	readErrors := make(chan error, 1)
	go func() {
		for {
			buffer := make([]byte, device.MRO()+65535)
			sizes := []int{0}
			count, readErr := device.Read([][]byte{buffer}, sizes, device.MRO())
			if readErr != nil {
				readErrors <- readErr
				return
			}
			if count == 1 && sizes[0] > 0 {
				packet := append([]byte(nil), buffer[device.MRO():device.MRO()+sizes[0]]...)
				select {
				case packets <- packet:
				default:
				}
			}
		}
	}()

	deadline := time.Now().Add(duration)
	iteration := 0
	for time.Now().Before(deadline) {
		iterationStarted := time.Now()
		suffix := 220 + iteration%2
		address := fmt.Sprintf("198.18.%d.1/32", suffix)
		route := fmt.Sprintf("203.0.113.%d/32", suffix)
		if err := system.SetTunAddrs(device, []string{address}); err != nil {
			t.Fatalf("iteration %d SetTunAddrs() error = %v", iteration, err)
		}
		if err := system.SetTunRoutes(device, []string{route}); err != nil {
			t.Fatalf("iteration %d SetTunRoutes() error = %v", iteration, err)
		}
		mtu := 1380 + iteration%2*20
		if err := system.SetTunMTU(device, mtu); err != nil {
			t.Fatalf("iteration %d SetTunMTU() error = %v", iteration, err)
		}
		if got, err := system.GetTunAddrs(device); err != nil || !slices.Equal(got, []string{address}) {
			t.Fatalf("iteration %d GetTunAddrs() = %v, %v", iteration, got, err)
		}
		// Discard unrelated packets captured before this observation. The read
		// worker must stay nonblocking so System.Close can always join it.
	drainPackets:
		for {
			select {
			case <-packets:
			default:
				break drainPackets
			}
		}
		token := []byte(fmt.Sprintf("sysnet-m6-%08d", iteration))
		remote, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("203.0.113.%d:47825", suffix))
		if err != nil {
			t.Fatalf("iteration %d ResolveUDPAddr() error = %v", iteration, err)
		}
		connection, err := net.DialUDP("udp4", nil, remote)
		if err != nil {
			t.Fatalf("iteration %d DialUDP() error = %v", iteration, err)
		}
		if _, err := connection.Write(token); err != nil {
			_ = connection.Close()
			t.Fatalf("iteration %d initial UDP transfer error = %v", iteration, err)
		}
		transferDeadline := time.NewTimer(5 * time.Second)
		retry := time.NewTicker(250 * time.Millisecond)
		observed := false
		for !observed {
			select {
			case packet := <-packets:
				observed = bytes.Contains(packet, token)
			case <-retry.C:
				if _, err := connection.Write(token); err != nil {
					retry.Stop()
					transferDeadline.Stop()
					_ = connection.Close()
					t.Fatalf("iteration %d retry UDP transfer error = %v", iteration, err)
				}
			case readErr := <-readErrors:
				retry.Stop()
				transferDeadline.Stop()
				_ = connection.Close()
				t.Fatalf("iteration %d TUN Read() error = %v", iteration, readErr)
			case <-transferDeadline.C:
				retry.Stop()
				_ = connection.Close()
				t.Fatalf("iteration %d transfer token was not observed on Wintun", iteration)
			}
		}
		retry.Stop()
		if !transferDeadline.Stop() {
			select {
			case <-transferDeadline.C:
			default:
			}
		}
		if err := connection.Close(); err != nil {
			t.Fatalf("iteration %d UDP close error = %v", iteration, err)
		}
		iteration++
		if delay := time.Second - time.Since(iterationStarted); delay > 0 {
			time.Sleep(delay)
		}
	}
	if err := system.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case readErr := <-readErrors:
		if !errors.Is(readErr, os.ErrClosed) {
			t.Fatalf("TUN Read() after close error = %v, want os.ErrClosed", readErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TUN read worker did not stop")
	}
	assertAdapterAbsent(t, name)
}

func runNativeResourceCycle(t *testing.T, cycle int) {
	t.Helper()
	guid, err := windows.GenerateGUID()
	if err != nil {
		t.Fatalf("cycle %d GenerateGUID() error = %v", cycle, err)
	}
	name := testAdapterName(fmt.Sprintf("m6-%03d", cycle), guid)
	system, err := sysnetwindows.New(sysnetwindows.SystemConfig{StableGUID: guid.String()})
	if err != nil {
		t.Fatalf("cycle %d New() error = %v", cycle, err)
	}
	device, err := system.BuildDefaultTun(sysnet.DefaultTunOpts{
		Name: name, TunAddrs: []string{fmt.Sprintf("198.18.%d.1/32", 100+cycle%100)},
		TunRoutes: []string{fmt.Sprintf("203.0.113.%d/32", 100+cycle%100)}, MTU: 1400,
	})
	if err != nil {
		_ = system.Close()
		t.Fatalf("cycle %d BuildDefaultTun() error = %v", cycle, err)
	}
	if err := device.SetDNS(nil); err != nil {
		_ = system.Close()
		t.Fatalf("cycle %d SetDNS(nil) error = %v", cycle, err)
	}
	if err := system.Close(); err != nil {
		t.Fatalf("cycle %d Close() error = %v", cycle, err)
	}
	assertAdapterAbsent(t, name)

	// Acquire and release the exclusive split session separately. This covers
	// committed WFP object accounting without engaging packet splitting, which
	// would require one executable exclusion for every lifecycle cycle.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := internalsplit.Acquire(ctx, internalsplit.Dependencies{
		Verifier: internalsplit.NativeVerifier{}, Opener: internalsplit.NativeOpener{},
		WFP:            internalwfp.NativeFactory{TransactionStartTimeout: 10 * time.Second},
		CleanupTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("cycle %d split Acquire() error = %v", cycle, err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("cycle %d split Close() error = %v", cycle, err)
	}
}

func assertAdapterAbsent(t *testing.T, name string) {
	t.Helper()
	adapter, err := wintun.OpenAdapter(name)
	if err == nil {
		_ = adapter.Close()
		t.Fatalf("owned adapter %q remains after cleanup", name)
	}
}

func sampleProcessResources(t *testing.T, phase string, cycles int) resourceSample {
	t.Helper()
	// Two collections and an idle scheduler turn make batch endpoints more
	// comparable without imposing a platform-specific absolute byte limit.
	runtime.GC()
	debug.FreeOSMemory()
	runtime.Gosched()
	process := windows.CurrentProcess()
	var handles uint32
	result, _, callErr := getHandleCount.Call(uintptr(process), uintptr(unsafe.Pointer(&handles)))
	if result == 0 {
		t.Fatalf("%s GetProcessHandleCount: %v", phase, callErr)
	}
	counters := processMemoryCounters{cb: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	result, _, callErr = getMemoryInfo.Call(
		uintptr(process), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb),
	)
	if result == 0 {
		t.Fatalf("%s GetProcessMemoryInfo: %v", phase, callErr)
	}
	return resourceSample{
		Phase: phase, Cycles: cycles, Handles: handles,
		Goroutines: runtime.NumGoroutine(), PrivateBytes: uint64(counters.privateUsage),
	}
}

func assertNoPersistentResourceTrend(t *testing.T, samples []resourceSample) {
	t.Helper()
	if len(samples) != resourceBatchCount+1 {
		t.Fatalf("resource samples = %d, want %d", len(samples), resourceBatchCount+1)
	}
	tests := []struct {
		name  string
		value func(resourceSample) uint64
	}{
		{name: "handles", value: func(sample resourceSample) uint64 { return uint64(sample.Handles) }},
		{name: "goroutines", value: func(sample resourceSample) uint64 { return uint64(sample.Goroutines) }},
		{name: "private bytes", value: func(sample resourceSample) uint64 { return sample.PrivateBytes }},
	}
	for _, test := range tests {
		strictGrowth := true
		for index := 1; index < len(samples); index++ {
			if test.value(samples[index]) <= test.value(samples[index-1]) {
				strictGrowth = false
				break
			}
		}
		if strictGrowth {
			t.Errorf("%s increased after every measured batch: %v", test.name, samples)
		}
	}
}

func writeResourceReport(t *testing.T, report resourceReport) {
	t.Helper()
	path := os.Getenv("SYSNET_RESOURCE_ARTIFACT")
	if path == "" {
		t.Logf("resource report: %+v", report)
		return
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal resource report: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write resource report: %v", err)
	}
}
