package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect/sockowner"
	"github.com/asciimoth/gonnect/sysnet"
	"github.com/asciimoth/sysnet-windows/internal/owner"
)

// matcher applies one immutable rule to best-effort socket ownership results.
// Closing it stops future lookups and releases it from System resource tracking.
type matcher struct {
	lookup  owner.Lookup
	timeout time.Duration
	rule    normalizedRule
	context context.Context
	cancel  context.CancelFunc

	mu      sync.RWMutex
	active  sync.WaitGroup
	closed  bool
	release func()
}

var _ sysnet.Matcher = (*matcher)(nil)

func (m *matcher) Match(flow sockowner.FlowTuple) (bool, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, os.ErrClosed
	}
	lookup, timeout, rule, parent := m.lookup, m.timeout, m.rule, m.context
	if parent == nil {
		parent = context.Background()
	}
	m.active.Add(1)
	m.mu.Unlock()
	defer m.active.Done()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result, err := lookup.Owner(ctx, flow)
	if err != nil {
		return false, err
	}
	pids, err := resultPIDs(result)
	if err != nil {
		return false, err
	}

	switch rule.typeName {
	case rulePID:
		return strconv.Itoa(pids[0]) == rule.value, nil
	case ruleExecutablePath:
		process, err := singleProcess(result, pids[0])
		if err != nil {
			return false, err
		}
		if process.EnrichmentErr != nil {
			return false, fmt.Errorf("enrich executable path for PID %d: %w", process.PID, process.EnrichmentErr)
		}
		observed, issue := canonicalWindowsExecutablePath(process.ExecutablePath)
		if issue != nil {
			return false, fmt.Errorf("canonicalize executable path for PID %d: %w", process.PID, validationError(*issue))
		}
		return strings.EqualFold(observed, rule.value), nil
	default:
		return false, fmt.Errorf("matcher rule %q: %w", rule.typeName, sysnet.ErrNotSupported)
	}
}

func resultPIDs(result *owner.Result) ([]int, error) {
	if result == nil || len(result.Owner.PIDs) == 0 {
		return nil, owner.ErrUnknownOwner
	}
	pids := slices.Clone(result.Owner.PIDs)
	slices.Sort(pids)
	pids = slices.Compact(pids)
	if len(pids) != 1 {
		return nil, owner.ErrAmbiguousOwner
	}
	return pids, nil
}

func singleProcess(result *owner.Result, pid int) (owner.Process, error) {
	var found *owner.Process
	for index := range result.Processes {
		if result.Processes[index].PID != pid {
			continue
		}
		if found != nil {
			return owner.Process{}, owner.ErrAmbiguousOwner
		}
		found = &result.Processes[index]
	}
	if found == nil {
		return owner.Process{}, owner.ErrUnknownOwner
	}
	return *found, nil
}

func (m *matcher) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.cancel
	release := m.release
	m.release = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.active.Wait()
	if release != nil {
		release()
	}
	return nil
}

func newMatcher(lookup owner.Lookup, timeout time.Duration, rule normalizedRule) *matcher {
	ctx, cancel := context.WithCancel(context.Background())
	return &matcher{lookup: lookup, timeout: timeout, rule: rule, context: ctx, cancel: cancel}
}

func (m *matcher) setRelease(release func()) error {
	if release == nil {
		return errors.New("matcher resource release is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return os.ErrClosed
	}
	m.release = release
	return nil
}
