//go:build windows

package wfp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

const (
	nativeProviderName = "sysnet-windows split routing"
	baselineName       = "sysnet-windows split baseline"
	dnsName            = "sysnet-windows split DNS"
)

// NativeFactory opens non-dynamic Windows Filtering Platform sessions.
type NativeFactory struct {
	TransactionStartTimeout time.Duration
}

func (f NativeFactory) Open(ctx context.Context) (Manager, error) {
	if ctx == nil {
		return nil, errors.New("open WFP session: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session, err := wf.New(&wf.Options{
		Name: nativeProviderName, Description: "Caller-owned split-routing objects",
		Dynamic: false, TransactionStartTimeout: f.TransactionStartTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("open WFP engine: %w", err)
	}
	return &nativeManager{session: session}, nil
}

type nativeManager struct {
	mu      sync.Mutex
	session *wf.Session
	closed  bool
}

func (m *nativeManager) CreateSplitResources(ctx context.Context) (Resources, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.usable(ctx); err != nil {
		return Resources{}, err
	}
	providerGUID, err := windows.GenerateGUID()
	if err != nil {
		return Resources{}, fmt.Errorf("generate WFP provider key: %w", err)
	}
	baselineGUID, err := windows.GenerateGUID()
	if err != nil {
		return Resources{}, fmt.Errorf("generate baseline WFP sublayer key: %w", err)
	}
	dnsGUID, err := windows.GenerateGUID()
	if err != nil {
		return Resources{}, fmt.Errorf("generate DNS WFP sublayer key: %w", err)
	}
	providerID := wf.ProviderID(providerGUID)
	baselineID := wf.SublayerID(baselineGUID)
	dnsID := wf.SublayerID(dnsGUID)
	resources := Resources{
		Provider: Object{Kind: KindProvider, Key: providerGUID.String()},
		Baseline: Object{Kind: KindBaselineSublayer, Key: baselineGUID.String()},
		DNS:      Object{Kind: KindDNSSublayer, Key: dnsGUID.String()},
	}
	if err := m.session.AddProvider(&wf.Provider{
		ID: providerID, Name: nativeProviderName,
		Description: "Owns sysnet-windows split-routing sublayers",
	}); err != nil {
		return Resources{}, fmt.Errorf("add WFP provider: %w", err)
	}
	addedBaseline := false
	cleanup := func(cause error) (Resources, error) {
		var cleanupErr error
		if addedBaseline {
			cleanupErr = errors.Join(cleanupErr, ignoreNotFound(m.session.DeleteSublayer(baselineID), windows.FWP_E_SUBLAYER_NOT_FOUND))
		}
		cleanupErr = errors.Join(cleanupErr, ignoreNotFound(m.session.DeleteProvider(providerID), windows.FWP_E_PROVIDER_NOT_FOUND))
		return Resources{}, errors.Join(cause, cleanupErr)
	}
	if err := ctx.Err(); err != nil {
		return cleanup(err)
	}
	if err := m.session.AddSublayer(&wf.Sublayer{
		ID: baselineID, Name: baselineName, Description: "General split-driver filters",
		Provider: providerID, Weight: 0x8000,
	}); err != nil {
		return cleanup(fmt.Errorf("add baseline WFP sublayer: %w", err))
	}
	addedBaseline = true
	if err := ctx.Err(); err != nil {
		return cleanup(err)
	}
	if err := m.session.AddSublayer(&wf.Sublayer{
		ID: dnsID, Name: dnsName, Description: "Split-driver DNS permit filters",
		Provider: providerID, Weight: 0x8001,
	}); err != nil {
		return cleanup(fmt.Errorf("add DNS WFP sublayer: %w", err))
	}
	return resources, nil
}

func (m *nativeManager) VerifySplitResources(ctx context.Context, resources Resources) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := resources.Validate(); err != nil {
		return err
	}
	if err := m.usable(ctx); err != nil {
		return err
	}
	providerID, baselineID, dnsID, err := nativeIDs(resources)
	if err != nil {
		return err
	}
	providers, err := m.session.Providers()
	if err != nil {
		return fmt.Errorf("enumerate WFP providers: %w", err)
	}
	providerFound := slices.ContainsFunc(providers, func(provider *wf.Provider) bool {
		return provider.ID == providerID && provider.Name == nativeProviderName
	})
	if !providerFound {
		return fmt.Errorf("provider %s: %w", resources.Provider.Key, ErrObjectNotFound)
	}
	sublayers, err := m.session.Sublayers(providerID)
	if err != nil {
		return fmt.Errorf("enumerate WFP sublayers: %w", err)
	}
	baselineFound := slices.ContainsFunc(sublayers, func(layer *wf.Sublayer) bool {
		return layer.ID == baselineID && layer.Provider == providerID && layer.Name == baselineName
	})
	dnsFound := slices.ContainsFunc(sublayers, func(layer *wf.Sublayer) bool {
		return layer.ID == dnsID && layer.Provider == providerID && layer.Name == dnsName
	})
	if !baselineFound || !dnsFound {
		return fmt.Errorf("baseline present=%t, DNS present=%t: %w", baselineFound, dnsFound, ErrObjectNotFound)
	}
	if len(resources.Filters) != 0 {
		rules, err := m.session.Rules()
		if err != nil {
			return fmt.Errorf("enumerate WFP filters: %w", err)
		}
		for _, object := range resources.Filters {
			guid, parseErr := windows.GUIDFromString(object.Key)
			if parseErr != nil {
				return fmt.Errorf("parse WFP filter key %q: %w", object.Key, parseErr)
			}
			found := slices.ContainsFunc(rules, func(rule *wf.Rule) bool {
				return rule.ID == wf.RuleID(guid) && rule.Provider == providerID &&
					(rule.Sublayer == baselineID || rule.Sublayer == dnsID)
			})
			if !found {
				return fmt.Errorf("filter %s: %w", object.Key, ErrObjectNotFound)
			}
		}
	}
	return nil
}

func (m *nativeManager) DeleteSplitResources(ctx context.Context, resources Resources) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := resources.Validate(); err != nil {
		return err
	}
	if err := m.usable(ctx); err != nil {
		return err
	}
	providerID, baselineID, dnsID, err := nativeIDs(resources)
	if err != nil {
		return err
	}
	// Delete in reverse dependency order. Exact GUID deletion preserves every
	// foreign provider, sublayer, and filter.
	var result error
	for index := len(resources.Filters) - 1; index >= 0; index-- {
		guid, parseErr := windows.GUIDFromString(resources.Filters[index].Key)
		if parseErr != nil {
			result = errors.Join(result, parseErr)
			continue
		}
		result = errors.Join(result, ignoreNotFound(m.session.DeleteRule(wf.RuleID(guid)), windows.FWP_E_FILTER_NOT_FOUND))
	}
	result = errors.Join(result, ignoreNotFound(m.session.DeleteSublayer(dnsID), windows.FWP_E_SUBLAYER_NOT_FOUND))
	result = errors.Join(result, ignoreNotFound(m.session.DeleteSublayer(baselineID), windows.FWP_E_SUBLAYER_NOT_FOUND))
	result = errors.Join(result, ignoreNotFound(m.session.DeleteProvider(providerID), windows.FWP_E_PROVIDER_NOT_FOUND))
	return result
}

func ignoreNotFound(err error, notFound windows.Handle) error {
	if errors.Is(err, syscall.Errno(notFound)) || errors.Is(err, syscall.Errno(windows.FWP_E_NOT_FOUND)) {
		return nil
	}
	return err
}

func (m *nativeManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.session == nil {
		return nil
	}
	return m.session.Close()
}

func (m *nativeManager) usable(ctx context.Context) error {
	if ctx == nil {
		return errors.New("WFP operation has nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || m.closed || m.session == nil {
		return errors.New("WFP session is closed")
	}
	return nil
}

func nativeIDs(resources Resources) (wf.ProviderID, wf.SublayerID, wf.SublayerID, error) {
	provider, err := windows.GUIDFromString(resources.Provider.Key)
	if err != nil {
		return wf.ProviderID{}, wf.SublayerID{}, wf.SublayerID{}, fmt.Errorf("parse WFP provider key: %w", err)
	}
	baseline, err := windows.GUIDFromString(resources.Baseline.Key)
	if err != nil {
		return wf.ProviderID{}, wf.SublayerID{}, wf.SublayerID{}, fmt.Errorf("parse baseline WFP sublayer key: %w", err)
	}
	dns, err := windows.GUIDFromString(resources.DNS.Key)
	if err != nil {
		return wf.ProviderID{}, wf.SublayerID{}, wf.SublayerID{}, fmt.Errorf("parse DNS WFP sublayer key: %w", err)
	}
	return wf.ProviderID(provider), wf.SublayerID(baseline), wf.SublayerID(dns), nil
}
