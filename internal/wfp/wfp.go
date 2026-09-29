// Package wfp defines the ownership boundary for split-routing WFP objects.
package wfp

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Kind identifies the purpose of one caller-owned WFP object.
type Kind uint8

const (
	KindProvider Kind = iota + 1
	KindBaselineSublayer
	KindDNSSublayer
	KindFilter
)

// Object identifies one exact WFP object. Key is its canonical GUID text.
type Object struct {
	Kind Kind
	Key  string
}

// Resources is the complete committed WFP resource set for one split session.
// Filters contains caller-created filters only. The driver can add more filters
// to the two sublayers after initialization.
type Resources struct {
	Provider Object
	Baseline Object
	DNS      Object
	Filters  []Object
}

// Validate rejects incomplete or aliased ownership records. Keeping this check
// outside native code also protects recovery data loaded from durable storage.
func (r Resources) Validate() error {
	objects := make([]Object, 0, 3+len(r.Filters))
	objects = append(objects, r.Provider, r.Baseline, r.DNS)
	objects = append(objects, r.Filters...)
	want := []Kind{KindProvider, KindBaselineSublayer, KindDNSSublayer}
	seen := make(map[string]struct{}, len(objects))
	for index, object := range objects {
		if object.Key == "" {
			return fmt.Errorf("WFP object %d has an empty key", index)
		}
		if index < len(want) && object.Kind != want[index] {
			return fmt.Errorf("WFP object %q has kind %d, want %d", object.Key, object.Kind, want[index])
		}
		if index >= len(want) && object.Kind != KindFilter {
			return fmt.Errorf("WFP filter %q has kind %d", object.Key, object.Kind)
		}
		canonicalKey := strings.ToLower(object.Key)
		if _, exists := seen[canonicalKey]; exists {
			return fmt.Errorf("WFP object key %q is used more than once", object.Key)
		}
		seen[canonicalKey] = struct{}{}
	}
	return nil
}

// Manager owns one non-dynamic WFP engine session. CreateSplitResources must
// commit all returned objects before it returns. DeleteSplitResources must
// delete only the supplied identifiers and must preserve foreign objects.
type Manager interface {
	CreateSplitResources(context.Context) (Resources, error)
	DeleteSplitResources(context.Context, Resources) error
	VerifySplitResources(context.Context, Resources) error
	// VerifySplitResourcesAbsent proves that none of the exact journaled
	// objects remains. A partial deletion is an error because a remaining
	// provider, sublayer, or filter is still owned state.
	VerifySplitResourcesAbsent(context.Context, Resources) error
	Close() error
}

// Factory opens a non-dynamic WFP engine session. Opening the engine must not
// create policy objects. Acquisition calls it only after exclusive driver
// ownership and a clean driver state are proved.
type Factory interface {
	Open(context.Context) (Manager, error)
}

// VerifyAbsent proves that none of resources still exists. Managers use this
// sentinel when a requested object is absent during verification.
var ErrObjectNotFound = errors.New("WFP object not found")
