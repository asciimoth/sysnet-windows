package wfp

import "testing"

func TestResourcesValidateExactDistinctOwnership(t *testing.T) {
	t.Parallel()
	valid := Resources{
		Provider: Object{Kind: KindProvider, Key: "provider"},
		Baseline: Object{Kind: KindBaselineSublayer, Key: "baseline"},
		DNS:      Object{Kind: KindDNSSublayer, Key: "dns"},
		Filters:  []Object{{Kind: KindFilter, Key: "filter-1"}, {Kind: KindFilter, Key: "filter-2"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	tests := map[string]Resources{
		"empty provider":      func() Resources { value := valid; value.Provider.Key = ""; return value }(),
		"wrong baseline kind": func() Resources { value := valid; value.Baseline.Kind = KindDNSSublayer; return value }(),
		"aliased sublayers":   func() Resources { value := valid; value.DNS.Key = value.Baseline.Key; return value }(),
		"case alias": func() Resources {
			value := valid
			value.Baseline.Key = "ABC"
			value.DNS.Key = "abc"
			return value
		}(),
		"wrong filter kind": func() Resources {
			value := valid
			value.Filters = []Object{{Kind: KindProvider, Key: "filter"}}
			return value
		}(),
	}
	for name, resources := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := resources.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}
