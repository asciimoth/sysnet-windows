//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestFlowCasesHaveUniqueCaptureMarkersAndRequiredPaths(t *testing.T) {
	required := map[string]bool{
		"N01-outnet-tcp4-underlay": false,
		"N02-outnet-tcp6-underlay": false,
		"N03-outnet-udp4-underlay": false,
		"N04-outnet-udp6-underlay": false,
	}
	tokens := make(map[string]struct{})
	for _, current := range flowCases() {
		if current.run == nil || current.observation.ExpectedPath != "underlay" {
			t.Fatalf("invalid flow case: %+v", current.observation)
		}
		token := current.observation.Token
		if token == "" {
			t.Fatal("flow case has an empty capture token")
		}
		if _, exists := tokens[token]; exists {
			t.Fatalf("duplicate capture token %q", token)
		}
		for existing := range tokens {
			if strings.Contains(token, existing) || strings.Contains(existing, token) {
				t.Fatalf("overlapping capture tokens %q and %q", token, existing)
			}
		}
		tokens[token] = struct{}{}
		if _, exists := required[current.observation.Case]; exists {
			required[current.observation.Case] = true
		}
	}
	for name, observed := range required {
		if !observed {
			t.Fatalf("required packet case %s is absent", name)
		}
	}
}
