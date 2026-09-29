//go:build windows && winintegration && winflow

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPacketFlowOutNetUnderlay runs the public System and OutNet contract in a
// separate process. The host gate validates each emitted token against captures
// from the isolated tunnel and underlay links.
func TestPacketFlowOutNetUnderlay(t *testing.T) {
	helper := os.Getenv("SYSNET_FLOW_EXE")
	artifactDir := os.Getenv("FLOW_ARTIFACT_DIR")
	if helper == "" || artifactDir == "" {
		t.Fatal("packet-flow helper or artifact directory is not configured")
	}
	output := filepath.Join(artifactDir, "packet-flow-outnet-observations.jsonl")
	command := exec.Command(helper, "-scenario", "outnet", "-output", output)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sysnetflow: %v\n%s", err, result)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("packet observations: %v", err)
	}
}

// TestPacketFlowDependencyConformanceRanFirst makes the dependency ordering a
// required Go test result. The VM gate creates the marker only after the pinned
// controller's nine-mode packet-flow conformance test passes.
func TestPacketFlowDependencyConformanceRanFirst(t *testing.T) {
	artifactDir := os.Getenv("FLOW_ARTIFACT_DIR")
	if artifactDir == "" {
		t.Fatal("packet-flow artifact directory is not configured")
	}
	marker := filepath.Join(artifactDir, "dependency-conformance-passed.json")
	info, err := os.Stat(marker)
	if err != nil || info.Size() == 0 {
		t.Fatalf("dependency conformance marker: %v", err)
	}
}

// TestPacketFlowPublicAPIExclusions proves application path behavior through
// New and BuildDefaultTun. The helper emits one independently captured marker
// for each role, family, transport, and DNS attribution case.
func TestPacketFlowPublicAPIExclusions(t *testing.T) {
	helper := os.Getenv("SYSNET_FLOW_EXE")
	artifactDir := os.Getenv("FLOW_ARTIFACT_DIR")
	if helper == "" || artifactDir == "" {
		t.Fatal("packet-flow helper or artifact directory is not configured")
	}
	output := filepath.Join(artifactDir, "packet-flow-public-api-observations.jsonl")
	command := exec.Command(helper, "-scenario", "split", "-output", output)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sysnetflow split scenario: %v\n%s", err, result)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("public API packet observations: %v", err)
	}
}
