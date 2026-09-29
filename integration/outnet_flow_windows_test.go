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
	output := filepath.Join(artifactDir, "packet-flow-observations.jsonl")
	command := exec.Command(helper, "-output", output)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sysnetflow: %v\n%s", err, result)
	}
	info, err := os.Stat(output)
	if err != nil || info.Size() == 0 {
		t.Fatalf("packet observations: %v", err)
	}
}
