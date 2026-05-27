package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckWfctlActionPinDoesNotRequireRipgrep(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not exercised on Windows")
	}

	binDir := t.TempDir()
	for _, name := range []string{"bash", "dirname", "grep"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatalf("find %s: %v", name, err)
		}
		if err := os.Symlink(path, filepath.Join(binDir, name)); err != nil {
			t.Fatalf("link %s: %v", name, err)
		}
	}

	cmd := exec.Command(
		"./check-wfctl-action-pin.sh",
		"--workflow", ".github/workflows/ci.yml",
		"--workflow", ".github/workflows/release.yml",
		"--workflow", ".github/workflows/release-candidate.yml",
		"--wfctl-version", "v0.64.7",
	)
	cmd.Env = append(os.Environ(), "PATH="+binDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("check-wfctl-action-pin.sh should not require rg: %v\n%s", err, out)
	}
}
