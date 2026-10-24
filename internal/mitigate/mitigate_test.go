package mitigate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	plan, err := Run(Options{ScanDir: dir, UploadProgress0: true, PostMax: "32M"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Wrote {
		t.Fatal("dry run wrote a file")
	}
	if _, err := os.Stat(plan.FilePath); !os.IsNotExist(err) {
		t.Fatal("file exists after dry run")
	}
	if !strings.Contains(plan.Content, "session.upload_progress.enabled = 0") ||
		!strings.Contains(plan.Content, "post_max_size = 32M") {
		t.Fatalf("plan content wrong:\n%s", plan.Content)
	}
}

func TestApplyAndRollback(t *testing.T) {
	dir := t.TempDir()
	plan, err := Run(Options{ScanDir: dir, Apply: true, UploadProgress0: true, MemoryUnlimited: true})
	if err != nil || !plan.Wrote {
		t.Fatalf("apply failed: %v %v", err, plan)
	}
	data, _ := os.ReadFile(plan.FilePath)
	if !strings.Contains(string(data), Marker) {
		t.Fatal("marker missing")
	}
	// Rollback refuses foreign files but removes ours.
	plan2, err := Run(Options{ScanDir: dir, Rollback: true, Apply: true})
	if err != nil || !plan2.Removed {
		t.Fatalf("rollback failed: %v %v", err, plan2)
	}
	if _, err := os.Stat(plan.FilePath); !os.IsNotExist(err) {
		t.Fatal("file not removed")
	}
}

func TestRollbackRefusesForeign(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileBaseName)
	os.WriteFile(p, []byte("; some other tool's config\n"), 0644)
	plan, err := Run(Options{ScanDir: dir, Rollback: true, Apply: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Removed {
		t.Fatal("removed a foreign file")
	}
	if len(plan.Warnings) == 0 {
		t.Fatal("expected warning")
	}
}

func TestVerify(t *testing.T) {
	dir := t.TempDir()
	plan, _ := Run(Options{ScanDir: dir, Apply: true, UploadProgress0: true})
	lines := Verify(plan.FilePath)
	if len(lines) == 0 || strings.Contains(lines[0], "failed") {
		t.Fatalf("verify failed: %v", lines)
	}
}
