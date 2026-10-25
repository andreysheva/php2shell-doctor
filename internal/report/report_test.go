package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/andreysheva/php2shell-doctor/internal/model"
)

func sampleReport() *model.ScanReport {
	return &model.ScanReport{
		SchemaVersion: 1, ToolName: "php2shell-doctor", ToolVersion: "test", DBRevision: "r1",
		Hostname: "h", OS: "linux", Arch: "amd64",
		Installs: []model.InstallReport{
			{
				Install: model.Install{ID: "install-1", BinaryPath: "/usr/bin/php8.3", Upstream: "8.3.6", PackageName: "php8.3", PackageVersion: "8.3.6-0ubuntu0.24.04.12"},
				Verdict: model.VerdictVulnerable, Reason: "before fixed revision",
				PerCVE: map[string]string{"CVE-2026-109618": "affected", "CVE-2026-109619": "affected"},
				Findings: []model.Finding{
					{Severity: model.SevCritical, Category: model.CatVersion, Code: "VULN-PKG", Title: "vulnerable", Detail: "details here", CVEs: []string{"CVE-2026-109618"}},
					{Severity: model.SevHigh, Category: model.CatConfig, Code: "CFG-UPLOADPROGRESS-ON", Title: "upload_progress enabled", Detail: "set it to 0"},
				},
			},
			{
				Install: model.Install{ID: "install-2", Source: "docker-image", ContainerImage: "php:8.3-apache"},
				Verdict: model.VerdictPatchUnknownVer, Reason: "tag partial",
			},
		},
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if back["schema_version"].(float64) != 1 {
		t.Fatal("schema_version missing")
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := CSV(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "VULN-PKG") || !strings.Contains(out, "install,verdict,severity,category,code,title,detail,cves,reference") {
		t.Fatalf("CSV wrong:\n%s", out)
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatal("SARIF version wrong")
	}
	runs := doc["runs"].([]interface{})
	results := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestCycloneDX(t *testing.T) {
	var buf bytes.Buffer
	if err := CycloneDX(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatal("bomFormat wrong")
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport(), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"[VULNERABLE]", "VULN-PKG", "CFG-UPLOADPROGRESS-ON", "Summary:", "UNKNOWN_VERSION"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
	if !strings.Contains(out, "UNKNOWN_VERSION") || !strings.Contains(out, "2 installs") {
		t.Errorf("summary box missing counts:\n%s", out)
	}
}

func TestDecideExit(t *testing.T) {
	rep := sampleReport()
	if got := DecideExit(rep); got != ExitVulnerable {
		t.Fatalf("exit = %d want 1", got)
	}
	rep.Installs = rep.Installs[1:] // only UNKNOWN_VERSION
	if got := DecideExit(rep); got != ExitVerify {
		t.Fatalf("exit = %d want 2", got)
	}
	rep.Installs[0].Verdict = model.VerdictPatched
	if got := DecideExit(rep); got != ExitOK {
		t.Fatalf("exit = %d want 0", got)
	}
}
