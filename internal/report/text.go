package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/andreysheva/php2shell-doctor/internal/model"
	"github.com/andreysheva/php2shell-doctor/internal/ui"
)

// TextOptions tunes the human reporter. Color is decided by the CLI
// (TTY + --no-color + output destination), not by this package.
type TextOptions struct {
	Color   bool
	Elapsed time.Duration
}

// JSON writes the machine-readable report (schema v1).
func JSON(w io.Writer, rep *model.ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// CSV writes one row per finding (install, verdict, severity, category, code, title, detail).
func CSV(w io.Writer, rep *model.ScanReport) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"install", "verdict", "severity", "category", "code", "title", "detail", "cves", "reference"}); err != nil {
		return err
	}
	for _, ir := range rep.Installs {
		name := ir.Install.BinaryPath
		if name == "" {
			name = ir.Install.PackageName + " " + ir.Install.PackageVersion
		}
		if ir.Install.ContainerImage != "" {
			name = ir.Install.ContainerImage
		}
		row := func(sev, cat, code, title, detail, cves, ref string) {
			_ = cw.Write([]string{name, string(ir.Verdict), sev, cat, code, title, detail, cves, ref})
		}
		row(string(model.SevInfo), "version", "VERDICT", string(ir.Verdict), ir.Reason, "", "")
		for _, f := range ir.Findings {
			row(string(f.Severity), string(f.Category), f.Code, f.Title, f.Detail, strings.Join(f.CVEs, ";"), f.Reference)
		}
	}
	return cw.Error()
}

// SARIF maps findings to the SARIF 2.1.0 format for GitHub code
// scanning / DefectDojo ingestion.
func SARIF(w io.Writer, rep *model.ScanReport) error {
	results := []map[string]interface{}{}
	ruleIndex := map[string]int{}
	rules := []map[string]interface{}{}
	addRule := func(code, title, help string) int {
		if i, ok := ruleIndex[code]; ok {
			return i
		}
		i := len(rules)
		ruleIndex[code] = i
		rules = append(rules, map[string]interface{}{
			"id": code,
			"shortDescription": map[string]string{"text": title},
			"fullDescription":  map[string]string{"text": title},
			"help":             map[string]string{"text": help, "markdown": help},
			"defaultConfiguration": map[string]string{"level": "warning"},
		})
		return i
	}
	level := func(s model.Severity) string {
		switch s {
		case model.SevCritical, model.SevHigh:
			return "error"
		case model.SevMedium:
			return "warning"
		}
		return "note"
	}
	for _, ir := range rep.Installs {
		who := installName(ir)
		for _, f := range ir.Findings {
			idx := addRule(f.Code, f.Title, f.Detail)
			results = append(results, map[string]interface{}{
				"ruleId":    f.Code,
				"ruleIndex": idx,
				"level":     level(f.Severity),
				"message": map[string]string{"text": who + ": " + f.Title + (func() string {
					if f.Detail != "" {
						return " — " + f.Detail
					}
					return ""
				}())},
				"properties": map[string]interface{}{
					"install": who, "verdict": string(ir.Verdict),
					"cves": f.CVEs, "category": string(f.Category),
				},
			})
		}
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":           "php2shell-doctor",
					"informationUri": "https://github.com/andreysheva/php2shell-doctor",
					"rules":          rules,
				},
			},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// CycloneDX emits a minimal CycloneDX 1.5 component report of the
// discovered PHP runtimes for asset-management pipelines.
func CycloneDX(w io.Writer, rep *model.ScanReport) error {
	components := []map[string]interface{}{}
	for _, ir := range rep.Installs {
		p := map[string]interface{}{
			"type": "application", "name": "php",
			"version": firstNonEmpty(ir.Install.Upstream, ir.Install.VersionRaw, "unknown"),
			"bom-ref": "php:" + installName(ir),
		}
		if ir.Install.PackageName != "" {
			p["name"] = ir.Install.PackageName
			p["version"] = firstNonEmpty(ir.Install.PackageVersion, ir.Install.VersionRaw, "unknown")
		}
		props := []map[string]string{
			{"name": "php2shell:verdict", "value": string(ir.Verdict)},
			{"name": "php2shell:source", "value": ir.Install.Source},
		}
		if ir.Install.ContainerImage != "" {
			props = append(props, map[string]string{"name": "php2shell:container-image", "value": ir.Install.ContainerImage})
		}
		p["properties"] = props
		components = append(components, p)
	}
	doc := map[string]interface{}{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:php2shell-doctor-scan",
		"version": 1,
		"metadata": map[string]interface{}{
			"tools": map[string]interface{}{"components": []map[string]string{{
				"type": "application", "name": "php2shell-doctor", "version": rep.ToolVersion,
			}}},
		},
		"components": components,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func installName(ir model.InstallReport) string {
	if ir.Install.ContainerImage != "" {
		return ir.Install.ContainerImage
	}
	if ir.Install.BinaryPath != "" {
		return ir.Install.BinaryPath
	}
	if ir.Install.PackageName != "" {
		return ir.Install.PackageName + " " + ir.Install.PackageVersion
	}
	return ir.Install.Root
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Text renders the human-readable console report. When opts.Color is
// set, verdicts, severities and the summary box are styled.
func Text(w io.Writer, rep *model.ScanReport, opts TextOptions) error {
	color := opts.Color
	C := func(fn func(string) string, s string) string {
		if !color {
			return s
		}
		return fn(s)
	}
	fmt.Fprintf(w, "%s (vendor DB %s)\n",
		C(ui.Cyan, "php2shell-doctor "+rep.ToolVersion), rep.DBRevision)
	fmt.Fprintf(w, "host %s  os %s/%s  generated %s\n\n",
		rep.Hostname, rep.OS, rep.Arch, rep.Generated.Format("2006-01-02 15:04:05"))
	if len(rep.Installs) == 0 {
		fmt.Fprintln(w, "No PHP installations found.")
		printWarnings(w, rep, color)
		return nil
	}
	counts := map[string]int{}
	for _, ir := range rep.Installs {
		counts[string(ir.Verdict)]++
		name := installName(ir)
		ver := firstNonEmpty(ir.Install.Upstream, ir.Install.VersionRaw, ir.Install.PackageVersion, "(version unknown)")
		vc := ui.VerdictColor(string(ir.Verdict))
		fmt.Fprintf(w, "%s %s %s (%s)\n",
			ui.VerdictSymbol(string(ir.Verdict)), // already colored when enabled
			C(vc, "["+string(ir.Verdict)+"]"),
			name, ver)
		fmt.Fprintf(w, "  %s\n", ir.Reason)
		for _, f := range ir.Findings {
			sc := ui.SeverityColor(string(f.Severity))
			fmt.Fprintf(w, "  - %s %s %s\n",
				C(ui.Grey, f.Code), C(sc, "["+string(f.Severity)+"]"), f.Title)
			if f.Detail != "" {
				parts := strings.Split(f.Detail, "\n")
				fmt.Fprintf(w, "      %s\n", parts[0])
				if len(parts) > 1 {
					fmt.Fprintf(w, "      %s\n", strings.Join(parts[1:], "\n      "))
				}
			}
			if len(f.CVEs) > 0 {
				fmt.Fprintf(w, "      %s %s\n", C(ui.Grey, "CVEs:"), strings.Join(f.CVEs, ", "))
			}
			if f.Reference != "" {
				fmt.Fprintf(w, "      %s %s\n", C(ui.Grey, "ref:"), f.Reference)
			}
		}
		fmt.Fprintln(w)
	}
	// Summary box
	order := []string{"VULNERABLE", "EOL_VULNERABLE", "PATCHED_STALE_WORKERS", "VERIFY_VENDOR", "UNKNOWN_VERSION", "PATCHED"}
	var lines []string
	total := 0
	for _, v := range order {
		if c := counts[v]; c > 0 {
			vc := ui.VerdictColor(v)
			lines = append(lines, C(vc, fmt.Sprintf("%-22s %d", v, c)))
			total += c
		}
	}
	if rep.HuntSummary != nil && len(rep.HuntSummary.Signatures) > 0 {
		lines = append(lines, "")
		lines = append(lines, C(ui.Bold, fmt.Sprintf("hunt: %d log files, %d lines", rep.HuntSummary.FilesScanned, rep.HuntSummary.LinesScanned)))
		for _, s := range rep.HuntSummary.Signatures {
			sc := ui.Yellow
			if s.Level == "high" || s.Level == "critical" {
				sc = ui.Red
			}
			lines = append(lines, fmt.Sprintf("%s %s x%d", C(sc, "•"), s.Name, s.Count))
		}
	}
	if len(rep.Remote) > 0 {
		lines = append(lines, "")
		lines = append(lines, C(ui.Bold, fmt.Sprintf("remote results: %d", len(rep.Remote))))
		for _, r := range rep.Remote {
			lines = append(lines, fmt.Sprintf("%s %s %s", C(ui.VerdictColor(r.Verdict), "•"), r.URL, r.Reason))
		}
	}
	elapsed := ""
	if opts.Elapsed > 0 {
		elapsed = fmt.Sprintf(" in %.1fs", opts.Elapsed.Seconds())
	}
	title := fmt.Sprintf("Summary: %d installs%s", total, elapsed)
	if len(lines) == 0 {
		lines = append(lines, "nothing to report")
	}
	fmt.Fprint(w, ui.Box(title, lines))
	printWarnings(w, rep, color)
	return nil
}

func printWarnings(w io.Writer, rep *model.ScanReport, color bool) {
	warn := func(s string) string {
		if color {
			return ui.Yellow(s)
		}
		return s
	}
	if len(rep.Warnings) > 0 {
		fmt.Fprintln(w, warn("Warnings:"))
		for _, wn := range rep.Warnings {
			fmt.Fprintf(w, "  ! %s\n", wn)
		}
	}
	if len(rep.EngineErrors) > 0 {
		fmt.Fprintln(w, warn("Engine errors (scan is partial):"))
		for _, e := range rep.EngineErrors {
			fmt.Fprintf(w, "  ! %s\n", e)
		}
	}
}
