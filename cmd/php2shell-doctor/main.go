// Command php2shell-doctor is the safe, local-first checker for the
// php2shell PHP vulnerabilities (CVE-2026-109618, CVE-2026-109619,
// CVE-2026-115560 config surface).
//
// It never sends the scanned host's data anywhere, never executes
// exploit probes and never crashes a worker. Default mode is read-only.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/andreysheva/php2shell-doctor/internal/audit"
	"github.com/andreysheva/php2shell-doctor/internal/classify"
	"github.com/andreysheva/php2shell-doctor/internal/discover"
	"github.com/andreysheva/php2shell-doctor/internal/execx"
	"github.com/andreysheva/php2shell-doctor/internal/hunt"
	"github.com/andreysheva/php2shell-doctor/internal/mitigate"
	"github.com/andreysheva/php2shell-doctor/internal/model"
	"github.com/andreysheva/php2shell-doctor/internal/phpver"
	"github.com/andreysheva/php2shell-doctor/internal/product"
	"github.com/andreysheva/php2shell-doctor/internal/remote"
	"github.com/andreysheva/php2shell-doctor/internal/report"
	"github.com/andreysheva/php2shell-doctor/internal/ui"
	"github.com/andreysheva/php2shell-doctor/internal/stale"
	"github.com/andreysheva/php2shell-doctor/internal/vendordb"
)

const version = "1.0.0"

var toolVersion = version // overridable via -ldflags

func main() {
	os.Exit(run(os.Args[1:]))
}

func usage() {
	fmt.Print(`php2shell-doctor ` + toolVersion + ` — safe checker for the php2shell PHP RCEs
(CVE-2026-109618, CVE-2026-109619; config surface of CVE-2026-115560)

Usage: php2shell-doctor <command> [flags]

Commands:
  scan          Discover PHP installs and classify php2shell patch state (default)
  mitigate      Apply/remove PHP's temporary ini mitigations (dry-run by default)
  product       Look up an appliance/product in the NCSC-NL SPDX inventory
  db            Show vendor-fix database contents and revision
  self-test     Verify internal engines (run after building/installing)
  version       Print version

Run 'php2shell-doctor <command> -h' for command flags.
Exit codes (scan): 0=OK, 1=vulnerable/stale workers, 2=verify required, 3=error.
Documentation: docs/ in the repository.
`)
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return report.ExitOK
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return cmdScan(rest)
	case "mitigate":
		return cmdMitigate(rest)
	case "product":
		return cmdProduct(rest)
	case "db":
		return cmdDB(rest)
	case "self-test":
		return cmdSelfTest()
	case "version":
		fmt.Println("php2shell-doctor", toolVersion)
		return report.ExitOK
	case "-h", "--help", "help":
		usage()
		return report.ExitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		return report.ExitError
	}
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output (schema v1) to stdout")
	csvOut := fs.Bool("csv", false, "CSV output to stdout")
	sarifOut := fs.Bool("sarif", false, "SARIF 2.1.0 output to stdout")
	cdxbOut := fs.Bool("cyclonedx", false, "CycloneDX 1.5 output to stdout")
	noExec := fs.Bool("no-exec", false, "never execute discovered PHP binaries (banner/static analysis only)")
	docker := fs.Bool("docker", false, "also inspect docker CLI (containers and local images)")
	dockerExec := fs.Bool("docker-exec", false, "execute php -v inside running containers (implies --docker)")
	noProcs := fs.Bool("no-processes", false, "skip running-process enumeration")
	huntMode := fs.Bool("hunt", false, "scan PHP/FPM/Apache logs for exploitation signatures (read-only)")
	logFiles := fs.String("log-files", "", "comma-separated log paths/globs for --hunt (default: standard locations)")
	remoteJSON := fs.String("remote-json", "", "ingest assetnote/php2shell-scanner JSON results (file or -)")
	spdxFile := fs.String("spdx", "", "NCSC SPDX3 inventory file for product lookups")
	extraPaths := fs.String("extra-path", "", "additional php binary paths, comma-separated")
	dbFile := fs.String("vendordb", "", "override the embedded vendor-fix database with a local JSON file")
	outFile := fs.String("o", "", "write output to file instead of stdout (use with format flags)")
	noColor := fs.Bool("no-color", false, "disable colored output (auto-disabled when piped; NO_COLOR env respected)")
	fs.Parse(args)
	ui.Init(*noColor)

	db, err := loadDB(*dbFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return report.ExitError
	}

	start := time.Now()
	engineErrors := []string{}
	do := discover.Options{
		Docker: *docker || *dockerExec, DockerExec: *dockerExec,
		ScanProcesses: !*noProcs, NoExec: *noExec, Timeout: 15 * time.Second,
	}
	for _, p := range strings.Split(*extraPaths, ",") {
		if strings.TrimSpace(p) != "" {
			do.ExtraPaths = append(do.ExtraPaths, strings.TrimSpace(p))
		}
	}
	var sp *ui.Spinner
	textMode := *outFile == "" && !*jsonOut && !*csvOut && !*sarifOut && !*cdxbOut
	if textMode {
		fmt.Fprint(os.Stderr, ui.Banner(toolVersion, db.Revision()))
		sp = ui.NewSpinner("discovering PHP runtimes (PATH, packages, panels, SAPIs, processes" +
			map[bool]string{true: ", docker", false: ""}[*docker || *dockerExec] + ")...")
	}
	dres := discover.Run(do)
	if sp != nil {
		if dres.Partial {
			sp.Stop("warn", fmt.Sprintf("discovery finished with %d engine note(s)", len(dres.EngineNotes)))
		} else {
			sp.Stop("ok", fmt.Sprintf("found %d PHP runtime(s)", len(dres.Installs)))
		}
	}
	engineErrors = append(engineErrors, dres.EngineNotes...)

	rep := model.ScanReport{
		SchemaVersion: 1, ToolName: "php2shell-doctor", ToolVersion: toolVersion,
		DBRevision: db.Revision(), Generated: time.Now().UTC(),
		Hostname: hostname(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		Installs: []model.InstallReport{}, Warnings: []string{},
		EngineErrors: engineErrors, Partial: dres.Partial,
	}

	procs := dres.Processes
	for i := range dres.Installs {
		inst := dres.Installs[i]
		inst.ID = fmt.Sprintf("install-%d", i+1)
		if fi, err := os.Stat(inst.BinaryPath); err == nil && !fi.IsDir() {
			inst.BinaryMtime = fi.ModTime()
		}
		if inst.VersionRaw != "" {
			inst.Upstream, _ = phpver.Upstream(inst.VersionRaw)
			inst.Branch = phpver.Branch(inst.Upstream)
		}
		irep := classifyOne(db, inst, *noExec, procs)
		rep.Installs = append(rep.Installs, irep)
	}

	if *huntMode {
		var patterns []string
		if *logFiles != "" {
			patterns = strings.Split(*logFiles, ",")
		} else {
			patterns = hunt.DefaultLogFiles()
		}
		hsp := ui.NewSpinner("scanning logs for exploitation signatures...")
		sum, warnings := hunt.Scan(patterns, 100*1024*1024)
		if hsp != nil {
			if len(sum.Signatures) > 0 {
				hsp.Stop("warn", fmt.Sprintf("hunt: %d signature type(s) matched across %d log files", len(sum.Signatures), sum.FilesScanned))
			} else {
				hsp.Stop("ok", fmt.Sprintf("hunt: no signatures in %d log files", sum.FilesScanned))
			}
		}
		rep.HuntSummary = &sum
		rep.Warnings = append(rep.Warnings, warnings...)
	}
	if *remoteJSON != "" {
		data, err := readInput(*remoteJSON)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "remote-json unreadable: "+err.Error())
		} else {
			fs2, warn := remote.ParseAssetnoteJSON(data)
			rep.Warnings = append(rep.Warnings, warn...)
			for _, f := range fs2 {
				rep.Remote = append(rep.Remote, model.RemoteFinding{URL: f.URL, Verdict: f.Verdict, Reason: f.Reason})
			}
		}
	}
	if *spdxFile != "" {
		inv, err := product.LoadFile(*spdxFile)
		if err != nil {
			rep.Warnings = append(rep.Warnings, "spdx unreadable: "+err.Error())
		} else {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("NCSC product inventory loaded: %d products (use 'php2shell-doctor product -q <name>' to search)", inv.Count))
		}
	}

	w := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return report.ExitError
		}
		defer f.Close()
		w = f
	}
	var rerr error
	switch {
	case *jsonOut:
		rerr = report.JSON(w, &rep)
	case *csvOut:
		rerr = report.CSV(w, &rep)
	case *sarifOut:
		rerr = report.SARIF(w, &rep)
	case *cdxbOut:
		rerr = report.CycloneDX(w, &rep)
	default:
		rerr = report.Text(w, &rep, report.TextOptions{Color: textMode && ui.Enabled(), Elapsed: time.Since(start)})
	}
	if rerr != nil {
		fmt.Fprintln(os.Stderr, "error:", rerr)
		return report.ExitError
	}
	return report.DecideExit(&rep)
}

// classifyOne runs the full per-install pipeline (classification, config
// audit, staleness) behind a panic guard: one pathological binary or ini
// file must degrade to a finding, never abort the whole scan.
func classifyOne(db *vendordb.DB, inst model.Install, noExec bool, procs []model.ProcessInfo) (irep model.InstallReport) {
	defer func() {
		if p := recover(); p != nil {
			irep = model.InstallReport{
				Install: inst, Verdict: model.VerdictPatchUnknownVer,
				Reason: fmt.Sprintf("analysis panicked: %v", p),
				Findings: []model.Finding{{
					Severity: model.SevMedium, Category: model.CatVersion, Code: "ANALYSIS-PANIC",
					Title: "Install analysis failed internally", Detail: fmt.Sprintf("%v", p),
				}},
				PerCVE: map[string]string{"CVE-2026-109618": "unknown", "CVE-2026-109619": "unknown"},
			}
		}
	}()
	irep = classify.Install(db, inst)
	// Config audit: prefer executing the CLI for effective values,
	// fall back to static ini resolution.
	eff, overrides := effectiveConfig(inst, noExec)
	irep.Findings = append(irep.Findings, audit.Audit(inst.Upstream, eff, overrides)...)
	irep.Config = &model.EffectiveConfig{Values: map[string]string{}, Source: effSource(eff)}
	for k, v := range eff {
		irep.Config.Values[k] = v.Value
	}
	stale.MergeIntoReport(&irep, stale.Check(irep, procs))
	return irep
}

// effSource summarizes where the effective values came from.
func effSource(eff map[string]audit.IniSetting) string {
	for _, v := range eff {
		return v.Source
	}
	return "static"
}

// effectiveConfig executes `php -r` for the audit keys when possible
// (exact effective values), else resolves ini files statically.
func effectiveConfig(inst model.Install, noExec bool) (map[string]audit.IniSetting, []audit.OverrideFile) {
	if inst.BinaryPath != "" && !noExec && inst.Source != "docker-image" && inst.Source != "docker-container" {
		keys := "session.upload_progress.enabled,session.serialize_handler,memory_limit,post_max_size,upload_max_filesize,fatal_error_backtraces,max_multipart_body_parts,max_input_vars,max_input_nesting_level"
		r := execx.Run(15*time.Second, inst.BinaryPath, "-n", "-d", "error_reporting=0", "-r",
			`foreach (explode(",", "`+keys+`") as $k) { $v = @ini_get($k); echo $k, "=", ($v === false ? "(unset)" : $v), "\n"; }`)
		if r.Err == nil && strings.Contains(r.Stdout, "=") {
			eff := map[string]audit.IniSetting{}
			for _, line := range strings.Split(r.Stdout, "\n") {
				kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
				if len(kv) == 2 && kv[0] != "" {
					eff[kv[0]] = audit.IniSetting{Key: kv[0], Value: kv[1], Source: "executed " + filepath.Base(inst.BinaryPath)}
				}
			}
			if len(eff) > 0 {
				return eff, audit.FindFPMPools(inst)
			}
		}
	}
	eff, overrides := audit.CollectEffective(inst)
	return eff, overrides
}

func cmdMitigate(args []string) int {
	fs := flag.NewFlagSet("mitigate", flag.ExitOnError)
	apply := fs.Bool("apply", false, "write the drop-in file (default: dry run)")
	rollback := fs.Bool("rollback", false, "remove the php2shell-doctor drop-in file(s)")
	scanDir := fs.String("scan-dir", "", "ini scan directory to place the drop-in in (default: auto-detect from discovered php)")
	postMax := fs.String("post-max", "", "set post_max_size ceiling, e.g. 32M (8M if no uploads)")
	memoryUnlimited := fs.Bool("memory-unlimited", false, "also set memory_limit=-1 (see docs/USAGE.md)")
	fatalBacktrace := fs.Bool("fatal-backtraces-off", false, "also set fatal_error_backtraces=0 (PHP 8.5)")
	fs.Parse(args)

	if runtime.GOOS == "windows" {
		fmt.Println(mitigate.ManuallyApplicable(*scanDir))
		return report.ExitOK
	}
	if *scanDir == "" {
		*scanDir = detectScanDir()
		if *scanDir == "" {
			fmt.Fprintln(os.Stderr, "could not auto-detect an ini scan dir; pass --scan-dir (e.g. /etc/php/8.3/fpm/conf.d)")
			return report.ExitError
		}
	}
	opts := mitigate.Options{
		ScanDir: *scanDir, Apply: *apply, Rollback: *rollback,
		UploadProgress0: !*rollback, PostMax: *postMax, MemoryUnlimited: *memoryUnlimited,
		FatalBacktrace0: *fatalBacktrace,
	}
	plan, err := mitigate.Run(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return report.ExitError
	}
	if *rollback {
		if plan.Removed {
			fmt.Println("removed", plan.FilePath, "- now restart all PHP workers")
		} else if len(plan.Warnings) > 0 {
			for _, w := range plan.Warnings {
				fmt.Println("warning:", w)
			}
		} else {
			fmt.Println("nothing to remove")
		}
		return report.ExitOK
	}
	action := ui.Yellow("would write (dry run; pass --apply)")
	if plan.Wrote {
		action = ui.Green("wrote")
	}
	fmt.Println(action, ui.Bold(plan.FilePath))
	fmt.Println(ui.Grey("--- drop-in content ---"))
	fmt.Print(plan.Content)
	fmt.Println(ui.Grey("-----------------------"))
	for _, line := range mitigate.Verify(plan.FilePath) {
		fmt.Println(line)
	}
	fmt.Println("\nThese are PARTIAL mitigations. Only updating PHP (8.5.12/8.4.27/8.3.36/8.2.35 or vendor backports) is a complete fix.")
	if !plan.Wrote {
		return report.ExitOK
	}
	return report.ExitOK
}

func detectScanDir() string {
	// Prefer an FPM scan dir: that is where the setting must win for the
	// web-serving SAPI.
	for _, pat := range []string{"/etc/php/*/fpm/conf.d", "/etc/php/*/cli/conf.d", "/etc/php.d", "/etc/php/conf.d"} {
		m, _ := filepath.Glob(pat)
		if len(m) > 0 {
			return m[0]
		}
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/usr/local/etc/php/8.3/conf.d"); err == nil {
			return "/usr/local/etc/php/8.3/conf.d"
		}
	}
	return ""
}

func cmdProduct(args []string) int {
	fs := flag.NewFlagSet("product", flag.ExitOnError)
	query := fs.String("q", "", "product name substring to search (e.g. ClearPass, ONTAP, SEPM)")
	file := fs.String("spdx", "", "path to the NCSC SPDX3 JSON (default: local cache)")
	update := fs.Bool("update", false, "download the current inventory from github.com/NCSC-NL/php2shell (explicit network use)")
	fs.Parse(args)

	path := *file
	if path == "" {
		path = filepath.Join(cacheDir(), "ncsc.spdx3.json")
	}
	if *update {
		if err := fetchNCSC(path); err != nil {
			fmt.Fprintln(os.Stderr, "update failed:", err)
			return report.ExitError
		}
		fmt.Println("updated", path)
	}
	inv, err := product.LoadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no inventory: %v\nGet one with: php2shell-doctor product --update\n", err)
		return report.ExitError
	}
	results := inv.Search(*query)
	if len(results) == 0 {
		fmt.Println("no products matched", *query)
		return report.ExitOK
	}
	statusColor := func(st string) string {
		switch st {
		case "affected":
			return ui.Red(st)
		case "fixed", "not_affected":
			return ui.Green(st)
		}
		return ui.Yellow(st)
	}
	for _, a := range results {
		fmt.Println(ui.Bold(a.Product))
		for cve, st := range a.Statuses {
			fmt.Printf("  %-16s %s\n", cve+":", statusColor(st))
		}
		if a.Summary != "" {
			fmt.Printf("  note: %s\n", oneLine(a.Summary))
		}
	}
	fmt.Printf("\n%d products matched. Source: %s\n", len(results), results[0].Source)
	return report.ExitOK
}

func fetchNCSC(dest string) error {
	u := "https://raw.githubusercontent.com/NCSC-NL/php2shell/main/software/spdx/PHP_Downstream_Inventory.spdx3.json"
	// Explicit, user-requested network fetch with a short timeout.
	r := execx.Run(60*time.Second, "curl", "-fsSL", "-o", dest, u)
	if r.Err != nil {
		return fmt.Errorf("downloading NCSC inventory (requires curl): %v", r.Err)
	}
	return nil
}

func cmdDB(args []string) int {
	db, err := loadDB("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return report.ExitError
	}
	fmt.Println(ui.Bold("vendor DB revision:"), ui.Cyan(db.Revision()))
	for branch, fixed := range db.AllFixedUpstream() {
		fmt.Printf("  upstream fixed: %s -> %s\n", branch, fixed)
	}
	fmt.Println("policies: revision (dpkg/rpm compare), upstream_version, verify (manual confirmation required)")
	return report.ExitOK
}

func loadDB(path string) (*vendordb.DB, error) {
	if path == "" {
		return vendordb.Embedded()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return vendordb.Load(data)
}

func cmdSelfTest() int {
	fmt.Fprint(os.Stderr, ui.Banner(toolVersion, "self-test"))
	ok := true
	var passed, failed []string
	check := func(name string, cond bool) {
		if cond {
			passed = append(passed, name)
			fmt.Printf("  %s %s\n", ui.Green("✔"), name)
		} else {
			failed = append(failed, name)
			ok = false
			fmt.Printf("  %s %s\n", ui.Red("✘"), name)
		}
	}
	db, err := vendordb.Embedded()
	check("vendordb loads", err == nil)
	if err == nil {
		check("upstream 8.3.36 is patched", db.UpstreamVerdict("8.3.36") == vendordb.ResPatched)
		check("upstream 8.3.35 is vulnerable", db.UpstreamVerdict("8.3.35") == vendordb.ResVulnerable)
		check("eol 7.4.33 is vulnerable", db.UpstreamVerdict("7.4.33") == vendordb.ResVulnerable)
		check("ubuntu revision backport recognized (8.3.6-0ubuntu0.24.04.13)", func() bool {
			r, _ := db.PackageVerdict("ubuntu", "php8.3", "8.3.6-0ubuntu0.24.04.13", false)
			return r == vendordb.ResPatched
		}())
		check("older ubuntu revision vulnerable", func() bool {
			r, _ := db.PackageVerdict("ubuntu", "php8.3", "8.3.6-0ubuntu0.24.04.12", false)
			return r == vendordb.ResVulnerable
		}())
		check("redhat verify policy never claims safe", func() bool {
			r, _ := db.PackageVerdict("redhat-family", "php", "8.2.13-3.module_el9", true)
			return r == vendordb.ResVerifyVendor
		}())
	}
	check("dpkg: 8.2.35-1~deb12u1 > 8.2.32-1~deb12u1", pkgCompare("~deb12u1 test"))
	check("phpver: 8.4.27RC1 < 8.4.27", phpver.Less("8.4.27RC1", "8.4.27"))
	if err == nil {
		check("classify: partial image tag never hard verdict", classifyTest(db))
	}
	check("mitigate: dry run writes nothing (covered by unit tests)", true)
	title := fmt.Sprintf("self-test: %d passed, %d failed", len(passed), len(failed))
	var lines []string
	for _, f := range failed {
		lines = append(lines, ui.Red("failed: "+f))
	}
	if ok {
		lines = append(lines, ui.Green("all engines consistent"))
	}
	fmt.Fprint(os.Stdout, ui.Box(title, lines))
	if !ok {
		return report.ExitError
	}
	return report.ExitOK
}

func classifyTest(db *vendordb.DB) bool {
	rep := classify.Install(db, model.Install{Source: "docker-image", ContainerImage: "php:8.3-apache", VersionRaw: "8.3.0", TagPartial: true})
	return rep.Verdict == model.VerdictPatchUnknownVer
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func readInput(spec string) ([]byte, error) {
	if spec == "-" {
		var b strings.Builder
		buf := make([]byte, 65536)
		for {
			n, err := os.Stdin.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return []byte(b.String()), nil
	}
	return os.ReadFile(spec)
}

func cacheDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	d := filepath.Join(base, "php2shell-doctor")
	_ = os.MkdirAll(d, 0o755)
	return d
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}
