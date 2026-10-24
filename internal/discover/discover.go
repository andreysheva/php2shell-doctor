// Package discover finds every PHP runtime on a host: PATH binaries,
// distro packages, hosting panels, FPM pools, Apache mod_php, LiteSpeed,
// FrankenPHP, running processes and Docker containers/images.
//
// Every sub-engine is independent and failure-isolated: one broken engine
// never aborts the scan; errors surface as engine errors and the report
// is marked partial.
package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/php2shell-doctor/php2shell-doctor/internal/execx"
	"github.com/php2shell-doctor/php2shell-doctor/internal/model"
	"github.com/php2shell-doctor/php2shell-doctor/internal/phpver"
)

// Options tunes discovery.
type Options struct {
	Docker       bool   // inspect docker CLI (containers + images)
	DockerExec   bool   // execute php -v inside running containers (read-only)
	ScanProcesses bool  // enumerate running PHP processes
	NoExec       bool   // never execute discovered binaries (banner-only environments)
	ExtraPaths   []string
	Timeout      time.Duration
}

// Result collects everything discovery found.
type Result struct {
	Installs    []model.Install
	Processes   []model.ProcessInfo
	EngineNotes []string
	Partial     bool
}

type engine struct {
	name string
	run  func(*Result) error
}

// Run executes all discovery engines.
func Run(opts Options) *Result {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	res := &Result{}
	engines := []engine{
		{"path-scan", func(r *Result) error { r.Installs = append(r.Installs, scanPath(opts)...); return nil }},
		{"distro-packages", func(r *Result) error { r.Installs = append(r.Installs, scanPackages()...); return nil }},
		{"panels", func(r *Result) error { r.Installs = append(r.Installs, scanPanels(opts)...); return nil }},
		{"sapi-layout", func(r *Result) error { r.Installs = append(r.Installs, scanSAPILayout()...); return nil }},
		{"processes", func(r *Result) error {
			if !opts.ScanProcesses {
				return nil
			}
			procs, err := scanProcesses()
			r.Processes = append(r.Processes, procs...)
			return err
		}},
		{"docker", func(r *Result) error {
			if !opts.Docker {
				return nil
			}
			inst, err := scanDocker(opts)
			r.Installs = append(r.Installs, inst...)
			return err
		}},
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func(e engine) {
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					mu.Lock()
					res.EngineNotes = append(res.EngineNotes, fmt.Sprintf("%s engine panicked: %v", e.name, p))
					res.Partial = true
					mu.Unlock()
				}
			}()
			if err := e.run(res); err != nil {
				mu.Lock()
				res.EngineNotes = append(res.EngineNotes, fmt.Sprintf("%s engine: %v", e.name, err))
				res.Partial = true
				mu.Unlock()
			}
		}(e)
	}
	wg.Wait()
	res.Installs = dedupe(res.Installs)
	EnrichSAPIMarkers(res)
	// Query versions (php -v) for installs that lack them, then fill the
	// upstream/branch fields for every install.
	for i := range res.Installs {
		if res.Installs[i].VersionRaw == "" && res.Installs[i].BinaryPath != "" && !opts.NoExec {
			queryVersion(&res.Installs[i], opts.Timeout)
		}
	}
	for i := range res.Installs {
		ver := res.Installs[i].VersionRaw
		if ver == "" {
			// distro installs never executed a binary: derive the upstream
			// version from the package version instead.
			ver = res.Installs[i].PackageVersion
		}
		if u, ok := phpver.Upstream(ver); ok {
			res.Installs[i].Upstream = u
			res.Installs[i].Branch = phpver.Branch(u)
		}
	}
	res.Installs = mergeVersionTwins(res.Installs)
	// Unversioned mod_php markers are noise when a versioned runtime was
	// found: drop the pseudo-install and surface the marker as a note.
	versioned := false
	for _, i := range res.Installs {
		if i.VersionRaw != "" || i.PackageVersion != "" {
			versioned = true
			break
		}
	}
	if versioned && len(modPHPMarkers) > 0 {
		kept := res.Installs[:0]
		for _, i := range res.Installs {
			if i.Source == "apache-mod-php" && i.VersionRaw == "" && i.PackageVersion == "" {
				res.EngineNotes = append(res.EngineNotes,
					"mod_php loaded ("+strings.Join(modPHPMarkers, ", ")+"); its SAPI risk applies to the matching runtime above")
				continue
			}
			kept = append(kept, i)
		}
		res.Installs = kept
	}
	return res
}

// mergeVersionTwins merges standalone installs (PATH hits, php-cgi
// markers, ...) into distro/panel installs describing the same runtime:
// same branch and upstream version. Amazon Linux, for example, ships
// /usr/bin/php while the owning package is php8.2-cli — without this
// pass the host reports one runtime twice.
func mergeVersionTwins(in []model.Install) []model.Install {
	merged := map[int]bool{}
	for i := range in {
		if in[i].Provenance != model.ProvStandalone || in[i].Upstream == "" {
			continue
		}
		for j := range in {
			if i == j || merged[j] || in[j].Provenance == model.ProvStandalone || in[j].Upstream == "" {
				continue
			}
			// Merge only when the package install has NO verified binary
			// of its own: the standalone hit then attaches a binary to it
			// (Amazon Linux /usr/bin/php -> php8.2-cli). When the package
			// install has its own binary, a same-version standalone is a
			// genuinely separate runtime with its own config — merging
			// would destroy its audit surface.
			if in[j].BinaryPath != "" {
				continue
			}
			if in[j].Upstream == in[i].Upstream && in[j].Branch == in[i].Branch {
				in[j] = mergeInstall(in[j], in[i])
				merged[i] = true
				break
			}
		}
	}
	out := make([]model.Install, 0, len(in))
	for i := range in {
		if !merged[i] {
			out = append(out, in[i])
		}
	}
	return out
}

// scanPath looks for php binaries on PATH and well-known locations.
func scanPath(opts Options) []model.Install {
	var out []model.Install
	seen := map[string]bool{}
	names := []string{"php", "php8", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0", "php7.4",
		"php85", "php84", "php83", "php82", "php81", "php80", "php74",
		"php-fpm", "php8.3-fpm", "php8.2-fpm", "php8.4-fpm", "php-cgi", "php8.3-cgi",
		"frankenphp", "lsphp"}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		for _, n := range names {
			p := filepath.Join(dir, n)
			if runtime.GOOS == "windows" {
				p += ".exe"
			}
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() && !seen[p] {
				seen[p] = true
				out = append(out, installFromBinary(p, model.ProvStandalone, "PATH"))
			}
		}
	}
	for _, p := range opts.ExtraPaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && !seen[p] {
			seen[p] = true
			out = append(out, installFromBinary(p, model.ProvStandalone, "--extra-path"))
		}
	}
	return out
}

// installFromBinary builds an Install from a binary path.
func installFromBinary(path string, prov model.ProvenanceKind, source string) model.Install {
	name := filepath.Base(path)
	sapi := model.SAPICLI
	ln := strings.ToLower(name)
	switch {
	case strings.Contains(ln, "fpm"):
		sapi = model.SAPIFPM
	case strings.Contains(ln, "cgi"):
		sapi = model.SAPICGI
	case strings.Contains(ln, "frankenphp"):
		sapi = model.SAPIFranken
	case strings.Contains(ln, "lsphp"):
		sapi = model.SAPILiteSpeed
	}
	return model.Install{
		BinaryPath: path,
		Root:       filepath.Dir(path),
		Source:     source,
		Provenance: prov,
		SAPIs:      []model.SAPI{sapi},
	}
}

// queryVersion executes php -v on the binary and fills version fields.
func queryVersion(inst *model.Install, timeout time.Duration) {
	r := execx.Run(timeout, inst.BinaryPath, "-v")
	if r.Err != nil && r.Stdout == "" {
		inst.Note = appendNote(inst.Note, fmt.Sprintf("php -v failed: %v", r.Err))
		return
	}
	parsePHPVersionBanner(inst, r.Stdout)
	// Ask for the loaded ini when the CLI is cooperative.
	ri := execx.Run(timeout, inst.BinaryPath, "--ini")
	for _, line := range strings.Split(ri.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Loaded Configuration File:") {
			inst.IniFile = strings.TrimSpace(strings.TrimPrefix(line, "Loaded Configuration File:"))
		} else if strings.HasPrefix(line, "Scan for additional .ini files in:") {
			inst.ScanDir = strings.TrimSpace(strings.TrimPrefix(line, "Scan for additional .ini files in:"))
		}
	}
}

func parsePHPVersionBanner(inst *model.Install, banner string) {
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PHP ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			inst.VersionRaw = fields[1]
			inst.Note = appendNote(inst.Note, "version from `php -v`")
		}
		break
	}
}

func appendNote(note, add string) string {
	if note == "" {
		return add
	}
	return note + "; " + add
}

// dedupe collapses installs pointing at the same runtime. Keys are
// symlink-resolved binary paths so /usr/bin/php, /bin/php and
// /usr/bin/php8.3 collapse into one install. When duplicates come from
// different engines, the richest provenance wins (distro package data
// beats a bare PATH hit) and missing fields are merged in.
func dedupe(in []model.Install) []model.Install {
	type group struct {
		best  model.Install
		rank  int
		extra []model.Install
	}
	rank := func(p model.ProvenanceKind) int {
		switch p {
		case model.ProvDpkg, model.ProvRpm, model.ProvApk, model.ProvCpanel, model.ProvPlesk:
			return 3
		case model.ProvHomebrew, model.ProvScoop, model.ProvChoco, model.ProvAsdf:
			return 2
		}
		return 1
	}
	groups := map[string]*group{}
	var order []string
	for _, i := range in {
		// A package install whose guessed binary path does not exist
		// must not be keyed by that path: it would never merge with the
		// real binary found via PATH.
		if i.BinaryPath != "" && (i.Provenance == model.ProvDpkg || i.Provenance == model.ProvRpm || i.Provenance == model.ProvApk) {
			if _, err := os.Stat(i.BinaryPath); err != nil {
				i.BinaryPath = ""
			}
		}
		key := resolveKey(i)
		g, ok := groups[key]
		if !ok {
			groups[key] = &group{best: i, rank: rank(i.Provenance)}
			order = append(order, key)
			continue
		}
		if r := rank(i.Provenance); r > g.rank {
			g.extra = append(g.extra, g.best)
			g.best, g.rank = i, r
		} else {
			g.extra = append(g.extra, i)
		}
	}
	out := make([]model.Install, 0, len(order))
	for _, key := range order {
		g := groups[key]
		best := g.best
		for _, e := range g.extra {
			best = mergeInstall(best, e)
		}
		out = append(out, best)
	}
	return out
}

// resolveKey is the identity of an install: its real (symlink-resolved)
// binary path, or a synthetic key for package/panel/container installs
// without a found binary.
func resolveKey(i model.Install) string {
	if i.BinaryPath != "" {
		if real, err := filepath.EvalSymlinks(i.BinaryPath); err == nil {
			return real
		}
		return i.BinaryPath
	}
	if i.ContainerID != "" {
		return "container:" + i.ContainerID
	}
	if i.ContainerImage != "" {
		return "image:" + i.ContainerImage
	}
	if i.PackageName != "" && i.PackageVersion != "" {
		return "pkg:" + i.PackageName + "@" + i.PackageVersion
	}
	return i.Root + "|" + i.Source
}

// mergeInstall fills fields of best that other knows about.
func mergeInstall(best, other model.Install) model.Install {
	if best.VersionRaw == "" {
		best.VersionRaw = other.VersionRaw
	}
	if best.PackageName == "" {
		best.PackageName = other.PackageName
		best.PackageVersion = other.PackageVersion
	}
	if best.VendorID == "" {
		best.VendorID = other.VendorID
	}
	if best.IniFile == "" {
		best.IniFile = other.IniFile
	}
	if best.ScanDir == "" {
		best.ScanDir = other.ScanDir
	}
	if !best.TagPartial {
		best.TagPartial = other.TagPartial
	}
	sapiSeen := map[model.SAPI]bool{}
	for _, s := range best.SAPIs {
		sapiSeen[s] = true
	}
	for _, s := range other.SAPIs {
		if !sapiSeen[s] {
			best.SAPIs = append(best.SAPIs, s)
		}
	}
	if other.Note != "" {
		best.Note = appendNote(best.Note, other.Note)
	}
	return best
}
