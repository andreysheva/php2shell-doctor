package discover

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/andreysheva/php2shell-doctor/internal/model"
)

// modPHPMarkers collects unversioned mod_php config markers found
// during layout scanning; they become host notes unless they are the
// only evidence of PHP on the host.
var modPHPMarkers []string

// scanSAPILayout detects FPM pools, Apache mod_php modules and
// php-cgi layouts from filesystem markers. Versioned markers enrich
// matching installs; unversioned ones are pseudo-installs only when no
// other engine found a versioned runtime (filtered in Run).
func scanSAPILayout() []model.Install {
	var out []model.Install
	for _, pat := range []string{
		"/etc/httpd/conf.d/php.conf", "/etc/httpd/conf.modules.d/*php*.conf",
	} {
		for _, f := range globDirs(pat) {
			if fileExists(f) {
				modPHPMarkers = append(modPHPMarkers, f)
				out = append(out, model.Install{
					Root: f, Source: "apache-mod-php", Provenance: model.ProvStandalone,
					SAPIs: []model.SAPI{model.SAPIApacheMod},
					Note:  "mod_php is loaded (version not determinable from this marker)",
				})
			}
		}
	}
	// FrankenPHP static binaries
	for _, p := range []string{"/usr/local/bin/frankenphp", "/usr/bin/frankenphp"} {
		if fileExists(p) {
			out = append(out, model.Install{
				BinaryPath: p, Root: "/usr/local/bin", Source: "frankenphp",
				Provenance: model.ProvStandalone, SAPIs: []model.SAPI{model.SAPIFranken},
			})
		}
	}
	// php-cgi binaries (classic cgi/fcgi setups)
	for _, p := range []string{"/usr/bin/php-cgi", "/usr/local/bin/php-cgi"} {
		if fileExists(p) {
			out = append(out, model.Install{
				BinaryPath: p, Root: "/usr/bin", Source: "php-cgi",
				Provenance: model.ProvStandalone, SAPIs: []model.SAPI{model.SAPICGI},
			})
		}
	}
	return out
}

// extractBranch pulls a PHP branch ("8.3") from a filename like
// php8.3.load or a path segment.
func extractBranch(name string) string {
	m := branchRe.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return m[1]
}

var branchRe = regexp.MustCompile(`php(\d+\.\d+)`)

// EnrichSAPIMarkers attaches SAPI evidence to installs after dedupe:
// FPM pool directories (/etc/php/<ver>/fpm) mark the matching branch's
// installs as FPM; mod_php markers mark apache-mod_php. Called from
// discover.Run so classification sees the real web-serving SAPIs.
func EnrichSAPIMarkers(res *Result) {
	for i := range res.Installs {
		inst := &res.Installs[i]
		// Distro packages already carry accurate per-binary SAPI info;
		// marker enrichment is for standalone/source-build installs.
		if inst.Provenance == model.ProvDpkg || inst.Provenance == model.ProvRpm || inst.Provenance == model.ProvApk {
			continue
		}
		branch := branchFromInstall(*inst)
		if branch == "" {
			continue
		}
		if dirExists("/etc/php/"+branch+"/fpm/pool.d") || fileExists("/etc/php-fpm.d") {
			if !hasSAPI(*inst, model.SAPIFPM) && branchServes(branch, "/etc/php/*/fpm/pool.d") {
				inst.SAPIs = append(inst.SAPIs, model.SAPIFPM)
			}
		}
		for _, f := range globDirs("/etc/apache2/mods-enabled/php*.load") {
			if fileExists(f) && extractBranch(filepath.Base(f)) == branch && !hasSAPI(*inst, model.SAPIApacheMod) {
				inst.SAPIs = append(inst.SAPIs, model.SAPIApacheMod)
				inst.Note = appendNote(inst.Note, "mod_php marker: "+f)
			}
		}
	}
}

// branchFromInstall finds the PHP branch ("8.3") for an install from
// its package name or ini scan dir.
func branchFromInstall(inst model.Install) string {
	for _, s := range []string{inst.PackageName, inst.IniFile, inst.ScanDir, inst.Root} {
		if b := extractBranch(s); b != "" {
			return b
		}
	}
	return ""
}

func branchServes(branch, pattern string) bool {
	for _, dir := range globDirs(pattern) {
		if strings.Contains(dir, "/"+branch+"/") {
			return true
		}
	}
	return false
}

func hasSAPI(inst model.Install, want model.SAPI) bool {
	for _, s := range inst.SAPIs {
		if s == want {
			return true
		}
	}
	return false
}
