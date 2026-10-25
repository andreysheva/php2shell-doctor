package discover

import (
	"bufio"
	"os"
	"regexp"
	"path/filepath"
	"strings"

	"github.com/andreysheva/php2shell-doctor/internal/execx"
	"github.com/andreysheva/php2shell-doctor/internal/model"
)

type pkgInstall struct {
	name    string
	version string
}

// scanPackages reads the distro package databases and turns PHP-related
// packages into installs. Vendor ID is inferred from the version string
// markers first (sury/remi/cloudlinux), then from /etc/os-release.
func scanPackages() []model.Install {
	var pkgs []pkgInstall
	var kind string // dpkg | rpm | apk
	switch {
	case fileExists("/var/lib/dpkg/status"):
		kind = "dpkg"
		pkgs = parseDpkgStatus("/var/lib/dpkg/status")
	case fileExists("/lib/apk/db/installed"):
		kind = "apk"
		pkgs = parseApkInstalled("/lib/apk/db/installed")
	case func() bool { _, ok := execx.LookPath("rpm"); return ok }():
		kind = "rpm"
		r := execx.Run(60e9, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		for _, line := range strings.Split(r.Stdout, "\n") {
			f := strings.Split(strings.TrimSpace(line), "\t")
			if len(f) == 2 {
				pkgs = append(pkgs, pkgInstall{f[0], f[1]})
			}
		}
	default:
		return nil
	}
	osID := osReleaseID()
	var out []model.Install
	for _, p := range pkgs {
		if !isRuntimePackage(p.name) {
			continue
		}
		prov := model.ProvStandalone
		switch kind {
		case "dpkg":
			prov = model.ProvDpkg
		case "rpm":
			prov = model.ProvRpm
		case "apk":
			prov = model.ProvApk
		}
		inst := model.Install{
			Source:         "distro-packages",
			Provenance:     prov,
			PackageName:    p.name,
			PackageVersion: p.version,
			Root:           "/usr",
		}
		inst.VendorID = mapVendorID(p.name, p.version, osID)
		inst.SAPIs = sapisForPackage(p.name)
		// CLI binary for the main package, if present.
		if bin := phpBinaryForPackage(p.name); bin != "" {
			inst.BinaryPath = bin
			if fi, err := os.Stat(bin); err != nil || fi.IsDir() {
				inst.BinaryPath = ""
			}
		}
		out = append(out, inst)
	}
	return out
}

// isRuntimePackage allowlists packages that provide a PHP runtime
// binary. Support packages (php-common) and extensions (php8.3-mbstring)
// are excluded: they are not runtimes and would only duplicate or
// dilute verdicts. Their patch state rides on the runtime package.
func isRuntimePackage(name string) bool {
	n := strings.ToLower(name)
	if n == "php" || n == "php-cli" || n == "php-fpm" || n == "php-cgi" {
		return true
	}
	// versioned debian/ubuntu/sury styles: php8.3, php8.3-cli/fpm/cgi/phpdbg/apache2
	if v := phpVersionInName(n); v != "" {
		suffix := strings.TrimPrefix(n, v)
		switch suffix {
		case "", "-cli", "-fpm", "-cgi", "-phpdbg", "-apache2":
			return true
		}
	}
	// concatenated styles (alpine/freebsd): php83, php74, ... optionally -cli/-fpm
	if m := concatRe.FindStringSubmatch(n); m != nil {
		suffix := strings.TrimPrefix(n, m[0])
		switch suffix {
		case "", "-cli", "-fpm", "-cgi", "-phpdbg":
			return true
		}
	}
	if strings.HasPrefix(n, "libapache2-mod-php") {
		return true
	}
	// panel/ecosystem families: alt-phpNN*, ea-phpNN*, lsphpNN*, remi phpNN-php*
	for _, prefix := range []string{"alt-php", "ea-php", "lsphp"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	if strings.HasPrefix(n, "php") && strings.Contains(n, "-php") {
		// remi collections: php83-php, php83-php-cli/fpm
		base := strings.SplitN(n, "-php", 2)[0]
		if strings.TrimPrefix(base, "php") != base && isDigits(strings.TrimPrefix(base, "php")) {
			suffix := strings.TrimPrefix(n, base+"-php")
			switch suffix {
			case "", "-cli", "-fpm", "-cgi", "-phpdbg":
				return true
			}
		}
	}
	return false
}

// concatRe matches concatenated branch names: php83 (8.3), php74 (7.4).
var concatRe = regexp.MustCompile(`^php(\d)(\d)`)

// phpVersionInName extracts "php8.3" from "php8.3-cli" ("" if absent).
func phpVersionInName(n string) string {
	if !strings.HasPrefix(n, "php") {
		return ""
	}
	rest := strings.TrimPrefix(n, "php")
	i := 0
	for i < len(rest) && (rest[i] >= '0' && rest[i] <= '9' || rest[i] == '.') {
		i++
	}
	ver := rest[:i]
	// require major.minor digits
	parts := strings.Split(ver, ".")
	if len(parts) != 2 || !isDigits(parts[0]) || !isDigits(parts[1]) || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "php" + ver
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mapVendorID decides which vendordb vendor a package belongs to.
func mapVendorID(pkgName, pkgVersion, osID string) string {
	lv := strings.ToLower(pkgVersion)
	switch {
	case strings.Contains(lv, "deb.sury.org"):
		return "sury"
	case strings.Contains(lv, "remi"):
		return "remi"
	case strings.HasPrefix(strings.ToLower(pkgName), "alt-php"):
		return "cloudlinux"
	case strings.HasPrefix(strings.ToLower(pkgName), "ea-php"):
		return "cpanel"
	}
	switch osID {
	case "ubuntu":
		return "ubuntu"
	case "debian":
		return "debian"
	case "alpine":
		return "alpine"
	case "rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora", "centos-stream":
		return "redhat-family"
	}
	return ""
}

func sapisForPackage(name string) []model.SAPI {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "fpm"):
		return []model.SAPI{model.SAPIFPM}
	case strings.Contains(n, "cgi"):
		return []model.SAPI{model.SAPICGI}
	case strings.Contains(n, "libapache2-mod-php"), strings.Contains(n, "mod_php"):
		return []model.SAPI{model.SAPIApacheMod}
	}
	return nil
}

func phpBinaryForPackage(pkgName string) string {
	n := strings.ToLower(pkgName)
	// Debian/Ubuntu versioned names: php8.3, php8.3-fpm, ...
	for _, v := range []string{"8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"} {
		if strings.Contains(n, "php"+v) {
			if strings.Contains(n, "fpm") {
				return "/usr/sbin/php-fpm" + v
			}
			return "/usr/bin/php" + v
		}
	}
	if m := concatRe.FindStringSubmatch(n); m != nil {
		digits := m[1] + m[2]
		if strings.Contains(n, "fpm") {
			return "/usr/sbin/php-fpm" + digits
		}
		return "/usr/bin/php" + digits
	}
	if n == "php" {
		return "/usr/bin/php"
	}
	return ""
}

// parseDpkgStatus reads installed packages from the dpkg database.
func parseDpkgStatus(path string) []pkgInstall {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pkgInstall
	var name, version, status string
	flush := func() {
		if name != "" && status == "install ok installed" {
			out = append(out, pkgInstall{name, version})
		}
		name, version, status = "", "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimPrefix(line, "Package: ")
		case strings.HasPrefix(line, "Version: "):
			version = strings.TrimPrefix(line, "Version: ")
		case strings.HasPrefix(line, "Status: "):
			status = strings.TrimPrefix(line, "Status: ")
		}
	}
	flush()
	return out
}

// parseApkInstalled reads installed packages from Alpine's apk DB.
func parseApkInstalled(path string) []pkgInstall {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []pkgInstall
	var name, version string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if name != "" {
				out = append(out, pkgInstall{name, version})
			}
			name, version = "", ""
			continue
		}
		switch {
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "V:"):
			version = strings.TrimPrefix(line, "V:")
		}
	}
	if name != "" {
		out = append(out, pkgInstall{name, version})
	}
	return out
}

// osReleaseID reads ID= from /etc/os-release.
func osReleaseID() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
	}
	return ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// globDirs returns directory paths matching pattern.
func globDirs(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}
