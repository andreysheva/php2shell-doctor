package discover

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/php2shell-doctor/php2shell-doctor/internal/model"
)

// scanPanels finds hosting-panel and platform PHP installations:
// cPanel EA4, Plesk, LiteSpeed, Homebrew, scoop, chocolatey, asdf and
// common Windows locations.
func scanPanels(opts Options) []model.Install {
	var out []model.Install
	// cPanel EasyApache 4
	for _, root := range globDirs("/opt/cpanel/ea-php*/root/usr/bin/php") {
		out = append(out, model.Install{
			BinaryPath: root, Root: filepath.Dir(filepath.Dir(root)),
			Source: "cpanel-ea4", Provenance: model.ProvCpanel,
			SAPIs: []model.SAPI{model.SAPICLI, model.SAPIFPM},
			Note:  "cPanel EA4 ships per-version CLI and FPM binaries; the active handler is configuration-specific",
		})
	}
	// Plesk
	for _, root := range globDirs("/opt/plesk/php/*/bin/php") {
		out = append(out, model.Install{
			BinaryPath: root, Root: filepath.Dir(filepath.Dir(root)),
			Source: "plesk", Provenance: model.ProvPlesk,
			SAPIs: []model.SAPI{model.SAPICLI, model.SAPIFPM},
		})
	}
	// LiteSpeed lsphp
	for _, root := range globDirs("/usr/local/lsws/lsphp*/bin/php") {
		i := installFromBinary(root, model.ProvStandalone, "litespeed-lsphp")
		i.SAPIs = []model.SAPI{model.SAPILiteSpeed}
		out = append(out, i)
	}
	// Homebrew
	for _, prefix := range []string{"/opt/homebrew", "/usr/local"} {
		for _, root := range globDirs(prefix + "/opt/php*/bin/php") {
			out = append(out, installFromBinary(root, model.ProvHomebrew, "homebrew"))
		}
	}
	// asdf
	for _, root := range globDirs(homeDir()+"/.asdf/installs/php/*/bin/php") {
		out = append(out, installFromBinary(root, model.ProvAsdf, "asdf"))
	}
	// Scoop & Chocolatey & plain Windows dirs
	if runtime.GOOS == "windows" {
		for _, pat := range []string{
			homeDir() + "/scoop/apps/php*/current/php.exe",
			"C:/tools/php*/php.exe",
			"C:/PHP*/php.exe",
			"C:/Program Files/PHP/*/php.exe",
			"C:/xampp/php/php.exe",
			"C:/wamp64/bin/php/php*/php.exe",
			"C:/laragon/bin/php/php*/php.exe",
		} {
			for _, root := range globDirs(pat) {
				out = append(out, installFromBinary(root, model.ProvStandalone, "windows-known-path"))
			}
		}
		out = append(out, scanWindowsRegistry()...)
	}
	return out
}

// scanWindowsRegistry uses reg.exe (no third-party deps) to find PHP
// installs registered in the uninstall keys.
func scanWindowsRegistry() []model.Install {
	var out []model.Install
	for _, hive := range []string{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"} {
		r := execReg(hive)
		for _, line := range strings.Split(r, "\n") {
			if !strings.Contains(line, "PHP") && !strings.Contains(line, "php") {
				continue
			}
			key := strings.TrimSpace(strings.TrimPrefix(line, "HKEY_LOCAL_MACHINE\\"))
			if key == "" {
				continue
			}
			// Only the install-location subkeys matter; the version string
			// alone is not enough to classify, so record the key as a hint.
			out = append(out, model.Install{
				Source: "windows-registry",
				Root:   key,
				Note:   "registry PHP entry; run with --extra-path <dir> if its php.exe is not found automatically",
			})
			break // one hint per hive is enough; reg output is noisy
		}
	}
	return out
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.ToSlash(h)
}
