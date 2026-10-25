// Package audit evaluates PHP configuration for the php2shell
// attack surface: session.upload_progress (CVE-2026-109619 and the
// unpatched CVE-2026-115560), memory_limit / post_max_size (the
// CVE-2026-109618 OOM trigger), PHP 8.5 fatal_error_backtraces, and
// per-directory overrides that silently undo global settings.
//
// Configuration resolution honours PHP's override hierarchy:
// php.ini -> ini scan-dir drop-ins (alphabetical) -> FPM pool
// php_value/php_admin_value -> per-directory .user.ini / .htaccess.
package audit

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/andreysheva/php2shell-doctor/internal/model"
)

// IniSetting is one key=value with its source.
type IniSetting struct {
	Key, Value, Source string
}

// OverrideFile is a per-directory config that can override global ini.
type OverrideFile struct {
	Path     string
	Kind     string // .user.ini | .htaccess | fpm-pool
	Settings []IniSetting
}

// CollectEffective resolves the effective ini for an install from its
// ini file + scan dir, in PHP's precedence order (last file wins).
func CollectEffective(inst model.Install) (map[string]IniSetting, []OverrideFile) {
	eff := map[string]IniSetting{}
	apply := func(path string, kind string) {
		for _, s := range parseIniFile(path, kind) {
			eff[strings.ToLower(s.Key)] = s
		}
	}
	if inst.IniFile != "" && fileExists(inst.IniFile) {
		apply(inst.IniFile, "php.ini")
	}
	if inst.ScanDir != "" && dirExists(inst.ScanDir) {
		var files []string
		m, _ := filepath.Glob(filepath.Join(inst.ScanDir, "*.ini"))
		files = append(files, m...)
		sort.Strings(files) // PHP loads scan-dir files alphabetically
		for _, f := range files {
			apply(f, "scan-dir")
		}
	}
	var overrides []OverrideFile
	// FPM pool configs (they beat php.ini for FPM workers)
	for _, pool := range FindFPMPools(inst) {
		overrides = append(overrides, pool)
		for _, s := range pool.Settings {
			eff[strings.ToLower(s.Key)] = s // php_admin_value wins for FPM
		}
	}
	// Per-directory overrides under common web roots (documented limits;
	// a full filesystem walk is opt-in via the CLI).
	for _, hit := range scanUserIniOverrides() {
		overrides = append(overrides, hit)
	}
	return eff, overrides
}

// parseIniFile reads key=value pairs, skipping comments. .htaccess
// files use php_value/php_flag/php_admin_value/php_admin_flag syntax.
func parseIniFile(path, kind string) []IniSetting {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []IniSetting
	isHT := kind == ".htaccess"
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if isHT {
			for _, directive := range []string{"php_admin_value", "php_value", "php_admin_flag", "php_flag"} {
				if strings.HasPrefix(line, directive) {
					rest := strings.TrimSpace(strings.TrimPrefix(line, directive))
					kv := strings.SplitN(rest, " ", 2)
					if len(kv) == 2 {
						out = append(out, IniSetting{Key: strings.Trim(kv[0], `"'`), Value: strings.Trim(strings.TrimSpace(kv[1]), `"'`), Source: path})
					}
					break
				}
			}
			continue
		}
		if kind == "fpm-pool" {
			// Canonical pool syntax: php_admin_value[key] = value (and
			// php_value/php_admin_flag/php_flag variants).
			if m := poolArrayRe.FindStringSubmatch(line); m != nil {
				out = append(out, IniSetting{Key: m[1], Value: strings.Trim(m[2], `"'`), Source: path})
				continue
			}
			matched := false
			for _, directive := range []string{"php_admin_value", "php_value", "php_admin_flag", "php_flag"} {
				if strings.HasPrefix(line, directive+" ") {
					rest := strings.TrimSpace(strings.TrimPrefix(line, directive))
					kv := strings.SplitN(rest, " ", 2)
					if len(kv) == 2 {
						out = append(out, IniSetting{Key: kv[0], Value: strings.Trim(strings.TrimSpace(kv[1]), `"'`), Source: path})
					}
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			// plain ini-style lines also allowed in pool files
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		// strip trailing inline comments (value may be quoted)
		if strings.HasPrefix(val, `"`) {
			if end := strings.IndexByte(val[1:], '"'); end >= 0 {
				val = val[1 : 1+end]
			}
		} else if i := strings.IndexAny(val, ";#"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		out = append(out, IniSetting{Key: key, Value: val, Source: path})
	}
	return out
}

// FindFPMPools parses FPM pool configs for php_value/php_admin_value
// overrides relevant to php2shell.
func FindFPMPools(inst model.Install) []OverrideFile {
	var patterns []string
	if inst.ScanDir != "" {
		// derive /etc/php/<ver>/fpm/pool.d from cli scan dir /etc/php/<ver>/cli/conf.d
		if i := strings.LastIndex(inst.ScanDir, "/cli/conf.d"); i > 0 {
			patterns = append(patterns, inst.ScanDir[:i]+"/fpm/pool.d/*.conf")
		}
	}
	patterns = append(patterns, "/etc/php/*/fpm/pool.d/*.conf", "/etc/php-fpm.d/*.conf", "/etc/php/*/fpm/pool.d/*.conf")
	var out []OverrideFile
	seen := map[string]bool{}
	for _, pat := range patterns {
		for _, f := range globFiles(pat) {
			if seen[f] {
				continue
			}
			seen[f] = true
			out = append(out, OverrideFile{Path: f, Kind: "fpm-pool", Settings: parseIniFile(f, "fpm-pool")})
		}
	}
	return out
}

// scanUserIniOverrides walks common web roots (bounded depth) for
// .user.ini and .htaccess files touching php2shell-relevant settings.
func scanUserIniOverrides() []OverrideFile {
	var out []OverrideFile
	roots := []string{"/var/www", "/home", "/srv", "/usr/share/nginx", "/opt/bitnami"}
	relevant := map[string]bool{
		"session.upload_progress.enabled": true, "memory_limit": true,
		"post_max_size": true, "upload_max_filesize": true,
		"session.serialize_handler": true, "fatal_error_backtraces": true,
	}
	for _, root := range roots {
		if !dirExists(root) {
			continue
		}
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return filepath.SkipDir
			}
			if d.IsDir() {
				// bound the walk: skip virtualfs, proc-like and deep trees
				switch d.Name() {
				case "virtfs", "vendor", "node_modules", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if name != ".user.ini" && name != ".htaccess" {
				return nil
			}
			kind := ".user.ini"
			if name == ".htaccess" {
				kind = ".htaccess"
			}
			settings := parseIniFile(path, kind)
			var rel []IniSetting
			for _, s := range settings {
				if relevant[strings.ToLower(s.Key)] {
					rel = append(rel, s)
				}
			}
			if len(rel) > 0 {
				out = append(out, OverrideFile{Path: path, Kind: kind, Settings: rel})
			}
			return nil
		})
	}
	return out
}

func globFiles(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// toBytes converts PHP shorthand sizes (K/M/G) to bytes; -1 means
// unlimited, 0 unparseable.
func toBytes(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "-1" {
		return -1
	}
	mult := int64(1)
	switch strings.ToUpper(v[len(v)-1:]) {
	case "K":
		mult, v = 1024, v[:len(v)-1]
	case "M":
		mult, v = 1024*1024, v[:len(v)-1]
	case "G":
		mult, v = 1024*1024*1024, v[:len(v)-1]
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

// truthy interprets PHP ini booleans.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "off", "false", "no":
		return false
	}
	return true
}

// Audit evaluates the resolved config and per-directory overrides,
// returning php2shell findings.
func Audit(upstream string, eff map[string]IniSetting, overrides []OverrideFile) []model.Finding {
	var out []model.Finding
	get := func(key string) (IniSetting, bool) {
		s, ok := eff[strings.ToLower(key)]
		return s, ok
	}
	add := func(sev model.Severity, code, title, detail, ref string) {
		out = append(out, model.Finding{Severity: sev, Category: model.CatConfig, Code: code, Title: title, Detail: detail, Reference: ref})
	}
	const upRef = "https://www.php.net/archive/2026.php#2026-10-21-5"

	// 1. session.upload_progress.enabled — CVE-2026-109619 primary vector
	//    and CVE-2026-115560 mitigation.
	if s, ok := get("session.upload_progress.enabled"); ok && !truthy(s.Value) {
		add(model.SevInfo, "CFG-UPLOADPROGRESS-OFF",
			"session.upload_progress is disabled (php2shell 109619 vector removed)",
			"Set in "+s.Source+". This removes the demonstrated CVE-2026-109619 vector and the CVE-2026-115560 surface, but is not a substitute for patching.",
			upRef)
	} else {
		add(model.SevHigh, "CFG-UPLOADPROGRESS-ON",
			"session.upload_progress is enabled",
			"This is the confirmed attack vector for CVE-2026-109619 (stale global state) and the mitigation surface for CVE-2026-115560. Set session.upload_progress.enabled=0 in php.ini or the FPM pool (php_admin_value) and restart all workers. ini_set() and .user.ini do NOT suffice.",
			upRef)
	}

	// 2. serialize_handler switching pattern — CVE-2026-115560.
	if s, ok := get("session.serialize_handler"); ok {
		v := strings.ToLower(s.Value)
		if v == "php_binary" || v == "php_serialize" {
			add(model.SevMedium, "CFG-115560-HANDLER",
				"session.serialize_handler="+v+" is exposed to CVE-2026-115560 when switched at runtime",
				"The vulnerable pattern is INI "+v+" plus a runtime ini_set('session.serialize_handler','php') before session_start(). Keep session.upload_progress.enabled=0 until the fix ships. Source: "+s.Source,
				"https://www.php.net/archive/2026.php#2026-10-23-1")
		}
	}

	// 3. memory_limit — the CVE-2026-109618 soft-limit OOM trigger.
	if s, ok := get("memory_limit"); ok {
		b := toBytes(s.Value)
		switch {
		case b == -1:
			add(model.SevInfo, "CFG-MEMORY-UNLIMITED",
				"memory_limit=-1 (PHP's temporary CVE-2026-109618 mitigation is present)",
				"The PHP-level soft-limit OOM path is removed, trading DoS exposure for it. Bound memory with cgroup/container limits instead. Never use RLIMIT_AS/RLIMIT_DATA/RLimitMEM. Only patching is a complete fix. Source: "+s.Source,
				upRef)
		case b > 0:
			add(model.SevMedium, "CFG-MEMORY-FINITE",
				fmt.Sprintf("memory_limit=%s is the CVE-2026-109618 OOM trigger surface", s.Value),
				"Any request that pushes allocations past this limit hits the vulnerable bailout path on unpatched PHP. Temporary mitigation: memory_limit=-1 (non-overridable via php_admin_value) plus cgroup/container limits. Source: "+s.Source,
				upRef)
		}
	}

	// 4. post_max_size / upload_max_filesize.
	if s, ok := get("post_max_size"); ok {
		if b := toBytes(s.Value); b > 64*1024*1024 {
			add(model.SevMedium, "CFG-POSTMAX-LARGE",
				fmt.Sprintf("post_max_size=%s is large", s.Value),
				"PHP checks post_max_size against the declared Content-Length only; chunked/HTTP2 lengthless bodies and decompressing proxies bypass it. A small ceiling (8M without uploads, ~32M with) reduces the attacker's allocation control on unpatched PHP. Source: "+s.Source,
				upRef)
		}
	}
	if s, ok := get("upload_max_filesize"); ok {
		if pm, ok2 := get("post_max_size"); ok2 {
			bu, bp := toBytes(s.Value), toBytes(pm.Value)
			if bu > 0 && bp > 0 && bu > bp {
				add(model.SevLow, "CFG-UPLOAD-GT-POST",
					"upload_max_filesize exceeds post_max_size",
					"upload_max_filesize can never be reached while post_max_size is smaller; the effective upload cap is post_max_size.",
					"https://www.php.net/manual/en/ini.core.php")
			}
		}
	}

	// 5. PHP 8.5 fatal_error_backtraces.
	if s, ok := get("fatal_error_backtraces"); ok && truthy(s.Value) {
		if strings.HasPrefix(upstream, "8.5") {
			add(model.SevMedium, "CFG-FATAL-BACKTRACE",
				"fatal_error_backtraces is enabled on PHP 8.5",
				"PHP advises setting fatal_error_backtraces=0 and restarting workers until fixed. Source: "+s.Source,
				upRef)
		}
	}

	// 6. Per-directory overrides that undo the global posture.
	for _, ov := range overrides {
		for _, s := range ov.Settings {
			k := strings.ToLower(s.Key)
			if k == "session.upload_progress.enabled" && truthy(s.Value) {
				add(model.SevHigh, "CFG-OVERRIDE-UPLOADPROGRESS",
					fmt.Sprintf("%s re-enables session.upload_progress", ov.Kind),
					s.Source+" sets session.upload_progress.enabled=On, undoing any global mitigation for this directory tree. Remove or correct the override.",
					upRef)
			}
			if k == "memory_limit" {
				if b := toBytes(s.Value); b > 0 {
					add(model.SevMedium, "CFG-OVERRIDE-MEMORY",
						fmt.Sprintf("%s sets a finite memory_limit", ov.Kind),
						s.Source+" re-introduces the CVE-2026-109618 OOM trigger surface for this directory tree.",
						upRef)
				}
			}
		}
	}
	return out
}

// poolArrayRe matches the canonical FPM pool directive syntax:
// php_admin_value[session.upload_progress.enabled] = 0
var poolArrayRe = regexp.MustCompile(`^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=\s*(.*)$`)
