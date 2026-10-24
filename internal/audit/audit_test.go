package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIniFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "php.ini")
	os.WriteFile(p, []byte(`
memory_limit = 128M  ; inline comment
session.upload_progress.enabled = 1
post_max_size = "8M"
; commented = out
upload_max_filesize = 16M
`), 0644)
	s := parseIniFile(p, "php.ini")
	got := map[string]string{}
	for _, kv := range s {
		got[strings.ToLower(kv.Key)] = kv.Value
	}
	if got["memory_limit"] != "128M" || got["session.upload_progress.enabled"] != "1" ||
		got["post_max_size"] != "8M" || got["upload_max_filesize"] != "16M" {
		t.Fatalf("ini parse wrong: %#v", got)
	}
	if _, ok := got["commented"]; ok {
		t.Fatal("comment parsed as setting")
	}
}

func TestParseHtaccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".htaccess")
	os.WriteFile(p, []byte(`
php_value session.upload_progress.enabled 1
php_admin_value memory_limit 256M
# php_flag ignore_repeated_errors 1
`), 0644)
	s := parseIniFile(p, ".htaccess")
	if len(s) != 2 ||
		s[0].Key != "session.upload_progress.enabled" || s[0].Value != "1" ||
		s[1].Key != "memory_limit" || s[1].Value != "256M" {
		t.Fatalf("htaccess parse wrong: %#v", s)
	}
}

func TestToBytes(t *testing.T) {
	cases := map[string]int64{"128M": 128 * 1024 * 1024, "8M": 8 * 1024 * 1024, "-1": -1, "1024K": 1024 * 1024, "2G": 2 * 1024 * 1024 * 1024, "bogus": 0}
	for in, want := range cases {
		if got := toBytes(in); got != want {
			t.Errorf("toBytes(%q) = %d want %d", in, got, want)
		}
	}
}

func TestAuditFindings(t *testing.T) {
	eff := map[string]IniSetting{
		"session.upload_progress.enabled": {"session.upload_progress.enabled", "1", "/etc/php/8.3/fpm/php.ini"},
		"memory_limit":                    {"memory_limit", "128M", "/etc/php/8.3/fpm/php.ini"},
		"post_max_size":                   {"post_max_size", "512M", "/etc/php/8.3/fpm/php.ini"},
	}
	f := Audit("8.3.6", eff, nil)
	codes := map[string]bool{}
	for _, x := range f {
		codes[x.Code] = true
	}
	for _, want := range []string{"CFG-UPLOADPROGRESS-ON", "CFG-MEMORY-FINITE", "CFG-POSTMAX-LARGE"} {
		if !codes[want] {
			t.Errorf("missing finding %s (got %v)", want, codes)
		}
	}
}

func TestAuditMitigated(t *testing.T) {
	eff := map[string]IniSetting{
		"session.upload_progress.enabled": {"session.upload_progress.enabled", "0", "/etc/php/8.3/fpm/php.ini"},
		"memory_limit":                    {"memory_limit", "-1", "/etc/php/8.3/fpm/php.ini"},
	}
	f := Audit("8.3.6", eff, nil)
	codes := map[string]bool{}
	for _, x := range f {
		codes[x.Code] = true
	}
	if codes["CFG-UPLOADPROGRESS-ON"] || codes["CFG-MEMORY-FINITE"] {
		t.Fatalf("mitigated config still flagged: %v", codes)
	}
	if !codes["CFG-MEMORY-UNLIMITED"] {
		t.Fatal("expected info finding for memory_limit=-1")
	}
}

func TestOverrideDetection(t *testing.T) {
	eff := map[string]IniSetting{
		"session.upload_progress.enabled": {"session.upload_progress.enabled", "0", "php.ini"},
	}
	ovs := []OverrideFile{{
		Path: "/var/www/html/.htaccess", Kind: ".htaccess",
		Settings: []IniSetting{{"session.upload_progress.enabled", "1", "/var/www/html/.htaccess"}},
	}}
	f := Audit("8.3.6", eff, ovs)
	found := false
	for _, x := range f {
		if x.Code == "CFG-OVERRIDE-UPLOADPROGRESS" {
			found = true
		}
	}
	if !found {
		t.Fatal("override not detected")
	}
}

func TestParseFPMPoolArraySyntax(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "www.conf")
	os.WriteFile(p, []byte(`
[www]
user = www-data
php_admin_value[session.upload_progress.enabled] = 0
php_value[memory_limit] = "256M"
php_admin_flag[log_errors] = on
`), 0644)
	s := parseIniFile(p, "fpm-pool")
	got := map[string]string{}
	for _, kv := range s {
		got[strings.ToLower(kv.Key)] = kv.Value
	}
	if got["session.upload_progress.enabled"] != "0" || got["memory_limit"] != "256M" || got["log_errors"] != "on" {
		t.Fatalf("pool array syntax wrong: %#v", got)
	}
}
