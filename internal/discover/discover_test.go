package discover

import (
	"testing"

	"github.com/andreysheva/php2shell-doctor/internal/model"
)

func TestMapVendorID(t *testing.T) {
	cases := []struct {
		pkg, ver, osID, want string
	}{
		{"php8.3", "8.3.6-0ubuntu0.24.04.13", "ubuntu", "ubuntu"},
		{"php8.2", "8.2.35-1~deb12u1", "debian", "debian"},
		{"php8.2", "8.2.24-1+ubuntu22.04.1+deb.sury.org+1", "ubuntu", "sury"},
		{"php83-php", "8.3.36-1.el9.remi", "rocky", "remi"},
		{"php", "8.2.13-3.module_el9.8.0", "almalinux", "redhat-family"},
		{"php83", "8.3.14-r0", "alpine", "alpine"},
		{"alt-php83", "8.3.36-1", "cloudlinux", "cloudlinux"},
		{"ea-php83-php", "8.3.36-1.el9", "centos", "cpanel"},
	}
	for _, c := range cases {
		if got := mapVendorID(c.pkg, c.ver, c.osID); got != c.want {
			t.Errorf("mapVendorID(%q,%q,%q) = %q want %q", c.pkg, c.ver, c.osID, got, c.want)
		}
	}
}

func TestIsRuntimePackage(t *testing.T) {
	runtime := []string{"php", "php-cli", "php-fpm", "php8.3", "php8.3-cli", "php8.3-fpm",
		"libapache2-mod-php8.2", "alt-php83", "ea-php83-php", "lsphp83", "php83-php", "php83-php-fpm"}
	for _, n := range runtime {
		if !isRuntimePackage(n) {
			t.Errorf("%q should be a runtime package", n)
		}
	}
	not := []string{"php-common", "php8.3-common", "php8.3-mbstring", "php8.3-xml",
		"php8.3-readline", "php8.3-opcache", "phpunit", "phpcs", "phpstan", "phpmyadmin", "php-dev"}
	for _, n := range not {
		if isRuntimePackage(n) {
			t.Errorf("%q should NOT be a runtime package", n)
		}
	}
}

func TestDedupe(t *testing.T) {
	in := []model.Install{
		{BinaryPath: "/usr/bin/php", Source: "PATH"},
		{BinaryPath: "/usr/bin/php", Source: "distro-packages"},
		{BinaryPath: "/usr/bin/php8.3"},
	}
	out := dedupe(in)
	if len(out) != 2 {
		t.Fatalf("dedupe kept %d want 2", len(out))
	}
}

func TestVersionFromImageTag(t *testing.T) {
	cases := []struct {
		ref, want    string
		exact, ok    bool
	}{
		{"php:8.3.6-fpm-alpine", "8.3.6", true, true},
		{"php:8.3-apache", "8.3.0", false, true},
		{"wordpress:6.4", "6.4.0", false, true},
		{"nginx:latest", "", false, false},
	}
	for _, c := range cases {
		got, exact, ok := versionFromImageTag(c.ref)
		if got != c.want || exact != c.exact || ok != c.ok {
			t.Errorf("versionFromImageTag(%q) = %q,%v,%v want %q,%v,%v", c.ref, got, exact, ok, c.want, c.exact, c.ok)
		}
	}
}

func TestConcatNames(t *testing.T) {
	for _, n := range []string{"php83", "php83-cli", "php83-fpm", "php74"} {
		if !isRuntimePackage(n) {
			t.Errorf("%q should be a runtime package (concatenated style)", n)
		}
	}
	if got := phpBinaryForPackage("php83"); got != "/usr/bin/php83" {
		t.Errorf("phpBinaryForPackage(php83) = %q", got)
	}
	if got := phpBinaryForPackage("php83-fpm"); got != "/usr/sbin/php-fpm83" {
		t.Errorf("phpBinaryForPackage(php83-fpm) = %q", got)
	}
}
