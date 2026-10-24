package vendordb

import "testing"

func load(t *testing.T) *DB {
	t.Helper()
	db, err := Load(mustRead())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return db
}

func mustRead() []byte {
	b, err := osRead()
	if err != nil {
		panic(err)
	}
	return b
}

func TestUpstreamVerdict(t *testing.T) {
	db := load(t)
	cases := []struct {
		v    string
		want Result
	}{
		{"8.5.12", ResPatched},
		{"8.5.11", ResVulnerable},
		{"8.4.27", ResPatched},
		{"8.4.26", ResVulnerable},
		{"8.3.36", ResPatched},
		{"8.3.6", ResVulnerable},
		{"8.2.35", ResPatched},
		{"8.2.13", ResVulnerable},
		{"7.4.33", ResVulnerable}, // EOL
		{"8.1.31", ResVulnerable}, // EOL
	}
	for _, c := range cases {
		if got := db.UpstreamVerdict(c.v); got != c.want {
			t.Errorf("UpstreamVerdict(%q) = %v want %v", c.v, got, c.want)
		}
	}
}

func TestPackageVerdictUbuntuRevision(t *testing.T) {
	db := load(t)
	// The canonical false-positive case: upstream stays 8.3.6, revision fixes it.
	got, p := db.PackageVerdict("ubuntu", "php8.3", "8.3.6-0ubuntu0.24.04.13", false)
	if got != ResPatched || p == nil {
		t.Fatalf("patched ubuntu revision misjudged: %v", got)
	}
	got, _ = db.PackageVerdict("ubuntu", "php8.3", "8.3.6-0ubuntu0.24.04.12", false)
	if got != ResVulnerable {
		t.Fatalf("older ubuntu revision misjudged: %v", got)
	}
	// verify policy: never silently safe
	got, p = db.PackageVerdict("ubuntu", "php8.1", "8.1.2-1ubuntu2.22", false)
	if got != ResVerifyVendor || p.Policy != PolicyVerify {
		t.Fatalf("verify policy misjudged: %v", got)
	}
	// sury: upstream comparison through the package version
	got, _ = db.PackageVerdict("sury", "php8.2", "8.2.24-1+ubuntu22.04.1+deb.sury.org+1", false)
	if got != ResVulnerable {
		t.Fatalf("old sury misjudged: %v", got)
	}
	got, _ = db.PackageVerdict("sury", "php8.3", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", false)
	if got != ResPatched {
		t.Fatalf("fixed sury misjudged: %v", got)
	}
	// debian revision policy
	got, _ = db.PackageVerdict("debian", "php8.2", "8.2.35-1~deb12u1", false)
	if got != ResPatched {
		t.Fatalf("fixed debian misjudged: %v", got)
	}
	got, _ = db.PackageVerdict("debian", "php8.2", "8.2.32-1~deb12u1", false)
	if got != ResVulnerable {
		t.Fatalf("vuln debian misjudged: %v", got)
	}
	// unknown vendor
	got, _ = db.PackageVerdict("unknown", "php8.3", "8.3.6", false)
	if got != ResNoMatch {
		t.Fatalf("unknown vendor misjudged: %v", got)
	}
}

func TestPackageVerdictRpm(t *testing.T) {
	db := load(t)
	got, _ := db.PackageVerdict("remi", "php83-php", "8.3.36-1.el9.remi", true)
	if got != ResPatched {
		t.Fatalf("remi fixed misjudged: %v", got)
	}
	got, _ = db.PackageVerdict("remi", "php83-php", "8.3.13-1.el9.remi", true)
	if got != ResVulnerable {
		t.Fatalf("remi old misjudged: %v", got)
	}
	// redhat-family: invisible-backport risk only exists below the fixed version
	got, _ = db.PackageVerdict("redhat-family", "php", "8.2.13-3.module_el9", true)
	if got != ResVerifyVendor {
		t.Fatalf("redhat below-fixed should verify: %v", got)
	}
	// at/after the fixed upstream release the runtime is genuinely patched
	got, _ = db.PackageVerdict("redhat-family", "php8.2-cli", "8.2.35-1.amzn2023.0.1", true)
	if got != ResPatched {
		t.Fatalf("redhat at-fixed should be patched: %v", got)
	}
	// EOL branch under verify policy still routes to verify (may be backported)
	got, _ = db.PackageVerdict("redhat-family", "php", "8.0.30-1.module+el8", true)
	if got != ResVerifyVendor {
		t.Fatalf("redhat EOL below-fixed should verify: %v", got)
	}
}

func TestPackageVerdictRealDistroNames(t *testing.T) {
	db := load(t)
	// Ubuntu/Debian ship versioned subpackages: php8.3-cli, php8.3-fpm, ...
	cases := []struct {
		vendor, pkg, ver string
		rpm              bool
		want             Result
	}{
		{"ubuntu", "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", false, ResPatched},
		{"ubuntu", "php8.3-cli", "8.3.6-0ubuntu0.24.04.12", false, ResVulnerable},
		{"ubuntu", "php8.3-fpm", "8.3.6-0ubuntu0.24.04.13", false, ResPatched},
		{"debian", "php8.2-cli", "8.2.35-1~deb12u1", false, ResPatched},
		{"debian", "libapache2-mod-php8.2", "8.2.35-1~deb12u1", false, ResPatched},
	}
	for _, c := range cases {
		got, _ := db.PackageVerdict(c.vendor, c.pkg, c.ver, c.rpm)
		if got != c.want {
			t.Errorf("PackageVerdict(%q,%q,%q) = %v want %v", c.vendor, c.pkg, c.ver, got, c.want)
		}
	}
}
