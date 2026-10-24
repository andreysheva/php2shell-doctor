package pkgver

import "testing"

// Test vectors from dpkg's own test suite (t/dpkg_version/?) semantics
// and from rpmvercmp documentation.
func TestDpkgCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Ubuntu php8.3 fixed revision vs an older revision of the same upstream.
		{"8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1},
		{"8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.13", 0},
		{"8.3.6-0ubuntu0.24.04.14", "8.3.6-0ubuntu0.24.04.13", 1},
		// Debian: version with ~ sorts before the same version without.
		{"8.2.35-1~deb12u1", "8.2.35-1", -1},
		{"8.2.32-1~deb12u1", "8.2.35-1~deb12u1", -1},
		{"8.4.24-1~deb13u1", "8.4.27-1~deb13u1", -1},
		// Numeric vs lexicographic.
		{"1.2.10-1", "1.2.9-1", 1},
		{"1.2.2-1", "1.2.10-1", -1},
		// Epoch dominates.
		{"0:1.0-1", "1:0.9-1", -1},
		{"2:1.0-1", "1:9.9-1", 1},
		// Letters sort before non-letters; tilde before everything.
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0a-1", "1.0+1-1", -1}, // '+' is non-letter, sorts after 'a'? letters < non-letters
		// Revision defaults.
		{"1.0", "1.0-1", -1}, // dpkg: no revision sorts before "1" revision
	}
	for _, c := range cases {
		if got := DpkgCompare(c.a, c.b); got != c.want {
			t.Errorf("DpkgCompare(%q,%q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRpmCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.0", "2.0", 1},
		{"8.2.13-1.module_el9.8.0", "8.2.13-2.module_el9.8.0", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0^post1", "1.0", 1},
		{"1.0^post1", "1.1", -1},
		{"1.05", "1.5", 0}, // numeric runs: 05 == 5
		{"1.7", "1.7.0", -1},
	}
	for _, c := range cases {
		if got := RpmCompare(c.a, c.b); got != c.want {
			t.Errorf("RpmCompare(%q,%q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
}
