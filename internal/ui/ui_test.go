package ui

import (
	"strings"
	"testing"
)

func TestDisabledByDefaultInTests(t *testing.T) {
	// Tests run without a TTY; Init with explicit no-color keeps styling off
	Init(true)
	if Enabled() {
		t.Fatal("styling must be disabled after Init(true)")
	}
	if Red("x") != "x" || Bold("x") != "x" {
		t.Fatal("color funcs must be identity when disabled")
	}
}

func TestForceColor(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	t.Setenv("NO_COLOR", "")
	Init(false)
	if !Enabled() {
		t.Fatal("FORCE_COLOR=1 must enable styling")
	}
	if Red("x") == "x" {
		t.Fatal("Red must wrap when enabled")
	}
	if !strings.Contains(Red("x"), "\x1b[31m") {
		t.Fatal("expected ANSI red")
	}
	Init(true) // restore disabled for other tests
}

func TestVerdictColorsAndSymbols(t *testing.T) {
	Init(true)
	cases := map[string]func(string) string{
		"PATCHED": Green, "VULNERABLE": Red, "EOL_VULNERABLE": Red,
		"PATCHED_STALE_WORKERS": Red, "VERIFY_VENDOR": Yellow, "UNKNOWN_VERSION": Cyan,
	}
	for v, fn := range cases {
		if VerdictColor(v)("x") != fn("x") {
			t.Errorf("verdict color mismatch for %s", v)
		}
	}
	Init(true)
	if VerdictSymbol("PATCHED") == "" {
		t.Fatal("symbol missing")
	}
}

func TestBoxWidthsIgnoreANSI(t *testing.T) {
	t.Setenv("FORCE_COLOR", "1")
	Init(false)
	box := Box("summary", []string{Red("a-vulnerable-line"), Green("ok")})
	// all box lines must have identical visible width
	lines := strings.Split(strings.TrimRight(box, "\n"), "\n")
	w := visibleWidth(lines[0])
	for _, l := range lines {
		if visibleWidth(l) != w {
			t.Fatalf("box width mismatch:\n%s", box)
		}
	}
	if !strings.Contains(box, "a-vulnerable-line") {
		t.Fatal("content lost")
	}
	Init(true)
	ascii := Box("summary", []string{"x"})
	if !strings.Contains(ascii, "+") {
		t.Fatal("ASCII fallback expected when disabled")
	}
}

func TestBannerContainsVersion(t *testing.T) {
	Init(true)
	b := Banner("1.2.3", "db1")
	if !strings.Contains(b, "1.2.3") || !strings.Contains(b, "db1") {
		t.Fatal("banner missing version info")
	}
}
