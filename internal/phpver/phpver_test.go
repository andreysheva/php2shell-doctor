package phpver

import "testing"

func TestUpstream(t *testing.T) {
	cases := []struct {
		raw, want string
		ok        bool
	}{
		{"8.3.6-0ubuntu0.24.04.13", "8.3.6", true},
		{"8.2.24-1+ubuntu22.04.1+deb.sury.org+1", "8.2.24", true},
		{"8.4.27-1~deb13u1", "8.4.27", true},
		{"8.5.12", "8.5.12", true},
		{"8.1.2-1ubuntu2.22", "8.1.2", true},
		{"PHP 8.3.6 (cli)", "", false}, // callers strip prefixes first
		{"8.4.14-2+deb.sury.org~bookworm+1", "8.4.14", true},
		{"7.4.33", "7.4.33", true},
		{"8.3.14-r0", "8.3.14", true},
	}
	for _, c := range cases {
		got, ok := Upstream(c.raw)
		if got != c.want || ok != c.ok {
			t.Errorf("Upstream(%q) = %q,%v want %q,%v", c.raw, got, ok, c.want, c.ok)
		}
	}
}

func TestBranch(t *testing.T) {
	if Branch("8.3.6") != "8.3" {
		t.Fatal("branch mismatch")
	}
}

func TestCompare(t *testing.T) {
	ordered := []string{
		"8.2.0dev", "8.2.0alpha1", "8.2.0beta2", "8.2.0RC1", "8.2.0", "8.2.1", "8.2.34", "8.2.35",
		"8.3.0", "8.3.35", "8.3.36", "8.4.26", "8.4.27", "8.5.11", "8.5.12",
	}
	for i := 0; i < len(ordered)-1; i++ {
		if !Less(ordered[i], ordered[i+1]) {
			t.Errorf("expected %s < %s", ordered[i], ordered[i+1])
		}
		if GreaterOrEqual(ordered[i], ordered[i+1]) {
			t.Errorf("expected %s < %s (GreaterOrEqual false)", ordered[i], ordered[i+1])
		}
	}
	if Compare("8.2.35", "8.2.35") != 0 {
		t.Error("equal versions must compare 0")
	}
}
