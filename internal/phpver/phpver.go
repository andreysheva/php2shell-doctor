// Package phpver parses PHP version strings (including distro-mangled
// ones) and compares upstream x.y.z versions the way the PHP release
// process orders them.
package phpver

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var upstreamRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:([.-])(dev|alpha|beta|RC|pl)(\d*))?`)

// Upstream extracts the leading upstream semantic version from a raw
// version string that may carry distro suffixes, e.g.
//
//	"8.3.6-0ubuntu0.24.04.13"     -> "8.3.6"
//	"8.2.24-1+ubuntu22.04.1+deb.sury.org+1" -> "8.2.24"
//	"8.4.27-1~deb13u1"            -> "8.4.27"
//	"8.5.12"                      -> "8.5.12"
//	"8.1.2-1ubuntu2.22"           -> "8.1.2"
//
// The second return value is false when no leading x.y.z exists.
func Upstream(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	m := upstreamRe.FindStringSubmatch(raw)
	if m == nil {
		return "", false
	}
	return m[1] + "." + m[2] + "." + m[3], true
}

// MustUpstream is Upstream but returns "" instead of ok=false.
func MustUpstream(raw string) string {
	v, _ := Upstream(raw)
	return v
}

// Branch returns the "8.x" maintenance branch of an upstream version.
func Branch(upstream string) string {
	parts := strings.Split(upstream, ".")
	if len(parts) < 2 {
		return upstream
	}
	return parts[0] + "." + parts[1]
}

// suffixRank orders pre-release suffixes below their release, per PHP
// conventions: dev < alpha < beta < RC < (release) < pl.
func suffixRank(name string) int {
	switch strings.ToUpper(name) {
	case "DEV":
		return 0
	case "ALPHA":
		return 1
	case "BETA":
		return 2
	case "RC":
		return 3
	case "":
		return 4
	case "PL":
		return 5
	}
	return 4
}

type parsed struct {
	major, minor, patch int
	suffix              string
	suffixNum           int
}

func parse(v string) (parsed, error) {
	m := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(?:[.-]?([A-Za-z]+)\.?(?:(\d+))?)?$`).FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return parsed{}, fmt.Errorf("not a PHP upstream version: %q", v)
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])
	suf := m[4]
	if suf != "" {
		suf = strings.ToUpper(suf)
		if suf != "DEV" && suf != "ALPHA" && suf != "BETA" && suf != "RC" && suf != "PL" {
			return parsed{}, fmt.Errorf("unknown suffix in %q", v)
		}
	}
	num, _ := strconv.Atoi(m[5])
	return parsed{maj, min, pat, suf, num}, nil
}

// Compare orders two upstream PHP versions. Returns -1, 0, or 1.
// Pre-releases sort below the final release ("8.4.27RC1" < "8.4.27").
func Compare(a, b string) int {
	pa, err := parse(a)
	if err != nil {
		panic(err)
	}
	pb, err := parse(b)
	if err != nil {
		panic(err)
	}
	if c := cmpInt(pa.major, pb.major); c != 0 {
		return c
	}
	if c := cmpInt(pa.minor, pb.minor); c != 0 {
		return c
	}
	if c := cmpInt(pa.patch, pb.patch); c != 0 {
		return c
	}
	ra, rb := suffixRank(pa.suffix), suffixRank(pb.suffix)
	if c := cmpInt(ra, rb); c != 0 {
		return c
	}
	return cmpInt(pa.suffixNum, pb.suffixNum)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Less reports whether a < b.
func Less(a, b string) bool { return Compare(a, b) < 0 }

// GreaterOrEqual reports whether a >= b.
func GreaterOrEqual(a, b string) bool { return Compare(a, b) >= 0 }
