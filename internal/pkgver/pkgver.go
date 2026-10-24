// Package pkgver implements distribution package-version ordering:
// Debian's dpkg comparison algorithm and RPM's rpmvercmp. These are
// required to decide whether an installed package revision (which may
// keep an old upstream version) is at or past a vendor's fixed revision.
package pkgver

import (
	"strings"
)

// DpkgCompare implements the algorithm of dpkg's `dpkg --compare-versions`
// for full versions of the form [epoch:]upstream[-revision].
// Returns -1, 0, or 1.
func DpkgCompare(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := cmpDpkgFragment(ua, ub); c != 0 {
		return c
	}
	return cmpDpkgFragment(ra, rb)
}

func splitDpkg(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 && allDigits(v[:i]) {
		epoch = atoi(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, "0"
}

func allDigits(s string) bool {
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

func atoi(s string) int {
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// cmpDpkgFragment implements the "order" function from dpkg's
// lib/dpkg/version.c: alternating non-digit/digit runs, '~' sorts
// before everything including the empty string, letters sort before
// non-letters, everything else compares by ASCII.
func cmpDpkgFragment(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		var na, nb string
		na, a = takeNonDigit(a)
		nb, b = takeNonDigit(b)
		if c := cmpDpkgChunk(na, nb); c != 0 {
			return c
		}
		na, a = takeDigit(a)
		nb, b = takeDigit(b)
		if c := cmpNumeric(na, nb); c != 0 {
			return c
		}
	}
	return 0
}

func takeNonDigit(s string) (chunk, rest string) {
	i := 0
	for i < len(s) && (s[i] < '0' || s[i] > '9') {
		i++
	}
	return s[:i], s[i:]
}

func takeDigit(s string) (chunk, rest string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// cmpNumeric compares digit runs numerically (leading zeros ignored).
func cmpNumeric(a, b string) int {
	ta := strings.TrimLeft(a, "0")
	tb := strings.TrimLeft(b, "0")
	if len(ta) != len(tb) {
		if len(ta) < len(tb) {
			return -1
		}
		return 1
	}
	if ta != tb {
		if ta < tb {
			return -1
		}
		return 1
	}
	return 0
}

// cmpDpkgChunk compares non-digit runs per dpkg rules.
func cmpDpkgChunk(a, b string) int {
	for len(a) > 0 && len(b) > 0 {
		ca, cb := a[0], b[0]
		switch {
		case ca == '~' || cb == '~':
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
		case isLetter(ca) && isLetter(cb):
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
		case isLetter(ca) && !isLetter(cb):
			return -1
		case !isLetter(ca) && isLetter(cb):
			return 1
		default:
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
		}
		a, b = a[1:], b[1:]
	}
	// One ran out: the shorter side is smaller unless the other's next
	// char is '~' (which sorts before end).
	if len(a) > 0 {
		if a[0] == '~' {
			return -1
		}
		return 1
	}
	if len(b) > 0 {
		if b[0] == '~' {
			return 1
		}
		return -1
	}
	return 0
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// RpmCompare implements rpmvercmp (libsolv/rpm variant with '^' support).
// Splits into alternating alpha/digit runs; '~' sorts before everything,
// '^' sorts after everything except end-of-string, letters > digits.
func RpmCompare(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		var ra, rb string
		ra, a = takeNonAlnum(a)
		rb, b = takeNonAlnum(b)
		if c := cmpRpmChunk(ra, rb); c != 0 {
			return c
		}
		ra, a = takeAlnum(a)
		rb, b = takeAlnum(b)
		if c := cmpNumeric(ra, rb); c != 0 {
			return c
		}
	}
	return 0
}

func takeNonAlnum(s string) (chunk, rest string) {
	i := 0
	for i < len(s) && !isAlnum(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func takeAlnum(s string) (chunk, rest string) {
	i := 0
	for i < len(s) && isAlnum(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func isAlnum(c byte) bool {
	return isLetter(c) || (c >= '0' && c <= '9')
}

// cmpRpmChunk compares non-alphanumeric chunks for rpmvercmp.
func cmpRpmChunk(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		ca, cb := byte(0), byte(0)
		if len(a) > 0 {
			ca = a[0]
		}
		if len(b) > 0 {
			cb = b[0]
		}
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
		} else if ca == '^' || cb == '^' {
			if ca != '^' { // end-of-string or other sorts before '^'
				return -1
			}
			if cb != '^' {
				return 1
			}
		} else {
			if ca == 0 && cb == 0 {
				return 0
			}
			if ca == 0 {
				return -1
			}
			if cb == 0 {
				return 1
			}
			if ca != cb {
				if ca < cb {
					return -1
				}
				return 1
			}
		}
		a, b = a[1:], b[1:]
	}
	return 0
}
