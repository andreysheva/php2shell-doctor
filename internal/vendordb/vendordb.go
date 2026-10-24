// Package vendordb loads the embedded vendor-fix database and answers
// "is this PHP install patched?" questions, honouring per-vendor
// backport policies.
package vendordb

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/php2shell-doctor/php2shell-doctor/internal/pkgver"
	"github.com/php2shell-doctor/php2shell-doctor/internal/phpver"
)

//go:embed vendordb.json
var embedded []byte

// Policy decides how a vendor package's fix state is judged.
type Policy string

const (
	PolicyRevision        Policy = "revision"         // judge by dpkg/rpm revision against fixed_revisions
	PolicyUpstreamVersion Policy = "upstream_version" // judge by upstream x.y.z
	PolicyVerify          Policy = "verify"           // never machine-judge; require human/vendor confirmation
)

// Result is the verdict of a vendor-DB lookup.
type Result int

const (
	ResNoMatch        Result = iota // vendor/package unknown to the DB
	ResPatched                      // at/after a verified fixed revision or upstream version
	ResVulnerable                   // before the fixed revision/upstream version
	ResVerifyVendor                 // policy=verify or fixed revision unknown
)

func (r Result) String() string {
	switch r {
	case ResPatched:
		return "PATCHED"
	case ResVulnerable:
		return "VULNERABLE"
	case ResVerifyVendor:
		return "VERIFY_VENDOR"
	}
	return "NO_MATCH"
}

// FixedCVEs are the CVEs fixed by the 2026-10-21 releases.
var FixedCVEs = []string{"CVE-2026-109618", "CVE-2026-109619"}

type advisory struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type VendorPackage struct {
	Package       string     `json:"package"`
	Distribution  string     `json:"distribution"`
	Policy        Policy     `json:"policy"`
	FixedRevision []string   `json:"fixed_revisions"`
	Advisories    []advisory `json:"advisories"`
	VerifiedAsOf  string     `json:"verified_as_of"`
	Source        string     `json:"source"`
	Note          string     `json:"note"`
}

type vendor struct {
	Vendor   string          `json:"vendor"`
	Kind     string          `json:"kind"`
	Packages []VendorPackage `json:"packages"`
}

type db struct {
	SchemaVersion int                `json:"schema_version"`
	DBRevision    string             `json:"db_revision"`
	Upstream      struct {
		Fixed map[string]string `json:"fixed"`
	} `json:"upstream"`
	Vendors []vendor `json:"vendors"`
}

// DB is a loaded vendor-fix database.
type DB struct {
	d      db
	loaded bool
}

// Load parses raw JSON vendordb content.
func Load(raw []byte) (*DB, error) {
	var d db
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("vendordb: %w", err)
	}
	if len(d.Upstream.Fixed) == 0 {
		return nil, fmt.Errorf("vendordb: no upstream fixed versions")
	}
	return &DB{d: d, loaded: true}, nil
}

// Embedded returns the DB compiled into the binary.
func Embedded() (*DB, error) { return Load(embedded) }

// Revision returns the database revision string.
func (d *DB) Revision() string { return d.d.DBRevision }

// FixedUpstream returns the fixed upstream release for a branch, e.g.
// FixedUpstream("8.3") == "8.3.36".
func (d *DB) FixedUpstream(branch string) (string, bool) {
	v, ok := d.d.Upstream.Fixed[branch]
	return v, ok
}

// AllFixedUpstream returns the full upstream fixed map.
func (d *DB) AllFixedUpstream() map[string]string {
	out := map[string]string{}
	for k, v := range d.d.Upstream.Fixed {
		out[k] = v
	}
	return out
}

// UpstreamVerdict classifies a pure upstream PHP version (standalone
// builds, Homebrew, Plesk, cPanel EA, official image tags, ...).
// EOL branches (8.1 and older) are vulnerable unless the caller knows a
// vendor backport applies.
func (d *DB) UpstreamVerdict(upstream string) Result {
	branch := phpver.Branch(upstream)
	fixed, ok := d.d.Upstream.Fixed[branch]
	if !ok {
		// EOL or unknown branch: vulnerable (no upstream fix exists).
		return ResVulnerable
	}
	if phpver.GreaterOrEqual(upstream, fixed) {
		return ResPatched
	}
	return ResVulnerable
}

// IsEOLBranch reports whether the branch receives no upstream fixes.
func (d *DB) IsEOLBranch(branch string) bool {
	_, ok := d.d.Upstream.Fixed[branch]
	return !ok
}

// PackageVerdict judges a distro package version against the vendor
// entries matching vendor+package name. pkgKind selects dpkg vs rpm
// comparison. nameMatch allows glob-ish vendor package patterns
// ("php8.*", "php* / php8x") matched against the actual package name.
func (d *DB) PackageVerdict(vendorID, packageName, packageVersion string, rpm bool) (Result, *VendorPackage) {
	var best *VendorPackage
	for i := range d.d.Vendors {
		v := &d.d.Vendors[i]
		if v.Vendor != vendorID {
			continue
		}
		for j := range v.Packages {
			p := &v.Packages[j]
			if pkgNameMatches(p.Package, packageName) {
				best = p
			}
		}
	}
	if best == nil {
		return ResNoMatch, nil
	}
	switch best.Policy {
	case PolicyVerify:
		// "Verify" protects against invisible backports: a version that
		// LOOKS old may secretly be patched. The reverse cannot happen —
		// a version at/after the fixed upstream release is genuinely
		// patched regardless of vendor backporting. Only route to
		// VERIFY_VENDOR when the version itself looks unfixed.
		if up, ok := phpver.Upstream(packageVersion); ok {
			if d.UpstreamVerdict(up) == ResPatched {
				return ResPatched, best
			}
		}
		return ResVerifyVendor, best
	case PolicyUpstreamVersion:
		up, ok := phpver.Upstream(packageVersion)
		if !ok {
			return ResVerifyVendor, best
		}
		return d.UpstreamVerdict(up), best
	case PolicyRevision:
		if len(best.FixedRevision) == 0 {
			return ResVerifyVendor, best
		}
		for _, fixed := range best.FixedRevision {
			var c int
			if rpm {
				c = pkgver.RpmCompare(packageVersion, fixed)
			} else {
				c = pkgver.DpkgCompare(packageVersion, fixed)
			}
			if c >= 0 {
				return ResPatched, best
			}
		}
		return ResVulnerable, best
	}
	return ResNoMatch, best
}

// pkgNameMatches matches a DB package pattern like "php8.*", "php*",
// "php / frankenphp" or an exact name.
func pkgNameMatches(pattern, name string) bool {
	for _, alt := range strings.Split(pattern, "/") {
		p := strings.TrimSpace(alt)
		if p == "" {
			continue
		}
		if globMatch(p, name) {
			return true
		}
	}
	return false
}

func globMatch(pattern, s string) bool {
	// simple * glob, case-insensitive prefix/suffix semantics
	pattern = strings.ToLower(pattern)
	s = strings.ToLower(s)
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(s[pos:], part)
		if i == 0 && !strings.HasPrefix(s, part) {
			return false
		}
		if i == len(parts)-1 && !strings.HasSuffix(s, part) {
			return false
		}
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
	}
	return true
}

// AdvisoryURLs returns advisories attached to the matching vendor package.
func (d *DB) AdvisoryURLs(vendorID, packageName string) []advisory {
	var out []advisory
	for i := range d.d.Vendors {
		v := &d.d.Vendors[i]
		if v.Vendor != vendorID {
			continue
		}
		for _, p := range v.Packages {
			if pkgNameMatches(p.Package, packageName) {
				out = append(out, p.Advisories...)
			}
		}
	}
	return out
}
