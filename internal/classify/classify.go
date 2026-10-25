// Package classify turns discovered installs into verdicts using the
// vendor-fix database. The logic is deliberately conservative: when a
// vendor backport policy or the install provenance makes the true patch
// state unknowable, the verdict is VERIFY_VENDOR / UNKNOWN_VERSION —
// never a silent "safe".
package classify

import (
	"fmt"
	"strings"

	"github.com/andreysheva/php2shell-doctor/internal/model"
	"github.com/andreysheva/php2shell-doctor/internal/phpver"
	"github.com/andreysheva/php2shell-doctor/internal/vendordb"
)

// FixCVEs are the CVEs whose status the version classification covers.
var FixCVEs = []string{"CVE-2026-109618", "CVE-2026-109619"}

// Install classifies one install against the DB.
func Install(db *vendordb.DB, inst model.Install) model.InstallReport {
	rep := model.InstallReport{Install: inst, PerCVE: map[string]string{}}
	for _, cve := range FixCVEs {
		rep.PerCVE[cve] = "unknown"
	}
	// Container images without an exact, in-container-verified version
	// can never yield a hard verdict.
	if inst.Source == "docker-image" && inst.TagPartial {
		rep.Verdict = model.VerdictPatchUnknownVer
		rep.Reason = fmt.Sprintf("image tag %q does not name a patch version; run with --docker-exec on the running container or verify the image build", inst.ContainerImage)
		addFinding(&rep, model.SevMedium, model.CatVersion, "IMG-TAG-AMBIGUOUS",
			"Image tag does not name a patch version", rep.Reason, FixCVEs, "https://www.php.net/archive/2026.php#2026-10-21-5")
		return rep
	}
	if inst.Source == "docker-container" && inst.TagPartial && strings.Contains(inst.Note, "tag") && !strings.Contains(inst.Note, "php -v") {
		rep.Verdict = model.VerdictPatchUnknownVer
		rep.Reason = "running container version unknown (tag is partial); re-run with --docker-exec"
		addFinding(&rep, model.SevMedium, model.CatVersion, "IMG-VER-UNKNOWN", "Container runtime version unknown", rep.Reason, FixCVEs, "")
		return rep
	}

	switch {
	case inst.PackageVersion != "" && isDistroProvenance(inst.Provenance):
		classifyPackage(db, &rep)
	case inst.VersionRaw != "":
		classifyUpstreamInstall(db, &rep)
	default:
		rep.Verdict = model.VerdictPatchUnknownVer
		rep.Reason = "no version information could be determined for this PHP installation"
		addFinding(&rep, model.SevMedium, model.CatVersion, "VER-UNKNOWN",
			"Version unknown", rep.Reason+" — locate the php binary or package and re-run", FixCVEs, "")
	}
	return rep
}

// classifyPackage handles distro packages (dpkg/rpm/apk).
func classifyPackage(db *vendordb.DB, rep *model.InstallReport) {
	inst := rep.Install
	rpm := inst.Provenance == model.ProvRpm
	res, entry := db.PackageVerdict(inst.VendorID, inst.PackageName, inst.PackageVersion, rpm)
	switch res {
	case vendordb.ResPatched:
		rep.Verdict = model.VerdictPatched
		rep.Reason = fmt.Sprintf("vendor %s package %s %s is at/after the verified fixed revision (%s)",
			inst.VendorID, inst.PackageName, inst.PackageVersion, firstFixedRevision(entry))
		for _, cve := range FixCVEs {
			rep.PerCVE[cve] = "fixed"
		}
		if entry != nil && len(entry.Advisories) > 0 {
			ids := advisoryIDs(entry)
			rep.Reason += "; advisory: " + ids
		}
		addFinding(rep, model.SevInfo, model.CatVersion, "PATCHED", "PHP is patched for php2shell", rep.Reason, nil, "")

	case vendordb.ResVulnerable:
		up := phpver.MustUpstream(inst.PackageVersion)
		eol := up != "" && db.IsEOLBranch(phpver.Branch(up))
		if eol {
			rep.Verdict = model.VerdictEOLVulnerable
			rep.Reason = fmt.Sprintf("%s %s is an end-of-life PHP branch with no branch fix; upgrade to a supported, patched branch", inst.PackageName, inst.PackageVersion)
			addFinding(rep, model.SevCritical, model.CatVersion, "VULN-EOL",
				"End-of-life PHP is vulnerable to php2shell", rep.Reason, FixCVEs, "https://www.php.net/supported-versions.php")
		} else {
			rep.Verdict = model.VerdictVulnerable
			rep.Reason = fmt.Sprintf("%s %s is before the verified fixed revision %s", inst.PackageName, inst.PackageVersion, firstFixedRevision(entry))
			addFinding(rep, model.SevCritical, model.CatVersion, "VULN-PKG",
				"PHP package is vulnerable to php2shell", rep.Reason, FixCVEs, advisoriesURL(entry))
		}
		for _, cve := range FixCVEs {
			rep.PerCVE[cve] = "affected"
		}

	case vendordb.ResVerifyVendor:
		rep.Verdict = model.VerdictVerifyVendor
		rep.Reason = fmt.Sprintf("vendor %s backports fixes without machine-comparable version bump; confirm %s against %s manually",
			inst.VendorID, inst.PackageVersion, advisoryIDs(entry))
		addFinding(rep, model.SevHigh, model.CatVersion, "VERIFY-BACKPORT",
			"Vendor backport status must be confirmed", rep.Reason, FixCVEs, advisoriesURL(entry))

	default: // ResNoMatch: vendor unknown to the DB — use upstream version as evidence
		up, ok := phpver.Upstream(inst.PackageVersion)
		if !ok {
			rep.Verdict = model.VerdictVerifyVendor
			rep.Reason = fmt.Sprintf("package %s %s is not in the vendor database and its upstream version could not be parsed", inst.PackageName, inst.PackageVersion)
			addFinding(rep, model.SevHigh, model.CatVersion, "VERIFY-UNKNOWN-VENDOR",
				"Unknown vendor; fix state unverifiable", rep.Reason, FixCVEs, "")
			return
		}
		if db.UpstreamVerdict(up) == vendordb.ResPatched {
			rep.Verdict = model.VerdictPatched
			rep.Reason = fmt.Sprintf("upstream version %s is at/after the fixed release; vendor %s not in database — verify the build actually includes the fix", up, inst.VendorID)
			for _, cve := range FixCVEs {
				rep.PerCVE[cve] = "fixed"
			}
			addFinding(rep, model.SevInfo, model.CatVersion, "PATCHED-UPSTREAM", "Patched by upstream version", rep.Reason, nil, "")
		} else {
			// Upstream version below fixed, but the vendor may have
			// backported silently. Never claim vulnerable here.
			rep.Verdict = model.VerdictVerifyVendor
			rep.Reason = fmt.Sprintf("upstream version %s predates the fixed release, but vendor %s is unknown to the database and may have backported the fix without a version bump", up, inst.VendorID)
			addFinding(rep, model.SevHigh, model.CatVersion, "VERIFY-UNKNOWN-VENDOR",
				"Possible backport; confirm with your vendor", rep.Reason, FixCVEs, "")
		}
	}
}

// classifyUpstreamInstall handles standalone binaries, panels, brew,
// image tags with exact versions, etc.
func classifyUpstreamInstall(db *vendordb.DB, rep *model.InstallReport) {
	inst := rep.Install
	up, ok := phpver.Upstream(inst.VersionRaw)
	if !ok {
		rep.Verdict = model.VerdictPatchUnknownVer
		rep.Reason = fmt.Sprintf("version %q is not a recognizable PHP release", inst.VersionRaw)
		addFinding(rep, model.SevMedium, model.CatVersion, "VER-UNKNOWN", "Version unparseable", rep.Reason, FixCVEs, "")
		return
	}
	rep.Install.Upstream = up
	rep.Install.Branch = phpver.Branch(up)
	switch db.UpstreamVerdict(up) {
	case vendordb.ResPatched:
		rep.Verdict = model.VerdictPatched
		rep.Reason = fmt.Sprintf("upstream version %s is at/after the fixed release for branch %s", up, rep.Install.Branch)
		for _, cve := range FixCVEs {
			rep.PerCVE[cve] = "fixed"
		}
		addFinding(rep, model.SevInfo, model.CatVersion, "PATCHED", "PHP is patched for php2shell", rep.Reason, nil, "")
	default:
		if db.IsEOLBranch(rep.Install.Branch) {
			rep.Verdict = model.VerdictEOLVulnerable
			rep.Reason = fmt.Sprintf("branch %s is end-of-life: no fix will ever ship for it; upgrade to a supported branch (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)", rep.Install.Branch)
			addFinding(rep, model.SevCritical, model.CatVersion, "VULN-EOL",
				"End-of-life PHP is vulnerable to php2shell", rep.Reason, FixCVEs, "https://www.php.net/supported-versions.php")
		} else {
			fixed, _ := db.FixedUpstream(rep.Install.Branch)
			rep.Verdict = model.VerdictVulnerable
			rep.Reason = fmt.Sprintf("upstream version %s is before the fixed release %s", up, fixed)
			addFinding(rep, model.SevCritical, model.CatVersion, "VULN-UPSTREAM",
				"PHP is vulnerable to php2shell", rep.Reason, FixCVEs, "https://www.php.net/archive/2026.php#2026-10-21-5")
		}
		for _, cve := range FixCVEs {
			rep.PerCVE[cve] = "affected"
		}
	}
	// Risk amplifier: mod_php means exploitation can complete before
	// application code runs.
	for _, s := range inst.SAPIs {
		if s == model.SAPIApacheMod {
			addFinding(rep, model.SevHigh, model.CatVersion, "SAPI-MODPHP",
				"mod_php detected: highest-risk SAPI for CVE-2026-109618",
				"An unauthenticated request can trigger exploitation before any application code runs. Patching is the only complete fix.",
				[]string{"CVE-2026-109618"}, "https://cert.europa.eu/publications/security-advisories/2026-018/")
		}
	}
}

func firstFixedRevision(entry *vendordb.VendorPackage) string {
	if entry == nil || len(entry.FixedRevision) == 0 {
		return "vendor-fixed revision"
	}
	return entry.FixedRevision[0]
}

func advisoryIDs(entry *vendordb.VendorPackage) string {
	if entry == nil {
		return "vendor advisory"
	}
	var ids []string
	for _, a := range entry.Advisories {
		ids = append(ids, a.ID)
	}
	if len(ids) == 0 {
		return "vendor advisory"
	}
	return strings.Join(ids, ", ")
}

func advisoriesURL(entry *vendordb.VendorPackage) string {
	if entry == nil || len(entry.Advisories) == 0 {
		return ""
	}
	return entry.Advisories[0].URL
}

func addFinding(rep *model.InstallReport, sev model.Severity, cat model.Category, code, title, detail string, cves []string, ref string) {
	rep.Findings = append(rep.Findings, model.Finding{
		InstallID: rep.Install.ID, Severity: sev, Category: cat,
		Code: code, Title: title, Detail: detail, CVEs: cves, Reference: ref,
	})
}

// isDistroProvenance reports whether the install came from a distro
// package database (dpkg/rpm/apk), which carries a full package revision.
func isDistroProvenance(p model.ProvenanceKind) bool {
	return p == model.ProvDpkg || p == model.ProvRpm || p == model.ProvApk
}
