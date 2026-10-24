// Package report renders scan results as text, JSON, CSV, SARIF and
// CycloneDX, and defines the exit-code contract consumed by CI and
// fleet tooling.
package report

import (
	"github.com/php2shell-doctor/php2shell-doctor/internal/model"
)

// Exit codes (stable API — see docs/USAGE.md):
const (
	ExitOK         = 0 // no vulnerable installs; at most config/staleness info
	ExitVulnerable = 1 // at least one VULNERABLE / EOL_VULNERABLE / STALE_WORKERS
	ExitVerify     = 2 // no hard-vulnerable, but VERIFY_VENDOR / UNKNOWN_VERSION present
	ExitError      = 3 // scan could not run (engine errors, bad arguments)
)

// DecideExit maps a report to the exit contract.
func DecideExit(rep *model.ScanReport) int {
	if rep == nil || (rep.Partial && len(rep.Installs) == 0) {
		return ExitError
	}
	vuln, verify := false, false
	for _, ir := range rep.Installs {
		switch ir.Verdict {
		case model.VerdictVulnerable, model.VerdictEOLVulnerable, model.VerdictStaleWorkers:
			vuln = true
		case model.VerdictVerifyVendor, model.VerdictPatchUnknownVer:
			verify = true
		}
	}
	switch {
	case vuln:
		return ExitVulnerable
	case verify:
		return ExitVerify
	}
	return ExitOK
}
