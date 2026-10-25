// Package stale detects workers still running pre-upgrade code: a
// patched binary on disk does not help while php-fpm children, Apache
// children or long-running PHP servers still execute the old image.
// After a patch event this is the single most common real-world gap.
package stale

import (
	"path/filepath"
	"strings"

	"github.com/andreysheva/php2shell-doctor/internal/model"
)

// Result summarizes staleness for one install.
type Result struct {
	StaleProcesses []model.ProcessInfo
	Checked        int
}

// Check matches processes against a patched install. A process is stale
// when its executable is the (now patched) binary path and it started
// before the binary's last modification time. When the binary mtime is
// unknown (custom installs), nothing is asserted — no false alarms.
func Check(inst model.InstallReport, procs []model.ProcessInfo) Result {
	var out Result
	if inst.Verdict != model.VerdictPatched {
		return out
	}
	bin := inst.Install.BinaryPath
	if bin == "" || inst.Install.BinaryMtime.IsZero() {
		return out // no binary mtime known: assert nothing, no false alarms
	}
	binMtime := inst.Install.BinaryMtime
	for _, p := range procs {
		if !procMatchesBinary(p, bin) {
			continue
		}
		out.Checked++
		if !p.Started.IsZero() && p.Started.Before(binMtime) {
			out.StaleProcesses = append(out.StaleProcesses, p)
		}
	}
	return out
}

// procMatchesBinary compares the process's resolved executable with the
// install binary. Name/cmdline heuristics apply only when no exe path is
// known (e.g. macOS ps output); they require the basename to EQUAL, not
// merely prefix-match — otherwise a "php"-named binary would claim every
// php-fpm worker on the host.
func procMatchesBinary(p model.ProcessInfo, bin string) bool {
	if p.ExePath != "" {
		return samePath(p.ExePath, bin) || sameRealPath(p.ExePath, bin)
	}
	// cmdline "php-fpm: master process" style: compare first token's base
	// name exactly.
	return strings.EqualFold(baseName(firstToken(p.Cmdline)), baseName(bin))
}

func firstToken(s string) string {
	if i := strings.IndexAny(s, " 	"); i >= 0 {
		return s[:i]
	}
	return s
}

// sameRealPath resolves symlinks on both sides when possible.
func sameRealPath(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 == nil && err2 == nil {
		return strings.EqualFold(ra, rb)
	}
	return false
}

func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// MergeIntoReport appends staleness findings to the install report.
func MergeIntoReport(rep *model.InstallReport, res Result) {
	if len(res.StaleProcesses) == 0 {
		return
	}
	var pids []string
	for _, p := range res.StaleProcesses {
		pids = append(pids, strings.TrimSpace(p.Name+"#"+itoa(p.PID)))
	}
	rep.Findings = append(rep.Findings, model.Finding{
		Severity: model.SevHigh, Category: model.CatStaleness, Code: "STALE-WORKERS",
		Title: "Running PHP workers predate the patched binary",
		Detail: "The binary on disk is patched, but these processes started before it changed and still run the vulnerable code: " +
			strings.Join(pids, ", ") + ". Restart the PHP-FPM pools / Apache / container so every worker picks up the fix.",
		CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"},
	})
	rep.Verdict = model.VerdictStaleWorkers
	rep.Reason = "patched on disk but at least one running worker predates the patch; restart required"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
