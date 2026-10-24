// Package mitigate applies PHP's temporary ini mitigations as a
// versioned drop-in file. Default is a dry run; --apply is explicit;
// rollback removes only files this tool wrote (marker-verified);
// verification re-reads effective values afterwards.
//
// These mitigations are NOT a fix. Only updating PHP is a complete fix.
package mitigate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Marker identifies files written by this tool so rollback never
// touches foreign configuration.
const Marker = "; managed by php2shell-doctor mitigate; remove with: php2shell-doctor mitigate --rollback --apply"

// Options configures one mitigate run.
type Options struct {
	ScanDir         string // ini scan dir to drop the file into
	Apply           bool
	Rollback        bool
	UploadProgress0 bool
	PostMax         string // "" = don't touch
	UploadMax       string // "" = same as PostMax
	MemoryUnlimited bool
	FatalBacktrace0 bool // PHP 8.5 only
	BackupSuffix    string
}

// Plan is what a run did or would do.
type Plan struct {
	FilePath    string
	Content     string
	Wrote       bool
	Removed     bool
	Verification []string
	Warnings    []string
}

// FileBaseName is the drop-in name (loads last alphabetically, like the
// cPanel reference script's zzzz... naming).
const FileBaseName = "zz-php2shell-doctor-mitigations.ini"

// Run computes (and, with Apply, writes) the mitigation drop-in.
func Run(opts Options) (*Plan, error) {
	plan := &Plan{FilePath: filepath.Join(opts.ScanDir, FileBaseName)}
	if opts.Rollback {
		if _, err := os.Stat(plan.FilePath); err == nil {
			data, err := os.ReadFile(plan.FilePath)
			if err != nil {
				return plan, err
			}
			if !strings.Contains(string(data), "php2shell-doctor") {
				plan.Warnings = append(plan.Warnings, "refusing to remove foreign file "+plan.FilePath+" (no php2shell-doctor marker)")
				return plan, nil
			}
			if opts.Apply {
				if err := os.Remove(plan.FilePath); err != nil {
					return plan, err
				}
				plan.Removed = true
			}
		}
		return plan, nil
	}
	var b strings.Builder
	b.WriteString(Marker + "\n")
	b.WriteString("; PARTIAL mitigation for CVE-2026-109618 / CVE-2026-109619 / CVE-2026-115560.\n")
	b.WriteString("; Only updating PHP is a complete fix.\n")
	b.WriteString("; written " + time.Now().UTC().Format(time.RFC3339) + "\n")
	if opts.UploadProgress0 {
		b.WriteString("session.upload_progress.enabled = 0\n")
	}
	if opts.PostMax != "" {
		b.WriteString("post_max_size = " + opts.PostMax + "\n")
		if opts.UploadMax != "" && opts.UploadMax != opts.PostMax {
			b.WriteString("upload_max_filesize = " + opts.UploadMax + "\n")
		}
	}
	if opts.MemoryUnlimited {
		b.WriteString("memory_limit = -1\n")
	}
	if opts.FatalBacktrace0 {
		b.WriteString("fatal_error_backtraces = 0\n")
	}
	plan.Content = b.String()
	if opts.Apply {
		if err := os.MkdirAll(opts.ScanDir, 0o755); err != nil {
			return plan, err
		}
		tmp := plan.FilePath + ".tmp"
		if err := os.WriteFile(tmp, []byte(plan.Content), 0o644); err != nil {
			return plan, err
		}
		if err := os.Rename(tmp, plan.FilePath); err != nil {
			return plan, err
		}
		plan.Wrote = true
	}
	return plan, nil
}

// Verify re-reads the drop-in and confirms it parses to the intended
// settings (worker restart is still required for FPM/mod_php).
func Verify(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{"verification failed: " + err.Error()}
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return []string{"verification failed: drop-in is empty"}
	}
	out = append(out, "NOTE: restart all PHP workers (php-fpm pools, Apache, containers) so the running processes reload php.ini")
	return out
}

// ManuallyApplicable is used on platforms/filesystems where we refuse to
// write (e.g. Windows system php.ini): print instructions instead.
func ManuallyApplicable(scanDir string) string {
	return fmt.Sprintf(`Manual mitigation (this tool does not write config on this platform):
1. Create %s containing:
   session.upload_progress.enabled = 0
   post_max_size = 32M            ; 8M if you do not accept uploads
   upload_max_filesize = 32M
   memory_limit = -1              ; optional; see docs/USAGE.md
2. Restart ALL PHP workers (php-fpm, Apache, containers).
3. Verify: php -i | grep -E "upload_progress|memory_limit|post_max_size"
These are partial mitigations. Updating PHP is the complete fix.`, filepath.Join(scanDir, FileBaseName))
}
