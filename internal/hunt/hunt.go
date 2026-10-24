// Package hunt scans PHP/FPM/Apache logs for the documented php2shell
// exploitation signatures: worker-exit churn, OOM fatals correlated with
// request anomalies, HashTable overflow fatals and heap corruption
// messages. Read-only; never touches the web server.
package hunt

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/php2shell-doctor/php2shell-doctor/internal/model"
)

// Signature is one detectable log pattern.
type Signature struct {
	Name    string
	Re      *regexp.Regexp
	Level   string // "review" = worth investigating, "info" = context
	About   string
}

// Signatures are derived from the public php2shell research
// (calif.io/php2shell, CERT-EU 2026-018) and PHP bug #78876 history.
var Signatures = []Signature{
	{
		Name: "fpm_worker_exit_signal", Level: "review",
		Re:    regexp.MustCompile(`(?i)(child\s+\d+.*exited on signal|exited on signal 11|SIGSEGV|signal Segmentation fault|core dumped)`),
		About: "PHP-FPM/Apache worker died on a signal — the observable effect of the CVE-2026-109618 corruption path or an exploit crashing on an incompatible target.",
	},
	{
		Name: "oom_fatal", Level: "review",
		Re:    regexp.MustCompile(`(?i)Allowed memory size of \d+ bytes exhausted`),
		About: "OOM fatals are the CVE-2026-109618 trigger surface. Occasional ones are normal app behavior; bursts correlated with large POSTs deserve review.",
	},
	{
		Name: "hash_overflow_fatal", Level: "review",
		Re:    regexp.MustCompile(`(?i)Possible integer overflow in memory allocation`),
		About: "The HashTable allocation-overflow fatal — the exact code path implicated by the php2shell HashTable/rawkey analyses. Investigate the source requests.",
	},
	{
		Name: "zend_mm_heap_corrupted", Level: "review",
		Re:    regexp.MustCompile(`(?i)zend_mm_heap corrupted`),
		About: "Heap-corruption detection fired. Can be a bug in an extension; combined with worker exits it is a strong php2shell indicator.",
	},
	{
		Name: "fpm_startup_failure", Level: "info",
		Re:    regexp.MustCompile(`(?i)(WARNING: .*(failed|unable) to (start|spawn|read)|ERROR: .*(failed|unable))`),
		About: "FPM worker startup/spawn problems — context for interpreting other signatures.",
	},
	{
		Name: "max_children_exhausted", Level: "info",
		Re:    regexp.MustCompile(`(?i)server reached max_children`),
		About: "Worker exhaustion. Alone it is a capacity signal; alongside request anomalies it may reflect memory-pressure probing.",
	},
	{
		Name: "request_startup_fatal", Level: "review",
		Re:    regexp.MustCompile(`(?i)PHP Fatal error: .* on line 0`),
		About: "Fatal error at line 0 typically means it fired during request startup (before any application code ran) — the mod_php-relevant exploitation window.",
	},
	{
		Name: "upload_progress_context", Level: "info",
		Re:    regexp.MustCompile(`(?i)PHP_SESSION_UPLOAD_PROGRESS`),
		About: "Upload-progress markers in logs. Their presence alongside fatals matches the documented two-request exploit pattern.",
	},
}

// DefaultLogFiles returns the standard PHP/FPM/Apache log locations.
func DefaultLogFiles() []string {
	return []string{
		"/var/log/php*fpm*.log", "/var/log/php*fpm/error.log", "/var/log/php-fpm/*error*.log",
		"/var/log/apache2/error.log", "/var/log/apache2/*error*.log",
		"/var/log/httpd/error_log", "/var/log/httpd/*error*_log",
		"/var/log/nginx/error.log", "/var/log/duckboard/php.log",
		"/var/log/frankenphp.log", "/usr/local/lsws/logs/error.log",
	}
}

// timestampRe recognizes common log line prefixes to derive first/last
// seen: ISO (nginx/PHP-FPM pool logs), Apache "Mon Jan 02 15:04:05 2006",
// and PHP-FPM's native "[02-Jan-2006 15:04:05]".
var timestampRe = regexp.MustCompile(`^\[?(\w{3} \w{3} +\d+ \d+:\d+:\d+ \d{4}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\d{1,2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2})`)

// Scan reads log files (glob patterns allowed) and counts signature hits.
// It never follows pipes and caps per-file size to stay predictable.
func Scan(patterns []string, maxFileBytes int64) (model.HuntSummary, []string) {
	sum := model.HuntSummary{Signatures: []model.SignatureHit{}}
	var warnings []string
	counts := map[string]int64{}
	seen := map[string]bool{}
	var files []string

	for _, pat := range patterns {
		m, _ := expandGlob(pat)
		for _, f := range m {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil || fi.IsDir() {
			continue
		}
		if maxFileBytes > 0 && fi.Size() > maxFileBytes {
			warnings = append(warnings, "skipped (too large): "+f)
			continue
		}
		sum.FilesScanned++
		hits, lines, first, last := scanFile(f)
		sum.LinesScanned += lines
		for name, c := range hits {
			counts[name] += c
		}
		if first != nil && (sum.FirstSeen == nil || first.Before(*sum.FirstSeen)) {
			sum.FirstSeen = first
		}
		if last != nil && (sum.LastSeen == nil || last.After(*sum.LastSeen)) {
			sum.LastSeen = last
		}
	}
	for _, sig := range Signatures {
		if c := counts[sig.Name]; c > 0 {
			sum.Signatures = append(sum.Signatures, model.SignatureHit{
				Name: sig.Name, Count: c, Level: sig.Level, About: sig.About,
			})
		}
	}
	sum.Files = files
	return sum, warnings
}

func scanFile(path string) (map[string]int64, int64, *time.Time, *time.Time) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, nil
	}
	defer f.Close()
	hits := map[string]int64{}
	var lines int64
	var first, last *time.Time
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	now := time.Now()
	for sc.Scan() {
		line := sc.Text()
		lines++
		for i := range Signatures {
			if Signatures[i].Re.MatchString(line) {
				hits[Signatures[i].Name]++
			}
		}
		if m := timestampRe.FindStringSubmatch(line); m != nil {
			for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02 15:04:05", "Mon Jan 02 15:04:05 2006", "02-Jan-2006 15:04:05"} {
				if t, err := time.Parse(layout, m[1]); err == nil {
					// Apache omits the year on some formats; guard absurd dates
					if t.Year() > 2015 && t.Before(now.Add(24*time.Hour)) {
						if first == nil || t.Before(*first) {
							tt := t
							first = &tt
						}
						if last == nil || t.After(*last) {
							tt := t
							last = &tt
						}
					}
					break
				}
			}
		}
	}
	return hits, lines, first, last
}

func expandGlob(pat string) ([]string, error) {
	if !strings.ContainsAny(pat, "*?[") {
		return []string{pat}, nil
	}
	return filepath.Glob(pat)
}
