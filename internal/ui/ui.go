// Package ui provides terminal polish for php2shell-doctor: ANSI colors,
// an ASCII banner, spinners and summary boxes. Everything is
// conservative by design:
//
//   - colors render only on an interactive TTY; NO_COLOR, TERM=dumb,
//     --no-color disable them; FORCE_COLOR=1 forces them on for demos/CI
//   - spinners write to stderr with a fixed frame rate and always clear
//     their line, so piped output stays clean
//   - machine-readable outputs (JSON/SARIF/CSV/CycloneDX) never touch
//     this package
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var enabled = false

// Init decides whether styling is on. Call once at startup.
// explicitNoColor is the --no-color flag.
func Init(explicitNoColor bool) {
	if explicitNoColor {
		enabled = false
		return
	}
	if os.Getenv("NO_COLOR") != "" {
		enabled = false
		return
	}
	if os.Getenv("FORCE_COLOR") != "" && os.Getenv("FORCE_COLOR") != "0" {
		enabled = true
		return
	}
	if t := os.Getenv("TERM"); t == "dumb" {
		enabled = false
		return
	}
	enabled = isTTY(os.Stdout)
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Enabled reports whether styling is active.
func Enabled() bool { return enabled }

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGrey   = "\x1b[90m"
)

func wrap(code, s string) string {
	if !enabled {
		return s
	}
	return code + s + ansiReset
}

func Red(s string) string    { return wrap(ansiRed, s) }
func Green(s string) string  { return wrap(ansiGreen, s) }
func Yellow(s string) string { return wrap(ansiYellow, s) }
func Cyan(s string) string   { return wrap(ansiCyan, s) }
func Grey(s string) string   { return wrap(ansiGrey, s) }
func Bold(s string) string   { return wrap(ansiBold, s) }
func Dim(s string) string    { return wrap(ansiDim, s) }

// VerdictColor returns the color function for a verdict string.
func VerdictColor(verdict string) func(string) string {
	switch verdict {
	case "PATCHED":
		return Green
	case "VULNERABLE", "EOL_VULNERABLE", "PATCHED_STALE_WORKERS":
		return Red
	case "VERIFY_VENDOR":
		return Yellow
	default: // UNKNOWN_VERSION and anything else
		return Cyan
	}
}

// VerdictSymbol is a one-glyph marker for a verdict.
func VerdictSymbol(verdict string) string {
	switch verdict {
	case "PATCHED":
		return Green("✔")
	case "VULNERABLE", "EOL_VULNERABLE":
		return Red("✘")
	case "PATCHED_STALE_WORKERS":
		return Red("↻")
	case "VERIFY_VENDOR":
		return Yellow("⚠")
	default:
		return Cyan("?")
	}
}

// SeverityColor returns the color function for a severity.
func SeverityColor(sev string) func(string) string {
	switch sev {
	case "critical", "high":
		return Red
	case "medium":
		return Yellow
	case "low":
		return Cyan
	}
	return Grey
}

const bannerArt = `       _ _                          _
  _ __(_|_) __ _  ___  _   _ ___    ___ __ _| |__  _   _ ___
 | '_ \| | |/ _` + "`" + ` |/ _ \| | | / __|  / __/ _` + "`" + ` | '_ \| | | / __|
 | |_) | | | (_| | (_) | |_| \__ \ | (_| (_| | | | | |_| \__ \
 | .__/|_|_|\__, |\___/ \__,_|___/  \___\__,_|_| |_|\__, |___/
 |_|        |___/                                   |___/  `

// Banner returns the stylized startup text (already colored when enabled).
func Banner(version, dbRevision string) string {
	var b strings.Builder
	if enabled {
		b.WriteString(Cyan(bannerArt))
	} else {
		b.WriteString(bannerArt)
	}
	b.WriteString("\n")
	sub := fmt.Sprintf("  the safe php2shell checker · v%s · vendor DB %s", version, dbRevision)
	b.WriteString(Bold(sub))
	b.WriteString("\n  CVE-2026-109618 · CVE-2026-109619 · config surface of CVE-2026-115560\n")
	b.WriteString(Dim("  local-first · read-only by default · zero network\n"))
	return b.String()
}

// Spinner is a minimal TTY spinner. When styling is disabled it prints
// nothing at all (piped/CI logs stay clean); Start/Stop are safe no-ops.
type Spinner struct {
	msg   string
	stop  chan struct{}
	done  sync.WaitGroup
	mu    sync.Mutex
	last  string // final line printed by Stop, for length clearing
	anim  bool
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// NewSpinner starts animating msg on stderr. Returns nil when styling is
// disabled (all methods are nil-safe).
func NewSpinner(msg string) *Spinner {
	if !enabled {
		return nil
	}
	s := &Spinner{msg: msg, stop: make(chan struct{}), anim: true}
	s.done.Add(1)
	go s.run()
	return s
}

func (s *Spinner) run() {
	defer s.done.Done()
	i := 0
	t := time.NewTicker(90 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			frame := spinnerFrames[i%len(spinnerFrames)]
			line := fmt.Sprintf("\r\x1b[K%s %s", Cyan(frame), s.msg)
			fmt.Fprint(os.Stderr, line)
			s.last = line
			s.mu.Unlock()
			i++
		}
	}
}

// Stop ends the spinner and prints a final colored line: mark + text.
func (s *Spinner) Stop(mark, text string) {
	if s == nil {
		return
	}
	close(s.stop)
	s.done.Wait()
	var colored string
	switch mark {
	case "ok":
		colored = Green("✔")
	case "warn":
		colored = Yellow("⚠")
	case "fail":
		colored = Red("✘")
	default:
		colored = mark
	}
	fmt.Fprintf(os.Stderr, "\r\x1b[K%s %s\n", colored, text)
}

// Box renders a summary box. Unicode box drawing when styling is on,
// plain ASCII otherwise.
func Box(title string, lines []string) string {
	inner := len(title)
	for _, l := range lines {
		if w := visibleWidth(l); w > inner {
			inner = w
		}
	}
	var b strings.Builder
	if enabled {
		b.WriteString("┌" + strings.Repeat("─", inner+2) + "┐\n")
		if title != "" {
			b.WriteString("│ " + Bold(pad(title, inner)) + " │\n")
			b.WriteString("├" + strings.Repeat("─", inner+2) + "┤\n")
		}
		for _, l := range lines {
			b.WriteString("│ " + pad(l, inner) + " │\n")
		}
		b.WriteString("└" + strings.Repeat("─", inner+2) + "┘\n")
	} else {
		b.WriteString("+" + strings.Repeat("-", inner+2) + "+\n")
		if title != "" {
			b.WriteString("| " + pad(title, inner) + " |\n")
			b.WriteString("+" + strings.Repeat("-", inner+2) + "+\n")
		}
		for _, l := range lines {
			b.WriteString("| " + pad(l, inner) + " |\n")
		}
		b.WriteString("+" + strings.Repeat("-", inner+2) + "+\n")
	}
	return b.String()
}

// visibleWidth ignores ANSI escape sequences so colored lines pad right.
func visibleWidth(s string) int {
	w := 0
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			w++
		}
	}
	return w
}

func pad(s string, w int) string {
	if d := w - visibleWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}
