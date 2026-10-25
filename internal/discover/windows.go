package discover

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/andreysheva/php2shell-doctor/internal/execx"
	"github.com/andreysheva/php2shell-doctor/internal/model"
)

// execReg runs reg.exe to list PHP-named subkeys (Windows only).
func execReg(key string) string {
	r := execx.Run(15e9, "reg", "query", key)
	return r.Stdout
}

// parsePSCIMIJSON parses PowerShell ConvertTo-Json output of
// Win32_Process rows (single object or array).
func parsePSCIMIJSON(s string) []model.ProcessInfo {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return nil
	}
	type psProc struct {
		ProcessId      interface{} `json:"ProcessId"`
		Name           string      `json:"Name"`
		ExecutablePath string      `json:"ExecutablePath"`
		CommandLine    string      `json:"CommandLine"`
		CreationDate   string      `json:"CreationDate"`
	}
	var rows []psProc
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &rows); err != nil {
			return nil
		}
	} else {
		var one psProc
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return nil
		}
		rows = append(rows, one)
	}
	var out []model.ProcessInfo
	for _, p := range rows {
		pid := 0
		switch v := p.ProcessId.(type) {
		case float64:
			pid = int(v)
		case string:
			pid = parseIntSafe(v)
		}
		started := parseCIMDate(p.CreationDate)
		out = append(out, model.ProcessInfo{
			PID: pid, Name: p.Name, ExePath: p.ExecutablePath, Cmdline: p.CommandLine, Started: started,
		})
	}
	return out
}

// parseCIMDate parses PowerShell CIM datetime values like
// "20261024091500.123456+120" defensively (length varies across
// PowerShell/locale versions); unparseable values yield the zero time.
func parseCIMDate(s string) time.Time {
	s = strings.TrimSpace(s)
	dot := strings.IndexByte(s, '.')
	if dot < 14 || len(s) < 21 {
		return time.Time{}
	}
	tail := s[len(s)-5:] // offset such as "+120"
	if tail[0] != '+' && tail[0] != '-' {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405.000000-0700", s[:dot]+"000000"+tail)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseIntSafe(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
