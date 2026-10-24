// Package remote ingests external scanner results so remote probes and
// local ground truth can be reconciled in one report. Currently supports
// assetnote/php2shell-scanner JSON output (flexible schema).
package remote

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Finding is one normalized remote verdict.
type Finding struct {
	URL      string
	Verdict  string
	Reason   string
	Evidence string
	Scanner  string
}

// ParseAssetnoteJSON accepts the assetnote scanner output: either a bare
// array of result objects or an object wrapping one. Unknown field names
// are handled leniently; entries without a recognizable URL are skipped
// with a warning.
func ParseAssetnoteJSON(data []byte) ([]Finding, []string) {
	var warnings []string
	var rows []map[string]interface{}
	if err := json.Unmarshal(data, &rows); err != nil {
		var wrapped struct {
			Results []map[string]interface{} `json:"results"`
			Vulnerable []map[string]interface{} `json:"vulnerable"`
		}
		if err2 := json.Unmarshal(data, &wrapped); err2 != nil {
			return nil, []string{fmt.Sprintf("unrecognized JSON structure: %v / %v", err, err2)}
		}
		rows = append(rows, wrapped.Results...)
		rows = append(rows, wrapped.Vulnerable...)
	}
	var out []Finding
	for i, r := range rows {
		url := firstString(r, "url", "target", "host", "uri", "input")
		if url == "" {
			warnings = append(warnings, fmt.Sprintf("entry %d: no URL field found", i))
			continue
		}
		verdict := firstString(r, "verdict", "vulnerable", "result", "status", "classification")
		if verdict == "" {
			verdict = "unknown"
		}
		reason := firstString(r, "reason", "detail", "details", "message", "explanation")
		out = append(out, Finding{
			URL: url, Verdict: normalizeVerdict(verdict), Reason: reason, Scanner: "assetnote/php2shell-scanner",
		})
	}
	return out, warnings
}

func normalizeVerdict(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "vulnerable", "true", "yes", "vuln":
		return "VULNERABLE"
	case "not vulnerable", "not_vulnerable", "safe", "false", "no", "patched":
		return "NOT_VULNERABLE"
	case "unknown", "inconclusive":
		return "UNKNOWN"
	}
	return strings.ToUpper(v)
}

func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if strings.TrimSpace(t) != "" {
					return strings.TrimSpace(t)
				}
			case bool:
				if t {
					return "true"
				}
				return "false"
			}
		}
	}
	return ""
}
