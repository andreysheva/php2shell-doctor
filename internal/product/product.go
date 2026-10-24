// Package product answers the appliance/product question — "is my
// ClearPass / ONTAP / SEPM affected?" — from the NCSC-NL php2shell
// SPDX 3 inventory (EUPL-1.2). The compiled SPDX document is not
// redistributed; it is fetched on demand (`db update --ncsc`) and
// cached locally.
package product

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Statuses produced by the NCSC VEX assessments.
const (
	StatusAffected          = "affected"
	StatusFixed             = "fixed"
	StatusNotAffected       = "not_affected"
	StatusUnderInvestigation = "under_investigation"
)

type spdxGraphEntry struct {
	Type          string   `json:"type"`
	SpdxID        string   `json:"spdxId"`
	Name          string   `json:"name"`
	Summary       string   `json:"summary"`
	Description   string   `json:"description"`
	Comment       string   `json:"comment"`
	From          string   `json:"from"`
	To            []string `json:"to"`
	RelationshipType string `json:"relationshipType"`
	ExternalIdentifier []struct {
		Type       string `json:"externalIdentifierType"`
		Identifier string `json:"identifier"`
	} `json:"externalIdentifier"`
}

type spdxDoc struct {
	Graph []spdxGraphEntry `json:"@graph"`
}

// Assessment is one product's per-CVE status.
type Assessment struct {
	Product    string            `json:"product"`
	Version    string            `json:"version,omitempty"`
	Statuses   map[string]string `json:"statuses"` // CVE -> status
	Summary    string            `json:"summary,omitempty"`
	Comment    string            `json:"comment,omitempty"`
	Source     string            `json:"source"`
}

// Inventory holds the parsed product assessments.
type Inventory struct {
	byProduct map[string][]Assessment // lowercase name -> assessments
	Count     int
}

// Load parses an NCSC SPDX3 JSON document.
func Load(data []byte) (*Inventory, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("ncsc spdx: %w", err)
	}
	inv := &Inventory{byProduct: map[string][]Assessment{}}
	// First pass: map every element id to its name (packages AND
	// vulnerabilities — VEX `from` points at the vulnerability's spdxId).
	idName := map[string]string{}
	for _, e := range doc.Graph {
		if e.SpdxID != "" && e.Name != "" {
			idName[e.SpdxID] = e.Name
		}
	}
	// Second pass: VEX relationships from vulnerability -> packages.
	for _, e := range doc.Graph {
		if !strings.HasPrefix(e.Type, "security_Vex") || !strings.HasSuffix(e.Type, "VulnAssessmentRelationship") {
			continue
		}
		cve := idName[e.From]
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		status := statusFromType(e.Type)
		if status == "" {
			continue
		}
		for _, to := range e.To {
			name := idName[to]
			if name == "" {
				continue
			}
			key := strings.ToLower(name)
			var a *Assessment
			for i := range inv.byProduct[key] {
				if inv.byProduct[key][i].Product == name {
					a = &inv.byProduct[key][i]
					break
				}
			}
			if a == nil {
				inv.byProduct[key] = append(inv.byProduct[key], Assessment{
					Product: name, Statuses: map[string]string{}, Source: "NCSC-NL/php2shell SPDX inventory (EUPL-1.2)",
					Summary: e.Summary, Comment: e.Comment,
				})
				a = &inv.byProduct[key][len(inv.byProduct[key])-1]
				inv.Count++
			}
			a.Statuses[cve] = status
		}
	}
	return inv, nil
}

// LoadFile reads and parses a cached SPDX document.
func LoadFile(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

func statusFromType(t string) string {
	switch {
	case strings.Contains(t, "Affected"):
		return StatusAffected
	case strings.Contains(t, "Fixed"):
		return StatusFixed
	case strings.Contains(t, "NotAffected"):
		return StatusNotAffected
	case strings.Contains(t, "UnderInvestigation"):
		return StatusUnderInvestigation
	}
	return ""
}

// Search finds assessments for products whose name contains q
// (case-insensitive).
func (inv *Inventory) Search(q string) []Assessment {
	var out []Assessment
	q = strings.ToLower(strings.TrimSpace(q))
	for key, list := range inv.byProduct {
		if q == "" || strings.Contains(key, q) {
			out = append(out, list...)
		}
	}
	// stable order by product name
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Product < out[j-1].Product; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
