package product

import "testing"

const fixture = `{
  "@graph": [
    {"type": "Tool", "spdxId": "urn:php2shell:tool:t", "name": "builder"},
    {"type": "security_Vulnerability", "spdxId": "urn:php2shell:inventory:vulnerability:CVE-2026-109618", "name": "CVE-2026-109618"},
    {"type": "security_Vulnerability", "spdxId": "urn:php2shell:inventory:vulnerability:CVE-2026-109619", "name": "CVE-2026-109619"},
    {"type": "software_Package", "spdxId": "urn:php2shell:inventory:package:P1", "name": "Fictional Appliance", "software_packageVersion": "6.14.0"},
    {"type": "software_Package", "spdxId": "urn:php2shell:inventory:package:P2", "name": "Fixed Widget"},
    {"type": "security_VexAffectedVulnAssessmentRelationship",
     "spdxId": "urn:php2shell:vex:a1",
     "from": "urn:php2shell:inventory:vulnerability:CVE-2026-109618",
     "to": ["urn:php2shell:inventory:package:P1"],
     "summary": "Vulnerable"},
    {"type": "security_VexAffectedVulnAssessmentRelationship",
     "spdxId": "urn:php2shell:vex:a2",
     "from": "urn:php2shell:inventory:vulnerability:CVE-2026-109619",
     "to": ["urn:php2shell:inventory:package:P1"],
     "summary": "Vulnerable"},
    {"type": "security_VexFixedVulnAssessmentRelationship",
     "spdxId": "urn:php2shell:vex:f1",
     "from": "urn:php2shell:inventory:vulnerability:CVE-2026-109618",
     "to": ["urn:php2shell:inventory:package:P2"]},
    {"type": "security_VexUnderInvestigationVulnAssessmentRelationship",
     "spdxId": "urn:php2shell:vex:u1",
     "from": "urn:php2shell:inventory:vulnerability:CVE-2026-109619",
     "to": ["urn:php2shell:inventory:package:P2"]}
  ]
}`

func TestLoadAndSearch(t *testing.T) {
	inv, err := Load([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Count != 2 {
		t.Fatalf("count = %d want 2", inv.Count)
	}
	res := inv.Search("fictional")
	if len(res) != 1 || res[0].Product != "Fictional Appliance" {
		t.Fatalf("search wrong: %+v", res)
	}
	if res[0].Statuses["CVE-2026-109618"] != StatusAffected || res[0].Statuses["CVE-2026-109619"] != StatusAffected {
		t.Fatalf("statuses wrong: %+v", res[0].Statuses)
	}
	res = inv.Search("fixed widget")
	if len(res) != 1 || res[0].Statuses["CVE-2026-109618"] != StatusFixed || res[0].Statuses["CVE-2026-109619"] != StatusUnderInvestigation {
		t.Fatalf("fixed/under-investigation wrong: %+v", res)
	}
	if len(inv.Search("nomatch")) != 0 {
		t.Fatal("expected empty result")
	}
}
