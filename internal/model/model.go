// Package model defines the shared data structures passed between the
// discovery, classification, audit and reporting engines.
package model

import "time"

// Verdict is the overall patch-state classification of one PHP install.
type Verdict string

const (
	VerdictPatched         Verdict = "PATCHED"
	VerdictVulnerable      Verdict = "VULNERABLE"
	VerdictEOLVulnerable   Verdict = "EOL_VULNERABLE"
	VerdictVerifyVendor    Verdict = "VERIFY_VENDOR"
	VerdictPatchUnknownVer Verdict = "UNKNOWN_VERSION"
	VerdictStaleWorkers    Verdict = "PATCHED_STALE_WORKERS"
	VerdictNotRunning      Verdict = "NOT_WEB_SERVING"
)

// ProvenanceKind describes how the PHP runtime was installed; it decides
// which vendor-fix policy applies.
type ProvenanceKind string

const (
	ProvStandalone ProvenanceKind = "standalone"
	ProvDpkg       ProvenanceKind = "dpkg"
	ProvRpm        ProvenanceKind = "rpm"
	ProvApk        ProvenanceKind = "apk"
	ProvCpanel     ProvenanceKind = "cpanel"
	ProvPlesk      ProvenanceKind = "plesk"
	ProvHomebrew   ProvenanceKind = "homebrew"
	ProvScoop      ProvenanceKind = "scoop"
	ProvChoco      ProvenanceKind = "choco"
	ProvAsdf       ProvenanceKind = "asdf"
	ProvImageTag   ProvenanceKind = "image-tag"
)

// SAPI values inferred during discovery. SAPI determines exploitability
// shape: mod_php is exploitable during request startup before application
// code; FPM needs a post-startup fatal plus a follow-up request.
type SAPI string

const (
	SAPICLI       SAPI = "cli"
	SAPIFPM       SAPI = "fpm"
	SAPICGI       SAPI = "cgi"
	SAPIApacheMod SAPI = "apache-mod_php"
	SAPILiteSpeed SAPI = "litespeed"
	SAPIFranken   SAPI = "frankenphp"
	SAPIUnknown   SAPI = "unknown"
)

// Install is one discovered PHP runtime.
type Install struct {
	ID             string         `json:"id"`
	BinaryPath     string         `json:"binary_path,omitempty"`
	Root           string         `json:"root,omitempty"`
	VersionRaw     string         `json:"version_raw,omitempty"` // e.g. "8.3.6-0ubuntu0.24.04.13"
	Upstream       string         `json:"upstream_version,omitempty"`
	Branch         string         `json:"branch,omitempty"` // "8.3"
	Source         string         `json:"source"`           // how it was found
	Provenance     ProvenanceKind `json:"provenance"`
	PackageName    string         `json:"package_name,omitempty"`
	PackageVersion string         `json:"package_version,omitempty"` // full distro revision
	VendorID       string         `json:"vendor_id,omitempty"`       // matched vendordb vendor
	SAPIs          []SAPI         `json:"sapis,omitempty"`
	IniFile        string         `json:"ini_file,omitempty"`
	ScanDir        string         `json:"scan_dir,omitempty"`
	ContainerID    string         `json:"container_id,omitempty"`
	ContainerImage string         `json:"container_image,omitempty"`
	TagPartial     bool           `json:"tag_partial,omitempty"` // image tag lacks patch version (e.g. "8.3-apache")
	BinaryMtime    time.Time      `json:"binary_mtime,omitempty"`
	Note           string         `json:"note,omitempty"`
}

// Severity levels used across all finding categories.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Finding categories.
type Category string

const (
	CatVersion   Category = "version"
	CatStaleness Category = "staleness"
	CatConfig    Category = "config"
	CatProduct   Category = "product"
	CatRemote    Category = "remote"
	CatHunt      Category = "hunt"
)

// Finding is one actionable observation. Codes are stable API; see
// docs/USAGE.md for the catalogue.
type Finding struct {
	InstallID string   `json:"install_id,omitempty"`
	Severity  Severity `json:"severity"`
	Category  Category `json:"category"`
	Code      string   `json:"code"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail,omitempty"`
	CVEs      []string `json:"cves,omitempty"`
	Reference string   `json:"reference,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
}

// EffectiveConfig is the resolved runtime configuration for an install
// (from executing the binary, or static analysis fallback).
type EffectiveConfig struct {
	Values  map[string]string `json:"values"`
	Source  string            `json:"source"` // "executed" | "static"
	IniFile string            `json:"ini_file,omitempty"`
}

// ProcessInfo describes a running PHP-related process for staleness checks.
type ProcessInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	ExePath     string    `json:"exe_path,omitempty"`
	Cmdline     string    `json:"cmdline,omitempty"`
	Started     time.Time `json:"started"`
	BinaryMtime time.Time `json:"binary_mtime,omitempty"`
}

// InstallReport bundles everything the scanners produced for one install.
type InstallReport struct {
	Install   Install         `json:"install"`
	Verdict   Verdict         `json:"verdict"`
	Reason    string          `json:"reason"`
	PerCVE    map[string]string `json:"per_cve_status"` // CVE -> affected | fixed | unknown
	Findings  []Finding       `json:"findings,omitempty"`
	Config    *EffectiveConfig `json:"config,omitempty"`
}

// RemoteFinding is a verdict imported from an external scanner
// (assetnote/php2shell-scanner JSON).
type RemoteFinding struct {
	URL      string `json:"url"`
	Verdict  string `json:"verdict"`
	Reason   string `json:"reason,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// ScanReport is the top-level result object for one scan.
type ScanReport struct {
	SchemaVersion int              `json:"schema_version"`
	ToolName      string           `json:"tool"`
	ToolVersion   string           `json:"tool_version"`
	DBRevision    string           `json:"db_revision"`
	Generated     time.Time        `json:"generated"`
	Hostname      string           `json:"host"`
	OS            string           `json:"os"`
	Arch          string           `json:"arch"`
	Installs      []InstallReport  `json:"installs"`
	Remote        []RemoteFinding  `json:"remote,omitempty"`
	HuntSummary   *HuntSummary     `json:"hunt,omitempty"`
	Warnings      []string         `json:"warnings"`
	EngineErrors  []string         `json:"engine_errors"`
	Partial       bool             `json:"partial"`
}

// HuntSummary aggregates log-signature hits from hunt mode.
type HuntSummary struct {
	FilesScanned int                `json:"files_scanned"`
	LinesScanned int64              `json:"lines_scanned"`
	Signatures   []SignatureHit     `json:"signatures"`
	FirstSeen    *time.Time         `json:"first_seen,omitempty"`
	LastSeen     *time.Time         `json:"last_seen,omitempty"`
	Files        []string           `json:"files"`
}

// SignatureHit is a count of one log signature.
type SignatureHit struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Level string `json:"level"` // review | info
	About string `json:"about"`
}
