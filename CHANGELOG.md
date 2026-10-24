# Changelog

## 1.0.0 — 2026-10-24

Initial release.

### Engines
- Discovery: PATH, dpkg/rpm/apk package databases, cPanel EA4, Plesk,
  LiteSpeed, Homebrew/scoop/choco/asdf/XAMPP/wamp/laragon, Windows
  registry hints, FPM pools, Apache mod_php markers, FrankenPHP,
  php-cgi, running processes (procfs/ps/PowerShell-CIM), Docker
  containers + images (`--docker`, `--docker-exec`).
- Classification: upstream + dpkg/rpm revision comparison against the
  versioned vendor-fix database; verdicts PATCHED / VULNERABLE /
  EOL_VULNERABLE / PATCHED_STALE_WORKERS / VERIFY_VENDOR /
  UNKNOWN_VERSION; conservative fallbacks (never a silent safe).
- Staleness: running workers predating the patched binary.
- Config audit: effective-ini resolution (php.ini → scan-dir → FPM
  pools → .user.ini/.htaccess), session.upload_progress,
  serialize_handler (CVE-2026-115560 pattern), memory_limit,
  post_max_size/upload_max_filesize, fatal_error_backtraces (8.5),
  per-directory override detection.
- Product VEX: NCSC-NL SPDX3 inventory lookup (`product`, 751
  products, fetched on explicit request).
- Hunt: read-only log signature scanning (worker exit signals, OOM
  fatals, HashTable overflow fatal, heap corruption, line-0 fatals).
- Remote ingestion: assetnote/php2shell-scanner JSON reconciliation.

### Interfaces
- Terminal UX: ASCII banner, status spinners (stderr), verdict glyphs,
  severity-colored findings, summary box with elapsed time; TTY-aware
  with NO_COLOR/TERM=dumb/--no-color/FORCE_COLOR support; machine
  outputs stay ANSI-free (`internal/ui`, stdlib-only).
- Outputs: human text, JSON (schema v1), CSV, SARIF 2.1.0, CycloneDX 1.5.
- Exit-code contract: 0/1/2/3.
- `mitigate`: dry-run-default drop-in writer with marker-based
  rollback and post-apply verification.
- `self-test`: engine consistency checks.

### Launch hardening
- Per-install analysis pipeline (classify + config audit + staleness)
  is panic-isolated: a pathological binary degrades to an
  `ANALYSIS-PANIC` finding instead of aborting the scan.
- Effective configuration is now embedded in JSON reports
  (`installs[].config`) for evidence trails.
- Windows process inventory uses the real `ExecutablePath` and a
  defensive CIM date parser; removed dead code and pointless
  indirections (stale.AttachBinaryMtimes, hunt glob stub).
- README rewritten to scanner-repo standard; CONTRIBUTING.md added.

### Validation
- Validated against 12 real-world deployment scenarios (Ubuntu 22.04/24.04,
  Debian 12, Alpine 3.20, Amazon Linux 2023; cPanel/source-build/multi-PHP/
  mitigated/air-gap/forensics; Windows IIS layout; lying docker tags via
  --docker-exec). 6 defects found during that validation and fixed with
  regression tests.

### Data
- Vendor-fix database 2026-10-24.01: upstream fixed set
  (8.5.12/8.4.27/8.3.36/8.2.35), Ubuntu noble revision backport
  (USN-8948-1/-2), Debian bookworm/trixie/sid (DLA-4848-1,
  DSA-6574-1), redhat-family/remi/sury/alpine/cpanel/plesk/
  cloudlinux/homebrew/docker policies. CC0-1.0 as open data.
