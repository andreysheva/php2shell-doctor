# Security Policy

## Reporting a vulnerability

Report security issues in php2shell-doctor itself via GitHub Security
Advisories ("Report a vulnerability" on the Security tab) or by email to
the maintainers listed in the repo profile. Please do not open public
issues for security problems.

Expect an initial response within 7 days and a fix or mitigation plan
within 30 days for confirmed issues. Credit is given unless you prefer
otherwise.

## Scope

In scope: anything that breaks the safety contract — network calls not
behind explicit flags, writes outside the documented paths, exploit-like
behavior (the scanner never sends crafted requests or induces OOM),
verdict logic that could silently claim safety (`PATCHED` without
evidence), path traversal via vendordb/remote-json parsing, command
injection via file contents, or a regression that makes `mitigate`
touch foreign files. For the full read/write surface, see
[docs/USAGE.md](docs/USAGE.md) (JSON schema) and the `scan` flow in
`cmd/php2shell-doctor`.

Out of scope: vulnerabilities in PHP itself (report those per
[php.net's process](https://www.php.net/security/)); verdicts derived
correctly from incorrect vendordb entries (fix those via PR per
the vendordb JSON — that is data quality, not a code vulnerability).

## Supported versions

The latest release line receives security fixes. The vendordb JSON is
correctable in any release via `--vendordb` override immediately.

## Supply chain

- The binary is stdlib-only: no third-party Go dependencies, so the
  dependency surface is the Go toolchain itself.
- Releases are built in GitHub Actions with pinned Go versions; assets
  are cosign-signed (verification steps in the release notes).
- The embedded vendordb carries `db_revision` and per-entry sources;
  self-test validates the embedded DB on install.
