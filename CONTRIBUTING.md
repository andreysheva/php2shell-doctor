# Contributing

Thank you for helping make php2shell response tooling better.

## The highest-value contribution: vendor-fix data

One verified line in `internal/vendordb/vendordb.json` protects every user
of that distro. Rules:

- A `fixed_revisions` entry must be traceable to a vendor advisory — link
  the USN/DSA/DLA/RHSA number in the entry's `advisories`.
- Set `verified_as_of` to the date you verified; bump `db_revision`.
- Vendors that backport invisibly get `policy: "verify"`, never a guessed
  revision. Never add a "fixed" claim without a source — a wrong entry
  would make the tool lie.
- Keep `data/vendordb.json` (published copy) identical to the embedded
  `internal/vendordb/vendordb.json` (CI checks).

## Code

- Go 1.22+, **standard library only** — CI rejects a `go.sum`. If you need
  a dependency, reimplement the small part you need instead.
- `go vet ./...` and `go test ./...` must pass on all three CI platforms.
- New behavior needs a test; bug fixes need a regression test.
- Finding codes (`VULN-PKG`, `CFG-UPLOADPROGRESS-ON`, …) are a stable API —
  additions fine, renames are a breaking change and need a schema bump.
- Follow the existing conservative-verdict rule: **never classify an
  unverifiable state as safe.** Add a `VERIFY_*` path instead.

## Testing

If you change discovery, classification or staleness logic, test on a real
Linux host (a WSL2 VM is fine): install PHP from the distro, start php-fpm,
patch, restart — the staleness and backport paths have caught every serious
bug so far.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) — please use private security advisories,
not public issues.
