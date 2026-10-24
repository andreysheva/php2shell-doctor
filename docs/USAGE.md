# Usage reference

Every command, flag, output field, finding code and the JSON schema.

## Commands

### `scan` (default)

Discovers PHP installations and classifies php2shell patch state.

```
php2shell-doctor scan [flags]
```

| Flag | Effect |
|---|---|
| `--json` | JSON output (schema v1) to stdout |
| `--csv` | CSV output (one row per finding) |
| `--sarif` | SARIF 2.1.0 (GitHub code scanning / DefectDojo) |
| `--cyclonedx` | CycloneDX 1.5 component list of PHP runtimes |
| `-o FILE` | write output to FILE instead of stdout |
| `--no-color` | disable colored output (auto-disabled when piped; `NO_COLOR` env respected, `FORCE_COLOR=1` forces on) |
| `--no-exec` | never execute discovered PHP binaries (banner/static analysis only; use in hardened environments where even `php -r` is unwanted) |
| `--no-processes` | skip running-process enumeration |
| `--docker` | inspect docker CLI: running containers + local images |
| `--docker-exec` | additionally run `php -v` / `frankenphp php-v` inside running containers (read-only; the only way to trust custom-built images) |
| `--extra-path DIR/BIN` | additional php binary to check (repeatable via commas) |
| `--vendordb FILE` | override the embedded vendor-fix DB (air-gapped updates) |
| `--hunt` | read-only scan of PHP/FPM/Apache logs for exploitation signatures |
| `--log-files a,b` | log paths/globs for `--hunt` (default: standard locations) |
| `--remote-json FILE/-` | ingest assetnote/php2shell-scanner JSON and reconcile |
| `--spdx FILE` | NCSC SPDX3 inventory: loads product counts into report notes |

Discovery engines are failure-isolated: one broken engine (e.g. no
docker CLI) degrades to `partial: true` with an engine error note —
it never aborts the scan.

### `mitigate`

Applies PHP's temporary ini mitigations as one marker-tagged drop-in
file. **Dry run by default.** Not a fix — patching is the fix.

```
php2shell-doctor mitigate [--apply] [--rollback] [--scan-dir D]
                          [--post-max 32M] [--memory-unlimited]
                          [--fatal-backtraces-off]
```

- Writes `zz-php2shell-doctor-mitigations.ini` into the ini scan dir
  (last alphabetically → wins the merge, mirroring the NCSC cPanel
  script's approach).
- `--rollback` removes **only** files carrying this tool's marker; it
  refuses foreign files.
- On Windows the command prints manual instructions instead of writing.
- After applying: **restart every PHP worker** (FPM pools, Apache,
  containers). The tool reminds you; it does not restart services for
  you (that is a state change your orchestration should own).

Mitigations applied (each optional):

| Setting | Addresses | Trade-off |
|---|---|---|
| `session.upload_progress.enabled = 0` | CVE-2026-109619 vector, CVE-2026-115560 surface | may break upload progress bars |
| `post_max_size` / `upload_max_filesize` ceiling | CVE-2026-109618 allocation control | smaller upload ceiling |
| `memory_limit = -1` | removes the PHP-level OOM trigger | shifts OOM risk to the OS; use cgroup/container limits |
| `fatal_error_backtraces = 0` (PHP 8.5) | CVE-2026-109619 handling | loss of fatal backtraces |

### `product`

Look up appliances/embedded products in the NCSC-NL SPDX inventory.

```
php2shell-doctor product --update          # one explicit network fetch
php2shell-doctor product -q ClearPass
php2shell-doctor product -q ONTAP
```

Statuses come straight from the NCSC VEX assessments:
`affected`, `fixed`, `not_affected`, `under_investigation`. The tool
reports them verbatim with their caveats.

### `db`

Prints the vendor-fix database revision and upstream fixed versions.
Use `scan --vendordb FILE` to run against a newer/older DB file.

### `self-test`

Runs engine self-checks (version comparators, vendor policies, the
Ubuntu-backport case, classification guards). Non-zero exit on failure.
Run it after building and after replacing the vendordb.

### `version`

Prints the version.

## Exit codes

| Code | Meaning | Typical consumer action |
|---|---|---|
| 0 | no vulnerable installs | continue |
| 1 | `VULNERABLE` / `EOL_VULNERABLE` / `PATCHED_STALE_WORKERS` present | fail the gate / page someone |
| 2 | only `VERIFY_VENDOR` / `UNKNOWN_VERSION` | route to a human with the printed advisory references |
| 3 | scan error (bad args, no DB) | fix invocation |

## Finding-code catalogue (stable API)

### version category

| Code | Severity | Meaning |
|---|---|---|
| `VULN-PKG` | critical | distro package before the verified fixed revision |
| `VULN-UPSTREAM` | critical | upstream version before the fixed release |
| `VULN-EOL` | critical | end-of-life branch, no fix will ever ship |
| `VERIFY-BACKPORT` | high | vendor backports invisibly; confirm against the cited advisory |
| `VERIFY-UNKNOWN-VENDOR` | high | vendor not in DB; fix state unverifiable |
| `VER-UNKNOWN` | medium | no version could be determined |
| `IMG-TAG-AMBIGUOUS` | medium | image tag lacks a patch version (`php:8.3-apache`) |
| `IMG-VER-UNKNOWN` | medium | running container version unknown; re-run with `--docker-exec` |
| `PATCHED` / `PATCHED-UPSTREAM` | info | verified fixed |
| `SAPI-MODPHP` | high | mod_php present: exploitation can complete before application code runs |

### staleness category

| Code | Severity | Meaning |
|---|---|---|
| `STALE-WORKERS` | high | patched binary on disk, running workers predate the patch → restart required |

### config category

| Code | Severity | Meaning |
|---|---|---|
| `CFG-UPLOADPROGRESS-ON` | high | `session.upload_progress` enabled (CVE-2026-109619 vector / 115560 surface) |
| `CFG-UPLOADPROGRESS-OFF` | info | mitigation present |
| `CFG-115560-HANDLER` | medium | `serialize_handler=php_binary/php_serialize` + runtime switching pattern |
| `CFG-MEMORY-FINITE` | medium | finite `memory_limit` is the CVE-2026-109618 OOM trigger surface |
| `CFG-MEMORY-UNLIMITED` | info | `memory_limit=-1` mitigation present |
| `CFG-POSTMAX-LARGE` | medium | large `post_max_size` (bypassable via chunked/HTTP2 anyway) |
| `CFG-UPLOAD-GT-POST` | low | `upload_max_filesize` > `post_max_size` (dead value) |
| `CFG-FATAL-BACKTRACE` | medium | PHP 8.5 `fatal_error_backtraces` enabled |
| `CFG-OVERRIDE-UPLOADPROGRESS` | high | `.user.ini`/`.htaccess` re-enables upload_progress per-directory |
| `CFG-OVERRIDE-MEMORY` | medium | per-directory finite `memory_limit` re-introduces the OOM surface |

### hunt category (via `--hunt`, summarized in `hunt.signatures`)

`fpm_worker_exit_signal`, `oom_fatal`, `hash_overflow_fatal`,
`zend_mm_heap_corrupted`, `request_startup_fatal` (level: **review**);
`fpm_startup_failure`, `max_children_exhausted`, `upload_progress_context`
(level: **info**). Counts are context, not proof — correlate with the
exploitation pattern documented at calif.io/php2shell before declaring
compromise.

## JSON schema (v1)

Top level:

```jsonc
{
  "schema_version": 1,
  "tool": "php2shell-doctor",
  "tool_version": "1.0.0",
  "db_revision": "2026-10-24.01",
  "generated": "2026-10-24T12:13:38Z",
  "host": "web01", "os": "linux", "arch": "amd64",
  "installs": [ /* InstallReport[] */ ],
  "remote": [ /* ingested assetnote findings */ ],
  "hunt": { "files_scanned": 3, "lines_scanned": 12345, "signatures": [ /* SignatureHit */ ] },
  "warnings": ["..."],
  "engine_errors": ["..."],
  "partial": false
}
```

`InstallReport`:

```jsonc
{
  "install": {
    "id": "install-1",
    "binary_path": "/usr/bin/php8.3",
    "version_raw": "8.3.6-0ubuntu0.24.04.13",
    "upstream_version": "8.3.6",
    "branch": "8.3",
    "source": "distro-packages",
    "provenance": "dpkg",
    "package_name": "php8.3",
    "package_version": "8.3.6-0ubuntu0.24.04.13",
    "vendor_id": "ubuntu",
    "sapis": ["cli", "fpm"],
    "ini_file": "/etc/php/8.3/cli/php.ini",
    "scan_dir": "/etc/php/8.3/cli/conf.d",
    "container_id": "...", "container_image": "...", "tag_partial": false,
    "note": "..."
  },
  "verdict": "PATCHED",
  "reason": "vendor ubuntu package php8.3 8.3.6-0ubuntu0.24.04.13 is at/after the verified fixed revision (...); advisory: USN-8948-1, USN-8948-2",
  "per_cve_status": { "CVE-2026-109618": "fixed", "CVE-2026-109619": "fixed" },
  "config": { "source": "executed php8.3", "values": { "memory_limit": "128M", "...": "..." } },
  "findings": [ /* Finding[] with stable codes above */ ]
}
```

Verdict values: `PATCHED`, `VULNERABLE`, `EOL_VULNERABLE`,
`PATCHED_STALE_WORKERS`, `VERIFY_VENDOR`, `UNKNOWN_VERSION`.

Per-CVE values: `affected`, `fixed`, `unknown`.

## Recipes

```bash
# CI gate: fail the build on vulnerable PHP in the base image
php2shell-doctor scan --docker --docker-exec --json | jq -e '.installs[] | select(.verdict=="VULNERABLE" or .verdict=="EOL_VULNERABLE" or .verdict=="PATCHED_STALE_WORKERS") | false' \
  || echo "vulnerable PHP in image"

# Fleet sweep over SSH (pull the binary once per host or run from a share)
for h in $(cat hosts.txt); do
  scp php2shell-doctor "$h:/tmp/" && ssh "$h" '/tmp/php2shell-doctor scan --json' \
    | jq -r --arg h "$h" '.installs[] | [$h, .verdict, (.install.binary_path // .install.package_name), (.install.package_version // .install.version_raw)] | @tsv'
done > fleet.tsv

# Reconcile assetnote's remote probes with local ground truth
php2shell-doctor scan --json --remote-json assetnote-results.json

# Air-gapped DB refresh
php2shell-doctor scan --vendordb ./vendordb-2026-11-01.json
```
