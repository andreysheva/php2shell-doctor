# FAQ

## Verdicts

**Q: My Ubuntu server runs PHP 8.3.6 but the tool says PATCHED. Isn't 8.3.6 below 8.3.36?**
A: That is exactly the case this tool exists for. Ubuntu backported the fix into the package revision `8.3.6-0ubuntu0.24.04.13` (USN-8948-1/-2) without changing the upstream version. The tool compares the full dpkg version against the verified fixed revision. If you are on `8.3.6-0ubuntu0.24.04.12` or older, it correctly says VULNERABLE. Verify with: `dpkg -l php8.3` or `apt policy php8.3`.

**Q: It says VERIFY_VENDOR on my RHEL server. What do I do?**
A: RHEL backports fixes while keeping the upstream version string, and no fixed package revision has been independently verified for your minor release yet. Open the erratum the tool printed (RHSA/CVE page for your release), check whether your `php` package release (`rpm -q php --qf '%{VERSION}-%{RELEASE}'`) is at or after the fixed build, and update the vendordb entry (`internal/vendordb/vendordb.json`) so the next run is automatic.

**Q: I updated PHP but it still says PATCHED_STALE_WORKERS.**
A: The binary on disk is patched, but running FPM children / Apache children started before the update and still execute the old code. Restart the PHP service (`systemctl restart php8.3-fpm`, `apachectl graceful` is not enough for mod_php — restart the service, or reboot the container). Re-run the tool to confirm.

**Q: My Docker image is php:8.3-apache and it says UNKNOWN_VERSION.**
A: That tag does not name a patch version, so the runtime could be any 8.3.x. Either use fully-versioned tags in builds, or run `php2shell-doctor scan --docker --docker-exec` to ask the running container for its real version.

**Q: It found PHP 7.4.33 and says EOL_VULNERABLE. There is no patch?**
A: Correct — branches below 8.2 get no upstream fix. The PHP project published minimal source backports for 7.4/8.0/8.1 (source only), some distros/LTS vendors ship backported packages (Debian bullseye, Ubuntu jammy php8.1 — hence VERIFY_VENDOR there), and commercial live-patch vendors offer coverage. Otherwise: upgrade.

## Config findings

**Q: Why does disabling session.upload_progress matter? It's just progress bars.**
A: The confirmed attack path for CVE-2026-109619 runs through it — the upload-progress callback unserializes attacker-influenced session data during request startup, before normal initialization. It is also the mitigation surface for CVE-2026-115560. Disabling it removes the demonstrated vector; it is not a complete fix for either CVE.

**Q: It flagged memory_limit=128M as medium. Isn't a memory limit good practice?**
A: On unpatched PHP, a finite memory_limit is precisely the trigger surface for CVE-2026-109618 — the bug lives in what happens when an allocation crosses that limit mid-request. PHP's temporary guidance is `memory_limit=-1` (non-overridably) and bounding memory with cgroup/container limits instead, which kill the worker safely. After patching, a sane finite memory_limit is fine again.

**Q: What is a .user.ini/.htaccess override finding?**
A: Your global mitigation can be silently undone per-directory: a stray `php_value session.upload_progress.enabled 1` in a web root re-enables the vector for that tree. The tool flags those files with their exact path.

## Safety and trust

**Q: Is it safe to run on production?**
A: That is the design centerpiece: read-only by default, no network, no exploit probes, bounded resource use, panic-isolated engines. The exact commands it executes are `php -v`, `php --ini` and one `ini_get` probe — or nothing at all with `--no-exec`.

**Q: How is this different from assetnote's scanner?**
A: Complementary. Assetnote's scanner asks the network "does this endpoint behave vulnerable?" — high fidelity, but it triggers OOM conditions and documents false positives on patched PHP with tight memory limits. php2shell-doctor asks the host "what is installed, patched, running and configured?" — no risk, plus staleness/config/product answers the remote scanner cannot give. Feed assetnote's JSON to `--remote-json` and reconcile both.

**Q: Why does the DB say 'verify' instead of listing RHEL revisions?**
A: Because none have been verified against a vendor advisory yet. A `verify` entry guarantees the tool never lies; a wrong revision entry would. Contribute verified revisions — one line protects every user of that vendor.

**Q: Can this tool exploit or test exploitability?**
A: No, by design and by policy. It contains no exploit code and sends no crafted requests.

## Operations

**Q: Exit code 2 — should my CI fail?**
A: Exit 2 means "I could not prove safety" (VERIFY_VENDOR/UNKNOWN_VERSION). That is a policy decision: strict fleets fail on 1 and 2; pragmatic fleets fail on 1 and ticket 2.

**Q: How do I update the vendor DB in an air gap?**
A: Download `data/vendordb.json` from a newer release, transfer it, run `scan --vendordb FILE` and `self-test`.

**Q: The scan is partial. What did I lose?**
A: One or more discovery engines errored (missing docker CLI, unreadable package DB…). The JSON `engine_errors` array names them. Everything else ran.
