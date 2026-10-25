---
name: Bug report
about: A scan verdict, finding or crash that looks wrong
title: ""
labels: bug
assignees: ""
---

**What happened?**

**What did you expect?**

**Command you ran**

```
php2shell-doctor scan ...
```

**Output** (attach the JSON report if possible — `scan --json`; it contains no
personal data, only package versions and paths)

**Environment**

- OS / version:
- How PHP is installed on the scanned host (distro package, cPanel, Docker, source build):
- php2shell-doctor version (`php2shell-doctor version`):
- Vendor DB revision (`php2shell-doctor db`):

**Is this a wrong verdict (PATCHED/VULNERABLE) rather than a crash?**

If the tool says VULNERABLE and you believe it is patched (or the reverse),
include the exact package version (`dpkg-query -W -f '${Version}' php8.x`,
`rpm -q php`, `php -v`) and a link to the vendor advisory that fixes this CVE
for your platform. Verdict fixes are only accepted with a checkable source.
