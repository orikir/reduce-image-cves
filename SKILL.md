---
name: reduce-image-cves
description: Reduce CVEs in a container image. Scan the original image, sort findings by fix status, then upgrade packages, remove unneeded ones, or move to a smaller base image. Prove the app still works with repeatable tests, rescan, and write a report that lists the remaining risks. Use when asked to harden, slim down, de-CVE, or fix vulnerabilities in a Docker/OCI image.
---

# Reduce CVEs in a container image

**Scripts produce every number; you make the decisions.** Never retype scan numbers — paste script output.

The mission in one line: find out what the app *actually* uses, then remove the rest, replace what can't be
fixed, upgrade what can — and prove with the same tests that nothing broke.

## Setup

```bash
S=<skill>/scripts; mkdir -p cve-work/<app> && cd cve-work/<app>     # run everything from here
mkdir -p summaries && bash $S/preflight.sh | tee summaries/tools.txt # tools, versions, DB date, env traps
```

## Workflow

| # | Step | Run | Your decision |
|---|---|---|---|
| 1 | Inspect | `inspect_image.sh IMAGE` | What does the app need at runtime? (`runtime-deps.txt`: libs + entrypoint tools → packages; ldd misses dlopen/plugins — cover those in tests) |
| 2 | Baseline | `scan.sh IMAGE@DIGEST baseline` | — (refuses to overwrite; freezes the grype DB from now on) |
| 3 | Origin | `summarize_scan.py scans/baseline.json --by-source --md` | Per source package: not needed → **remove** / fix exists → **upgrade** / needed, no fix → **replace base** / the app → **accept**. This is the plan. |
| 4 | Fixable? | read `summaries/baseline.txt` fix-state table | If 0 are `fixed`, upgrading can't help — go to 5/6. Try a newer tag with `scan.sh`. |
| 5 | Remove | `templates/Dockerfile.purge-debian` → `build_scan.sh purge` | KEEP list. Replace root-only entrypoints (chown/setpriv/gosu) with a minimal one + `USER`. |
| 6 | New base | `scan_bases.sh IMG…` → `Dockerfile.<name>` → `build_scan.sh <name>` | Keep the original libc; rebuild from the same source + build behaviour; install runtime libs as packages. |
| 7 | Upgrade | add the upgrade to the chosen Dockerfile → `build_scan.sh` | Only what has a fix (rolling distros: `apk upgrade`). |
| 8 | Leftovers | read `summaries/compare-<final>.txt` (shows how grype matched each) | Vendor tracker: fix coming? disputed? reachable in this app? Note source + date. |
| 9 | Test | `app_test.sh` (+ app checks) on every image, `RUNS=3` → `compare_tests.py tests/original.tsv tests/<x>.tsv` | Define "working" (main feature, data types, persistence, network by name, TLS accept *and* reject, user, shutdown). Exit 1 = regression or flaky → blocks the change. Run any user-supplied test script unchanged too. |
| 10 | Final | `scan.sh <tag> final`, `summarize_scan.py --compare … --removed`, `--outcome BASE STEP… FINAL --md` | Explain every NEW CVE. Tag meaningfully (`<app>:<ver>-<base>-<purpose>`). |
| 11 | Report | `templates/REPORT.md` (styled .docx: `tech-report` skill) | Leftover table (decision + mitigation), prioritized next steps, behaviour changes. Map any required sections to a checklist. |

All scripts take `DOCKER=podman`. `build_scan.sh` takes `VERSION_CMD="<app> --version"` as a smoke check.

## Rules

- A CVE is fixed only when a rescan shows it gone.
- No candidate with a regression ships.
- Count unique CVE IDs (not matches); compare only scans from the same DB build, and state its date.
- A 0-CVE static/distroless result can mean the libraries are invisible to the scanner — never pick it for that.
- Report skipped steps and behaviour changes (fixed `USER`, removed tools, no shell).

## Traps

- **DB drift:** the same image can score differently tomorrow. `scan.sh` freezes the DB after the baseline;
  `--compare` warns on mixed DBs and lists added/removed IDs and severity changes.
- **Purging essential Debian packages** leaves half-removed (still reported) packages unless removal scripts are
  skipped — the template does it.
- **snap docker** can't see `/tmp`: bind-mount files from `$HOME`. `~/snap` without the x bit breaks the client.
- **WSL from Windows:** put commands in script files (no inline quoting), strip CRLF (`sed -i 's/\r$//'`).
- **Size:** report `docker image inspect` (uncompressed), not grype's size; `scan.sh` prints it.
