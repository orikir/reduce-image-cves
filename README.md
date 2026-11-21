# reduce-image-cves

A [Claude Code](https://claude.com/claude-code) skill that cuts the CVE count of a container image without breaking the app.

It finds out what the app actually uses, removes the rest, replaces what can't be fixed, upgrades what can, and proves with the same tests before and after that nothing broke. Scripts produce every number; Claude makes the decisions.

## Install

Copy the folder into your skills directory:

```bash
git clone <this repo> ~/.claude/skills/reduce-image-cves          # all projects
# or: <project>/.claude/skills/reduce-image-cves                   # one project
```

Then ask Claude something like *"reduce the CVEs in redis:7-bookworm"* or run `/reduce-image-cves`.

## Requirements

`docker` (or `podman`), [`grype`](https://github.com/anchore/grype), `python3`. Optional: `openssl` (TLS test certificates), `syft`.
Run `scripts/preflight.sh` to check.

## What's inside

| Path | Purpose |
|---|---|
| `SKILL.md` | The workflow: step → script → decision |
| `scripts/preflight.sh` | Check tools, record versions + grype DB date, warn about environment traps |
| `scripts/inspect_image.sh` | Digest, config, history, packages; map app libraries and entrypoint tools to packages |
| `scripts/scan.sh` | Scan + summarize + compare with the baseline (protects the baseline, freezes the DB) |
| `scripts/build_scan.sh` | Build `Dockerfile.<name>`, smoke-check, scan, compare |
| `scripts/scan_bases.sh` | Scan and rank candidate base images |
| `scripts/summarize_scan.py` | Unique-CVE summary, `--by-source`, `--compare`, `--outcome`, `--oneline`, `--md` |
| `scripts/app_test.sh` | Repeatable smoke-test harness (readiness polling, exact checks, N runs, TSV) |
| `scripts/compare_tests.py` | Line up test results across images; exit 1 on regressions or flaky checks |
| `templates/Dockerfile.purge-debian` | Remove unused Debian packages cleanly and flatten into `scratch` |
| `templates/REPORT.md` | Report skeleton |

## Example

[`examples/redis`](examples/redis): `redis:7-bookworm` went from 113 → 4 unique CVEs (0 Critical/High) and 167 → 79 MB,
with 114/114 functional checks passing on both images. Includes the Dockerfiles, test scripts, results and the full report.
