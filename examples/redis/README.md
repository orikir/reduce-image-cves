# Example: redis:7-bookworm

The skill applied to the official Redis image (grype 0.122.0, DB built 2026-11-20).

| | Original | Step 1: package removal | Final: Wolfi rebuild |
|---|---|---|---|
| Unique CVEs | 113 | 39 | **4** |
| Critical / High | 1 / 21 | 1 / 7 | **0 / 0** |
| Size | 167.3 MB | 67.3 MB | **79.3 MB** |
| Tests (38 checks × 3 runs) | 114/114 | 114/114 | **114/114** |

**Key insight:** Redis loads only 4 libraries (libc, libm, libssl, libcrypto), and none of the 113 CVEs had a fix in
Debian. So the answer was not "upgrade" but "remove what Redis doesn't use, replace what it does use".

## Files

| Path | What |
|---|---|
| `Dockerfile.wolfi` | Final image: Redis 7.4.12 rebuilt from source on Wolfi (31 lines) |
| `Dockerfile.purge` | Step 1: original image with 83 of 89 packages purged, flattened into `scratch` |
| `files/docker-entrypoint.sh` | Minimal entrypoint (runs as `redis`, no root → setpriv step) |
| `tests/redis_test.sh` | 38 checks: commands, persistence, network, shutdown, TLS accept/reject |
| `tests/compare_test.sh` | Independent comparison script, run unchanged (27/27 on both images) |
| `results/` | Scan summaries, before/after comparisons, CVE outcome table, test results |
| `REPORT.md`, `Redis-on-a-Diet.docx` | Full write-up (technical / plain-language) |

## Reproduce

```bash
cd examples/redis
docker build -f Dockerfile.wolfi -t redis:7.4.12-wolfi-lowcve .
S=../../scripts
bash $S/scan.sh redis:7-bookworm baseline
bash $S/scan.sh redis:7.4.12-wolfi-lowcve final
IMAGE=redis:7-bookworm LABEL=original bash tests/redis_test.sh
IMAGE=redis:7.4.12-wolfi-lowcve LABEL=final bash tests/redis_test.sh
python3 $S/compare_tests.py tests/original.tsv tests/final.tsv
```

CVE counts depend on the grype DB date; expect small differences on a newer DB.
