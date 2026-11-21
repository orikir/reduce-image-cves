# CVE reduction report: <image>

Date: <YYYY-MM-DD> · grype <ver>, DB built <date> (all scans used this DB) · Final image: `<tag>`

<!-- If the task lists required sections, start with a checklist: requirement -> section. -->

## 1. Results summary

| | Original | <candidate> | Final | Change |
|---|---|---|---|---|
| Image | `<image>@<digest>` | | `<tag>` | |
| Base / OS | | | | |
| App version | | | | |
| Size (MB, `docker image inspect`) | | | | |
| Critical / High | | | | |
| Medium / Low / Negligible | | | | |
| **Total unique CVEs** | | | | |
| New CVEs vs original | — | | | |
| Tests passed (checks × runs) | x/y | x/y | x/y | |

Key outcomes (3–5 bullets):
-

## 2. Where the CVEs come from, and the plan

<paste: summarize_scan.py scans/baseline.json --by-source --md, plus one "plan" column:
 not needed -> remove / needed + fix exists -> upgrade / needed, no fix -> replace base / the app -> accept>

Fix states of the baseline: fixed <n>, not-fixed <n>, wont-fix <n>, unknown <n>.

## 3. Final Dockerfile

```dockerfile
<full final Dockerfile and any files it copies in (entrypoint, configs)>
```

## 4. How it was done

- Tools: docker <ver>, grype <ver> (DB <date>), <others> (`summaries/tools.txt`)
- Counting: unique CVE IDs (GHSA folded into CVE), worst severity, best fix state.
- Analysis of the original: `summaries/image-info.txt`, `runtime-deps.txt` (what the app actually loads).
- Approaches used: <1, 2, 3 ...>

## 5. Steps

| # | Change tried | Unique CVEs after | vs baseline | Tests | Kept? | Why |
|---|---|---|---|---|---|---|
| 0 | Baseline | | — | | — | |

## 6. Remaining risks

| CVE | Package | Severity | Fix status | Fix coming? (source, checked on) | Decision | Mitigation |
|---|---|---|---|---|---|---|

### Next steps, in priority order

| Priority | Action | Resolves | When |
|---|---|---|---|

### Behaviour differences from the original
- <USER, removed tools, entrypoint changes ...>

## 7. Test plan and results

What "working correctly" means for this app: <list>.
Method: same script, same settings, <N> runs per image, readiness polled, exact expected values.

<paste: compare_tests.py tests/original.tsv tests/<...>.tsv --md>

## 8. Challenges and lessons learned
-

## Appendix A: Every baseline CVE and what removed it
<paste: summarize_scan.py --outcome scans/baseline.json scans/<step>.json ... scans/final.json --md>

## Appendix B: Files and commands
<scans/, summaries/, tests/, steps/ and the condensed command log>
