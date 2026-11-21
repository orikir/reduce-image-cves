#!/usr/bin/env python3
"""Line up test results of several images and flag regressions.

Usage: compare_tests.py tests/original.tsv tests/final.tsv [tests/other.tsv ...] [--md]
  The FIRST file is the reference (the original image).
  Input: TSV lines "run<TAB>check<TAB>PASS|FAIL<TAB>detail" (a header line is optional), as written by app_test.sh.

Exit code 1 if any check passes on the reference but fails on another image (a regression: blocks the change),
or if a check is flaky (some runs pass, some fail) on any image.
"""
import sys
from collections import OrderedDict, defaultdict


def load(path):
    res = defaultdict(lambda: [0, 0])  # check -> [passed, total]
    order = OrderedDict()
    with open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3 or parts[2] not in ("PASS", "FAIL"):
                continue  # header or noise
            check, result = parts[1], parts[2]
            order[check] = None
            res[check][1] += 1
            if result == "PASS":
                res[check][0] += 1
    return res, list(order)


def main(argv):
    md = "--md" in argv
    files = [a for a in argv if a != "--md"]
    if len(files) < 2:
        print(__doc__)
        return 2
    data = [load(f) for f in files]
    labels = [f.rsplit("/", 1)[-1].rsplit(".", 1)[0] for f in files]
    checks = list(OrderedDict.fromkeys(c for _r, order in data for c in order))
    ref = data[0][0]
    regressions, flaky, rows = [], [], []
    for c in checks:
        cells, notes = [], []
        for i, (res, _o) in enumerate(data):
            p, t = res.get(c, [0, 0])
            cells.append(f"{p}/{t}" if t else "missing")
            if t and 0 < p < t:
                flaky.append((labels[i], c)); notes.append(f"FLAKY on {labels[i]}")
            rp, rt = ref.get(c, [0, 0])
            if i > 0 and rt and rp == rt and (t == 0 or p < t):
                regressions.append((labels[i], c)); notes.append(f"REGRESSION on {labels[i]}")
        rows.append([c, *cells, "; ".join(notes)])
    totals = []
    for res, _o in data:
        totals.append(f"{sum(v[0] for v in res.values())}/{sum(v[1] for v in res.values())}")
    headers = ["check", *labels, "note"]
    if md:
        print("| " + " | ".join(headers) + " |\n|" + "---|" * len(headers))
        for r in rows:
            print("| " + " | ".join(r) + " |")
        print("| **Total** | " + " | ".join(f"**{t}**" for t in totals) + " | |")
    else:
        w = max(len(c) for c in checks) + 2
        print(f"{'check':<{w}}" + "".join(f"{l[:12]:>13}" for l in labels) + "  note")
        for r in rows:
            print(f"{r[0]:<{w}}" + "".join(f"{x:>13}" for x in r[1:-1]) + f"  {r[-1]}")
        print(f"{'TOTAL':<{w}}" + "".join(f"{t:>13}" for t in totals))
    print(f"\n{len(checks)} checks, {len(regressions)} regressions, {len(flaky)} flaky")
    return 1 if regressions or flaky else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
