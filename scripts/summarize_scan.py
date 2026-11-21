#!/usr/bin/env python3
"""Summarize or compare grype JSON scans, counting unique CVEs (not matches).

Usage:
  summarize_scan.py SCAN.json                          # summary
  summarize_scan.py SCAN.json --csv out.csv            # summary + one row per CVE/package
  summarize_scan.py SCAN.json --by-source [--md]       # where CVEs come from, grouped by source package
  summarize_scan.py SCAN.json [SCAN2.json ...] --oneline
                                                       # one TSV line per scan (rank candidate base images)
  summarize_scan.py --compare BEFORE.json AFTER.json   # before/after (+ DB and digest sanity check)
  summarize_scan.py --outcome BASE.json STEP1.json [STEP2.json ...] [--md]
                                                       # every baseline CVE and the step that removed it

Counting rules (use them everywhere in the report):
  * one CVE ID counts once, however many packages match it (one util-linux CVE can match 8 binary packages)
  * GHSA / other IDs are folded into their CVE alias
  * a CVE's severity is the worst seen; its fix state is the best seen (fixed > not-fixed > wont-fix > unknown)
"""
import argparse
import csv
import json
import sys
from collections import defaultdict

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
STATE_ORDER = ["fixed", "not-fixed", "wont-fix", "unknown"]
STATE_RANK = {s: i for i, s in enumerate(STATE_ORDER)}


def norm_sev(s):
    s = (s or "Unknown").capitalize()
    return s if s in SEV_RANK else "Unknown"


def norm_state(s):
    s = (s or "unknown").lower()
    return s if s in STATE_RANK else "unknown"


def cve_id(match):
    """Prefer a CVE ID; fold GHSA/other IDs into their CVE alias."""
    vid = match["vulnerability"]["id"]
    if vid.startswith("CVE-"):
        return vid
    for rel in match.get("relatedVulnerabilities") or []:
        if rel.get("id", "").startswith("CVE-"):
            return rel["id"]
    return vid


def source_pkg(artifact):
    """Source package (e.g. glibc for libc6/libc-bin) - the unit you actually remove or upgrade."""
    ups = artifact.get("upstreams") or []
    if ups and ups[0].get("name"):
        return ups[0]["name"]
    return artifact.get("name") or "?"


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    cves = {}  # id -> {sev, state, pkgs: {(name, ver, type): (state, fix_versions)}, src: set()}
    for m in data.get("matches", []):
        vid = cve_id(m)
        v = m["vulnerability"]
        a = m["artifact"]
        sev = norm_sev(v.get("severity"))
        fix = v.get("fix") or {}
        state = norm_state(fix.get("state"))
        e = cves.setdefault(vid, {"sev": sev, "state": state, "pkgs": {}, "src": set(), "matchers": set()})
        if SEV_RANK[sev] < SEV_RANK[e["sev"]]:
            e["sev"] = sev
        if STATE_RANK[state] < STATE_RANK[e["state"]]:
            e["state"] = state
        key = (a.get("name"), a.get("version"), a.get("type"))
        e["pkgs"][key] = (state, ",".join(fix.get("versions") or []))
        e["src"].add(source_pkg(a))
        for md in m.get("matchDetails") or []:
            e["matchers"].add(f"{md.get('matcher', '?')}:{v.get('namespace', '?')}")
    distro = data.get("distro") or {}
    src = (data.get("source") or {}).get("target") or {}
    desc = data.get("descriptor") or {}
    db = desc.get("db") or {}
    status = db.get("status") or db
    meta = {
        "matches": len(data.get("matches", [])),
        "distro": f"{distro.get('name', '?')} {distro.get('version', '')}".strip(),
        "image": src.get("userInput") or src.get("imageID") or "?",
        "digest": src.get("manifestDigest") or src.get("imageID") or "",
        "size": src.get("imageSize"),
        "grype": desc.get("version", "?"),
        "db_built": status.get("built", "?"),
    }
    return cves, meta


def by_sev(cves):
    c = {s: 0 for s in SEV_ORDER}
    for e in cves.values():
        c[e["sev"]] += 1
    return c


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def summary(path, csv_path=None):
    cves, meta = load(path)
    print(f"Image:   {meta['image']}")
    print(f"Digest:  {meta['digest']}")
    print(f"Distro:  {meta['distro']}")
    print(f"Scanner: grype {meta['grype']}, DB built {meta['db_built']}")
    if meta["size"]:
        print(f"Size:    {meta['size'] / 1e6:.1f} MB (as reported by grype)")
    print(f"Matches: {meta['matches']}   Unique CVEs: {len(cves)}\n")

    print("Unique CVEs by severity:")
    for s, n in by_sev(cves).items():
        print(f"  {s:<11}{n:>5}")

    states = defaultdict(lambda: defaultdict(int))
    for e in cves.values():
        states[e["state"]][e["sev"]] += 1
    print("\nFix status (unique CVEs, best state across matches):")
    print("  " + f"{'state':<11}" + "".join(f"{s[:4]:>6}" for s in SEV_ORDER) + "  total")
    for st in STATE_ORDER:
        row = states.get(st, {})
        print("  " + f"{st:<11}" + "".join(f"{row.get(s, 0):>6}" for s in SEV_ORDER)
              + f"  {sum(row.values()):>5}")
    nfixed = sum(states.get("fixed", {}).values())
    if nfixed == 0:
        print("\n  -> 0 CVEs have a fixed package version: upgrading cannot help here;"
              " remove packages or change the base image.")

    pkgs = defaultdict(lambda: {"cves": set(), "fixed": set(), "worst": "Unknown", "fixv": set()})
    for vid, e in cves.items():
        for (name, ver, typ), (st, fv) in e["pkgs"].items():
            p = pkgs[(name, ver, typ)]
            p["cves"].add(vid)
            if st == "fixed":
                p["fixed"].add(vid)
                if fv:
                    p["fixv"].add(fv)
            if SEV_RANK[e["sev"]] < SEV_RANK[p["worst"]]:
                p["worst"] = e["sev"]
    print("\nPackages by unique CVE count:")
    print(f"  {'package':<34}{'version':<26}{'type':<8}{'CVEs':>5}{'fixed':>6}  worst     fix-in")
    for (name, ver, typ), p in sorted(pkgs.items(), key=lambda kv: (-len(kv[1]["cves"]), SEV_RANK[kv[1]["worst"]])):
        print(f"  {str(name)[:33]:<34}{str(ver)[:25]:<26}{str(typ)[:7]:<8}{len(p['cves']):>5}"
              f"{len(p['fixed']):>6}  {p['worst']:<10}{';'.join(sorted(p['fixv']))[:40]}")

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["cve", "severity", "source_package", "package", "version", "type", "fix_state", "fix_versions"])
            for vid, e in sorted(cves.items(), key=lambda kv: (SEV_RANK[kv[1]["sev"]], kv[0])):
                for (name, ver, typ), (st, fv) in sorted(e["pkgs"].items(), key=lambda kv: str(kv[0])):
                    w.writerow([vid, e["sev"], ";".join(sorted(e["src"])), name, ver, typ, st, fv])
        print(f"\nCSV written: {csv_path}")


def by_source(path, md=False):
    """Group unique CVEs by source package: the 'where do the CVEs come from' table for the plan."""
    cves, meta = load(path)
    groups = defaultdict(lambda: {"cves": set(), "bins": set(), "sev": defaultdict(int), "state": defaultdict(int)})
    for vid, e in cves.items():
        for s in e["src"]:
            g = groups[s]
            g["cves"].add(vid)
            g["bins"] |= {k[0] for k in e["pkgs"]}
            g["sev"][e["sev"]] += 1
            g["state"][e["state"]] += 1
    rows = []
    for s, g in sorted(groups.items(), key=lambda kv: (-len(kv[1]["cves"]), kv[0])):
        sev = [g["sev"].get(x, 0) or "" for x in SEV_ORDER[:5]]
        st = ", ".join(f"{k} {v}" for k, v in sorted(g["state"].items(), key=lambda kv: STATE_RANK[kv[0]]))
        rows.append([s, ", ".join(sorted(g["bins"])), len(g["cves"]), *sev, st])
    headers = ["source package", "binary packages", "CVEs", "Crit", "High", "Med", "Low", "Negl", "fix states"]
    print(f"# {meta['image']}: {len(cves)} unique CVEs in {len(groups)} source packages (DB {meta['db_built']})\n")
    if md:
        print(md_table(headers, rows))
    else:
        print(f"{'source':<18}{'CVEs':>5} {'C':>3}{'H':>4}{'M':>4}{'L':>4}{'N':>4}  fix states / binary packages")
        for r in rows:
            print(f"{r[0][:17]:<18}{r[2]:>5} " + "".join(f"{str(x):>4}" for x in r[3:8])[1:] + f"  {r[8]}  [{r[1][:60]}]")
    print("\nNext: for each source package decide: needed at runtime? -> remove it / replace the base / upgrade / accept.")


def compare(before, after, list_removed=False):
    b, bm = load(before)
    a, am = load(after)
    print(f"Before: {bm['image']} ({bm['distro']})  DB {bm['db_built']}")
    print(f"After:  {am['image']} ({am['distro']})  DB {am['db_built']}")
    if bm["db_built"] != am["db_built"]:
        print("\n  WARNING: the two scans used DIFFERENT grype DB builds. Some of the difference may come from the\n"
              "  vulnerability data, not the image. Rescan both with the same DB before reporting numbers.")
    if bm["digest"] and bm["digest"] == am["digest"]:
        print("\n  NOTE: same image digest on both sides - any difference below comes from the scanner/DB, not the image.")
    bs, as_ = by_sev(b), by_sev(a)
    print(f"\n  {'severity':<11}{'before':>8}{'after':>8}{'delta':>8}")
    for s in SEV_ORDER:
        print(f"  {s:<11}{bs[s]:>8}{as_[s]:>8}{as_[s] - bs[s]:>+8}")
    print(f"  {'TOTAL':<11}{len(b):>8}{len(a):>8}{len(a) - len(b):>+8}")
    print(f"  {'matches':<11}{bm['matches']:>8}{am['matches']:>8}{am['matches'] - bm['matches']:>+8}")
    if bm["size"] and am["size"]:
        d = (am["size"] - bm["size"]) / bm["size"] * 100
        print(f"\n  size MB    {bm['size'] / 1e6:>8.1f}{am['size'] / 1e6:>8.1f}{d:>+7.0f}%   (grype-reported size)")

    removed = sorted(set(b) - set(a), key=lambda k: (SEV_RANK[b[k]["sev"]], k))
    added = sorted(set(a) - set(b), key=lambda k: (SEV_RANK[a[k]["sev"]], k))
    changed = sorted(k for k in set(a) & set(b) if a[k]["sev"] != b[k]["sev"])
    print(f"\nRemoved: {len(removed)}   Remaining: {len(set(a) & set(b))}   NEW: {len(added)}   Severity changed: {len(changed)}")

    def pk(e):
        return ", ".join(f"{n}@{v}" for (n, v, _t) in e["pkgs"])
    if added:
        print("\nNEW CVEs (each needs an explanation in the report):")
        for k in added:
            print(f"  {k:<20}{a[k]['sev']:<11}{a[k]['state']:<10}{pk(a[k])}")
    if changed:
        print("\nSeverity changed (usually a DB update):")
        for k in changed:
            print(f"  {k:<20}{b[k]['sev']:>10} -> {a[k]['sev']:<10}{pk(a[k])}")
    if list_removed and removed:
        print("\nRemoved CVEs:")
        for k in removed:
            print(f"  {k:<20}{b[k]['sev']:<11}{b[k]['state']:<10}{pk(b[k])}")
    remaining = sorted(set(a) & set(b), key=lambda k: (SEV_RANK[a[k]["sev"]], k))
    if remaining:
        print("\nRemaining CVEs (matcher shows how grype found them; nvd:cpe matches often have no distro fix data):")
        for k in remaining:
            print(f"  {k:<20}{a[k]['sev']:<11}{a[k]['state']:<10}{pk(a[k])}   [{', '.join(sorted(a[k]['matchers']))}]")


def outcome(paths, md=False):
    """Trace every baseline CVE through the steps: which step's image no longer has it."""
    scans = [load(p) for p in paths]
    base = scans[0][0]
    names = [p.rsplit("/", 1)[-1].replace(".json", "") for p in paths]
    rows, counts = [], defaultdict(int)
    for vid, e in sorted(base.items(), key=lambda kv: (SEV_RANK[kv[1]["sev"]], sorted(kv[1]["src"])[0], kv[0])):
        result = "remains"
        for i, (c, _m) in enumerate(scans[1:], 1):
            if vid not in c:
                result = f"removed by {names[i]}"
                break
        counts[result] += 1
        rows.append([vid, e["sev"], ", ".join(sorted(e["src"])), e["state"], result])
    final = scans[-1][0]
    new = sorted(set(final) - set(base))
    headers = ["#", "CVE", "severity", "source package", "fix state (baseline)", "outcome"]
    numbered = [[i, *r] for i, r in enumerate(rows, 1)]
    if md:
        print(md_table(headers, numbered))
    else:
        for r in numbered:
            print(f"{r[0]:>4} {r[1]:<20}{r[2]:<11}{r[3][:16]:<17}{r[4]:<10}{r[5]}")
    print("\nTotals: " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) + f", NEW in final: {len(new)} {new}")
    dbs = {m["db_built"] for _c, m in scans}
    if len(dbs) > 1:
        print(f"WARNING: scans used different DB builds {sorted(dbs)} - rescan with one DB before reporting.")


def oneline(paths):
    print("unique	Crit	High	Med	Low	Negl	matches	sizeMB	distro	image")
    rows = []
    for p in paths:
        c, m = load(p)
        s = by_sev(c)
        size = f"{m['size'] / 1e6:.1f}" if m["size"] else "?"
        rows.append((len(c), s["Critical"], s["High"], s["Medium"], s["Low"], s["Negligible"], m["matches"], size, m["distro"], m["image"]))
    for r in sorted(rows, key=lambda r: (r[1], r[2], r[0])):
        print("	".join(str(x) for x in r))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan", nargs="*")
    ap.add_argument("--csv")
    ap.add_argument("--by-source", action="store_true", help="group CVEs by source package")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--removed", action="store_true", help="with --compare: also list removed CVEs")
    ap.add_argument("--outcome", nargs="+", metavar="SCAN", help="BASE then one scan per step, in order")
    ap.add_argument("--md", action="store_true", help="markdown tables (for --by-source / --outcome)")
    ap.add_argument("--oneline", action="store_true", help="one TSV line per scan, sorted by Critical, High, total")
    args = ap.parse_args()
    if args.compare:
        compare(*args.compare, list_removed=args.removed)
    elif args.outcome:
        if len(args.outcome) < 2:
            ap.error("--outcome needs the baseline and at least one step scan")
        outcome(args.outcome, md=args.md)
    elif args.scan and args.oneline:
        oneline(args.scan)
    elif args.scan and args.by_source:
        by_source(args.scan[0], md=args.md)
    elif args.scan:
        summary(args.scan[0], args.csv)
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
