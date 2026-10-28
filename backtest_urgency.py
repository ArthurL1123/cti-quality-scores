"""
Back-test the urgency score: would it have put the vulnerabilities that were
attacked later near the top of the list?

Method (after Jacobs et al. 2023, "Enhancing Vulnerability Prioritization",
arXiv:2302.14172, Section 5 and Figure 4):
  1. Pick a cut-off date T and pretend it is today.
  2. Candidates: every CVE that had an EPSS score on T and was NOT yet in
     CISA KEV on T (a team on day T could not know about later attacks).
  3. Score each candidate as it would have been scored on T: EPSS from FIRST's
     API for date T, CVSS v3.x base score from NVD. KEV is 0 for every
     candidate, because of step 2.
  4. Outcome: the CVE was added to KEV in the N days after T.
  5. Rank candidates four ways (pipeline urgency score, CVSS only, EPSS only,
     random) and measure, for each work budget, coverage (share of the later
     KEV additions that are inside the budget) and efficiency (share of the
     budget that was later added to KEV). Coverage and efficiency are the
     measures used by Jacobs et al. 2023.

Budgets are given as a share of the candidate list. Two of them come from
published sources:
  - 10%: "A typical organization ... will have the capacity to remediate about
    one out of every 10 vulnerabilities in their environment within a given
    month" (Kenna Security / Cyentia Institute, Prioritization to Prediction
    Vol. 3, 2019, p. 19). Their base is vulnerabilities found in an
    organisation's own environment, not all published CVEs.
  - 15.5%: "companies were only able to remediate about 15.5% of their open
    vulnerabilities in a month", a later Kenna/Cyentia figure (2022) quoted by
    Jacobs et al. 2023 (WEIS version, p. 8). Same base as above.
  - The effort of a "patch everything rated CVSS 7 or above" policy, which
    Jacobs et al. 2023 use as their baseline strategy.

Limitations: NVD gives today's CVSS score, not the score as it was on T. KEV
records when CISA added a CVE, not when exploitation started.

Downloaded data is cached in output/backtest_cache/ (git-ignored). Read-only:
nothing is written to OpenCTI.

Usage:
    python backtest_urgency.py --date 2026-04-01
    python backtest_urgency.py --date 2026-04-01 --windows 30 180
    python backtest_urgency.py --range 2025-04-01 2026-04-01   # 1st of each month
"""
import argparse
import csv
import json
import logging
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import requests

from healthcare_cti_pipeline import Config

logging.getLogger("matplotlib").setLevel(logging.WARNING)
CACHE = Path("output/backtest_cache")
OUT = Path("output/backtest")
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000
NVD_DELAY = 6.5          # NVD allows 5 requests per 30 s without an API key
BUDGETS = (0.01, 0.05, 0.10, 0.155, 0.25, 0.50)
CAPACITY = {0.10: "10% of list (Kenna/Cyentia monthly capacity)",       # 2019 report
            0.155: "15.5% of list (Kenna/Cyentia 2022, via Jacobs et al.)"}


def _get(url: str, params: dict, tries: int = 5) -> dict:
    for attempt in range(1, tries + 1):
        try:
            resp = requests.get(url, params=params, timeout=120)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            if attempt == tries:
                raise
            print(f"  retry {attempt}/{tries} after error: {exc}")
            time.sleep(10 * attempt)


def fetch_kev(cfg: Config) -> dict[str, date]:
    """CVE id -> date CISA added it to KEV."""
    data = _get(cfg.KEV_API_URL, {})
    return {v["cveID"].upper(): date.fromisoformat(v["dateAdded"]) for v in data["vulnerabilities"]}


def fetch_epss_on(day: date) -> dict[str, float]:
    """EPSS score of every CVE as published by FIRST on `day`."""
    path = CACHE / f"epss_{day}.csv"
    if path.exists():
        with path.open() as f:
            return {r["cve"]: float(r["epss"]) for r in csv.DictReader(f)}
    scores, offset = {}, 0
    while True:
        page = _get(EPSS_API, {"date": str(day), "limit": 10000, "offset": offset})
        for row in page["data"]:
            scores[row["cve"].upper()] = float(row["epss"])
        offset += len(page["data"])
        print(f"  EPSS {day}: {offset}/{page['total']}")
        if not page["data"] or offset >= page["total"]:
            break
    if not scores:
        raise SystemExit(f"FIRST returned no EPSS scores for {day}.")
    CACHE.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve", "epss"])
        w.writerows(scores.items())
    return scores


def _cvss_v3(cve: dict) -> float | None:
    """CVSS v3.1 base score, else v3.0; NVD's own (Primary) score first."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        entries = sorted(entries, key=lambda m: m.get("type") != "Primary")
        if entries:
            return float(entries[0]["cvssData"]["baseScore"])
    return None


def fetch_nvd_cvss() -> dict[str, float | None]:
    """CVE id -> CVSS v3.x base score (None if NVD has none). Rejected CVEs left out."""
    path = CACHE / "nvd_cvss.csv"
    if path.exists():
        with path.open() as f:
            return {r["cve"]: (float(r["cvss"]) if r["cvss"] else None) for r in csv.DictReader(f)}
    cvss, start, total = {}, 0, None
    while total is None or start < total:
        page = _get(NVD_API, {"resultsPerPage": NVD_PAGE, "startIndex": start})
        total = page["totalResults"]
        for item in page["vulnerabilities"]:
            cve = item["cve"]
            if cve.get("vulnStatus") != "Rejected":
                cvss[cve["id"].upper()] = _cvss_v3(cve)
        start += NVD_PAGE
        print(f"  NVD: {min(start, total)}/{total}")
        time.sleep(NVD_DELAY)
    CACHE.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve", "cvss"])
        w.writerows((k, "" if v is None else v) for k, v in cvss.items())
    return cvss


def urgency(epss: float | None, cvss: float | None, cfg: Config) -> float:
    """The pipeline's composite score (enrich_vulnerabilities_with_epss) with KEV = 0."""
    if epss is None and cvss is None:
        return 0.0
    weights = {"kev": cfg.KEV_WEIGHT}
    if epss is not None:
        weights["epss"] = cfg.EPSS_WEIGHT
    if cvss is not None:
        weights["cvss"] = cfg.CVSS_WEIGHT
    denom = sum(weights.values())
    score = 0.0
    if epss is not None:
        score += weights["epss"] / denom * epss
    if cvss is not None:
        score += weights["cvss"] / denom * (cvss / 10.0)
    return score


def hits_in_top(scores: list[float], positive: list[bool], ks: list[int]) -> list[float]:
    """Later-KEV CVEs inside the top k, for each k in ks. Ties at the cut are
    split evenly (the expected count if ties were broken at random)."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    groups, i = [], 0                      # (size, positives) per tied score, best first
    while i < len(order):
        j = i
        while j < len(order) and scores[order[j]] == scores[order[i]]:
            j += 1
        groups.append((j - i, sum(positive[g] for g in order[i:j])))
        i = j
    out = []
    for k in ks:
        hits, taken = 0.0, 0
        for size, pos in groups:
            if taken + size <= k:
                hits += pos
                taken += size
            else:
                hits += pos * (k - taken) / size
                break
        out.append(hits)
    return out


def run_one(T: date, windows: list[int], kev: dict, cvss: dict, cfg: Config, plot: bool = True) -> dict:
    """Back-test one cut-off date T. Prints the tables and returns the results."""
    epss = fetch_epss_on(T)
    cands = sorted(c for c in epss if not (c in kev and kev[c] <= T))
    n = len(cands)
    cvss_of = [cvss.get(c) for c in cands]
    methods = {
        "Urgency score (pipeline)": [urgency(epss[c], s, cfg) for c, s in zip(cands, cvss_of)],
        "CVSS only": [s if s is not None else -1.0 for s in cvss_of],
        "EPSS only": [epss[c] for c in cands],
    }
    cvss7 = sum(1 for s in cvss_of if s is not None and s >= 7.0)
    thresh = sum(1 for s in methods["Urgency score (pipeline)"] if s >= cfg.COMPOSITE_THRESHOLD)
    budgets = [(CAPACITY.get(b, f"{b:.0%} of list"), round(b * n)) for b in BUDGETS]
    budgets.append((f"CVSS 7+ policy ({cvss7 / n:.1%})", cvss7))
    budgets.append((f"Pipeline threshold {cfg.COMPOSITE_THRESHOLD} ({thresh / n:.1%})", thresh))

    print(f"\nCut-off date T: {T}")
    print(f"Candidates (EPSS-scored on T, not in KEV on T): {n}")
    print(f"  with a CVSS v3.x score in NVD: {sum(s is not None for s in cvss_of)}")
    results = {"date": str(T), "candidates": n, "windows": {}}
    for win in windows:
        end = T + timedelta(days=win)
        if end > date.today():
            print(f"\n=== {win}-day window ends {end}, after today: skipped ===")
            continue
        positive = [c in kev and T < kev[c] <= end for c in cands]
        P = sum(positive)
        print(f"\n=== Added to KEV within {win} days after T ({T} to {end}): {P} candidates ===")
        if P == 0:
            continue
        rows = []
        print(f"{'Budget':42} {'CVEs':>8}  " + "  ".join(f"{m[:24]:>24}" for m in list(methods) + ["Random"]))
        ks = [k for _, k in budgets]
        method_hits = {m: hits_in_top(scores, positive, ks) for m, scores in methods.items()}
        for b, (label, k) in enumerate(budgets):
            cells, row = [], {"budget": label, "k": k}
            for m in methods:
                h = method_hits[m][b]
                row[m] = {"hits": h, "coverage": h / P, "efficiency": h / k if k else 0.0}
                cells.append(f"{h:6.1f} ({h / P:5.1%})")
            h = P * k / n
            row["Random"] = {"hits": h, "coverage": h / P, "efficiency": h / k if k else 0.0}
            cells.append(f"{h:6.1f} ({h / P:5.1%})")
            rows.append(row)
            print(f"{label:42} {k:8}  " + "  ".join(f"{c:>24}" for c in cells))
        print("(cells: later-KEV CVEs inside the budget, and coverage)")
        results["windows"][str(win)] = {"positives": P, "rows": rows}
        if plot:
            _plot(methods, positive, n, P, T, win, cvss7)

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"backtest_{T}.json").write_text(json.dumps(results, indent=2))
    return results


def summarise(all_results: list[dict], windows: list[int]) -> None:
    """Across all cut-off dates: coverage at each published capacity budget per method
    (mean, lowest, highest, pooled) and how often the urgency score beat each other
    method. Keys: "<window>" for the 10% budget, "<window>@15.5%" for the other."""
    methods = ["Urgency score (pipeline)", "CVSS only", "EPSS only", "Random"]
    summary = {}
    for (budget, label), win in [(c, w) for c in CAPACITY.items() for w in windows]:
        key = str(win) if budget == 0.10 else f"{win}@{budget:.1%}"
        per_date = []
        for r in all_results:
            w = r["windows"].get(str(win))
            if w:
                row = next(x for x in w["rows"] if x["budget"] == label)
                per_date.append((r["date"], w["positives"], {m: row[m]["hits"] for m in methods}))
        if not per_date:
            continue
        print(f"\n##### Summary, {win}-day window, {budget:.1%} budget: {len(per_date)} cut-off dates #####")
        print(f"{'Date':12} {'Later-KEV':>9}  " + "  ".join(f"{m[:24]:>24}" for m in methods))
        for d, P, hits in per_date:
            print(f"{d:12} {P:9}  " + "  ".join(f"{hits[m]:6.1f} ({hits[m] / P:5.1%})".rjust(24) for m in methods))
        total_P = sum(P for _, P, _ in per_date)
        stats = {}
        for m in methods:
            cov = [hits[m] / P for _, P, hits in per_date]
            stats[m] = {"mean": sum(cov) / len(cov), "min": min(cov), "max": max(cov),
                        "pooled": sum(hits[m] for _, _, hits in per_date) / total_P}
        for name in ("mean", "min", "max", "pooled"):
            print(f"{name.capitalize():12} {total_P if name == 'pooled' else '':>9}  "
                  + "  ".join(f"{stats[m][name]:.1%}".rjust(24) for m in methods))
        u = "Urgency score (pipeline)"
        for m in ("CVSS only", "EPSS only"):
            higher = sum(h[u] > h[m] for _, _, h in per_date)
            equal = sum(h[u] == h[m] for _, _, h in per_date)
            lower = len(per_date) - higher - equal
            print(f"Urgency score vs {m}: higher on {higher}, equal on {equal}, lower on {lower} "
                  f"of {len(per_date)} dates")
            stats[f"vs {m}"] = {"higher": higher, "equal": equal, "lower": lower}
        summary[key] = {"budget": budget, "positives_total": total_P, "stats": stats,
                        "per_date": [{"date": d, "positives": P, "hits": h} for d, P, h in per_date]}
        _plot_summary(per_date, methods, win, budget)
    out = OUT / f"backtest_summary_{all_results[0]['date']}_to_{all_results[-1]['date']}.json"
    out.write_text(json.dumps(summary, indent=2))
    print(f"\nSaved {out}")


def _month_starts(start: date, end: date) -> list[date]:
    days, d = [], start.replace(day=1)
    if d < start:
        d = (d + timedelta(days=32)).replace(day=1)
    while d <= end:
        days.append(d)
        d = (d + timedelta(days=32)).replace(day=1)
    return days


def main() -> int:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--date", type=date.fromisoformat, help="One cut-off date T (YYYY-MM-DD).")
    g.add_argument("--range", nargs=2, type=date.fromisoformat, metavar=("START", "END"),
                   help="Use the 1st of every month from START to END as cut-off dates.")
    p.add_argument("--windows", type=int, nargs="+", default=[30, 180],
                   help="Days after T in which a KEV addition counts as 'attacked later'.")
    args = p.parse_args()
    cfg = Config()
    dates = [args.date] if args.date else _month_starts(*args.range)

    print("Fetching CISA KEV ...")
    kev = fetch_kev(cfg)
    print("Fetching CVSS from NVD (slow the first time, then cached) ...")
    cvss = fetch_nvd_cvss()
    all_results = []
    for T in dates:
        print(f"Fetching EPSS scores as of {T} ...")
        all_results.append(run_one(T, args.windows, kev, cvss, cfg, plot=len(dates) == 1))
    if len(dates) > 1:
        summarise(all_results, args.windows)
    return 0


def _plot_summary(per_date: list, methods: list[str], win: int, budget: float) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    xs = [d for d, _, _ in per_date]
    fig, ax = plt.subplots(figsize=(9, 5))
    for m in methods:
        style = {"ls": "--", "color": "grey"} if m == "Random" else {}
        ax.plot(xs, [h[m] / P * 100 for _, P, h in per_date], marker="o", label=m, **style)
    ax.set_ylabel(f"Coverage at the {budget:.1%} budget (%)")
    ax.set_xlabel("Cut-off date T")
    ax.set_title(f"Share of later-KEV CVEs caught with a {budget:.1%} patching budget ({win}-day window)")
    ax.set_ylim(0, 100)
    ax.legend(loc="upper left", fontsize=8)
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    tag = "" if budget == 0.10 else f"_{budget * 100:g}pct"
    fig.savefig(OUT / f"backtest_summary_{xs[0]}_to_{xs[-1]}_{win}d{tag}.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def _plot(methods: dict, positive: list[bool], n: int, P: int, T: date, win: int, cvss7: int) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    xs = sorted({max(1, round(n * f / 200)) for f in range(0, 201)} | {round(0.10 * n), cvss7})
    fig, ax = plt.subplots(figsize=(8, 5))
    for m, scores in methods.items():
        ax.plot([x / n * 100 for x in xs], [h / P * 100 for h in hits_in_top(scores, positive, xs)], label=m)
    ax.plot([0, 100], [0, 100], "--", color="grey", label="Random")
    ax.axvline(10, color="black", lw=0.8, ls=":")
    ax.text(10.5, 3, "10%: Kenna/Cyentia\nmonthly capacity", fontsize=8)
    ax.axvline(cvss7 / n * 100, color="black", lw=0.8, ls=":")
    ax.text(cvss7 / n * 100 + 0.5, 3, "CVSS 7+ policy", fontsize=8)
    ax.set_xlabel("Work budget: share of candidate CVEs patched (%)")
    ax.set_ylabel(f"Coverage: share of the {P} later-KEV CVEs caught (%)")
    ax.set_title(f"Scored on {T}; outcome: added to KEV within {win} days")
    ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.legend(loc="lower right")
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"backtest_{T}_{win}d.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    sys.exit(main())
