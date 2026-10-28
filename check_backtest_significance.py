"""
Test whether the urgency score's lead in the back-test is real or chance.

Uses the 30-day windows of backtest_urgency.py for the 1st of each month: each
CVE is added to KEV once, so it is an "attacked later" case in at most one
window and no CVE is counted twice. For every such CVE, records whether it was
inside the budget (default 10%, the Kenna/Cyentia monthly capacity) under each ranking. A
CVE in a tie that straddles the budget cut counts as the share of the tie
that fits (the chance of being inside if ties were broken at random).

Then compares the urgency score with CVSS only and with EPSS only:
  - difference in coverage (urgency minus the other)
  - 95% bootstrap confidence interval (resampling CVEs)
  - two-sided paired permutation test: each CVE's pair of results is swapped
    at random, which is what "both rankings are equally good" would allow

Reads the data cached by backtest_urgency.py (run it with --range first).
The results are saved to output/backtest/significance_<start>_to_<end>.json.
Read-only.

Usage:
    python check_backtest_significance.py --range 2025-04-01 2026-04-01
"""
import argparse
import json
import sys
from datetime import date, timedelta

import numpy as np

from backtest_urgency import OUT, _month_starts, fetch_epss_on, fetch_kev, fetch_nvd_cvss, urgency
from healthcare_cti_pipeline import Config

SEED = 42
RESAMPLES = 10_000
BUDGET = 0.10
WINDOW = 30


def inside_budget(scores: list[float], targets: list[int], k: int) -> list[float]:
    """For each target index: 1 if inside the top k, 0 if not, the fitting
    share of the tie if its tie group straddles the cut."""
    above = {}
    for t in targets:
        v = scores[t]
        above[t] = (sum(1 for s in scores if s > v), sum(1 for s in scores if s == v))
    out = []
    for t in targets:
        higher, tied = above[t]
        out.append(max(0.0, min(1.0, (k - higher) / tied)))
    return out


def paired_test(a: np.ndarray, b: np.ndarray, rng: np.random.Generator) -> dict:
    diff = a - b
    observed = diff.mean()
    boots = np.array([rng.choice(diff, len(diff)).mean() for _ in range(RESAMPLES)])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    extreme = 0
    for _ in range(RESAMPLES):
        signs = rng.choice([-1.0, 1.0], len(diff))
        if abs((signs * diff).mean()) >= abs(observed) - 1e-12:
            extreme += 1
    return {"diff": observed, "ci": (lo, hi), "p": (extreme + 1) / (RESAMPLES + 1),
            "only_a": int((diff > 0).sum()), "only_b": int((diff < 0).sum())}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--range", nargs=2, type=date.fromisoformat, metavar=("START", "END"), required=True)
    p.add_argument("--budget", type=float, default=BUDGET,
                   help="Share of candidates patched (0.10 Kenna/Cyentia 2019; 0.155 their 2022 figure).")
    args = p.parse_args()
    cfg = Config()
    kev = fetch_kev(cfg)
    cvss = fetch_nvd_cvss()

    per_cve = {"Urgency score": [], "CVSS only": [], "EPSS only": []}
    for T in _month_starts(*args.range):
        epss = fetch_epss_on(T)
        cands = sorted(c for c in epss if not (c in kev and kev[c] <= T))
        end = T + timedelta(days=WINDOW)
        targets = [i for i, c in enumerate(cands) if c in kev and T < kev[c] <= end]
        k = round(args.budget * len(cands))
        cvss_of = [cvss.get(c) for c in cands]
        rankings = {
            "Urgency score": [urgency(epss[c], s, cfg) for c, s in zip(cands, cvss_of)],
            "CVSS only": [s if s is not None else -1.0 for s in cvss_of],
            "EPSS only": [epss[c] for c in cands],
        }
        for m, scores in rankings.items():
            per_cve[m].extend(inside_budget(scores, targets, k))
        print(f"  {T}: {len(targets)} CVEs added to KEV within {WINDOW} days", flush=True)

    rng = np.random.default_rng(SEED)
    n = len(per_cve["Urgency score"])
    arrays = {m: np.array(v) for m, v in per_cve.items()}
    print(f"\n{n} CVEs added to KEV within {WINDOW} days of a cut-off date, budget {args.budget:.1%}, "
          f"seed {SEED}, {RESAMPLES:,} resamples")
    results = {"cves": n, "budget": args.budget, "window_days": WINDOW, "seed": SEED, "resamples": RESAMPLES,
               "coverage": {m: a.mean() for m, a in arrays.items()}, "vs": {}}
    for m, a in arrays.items():
        print(f"  coverage {m:14} {a.mean():.1%}")
    for other in ("CVSS only", "EPSS only"):
        t = paired_test(arrays["Urgency score"], arrays[other], rng)
        results["vs"][other] = {"diff": t["diff"], "ci": list(t["ci"]), "p": t["p"],
                                "better": t["only_a"], "worse": t["only_b"]}
        print(f"\nUrgency score minus {other}: {t['diff']:+.1%} "
              f"(95% CI {t['ci'][0]:+.1%} to {t['ci'][1]:+.1%}), p = {t['p']:.4f}")
        print(f"  CVEs where the urgency score did better: {t['only_a']}, worse: {t['only_b']}")
    tag = "" if args.budget == BUDGET else f"_{args.budget * 100:g}pct"
    out = OUT / f"significance_{args.range[0]}_to_{args.range[1]}{tag}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"\nSaved {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
