"""
Test whether the sector filter's effect on quality scores is real or chance.

Fetches native indicators from OpenCTI, scores every one with the pipeline's
own functions (before any filtering), and compares the indicators that pass
the filter with those that do not, overall and inside each feed:

  - difference in average score (passed minus dropped)
  - 95% bootstrap confidence interval for that difference
  - two-sided permutation test p-value

Both methods make no assumption about the shape of the distribution, which
suits scores that only take a few values. Also splits the overall rise in
average actionability into the part caused by the change in feed mix and the
part from changes inside the feeds. Per-indicator scores (no IOC values) are
saved to output/ so the result can be re-checked. Read-only.

Usage:
    python check_significance.py
    python check_significance.py --limit 5000
"""
import argparse
import csv
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from healthcare_cti_pipeline import (
    Config,
    _fetch_related_entity_types,
    _get_actionability,
    _get_admiralty,
    _source_name,
    connect_opencti,
    fetch_native_indicators,
    filter_reason,
)

SEED = 42
RESAMPLES = 10_000


def diff_test(passed: np.ndarray, dropped: np.ndarray, rng: np.random.Generator) -> dict:
    """Mean difference, bootstrap CI and permutation p-value (two-sided)."""
    if len(passed) == 0 or len(dropped) == 0:
        return {"diff": None, "ci": (None, None), "p": None}
    observed = passed.mean() - dropped.mean()

    boots = np.empty(RESAMPLES)
    for i in range(RESAMPLES):
        boots[i] = (rng.choice(passed, len(passed)).mean()
                    - rng.choice(dropped, len(dropped)).mean())
    lo, hi = np.percentile(boots, [2.5, 97.5])

    pooled = np.concatenate([passed, dropped])
    n = len(passed)
    extreme = 0
    for _ in range(RESAMPLES):
        rng.shuffle(pooled)
        if abs(pooled[:n].mean() - pooled[n:].mean()) >= abs(observed) - 1e-12:
            extreme += 1
    p = (extreme + 1) / (RESAMPLES + 1)
    return {"diff": observed, "ci": (lo, hi), "p": p}


def fmt(x: float | None, nd: int = 3) -> str:
    return "n/a" if x is None else f"{x:.{nd}f}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5000, help="Native indicators to fetch.")
    args = ap.parse_args()
    logging.disable(logging.INFO)

    cfg = Config()
    cfg.FETCH_LIMIT = args.limit
    client = connect_opencti(cfg)
    indicators = fetch_native_indicators(client, cfg)
    print(f"Fetched {len(indicators)} indicators. Scoring...", flush=True)

    rows = []
    for n, ind in enumerate(indicators, 1):
        related, ap_ids = _fetch_related_entity_types(client, ind["id"], cfg)
        _, reliability = _get_admiralty(ind, cfg)
        actionability, *_ = _get_actionability(ind, related, ap_ids, client, cfg)
        rows.append({
            "opencti_id":    ind["id"],
            "feed":          _source_name(ind),
            "filter_reason": filter_reason(ind, cfg) or "dropped",
            "reliability":   reliability,
            "actionability": actionability,
        })
        if n % 250 == 0 or n == len(indicators):
            print(f"  scored {n} of {len(indicators)}", flush=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(cfg.OUTPUT_DIR) / f"significance_scores_{ts}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    rng = np.random.default_rng(SEED)
    feeds = sorted({r["feed"] for r in rows})
    groups = [("All feeds", rows)] + [(f, [r for r in rows if r["feed"] == f]) for f in feeds]

    print(f"\nRun {ts}, {len(rows)} indicators, seed {SEED}, {RESAMPLES:,} resamples")
    print(f"Per-indicator scores saved to {out}\n")
    for dim in ("reliability", "actionability"):
        print(f"== {dim.upper()}: passed vs dropped (difference = passed minus dropped)")
        for name, grp in groups:
            passed = np.array([r[dim] for r in grp if r["filter_reason"] != "dropped"], dtype=float)
            dropped = np.array([r[dim] for r in grp if r["filter_reason"] == "dropped"], dtype=float)
            before = np.array([r[dim] for r in grp], dtype=float)
            t = diff_test(passed, dropped, rng)
            print(f"  {name[:22]:<22} n={len(grp):>5} passed={len(passed):>4}  "
                  f"before={fmt(before.mean())} after={fmt(passed.mean() if len(passed) else None)}  "
                  f"diff={fmt(t['diff'])} 95% CI [{fmt(t['ci'][0])}, {fmt(t['ci'][1])}] "
                  f"p={fmt(t['p'], 4)}")
        print()

    # Split the overall rise in actionability: feed mix vs. change inside feeds.
    before_all = np.mean([r["actionability"] for r in rows])
    after_rows = [r for r in rows if r["filter_reason"] != "dropped"]
    after_all = np.mean([r["actionability"] for r in after_rows]) if after_rows else float("nan")
    mix_held = 0.0
    for f in feeds:
        share = sum(r["feed"] == f for r in rows) / len(rows)
        kept = [r["actionability"] for r in after_rows if r["feed"] == f]
        mix_held += share * (np.mean(kept) if kept else np.mean([r["actionability"] for r in rows if r["feed"] == f]))
    print("== ACTIONABILITY: where the overall rise comes from")
    print(f"  before {before_all:.3f} -> after {after_all:.3f}  (rise {after_all - before_all:+.3f})")
    print(f"  after, with the feed mix held at its before-filter shares: {mix_held:.3f}")
    print(f"  rise from changes inside the feeds: {mix_held - before_all:+.3f}")
    print(f"  rise from the change in feed mix:   {after_all - mix_held:+.3f}")

    print("\n== Why indicators passed:",
          {k: sum(r["filter_reason"] == k for r in rows) for k in ("sector", "threat", "unlabelled")})
    return 0


if __name__ == "__main__":
    sys.exit(main())
