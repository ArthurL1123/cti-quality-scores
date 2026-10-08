"""
Check what the urgency threshold removes from the vulnerability list.

Scores vulnerabilities with the pipeline's own function, but keeps every one
(threshold 0) so the effect of different thresholds can be compared. Reports,
for the pipeline's threshold, which CVSS severity bands are dropped and kept,
using the CVSS v3.1 qualitative scale (Low 0.1-3.9, Medium 4.0-6.9,
High 7.0-8.9, Critical 9.0-10.0). Read-only: nothing is written to OpenCTI.

Usage:
    python check_threshold.py
    python check_threshold.py --limit 2000
"""
import argparse
import logging
import sys
from collections import Counter

from healthcare_cti_pipeline import Config, connect_opencti, enrich_vulnerabilities_with_epss

COMPARE = (0.05, 0.10, 0.15, 0.20, 0.25)


def band(cvss: float | None) -> str:
    if cvss is None:
        return "no CVSS"
    if cvss < 4.0:
        return "Low"
    if cvss < 7.0:
        return "Medium"
    if cvss < 9.0:
        return "High"
    return "Critical"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=2000, help="Vulnerabilities to fetch.")
    args = p.parse_args()
    logging.disable(logging.INFO)

    cfg = Config()
    threshold = cfg.COMPOSITE_THRESHOLD
    cfg.FETCH_LIMIT = args.limit
    cfg.COMPOSITE_THRESHOLD = 0.0

    scored = enrich_vulnerabilities_with_epss(connect_opencti(cfg), cfg)
    rows = []
    for cve, e in scored.items():
        d = e["composite_breakdown"]
        rows.append({
            "cve":   cve,
            "score": e["composite_score"],
            "kev":   e["kev_listed"],
            "epss":  None if "EPSS=N/A" in d else e["epss_score"],
            "cvss":  None if "CVSS=N/A" in d else e["cvss_base"],
        })
    if not rows:
        print("No vulnerabilities scored.")
        return 1

    def kept(t: float) -> list[dict]:
        return [r for r in rows if r["score"] >= t or r["kev"]]

    print(f"Vulnerabilities scored: {len(rows)}\n")
    print("Threshold   kept          dropped")
    for t in COMPARE:
        k = len(kept(t))
        print(f"  {t:.2f}     {k:>5} ({100 * k / len(rows):4.1f}%)   {len(rows) - k:>5}")

    keep = kept(threshold)
    drop = [r for r in rows if r not in keep]
    print(f"\nAt the pipeline threshold ({threshold:.2f}):")
    print("  Dropped by CVSS band:", dict(Counter(band(r["cvss"]) for r in drop)))
    print("  Kept by CVSS band:   ", dict(Counter(band(r["cvss"]) for r in keep)))
    print("  KEV listed dropped:  ", sum(r["kev"] for r in drop))
    print("  Medium or higher dropped:",
          sum(1 for r in drop if r["cvss"] is not None and r["cvss"] >= 4.0))
    print("  Low kept:            ",
          sum(1 for r in keep if r["cvss"] is not None and r["cvss"] < 4.0))

    no_cvss = sorted(r["epss"] for r in drop if r["cvss"] is None and r["epss"] is not None)
    if no_cvss:
        print(f"  Dropped with no CVSS: {len(no_cvss)}, EPSS median {no_cvss[len(no_cvss) // 2]:.4f}, "
              f"max {no_cvss[-1]:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
