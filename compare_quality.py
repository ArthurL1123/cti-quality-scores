"""
Standalone quality comparison script.

Does NOT modify the main pipeline. Fetches ALL native indicators from
OpenCTI (no healthcare-relevance filter applied), scores each for
reliability and actionability using the exact same logic as the main
pipeline, and prints the average scores.

Compare these "before filter" averages against the averages from your
already-exported, filtered bundle (the "after filter" numbers) to see
whether filtering actually selects for quality.

Usage:
    python compare_quality.py
    python compare_quality.py --limit 500      # smaller test run
"""
import argparse
import sys

# Reuse the exact same scoring logic as the main pipeline - no duplication.
from healthcare_cti_pipeline import (
    Config,
    connect_opencti,
    fetch_native_indicators,
    _get_admiralty,
    _get_actionability,
    _fetch_related_entity_types,
)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=None,
                   help="Cap the number of raw indicators fetched (for a quick test run).")
    args = p.parse_args()

    cfg = Config()
    if args.limit:
        cfg.FETCH_LIMIT = args.limit

    token = cfg.OPENCTI_TOKEN
    if not token or len(token) < 20:
        print("ERROR: OPENCTI_TOKEN missing or invalid.")
        return 1

    client = connect_opencti(cfg)

    print("Fetching ALL native indicators (no healthcare-relevance filter)...")
    raw_indicators = fetch_native_indicators(client, cfg)
    print(f"Fetched {len(raw_indicators)} raw indicators.\n")

    admiralty_scores: list[float] = []
    actionability_scores: list[float] = []

    for i, ind in enumerate(raw_indicators, 1):
        _, adm_score = _get_admiralty(ind, cfg)
        if adm_score is not None:
            admiralty_scores.append(adm_score)

        related_types, ap_ids = (
            _fetch_related_entity_types(client, ind["id"], cfg)
            if ind.get("id") else (set(), set())
        )
        act_score, *_ = _get_actionability(ind, related_types, ap_ids, client, cfg)
        if act_score is not None:
            actionability_scores.append(act_score)

        if i % 100 == 0:
            print(f"  ...scored {i}/{len(raw_indicators)}")

    avg_adm = sum(admiralty_scores) / len(admiralty_scores) if admiralty_scores else None
    avg_act = sum(actionability_scores) / len(actionability_scores) if actionability_scores else None

    print("\n" + "=" * 60)
    print("  RAW (UNFILTERED) INDICATOR QUALITY - BASELINE")
    print("=" * 60)
    print(f"  Sample size            : {len(raw_indicators)}")
    print(f"  Avg reliability score  : {avg_adm}")
    print(f"  Avg actionability score: {avg_act}")
    print("=" * 60)
    print("\nCompare these numbers against the averages computed from your")
    print("already-exported, filtered bundle to see whether the healthcare-")
    print("relevance filter selects for higher-quality artefacts.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
