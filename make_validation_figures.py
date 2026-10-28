"""
Draw the validation figures from saved results (no OpenCTI, no downloads).

Reads:
  output/backtest/backtest_summary_<start>_to_<end>.json   (backtest_urgency.py --range)
  output/backtest/significance_<start>_to_<end>.json       (check_backtest_significance.py)
  output/validation_indicators_<ts>.csv                    (validate_indicators.py; newest is used)

Writes PNGs to output/figures/.

Usage:
    python make_validation_figures.py
    python make_validation_figures.py --start 2025-04-01 --end 2026-04-01
"""
import argparse
import csv
import json
import logging
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from validate_indicators import wilson

logging.getLogger("matplotlib").setLevel(logging.WARNING)
OUT = Path("output/figures")
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
COLOR = {"Urgency score (pipeline)": "#2a78d6", "CVSS only": "#eb6834", "EPSS only": "#1baf7a",
         "Random": "#9a9893", "AlienVault": "#2a78d6", "Threat Fox | Abuse.ch": "#eb6834"}
LABEL = {"Urgency score (pipeline)": "Urgency score", "Threat Fox | Abuse.ch": "ThreatFox"}


def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9)
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)


def _save(fig, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    fig.patch.set_facecolor(SURFACE)
    fig.savefig(OUT / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  {OUT / name}")


def backtest_monthly(summary: dict, win: str) -> None:
    per_date = summary[win]["per_date"]
    dates = [d["date"][:7] for d in per_date]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ends = {}
    for m in ("Urgency score (pipeline)", "EPSS only", "CVSS only", "Random"):
        ys = [d["hits"][m] / d["positives"] * 100 for d in per_date]
        ax.plot(dates, ys, color=COLOR[m], lw=2, marker="o", ms=5, ls="--" if m == "Random" else "-")
        ends[m] = ys[-1]
    placed = []                                  # end labels, pushed apart so they never overlap
    for m, y in sorted(ends.items(), key=lambda kv: kv[1]):
        y = max(y, placed[-1] + 5) if placed else y
        placed.append(y)
        ax.annotate(LABEL.get(m, m), (len(dates) - 1, y), xytext=(10, 0), textcoords="offset points",
                    va="center", fontsize=9, color=INK)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Later-attacked CVEs caught (%)", color=INK2, fontsize=9)
    ax.set_xlabel("Cut-off date (scored using only data known on the 1st of the month)", color=INK2, fontsize=9)
    ax.set_title(f"Patching 1 in 10 CVEs: share of those added to CISA KEV within {win} days",
                 color=INK, fontsize=11, loc="left")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    _style(ax)
    _save(fig, f"fig_backtest_monthly_{win}d.png")


def significance(sig: dict) -> None:
    fig, ax = plt.subplots(figsize=(7, 2.4))
    names = ["CVSS only", "EPSS only"]
    for y, other in enumerate(names):
        r = sig["vs"][other]
        d, lo, hi = r["diff"] * 100, r["ci"][0] * 100, r["ci"][1] * 100
        ax.plot([lo, hi], [y, y], color=COLOR[other], lw=2, solid_capstyle="round")
        ax.plot(d, y, "o", color=COLOR[other], ms=9)
        ax.annotate(f"+{d:.1f} points (95% CI +{lo:.1f} to +{hi:.1f}), p = {r['p']:.4f}", (hi, y),
                    xytext=(8, 0), textcoords="offset points", va="center", fontsize=9, color=INK)
    ax.axvline(0, color=INK2, lw=1)
    ax.set_yticks(range(len(names)), [f"vs {n}" for n in names])
    ax.set_ylim(-0.6, len(names) - 0.4)
    ax.set_xlim(-5, 45)
    ax.set_xlabel("Extra later-attacked CVEs caught by the urgency score (percentage points)",
                  color=INK2, fontsize=9)
    ax.set_title(f"Urgency score lead at a 10% budget ({sig['cves']} CVEs, {sig['window_days']}-day windows)",
                 color=INK, fontsize=11, loc="left")
    _style(ax)
    ax.yaxis.grid(False)
    ax.xaxis.grid(True, color=GRID, lw=0.8)
    _save(fig, "fig_backtest_significance.png")


def reliability(rows: list[dict]) -> None:
    groups = [("Domains and hostnames", {"domain-name", "hostname"}), ("IPv4 addresses", {"ipv4-addr"})]
    feeds = [("AlienVault", "B"), ("Threat Fox | Abuse.ch", "C")]
    fig, ax = plt.subplots(figsize=(7, 3.8))
    width = 0.36
    for g, (gname, types) in enumerate(groups):
        for f, (feed, grade) in enumerate(feeds):
            sub = [r for r in rows if r["feed"] == feed and r["type"] in types]
            k, n = sum(r["hit_harmless"] == "True" for r in sub), len(sub)
            lo, hi = wilson(k, n)
            x = g + (f - 0.5) * (width + 0.04)
            ax.bar(x, k / n * 100, width, color=COLOR[feed], label=f"{LABEL.get(feed, feed)} (grade {grade})" if g == 0 else None)
            ax.errorbar(x, k / n * 100, yerr=[[(k / n - lo) * 100], [(hi - k / n) * 100]], color=INK, capsize=3, lw=1)
            ax.annotate(f"{k / n:.1%}\n({k:,}/{n:,})", (x, hi * 100), xytext=(0, 4), textcoords="offset points",
                        ha="center", fontsize=8, color=INK)
    ax.set_xticks(range(len(groups)), [g for g, _ in groups])
    ax.set_ylim(0, 9)
    ax.set_ylabel("Indicators on a harmless warninglist (%)", color=INK2, fontsize=9)
    ax.set_title("Values that would block legitimate traffic, by feed", color=INK, fontsize=11, loc="left")
    ax.legend(frameon=False, fontsize=9, loc="upper left")
    _style(ax)
    _save(fig, "fig_reliability_warninglists.png")


def actionability(rows: list[dict]) -> None:
    sub = [r for r in rows if r["sampled"] == "True"]
    scores = sorted({r["actionability"] for r in sub}, key=float)
    fig, ax = plt.subplots(figsize=(6, 3.4))
    for i, s in enumerate(scores):
        grp = [r for r in sub if r["actionability"] == s]
        k, n = sum(r["usable"] == "True" for r in grp), len(grp)
        lo, hi = wilson(k, n)
        ax.plot([i, i], [lo * 100, hi * 100], color=COLOR["Urgency score (pipeline)"], lw=2)
        ax.plot(i, k / n * 100, "o", color=COLOR["Urgency score (pipeline)"], ms=9)
        ax.annotate(f"{k / n:.1%}  (n={n})", (i, k / n * 100), xytext=(10, 0), textcoords="offset points",
                    va="center", fontsize=9, color=INK)
    ax.set_xticks(range(len(scores)), [f"score {float(s):.1f}" for s in scores])
    ax.set_xlim(-0.5, len(scores) - 0.2)
    ax.set_ylim(85, 100)
    ax.set_ylabel("Usable as-is (%), 95% CI", color=INK2, fontsize=9)
    ax.set_title("Actionability score vs usability (1,000 sampled indicators)", color=INK, fontsize=11, loc="left")
    _style(ax)
    _save(fig, "fig_actionability_usability.png")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--start", default="2025-04-01")
    p.add_argument("--end", default="2026-04-01")
    args = p.parse_args()
    base = Path("output/backtest")
    summary = json.loads((base / f"backtest_summary_{args.start}_to_{args.end}.json").read_text())
    sig = json.loads((base / f"significance_{args.start}_to_{args.end}.json").read_text())
    csv_path = max(Path("output").glob("validation_indicators_*.csv"))
    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"Indicator results from {csv_path}")
    for win in ("180", "30"):
        backtest_monthly(summary, win)
    significance(sig)
    reliability(rows)
    actionability(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
