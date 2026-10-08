"""
Demo dashboard for the healthcare CTI quality pipeline.

Shows a saved pipeline run (bundle + run summary from output/) and can start
a new live run against OpenCTI.

Usage:
    streamlit run app.py
"""
import csv
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from healthcare_cti_pipeline import Config

OUTPUT_DIR = Path("output")
HAND_CHECK = OUTPUT_DIR / "hand_check_sample.csv"
HAND_LABEL = "healthcare_relevant (yes/no/unclear)"

st.set_page_config(page_title="Healthcare CTI Quality", layout="wide")


# ==============================================================================
#  LOADING
# ==============================================================================

def list_runs() -> list[Path]:
    return sorted(OUTPUT_DIR.glob("healthcare_cti_*.json"), key=os.path.getmtime, reverse=True)


def summary_for(bundle: Path) -> dict | None:
    path = bundle.with_name(bundle.name.replace("healthcare_cti_", "run_summary_"))
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _signal(desc: str, name: str) -> float | None:
    """Read one signal value from the composite breakdown string."""
    # Present signals look like "CVSS=9.8/10(eff_w=0.250)"; missing ones like "CVSS=N/A".
    m = re.search(rf"{name}=(N/A|[^(\s]+)", desc)
    if not m or m.group(1) == "N/A":
        return None
    raw = m.group(1)
    if name == "KEV":
        return 1.0 if raw.upper() == "YES" else 0.0
    if name == "CVSS":
        return float(raw.split("/")[0])
    return float(raw)


def _weight(desc: str, name: str) -> float:
    m = re.search(rf"{name}=[^(]+\(eff_w=([\d.]+)\)", desc)
    return float(m.group(1)) if m else 0.0


@st.cache_data
def load_bundle(path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    objects = json.loads(Path(path).read_text(encoding="utf-8"))["objects"]

    vulns = []
    for o in objects:
        if o["type"] != "vulnerability":
            continue
        d = o.get("description", "")
        vulns.append({
            "CVE": o["name"],
            "Urgency": o.get("x_composite_score"),
            "EPSS": _signal(d, "EPSS"),
            "CVSS": _signal(d, "CVSS"),
            "KEV listed": bool(o.get("x_kev_listed")),
            "Signals": o.get("x_signal_count"),
            "_desc": d,
        })

    inds = []
    for o in objects:
        if o["type"] != "indicator":
            continue
        inds.append({
            "Feed": o.get("x_pipeline_source", "unknown"),
            "Type": o.get("x_observable_type", "Unknown"),
            "Value": o.get("pattern", ""),
            "Reliability grade": o.get("x_admiralty_grade"),
            "Reliability": o.get("x_admiralty_score"),
            "Actionability": o.get("x_actionability_score"),
            "IOC": o.get("x_ioc_present"),
            "ATT&CK technique": o.get("x_ttp_linked"),
            "Mitigation": o.get("x_mitigation_linked"),
            "Labels": ", ".join(o.get("labels", [])),
            "STIX id": o["id"],
        })
    return pd.DataFrame(vulns), pd.DataFrame(inds)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - m), min(1.0, c + m)


# ==============================================================================
#  SIDEBAR: PICK A RUN OR START A NEW ONE
# ==============================================================================

st.sidebar.title("Healthcare CTI Quality")
st.sidebar.caption("Urgency on vulnerabilities. Reliability and actionability on indicators. "
                   "Each scored separately, never blended.")

with st.sidebar.expander("Run the pipeline now", expanded=False):
    st.write("Fetches live data from OpenCTI, filters it, scores it and writes a new bundle.")
    limit = st.number_input("Indicators to fetch", min_value=50, max_value=5000, value=100, step=50)
    if st.button("Start run", type="primary"):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        proc = subprocess.Popen(
            [sys.executable, "healthcare_cti_pipeline.py", "--limit", str(int(limit))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env,
        )
        box = st.empty()
        lines: list[str] = []
        with st.spinner("Running..."):
            for line in proc.stdout:
                lines.append(line.rstrip())
                box.code("\n".join(lines[-12:]), language=None)
            proc.wait()
        if proc.returncode == 0:
            st.success("Run finished. Showing the new run.")
            st.cache_data.clear()
            st.rerun()
        else:
            st.error(f"Run failed (exit code {proc.returncode}). Is OpenCTI running and OPENCTI_TOKEN set?")

runs = list_runs()
if not runs:
    st.info("No runs found in output/. Start a run from the sidebar.")
    st.stop()

choice = st.sidebar.selectbox("Run to show", runs, format_func=lambda p: p.stem.replace("healthcare_cti_", "Run "))
summary = summary_for(choice)
vulns, inds = load_bundle(str(choice))
if summary is None:
    st.sidebar.warning("No run summary for this bundle (it was made by an older version). "
                       "The before and after comparison is not available.")


# ==============================================================================
#  HEADER
# ==============================================================================

st.title("Judging the quality of open threat intelligence for healthcare")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Indicators fetched", f"{summary['native_count']:,}" if summary else "n/a")
c2.metric("Indicators kept by the filter", f"{len(inds):,}")
c3.metric("Vulnerabilities ranked", f"{len(vulns):,}")
c4.metric("Confirmed exploited (KEV)", int(vulns["KEV listed"].sum()) if len(vulns) else 0)

tab_overview, tab_vulns, tab_inds, tab_filter = st.tabs(
    ["Overview", "Urgency: vulnerabilities", "Reliability and actionability: indicators", "Filter check"])


# ==============================================================================
#  OVERVIEW
# ==============================================================================

with tab_overview:
    st.subheader("Does the filter keep better intelligence, or just less of it?")
    if summary is None:
        st.info("Not available for this run.")
    else:
        qr = summary["quality_report"]
        rows = [("All feeds", qr["overall"])] + list(qr["by_source"].items())
        table = pd.DataFrame([{
            "Feed": name,
            "Before": ba["before"]["count"], "After": ba["after"]["count"],
            "Reliability before": ba["before"]["reliability"], "Reliability after": ba["after"]["reliability"],
            "Actionability before": ba["before"]["actionability"], "Actionability after": ba["after"]["actionability"],
        } for name, ba in rows])
        st.dataframe(table, hide_index=True, width="stretch")

        long = []
        for name, ba in rows:
            for dim in ("reliability", "actionability"):
                for stage in ("before", "after"):
                    long.append({"Feed": name, "Dimension": dim.capitalize(),
                                 "Stage": stage.capitalize(), "Score": ba[stage][dim]})
        chart = alt.Chart(pd.DataFrame(long)).mark_bar().encode(
            x=alt.X("Stage:N", sort=["Before", "After"], title=None),
            y=alt.Y("Score:Q", scale=alt.Scale(domain=[0, 1])),
            color=alt.Color("Stage:N", sort=["Before", "After"], legend=None),
            column=alt.Column("Feed:N", title=None, sort=[name for name, _ in rows]),
            row=alt.Row("Dimension:N", title=None),
            tooltip=["Feed", "Dimension", "Stage", alt.Tooltip("Score:Q", format=".3f")],
        ).properties(width=140, height=140)
        st.altair_chart(chart)

        st.markdown(
            "**How to read this.** For all feeds together, both scores rise after filtering. "
            "But inside each feed, reliability does not change at all. The overall rise comes from "
            "the filter keeping much more of one feed than the other. Separate dimensions make this "
            "visible; a single blended score would have hidden it.")


# ==============================================================================
#  VULNERABILITIES (URGENCY)
# ==============================================================================

with tab_vulns:
    st.subheader("Urgency = 0.35 EPSS + 0.25 CVSS + 0.40 KEV")
    st.caption("A missing signal has its weight removed and the rest rescaled. "
               "KEV is the only signal based on confirmed exploitation.")
    f1, f2 = st.columns([1, 2])
    only_kev = f1.checkbox("Only confirmed exploited (KEV)")
    min_score = f2.slider("Minimum urgency", 0.0, 1.0, 0.0, 0.05)
    view = vulns[vulns["Urgency"] >= min_score]
    if only_kev:
        view = view[view["KEV listed"]]
    view = view.sort_values("Urgency", ascending=False)

    left, right = st.columns([3, 2])
    with left:
        picked = st.dataframe(
            view.drop(columns=["_desc"]), hide_index=True, width="stretch", height=420,
            on_select="rerun", selection_mode="single-row",
            column_config={"Urgency": st.column_config.ProgressColumn(format="%.3f", min_value=0, max_value=1)})
    with right:
        st.altair_chart(alt.Chart(vulns).mark_bar().encode(
            x=alt.X("Urgency:Q", bin=alt.Bin(step=0.1), title="Urgency"),
            y=alt.Y("count():Q", title="Vulnerabilities"),
        ).properties(height=220, title="Most vulnerabilities are low priority"), width="stretch")

        sel = picked.selection.rows
        if sel:
            v = view.iloc[sel[0]]
            st.markdown(f"**{v['CVE']}**: urgency **{v['Urgency']:.3f}**. Where the score comes from:")
            for name in ("EPSS", "CVSS", "KEV"):
                value = _signal(v["_desc"], name)
                if value is None:
                    st.caption(f"{name}: missing, so its weight is moved to the other signals")
                    continue
                norm = value / 10 if name == "CVSS" else value
                weight = _weight(v["_desc"], name)
                shown = {"EPSS": f"{value:.4f}", "CVSS": f"{value:g}/10",
                         "KEV": "yes" if value else "no"}[name]
                st.progress(min(weight * norm, 1.0),
                            text=f"{name}: {shown} × weight {weight:.3f} = {weight * norm:.3f}")
        else:
            st.caption("Click a row to see where its score comes from.")


# ==============================================================================
#  INDICATORS (RELIABILITY + ACTIONABILITY)
# ==============================================================================

with tab_inds:
    st.subheader("Reliability and actionability, shown side by side")
    st.caption("Reliability: the source's NATO Admiralty grade in OpenCTI. "
               "Actionability = 0.30 IOC + 0.40 linked ATT&CK technique + 0.30 linked mitigation.")
    feeds = sorted(inds["Feed"].unique()) if len(inds) else []
    g1, g2 = st.columns(2)
    chosen = g1.multiselect("Feed", feeds, default=feeds)
    tiers = sorted(inds["Actionability"].dropna().unique()) if len(inds) else []
    tier = g2.multiselect("Actionability", tiers, default=tiers)
    view = inds[inds["Feed"].isin(chosen) & inds["Actionability"].isin(tier)]

    left, right = st.columns([3, 2])
    with left:
        picked = st.dataframe(
            view.drop(columns=["STIX id", "Labels"]), hide_index=True, width="stretch", height=420,
            on_select="rerun", selection_mode="single-row",
            column_config={"Actionability": st.column_config.ProgressColumn(format="%.1f", min_value=0, max_value=1),
                           "Reliability": st.column_config.ProgressColumn(format="%.2f", min_value=0, max_value=1)})
    with right:
        if len(view):
            st.altair_chart(alt.Chart(view).mark_bar().encode(
                x=alt.X("Actionability:O", title="Actionability"),
                y=alt.Y("count():Q", title="Indicators"),
                color=alt.Color("Feed:N"),
            ).properties(height=220, title="Actionability by feed"), width="stretch")
        sel = picked.selection.rows
        if sel:
            i = view.iloc[sel[0]]
            st.markdown(f"**{i['Type']}** from **{i['Feed']}**")
            st.code(i["Value"], language=None)
            m1, m2 = st.columns(2)
            m1.metric("Reliability", f"Grade {i['Reliability grade']}", f"{i['Reliability']:.2f}", delta_color="off")
            m2.metric("Actionability", f"{i['Actionability']:.1f}", delta_color="off")
            tick = lambda b: "yes" if b else "no"
            st.markdown(f"IOC present: **{tick(i['IOC'])}** · ATT&CK technique: **{tick(i['ATT&CK technique'])}** · "
                        f"Mitigation: **{tick(i['Mitigation'])}**")
            if i["Labels"]:
                st.caption(f"Labels: {i['Labels']}")
        else:
            st.caption("Click a row to see its scores. A trusted source (high reliability) can still give "
                       "an analyst little to act on (low actionability).")


# ==============================================================================
#  FILTER CHECK
# ==============================================================================

with tab_filter:
    cfg = Config()
    st.subheader("What does the healthcare filter actually keep?")
    k1, k2 = st.columns(2)
    k1.markdown("**Sector words** (STIX 2.1, ENISA 2023)  \n" + ", ".join(sorted(cfg.SECTOR_KEYWORDS)))
    k2.markdown("**Threat words** (ENISA 2023)  \n" + ", ".join(sorted(cfg.THREAT_KEYWORDS)))

    if summary is not None:
        reasons = summary["quality_report"].get("after_by_reason", {})
        labels = {"sector": "Sector word", "threat": "Threat word only", "unlabelled": "No labels (soft mode)"}
        df = pd.DataFrame([{"Why it passed": labels[k], "Indicators": reasons.get(k, 0)} for k in labels])
        st.altair_chart(alt.Chart(df).mark_bar().encode(
            x="Indicators:Q", y=alt.Y("Why it passed:N", sort=None, title=None),
            tooltip=["Why it passed", "Indicators"],
        ).properties(height=150, title="Why indicators passed the filter"), width="stretch")

    st.markdown("**Hand check of a random sample of filtered indicators**")
    if HAND_CHECK.exists():
        with open(HAND_CHECK, encoding="utf-8-sig") as f:
            rows = [r for r in csv.DictReader(f) if r[HAND_LABEL].strip()]
        n = len(rows)
        yes = sum(r[HAND_LABEL] == "yes" for r in rows)
        lo, hi = wilson(yes, n)
        h1, h2, h3 = st.columns(3)
        h1.metric("Checked by hand", n)
        h2.metric("About a healthcare target", f"{yes} of {n}")
        h3.metric("95% confidence interval", f"{100*lo:.1f}% to {100*hi:.1f}%")
        st.dataframe(pd.DataFrame([{"Label": r[HAND_LABEL], "Feed": r["source"], "Value": r["value"],
                                    "Report": r["report_name"]} for r in rows]),
                     hide_index=True, width="stretch", height=300)
        st.caption("Free, general feeds hold very little intelligence that is specific to healthcare.")
    else:
        st.info("No hand check found. Create one with label_hand_check.py.")
