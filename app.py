"""
Demo dashboard for the healthcare CTI quality pipeline.

Runs the pipeline against OpenCTI, loads saved results from output/, and
compares the indicators before and after the sector filter.

Usage:
    streamlit run app.py
"""
import json
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
        })
    return pd.DataFrame(vulns), pd.DataFrame(inds)


def run_label(path: Path) -> str:
    ts = path.stem.replace("healthcare_cti_", "")
    s = summary_for(path)
    size = f"{s['native_count']:,} indicators" if s else "older run"
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]} UTC ({size})"


# ==============================================================================
#  SIDEBAR: LOAD RESULTS
# ==============================================================================

st.sidebar.title("Healthcare CTI Quality")
st.sidebar.caption("Urgency on vulnerabilities. Reliability and actionability on indicators. "
                   "Each scored separately, never blended.")

runs = list_runs()
# After a run finishes, select the newest run. This has to happen before the
# selectbox below is created, so the run handler only sets a flag.
if st.session_state.pop("select_newest", False) and runs:
    st.session_state["run_choice"] = runs[0]
st.sidebar.subheader("Load results")
if runs:
    choice = st.sidebar.selectbox("Pipeline run", runs, format_func=run_label, key="run_choice")
else:
    choice = None
    st.sidebar.info("No results yet. Run the pipeline first.")

st.title("Judging the quality of open threat intelligence for healthcare")
tab_run, tab_compare, tab_vulns, tab_inds = st.tabs(
    ["Run pipeline", "Before vs after filter", "Urgency: vulnerabilities", "Reliability and actionability: indicators"])


# ==============================================================================
#  RUN PIPELINE
# ==============================================================================

with tab_run:
    st.subheader("Run the pipeline on live OpenCTI data")
    st.write("Fetches indicators and vulnerabilities from OpenCTI, filters the indicators for healthcare, "
             "scores urgency, reliability and actionability, and saves a STIX 2.1 bundle. "
             "About 100 indicators take under a minute; 2,000 take a few minutes.")
    limit = st.number_input("Indicators to fetch", min_value=50, max_value=5000, value=100, step=50)

    if st.session_state.pop("just_finished", False):
        st.success("Run finished and loaded. Open the other tabs to see the results.")

    if st.button("Start run", type="primary"):
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        proc = subprocess.Popen(
            [sys.executable, "healthcare_cti_pipeline.py", "--limit", str(int(limit))],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", env=env,
        )
        log_box = st.empty()
        lines: list[str] = []
        with st.spinner("Running the pipeline..."):
            for line in proc.stdout:
                lines.append(line.rstrip())
                log_box.code("\n".join(lines[-15:]), language=None)
            proc.wait()
        if proc.returncode == 0:
            st.cache_data.clear()
            st.session_state["select_newest"] = True
            st.session_state["just_finished"] = True
            st.rerun()
        else:
            st.error(f"The run failed (exit code {proc.returncode}). "
                     "Check that OpenCTI is running and OPENCTI_TOKEN is set.")

if choice is None:
    st.stop()

summary = summary_for(choice)
vulns, inds = load_bundle(str(choice))


# ==============================================================================
#  BEFORE VS AFTER
# ==============================================================================

with tab_compare:
    if summary is None:
        st.info("This run was made by an older version of the pipeline, so it has no before and after data. "
                "Run the pipeline again to get it.")
    else:
        qr = summary["quality_report"]
        overall = qr["overall"]
        before_n, after_n = overall["before"]["count"], overall["after"]["count"]

        st.subheader("Volume: how many indicators the filter keeps")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Indicators before filter", f"{before_n:,}")
        c2.metric("Indicators after filter", f"{after_n:,}",
                  f"-{100 * (1 - after_n / before_n):.1f}%" if before_n else None, delta_color="off")
        c3.metric("Vulnerabilities ranked", f"{len(vulns):,}")
        c4.metric("Confirmed exploited (KEV)", int(vulns["KEV listed"].sum()) if len(vulns) else 0)

        feeds = list(qr["by_source"].items())
        counts = pd.DataFrame([{"Feed": name, "Stage": stage.capitalize(), "Indicators": ba[stage]["count"]}
                               for name, ba in feeds for stage in ("before", "after")])
        kept = pd.DataFrame([{"Feed": name, "Kept": f"{ba['after']['count']:,} of {ba['before']['count']:,}",
                              "Share kept": f"{100 * ba['after']['count'] / ba['before']['count']:.1f}%"
                              if ba["before"]["count"] else "n/a"} for name, ba in feeds])
        left, right = st.columns([3, 2])
        left.altair_chart(alt.Chart(counts).mark_bar().encode(
            x=alt.X("Feed:N", title=None),
            xOffset=alt.XOffset("Stage:N", sort=["Before", "After"]),
            y=alt.Y("Indicators:Q"),
            color=alt.Color("Stage:N", sort=["Before", "After"]),
            tooltip=["Feed", "Stage", "Indicators"],
        ).properties(height=260), width="stretch")
        right.dataframe(kept, hide_index=True, width="stretch")
        right.caption("The filter keeps a much larger share of one feed than the other.")

        st.subheader("Quality: average scores before and after")
        rows = [("All feeds", overall)] + feeds
        st.dataframe(pd.DataFrame([{
            "Feed": name,
            "Reliability before": ba["before"]["reliability"], "Reliability after": ba["after"]["reliability"],
            "Actionability before": ba["before"]["actionability"], "Actionability after": ba["after"]["actionability"],
        } for name, ba in rows]), hide_index=True, width="stretch")

        long = [{"Feed": name, "Dimension": dim.capitalize(), "Stage": stage.capitalize(), "Score": ba[stage][dim]}
                for name, ba in rows for dim in ("reliability", "actionability") for stage in ("before", "after")]
        st.altair_chart(alt.Chart(pd.DataFrame(long)).mark_bar().encode(
            x=alt.X("Stage:N", sort=["Before", "After"], title=None),
            y=alt.Y("Score:Q", scale=alt.Scale(domain=[0, 1])),
            color=alt.Color("Stage:N", sort=["Before", "After"], legend=None),
            column=alt.Column("Feed:N", title=None, sort=[name for name, _ in rows]),
            row=alt.Row("Dimension:N", title=None),
            tooltip=["Feed", "Dimension", "Stage", alt.Tooltip("Score:Q", format=".3f")],
        ).properties(width=150, height=140))
        st.info("**How to read this.** For all feeds together, both scores rise after filtering. "
                "But inside each feed, reliability does not change at all. The overall rise comes from the "
                "filter keeping much more of one feed than the other. Separate dimensions make this visible; "
                "a single blended score would have hidden it.")

        st.subheader("Why indicators passed the filter")
        cfg = Config()
        reasons = qr.get("after_by_reason", {})
        names = {"threat": "Threat word only", "sector": "Sector word", "unlabelled": "No labels (soft mode)"}
        left, right = st.columns([3, 2])
        left.altair_chart(alt.Chart(pd.DataFrame(
            [{"Reason": names[k], "Indicators": reasons.get(k, 0)} for k in names])).mark_bar().encode(
            x="Indicators:Q", y=alt.Y("Reason:N", sort=None, title=None), tooltip=["Reason", "Indicators"],
        ).properties(height=150), width="stretch")
        right.markdown("**Sector words** (STIX 2.1, ENISA 2023)  \n" + ", ".join(sorted(cfg.SECTOR_KEYWORDS)))
        right.markdown("**Threat words** (ENISA 2023)  \n" + ", ".join(sorted(cfg.THREAT_KEYWORDS)))


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
    view = inds[inds["Feed"].isin(chosen) & inds["Actionability"].isin(tier)] if len(inds) else inds

    left, right = st.columns([3, 2])
    with left:
        picked = st.dataframe(
            view.drop(columns=["Labels"]), hide_index=True, width="stretch", height=420,
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
            m2.metric("Actionability", f"{i['Actionability']:.1f}")
            tick = lambda b: "yes" if b else "no"
            st.markdown(f"IOC present: **{tick(i['IOC'])}** · ATT&CK technique: **{tick(i['ATT&CK technique'])}** · "
                        f"Mitigation: **{tick(i['Mitigation'])}**")
            if i["Labels"]:
                st.caption(f"Labels: {i['Labels']}")
        else:
            st.caption("Click a row to see its scores. A trusted source (high reliability) can still give "
                       "an analyst little to act on (low actionability).")
