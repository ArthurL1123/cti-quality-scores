"""Draw a reproducible random sample of filtered indicators for hand labelling."""
import csv, glob, json, logging, os, random, sys
logging.disable(logging.INFO)
sys.path.insert(0, os.getcwd())
from healthcare_cti_pipeline import Config, connect_opencti, filter_reason

SEED, N = 42, 50
cfg = Config()
c = connect_opencti(cfg)
# Pass the bundle to sample from; the report used output/healthcare_cti_20261009T042040Z.json
bundle_path = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob("output/healthcare_cti_*.json"), key=os.path.getmtime)
I = [o for o in json.load(open(bundle_path, encoding="utf-8"))["objects"] if o["type"] == "indicator"]
I.sort(key=lambda o: o["id"])
sample = random.Random(SEED).sample(I, N)

q = """query($id: String!) { indicator(id: $id) {
  reports(first: 3) { edges { node { name description } } } } }"""
rows = []
for k, ind in enumerate(sample, 1):
    rep = c.query(q, {"id": ind["id"]})["data"]["indicator"]
    reports = [e["node"] for e in (rep or {}).get("reports", {}).get("edges", [])]
    shaped = {"objectLabel": [{"value": v} for v in ind.get("labels", [])],
              "name": ind.get("name"), "pattern": ind.get("pattern")}
    rows.append({
        "no": k,
        "healthcare_relevant (yes/no/unclear)": "",
        "note": "",
        "source": ind["x_pipeline_source"],
        "type": ind["x_observable_type"],
        "value": ind["pattern"],
        "labels": ", ".join(ind.get("labels", [])),
        "report_name": " | ".join(r["name"] for r in reports),
        "report_description": " | ".join((r.get("description") or "").replace("\n", " ") for r in reports),
        "filter_matched_on": filter_reason(shaped, cfg),
        "indicator_id": ind["id"],
    })

out = "output/hand_check_sample.csv"
if os.path.exists(out):  # never overwrite the labelled sample
    out = "output/hand_check_sample_redraw.csv"
with open(out, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader(); w.writerows(rows)
print(f"bundle={bundle_path} seed={SEED} n={N} -> {out}")
print("with a linked report:", sum(1 for r in rows if r["report_name"]))
print("matched on:", {k: sum(r['filter_matched_on'] == k for r in rows) for k in ('sector', 'threat', 'unlabelled')})
