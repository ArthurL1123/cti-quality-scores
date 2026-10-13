"""Compute every Chapter 5 figure from one exported bundle."""
import collections, glob, json, math, os, re, sys

path = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob("output/healthcare_cti_*.json"), key=os.path.getmtime)
b = json.load(open(path, encoding="utf-8"))
V = [o for o in b["objects"] if o["type"] == "vulnerability"]
I = [o for o in b["objects"] if o["type"] == "indicator"]
print("bundle:", path)
print(f"vulnerabilities={len(V)} indicators={len(I)}")

# ---------------- vulnerabilities ----------------
def signals(v):
    d = v.get("description", "")
    epss = None if "EPSS=N/A" in d else v.get("x_epss_score")
    cvss = None if "CVSS=N/A" in d else v.get("x_cvss_base")
    return epss, cvss, bool(v.get("x_kev_listed"))

def composite(v, w):
    epss, cvss, kev = signals(v)
    parts = {"kev": 1.0 if kev else 0.0}
    if epss is not None: parts["epss"] = epss
    if cvss is not None: parts["cvss"] = cvss / 10
    if "epss" not in parts and "cvss" not in parts:
        return w["kev"] * parts["kev"]
    tw = sum(w[k] for k in parts)
    return sum(w[k] * parts[k] for k in parts) / tw

W0 = {"epss": .35, "cvss": .25, "kev": .40}
mism = sum(1 for v in V if abs(composite(v, W0) - v["x_composite_score"]) > 1e-3)
print(f"recompute mismatches vs pipeline: {mism}")

bins = collections.Counter(min(int(v["x_composite_score"] / 0.2), 4) for v in V)
print("score bins:", {f"{k*0.2:.1f}-{k*0.2+0.2:.1f}": (bins[k], round(100*bins[k]/len(V),1)) for k in range(5)})
sc = collections.Counter(v["x_signal_count"] for v in V)
print("signal_count:", dict(sc))
miss = collections.Counter((signals(v)[0] is None, signals(v)[1] is None) for v in V)
print("missing (epss_missing, cvss_missing):", dict(miss))
kev = [v for v in V if v["x_kev_listed"]]; non = [v for v in V if not v["x_kev_listed"]]
avg = lambda xs: sum(xs) / len(xs) if xs else float("nan")
print(f"KEV={len(kev)} ({100*len(kev)/len(V):.1f}%) avg={avg([v['x_composite_score'] for v in kev]):.4f} "
      f"nonKEV avg={avg([v['x_composite_score'] for v in non]):.4f} "
      f"KEV>0.5: {sum(v['x_composite_score']>0.5 for v in kev)} min KEV={min([v['x_composite_score'] for v in kev], default=None)}")
top_bin = bins[4]

# sensitivity
def ranks(xs):
    order = sorted(range(len(xs)), key=lambda i: -xs[i]); r = [0.0]*len(xs); i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j+1]] == xs[order[i]]: j += 1
        for k in range(i, j+1): r[order[k]] = (i + j) / 2 + 1
        i = j + 1
    return r
def spearman(a, b):
    ra, rb = ranks(a), ranks(b); n = len(a); ma, mb = sum(ra)/n, sum(rb)/n
    cov = sum((x-ma)*(y-mb) for x, y in zip(ra, rb))
    return cov / math.sqrt(sum((x-ma)**2 for x in ra) * sum((y-mb)**2 for y in rb))
def topn(scores, n): return set(sorted(range(len(scores)), key=lambda i: -scores[i])[:n])
sets = [("Original (0.35 / 0.25 / 0.40)", W0),
        ("Equal (1/3 each)", {"epss": 1/3, "cvss": 1/3, "kev": 1/3}),
        ("CVSS heavy (0.20 / 0.50 / 0.30)", {"epss": .2, "cvss": .5, "kev": .3}),
        ("EPSS heavy (0.50 / 0.20 / 0.30)", {"epss": .5, "cvss": .2, "kev": .3}),
        ("KEV light (0.40 / 0.40 / 0.20)", {"epss": .4, "cvss": .4, "kev": .2}),
        ("KEV heavy (0.20 / 0.20 / 0.60)", {"epss": .2, "cvss": .2, "kev": .6})]
base = [composite(v, W0) for v in V]; nk = len(kev)
kev_idx = {i for i, v in enumerate(V) if v["x_kev_listed"]}
print(f"\nsensitivity: top_bin={top_bin} n_kev={nk}")
for name, w in sets:
    s = [composite(v, w) for v in V]
    print(f"  {name:34} spearman={spearman(base, s):.3f} top{top_bin}={len(topn(base,top_bin)&topn(s,top_bin))} "
          f"top{nk}={len(topn(base,nk)&topn(s,nk))} KEVin{nk}={len(topn(s,nk)&kev_idx)}")

# case examples
def show(v): e, c, k = signals(v); return f"{v['name']} EPSS={e} CVSS={c} KEV={k} score={v['x_composite_score']}"
nocvss = sorted([v for v in V if signals(v)[1] is None], key=lambda v: -v["x_composite_score"])
print("\nmissing CVSS, highest:", show(nocvss[0]) if nocvss else None)
print("top of ranking:", show(max(V, key=lambda v: v["x_composite_score"])))
hc = sorted([v for v in V if (signals(v)[1] or 0) >= 9.8 and not v["x_kev_listed"]], key=lambda v: v["x_composite_score"])
print("high CVSS, not KEV, lowest score:", show(hc[0]) if hc else None)
kl = sorted([v for v in kev if (signals(v)[0] or 1) < 0.1], key=lambda v: v["x_composite_score"])
print("KEV with low EPSS:", [show(v) for v in kl[:3]])

# ---------------- indicators ----------------
print()
src = collections.Counter(i["x_pipeline_source"] for i in I)
print("indicators by feed:", dict(src))
print("grades:", dict(collections.Counter((i["x_pipeline_source"], i.get("x_admiralty_grade")) for i in I)))
combo = collections.Counter((i["x_ioc_present"], i["x_ttp_linked"], i["x_mitigation_linked"]) for i in I)
print("signal combos (ioc,ttp,mit):", dict(combo))
act = collections.Counter(i["x_actionability_score"] for i in I)
print("actionability dist:", {k: (v, round(100*v/len(I), 1)) for k, v in sorted(act.items())})
for s in sorted(src):
    xs = [i for i in I if i["x_pipeline_source"] == s]
    print(f"  {s}: n={len(xs)} ttp={sum(i['x_ttp_linked'] for i in xs)} ({100*sum(i['x_ttp_linked'] for i in xs)/len(xs):.1f}%) "
          f"mit={sum(i['x_mitigation_linked'] for i in xs)} ({100*sum(i['x_mitigation_linked'] for i in xs)/len(xs):.1f}%)")
n = len(I)
print(f"overall ttp={sum(i['x_ttp_linked'] for i in I)} ({100*sum(i['x_ttp_linked'] for i in I)/n:.1f}%) "
      f"mit={sum(i['x_mitigation_linked'] for i in I)} ({100*sum(i['x_mitigation_linked'] for i in I)/n:.1f}%)")

# entropy weights
def entropy_w(cols):
    k = 1 / math.log(n); d = {}
    for name, xs in cols.items():
        tot = sum(xs)
        e = -k * sum((x/tot) * math.log(x/tot) for x in xs if x) if tot else 1.0
        d[name] = 1 - e
    t = sum(d.values()); return {k_: round(v/t, 3) for k_, v in d.items()}
print("entropy weights:", entropy_w({"ioc": [int(i["x_ioc_present"]) for i in I],
                                     "ttp": [int(i["x_ttp_linked"]) for i in I],
                                     "mit": [int(i["x_mitigation_linked"]) for i in I]}))

# example indicators
def ex(pred, label):
    xs = [i for i in I if pred(i)]
    print(f"{label}: {len(xs)}", [(i["id"][11:19], i["x_pipeline_source"][:10], i.get("x_admiralty_grade"), i["x_actionability_score"]) for i in xs[:3]])
ex(lambda i: i.get("x_admiralty_grade") == "B" and i["x_actionability_score"] == 0.3, "B with 0.3")
ex(lambda i: i["x_actionability_score"] == 1.0, "full 1.0")
ex(lambda i: i.get("x_admiralty_grade") == "C", "grade C")
ex(lambda i: i["x_actionability_score"] == 0.7, "0.7 tier")
