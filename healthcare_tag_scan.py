"""Count indicators that sit in OpenCTI reports linked to the Healthcare sector."""
import collections, datetime, logging, os, sys
logging.disable(logging.WARNING)
sys.path.insert(0, os.getcwd())
from healthcare_cti_pipeline import Config, connect_opencti

cfg = Config()
c = connect_opencti(cfg); Q = c.query
print(f"Healthcare tag scan  |  {datetime.datetime.now():%Y-%m-%d %H:%M}  |  OpenCTI at {cfg.OPENCTI_URL}")
print("-" * 78)

hc = next(e["node"] for e in Q('{ sectors(first:5, search:"Healthcare"){ edges{ node{ id name } } } }')
          ["data"]["sectors"]["edges"] if e["node"]["name"] == "Healthcare")
f = {"mode": "and", "filters": [{"key": "objects", "values": [hc["id"]]}], "filterGroups": []}
reps = [e["node"] for e in Q('query($f: FilterGroup){ reports(first:1000, filters:$f){ edges{ node{ id '
                             'createdBy{ ... on Identity{ name } } } } } }', {"f": f})["data"]["reports"]["edges"]]
by_src = dict(collections.Counter((r.get("createdBy") or {}).get("name") or "unknown" for r in reps))
print(f"1. Reports linked to the Healthcare sector:     {len(reps):>7,}   {by_src}")

oq = '''query($id:String!,$a:ID){ report(id:$id){ objects(first:200, after:$a, types:["Indicator"]){
        pageInfo{hasNextPage endCursor} edges{ node{ ... on Indicator{ id } } } } } }'''
tagged = set()
for i, r in enumerate(reps, 1):
    a = None
    while True:
        o = Q(oq, {"id": r["id"], "a": a})["data"]["report"]["objects"]
        tagged |= {e["node"]["id"] for e in o["edges"] if e["node"].get("id")}
        if not o["pageInfo"]["hasNextPage"]:
            break
        a = o["pageInfo"]["endCursor"]
    print(f"   scanning reports {i}/{len(reps)}", end="\r")
print(" " * 40, end="\r")
print(f"2. Distinct indicators inside those reports:    {len(tagged):>7,}")

total = Q('{indicators(first:1){pageInfo{globalCount}}}')["data"]["indicators"]["pageInfo"]["globalCount"]
print(f"3. All indicators in OpenCTI:                   {total:>7,}")
print("-" * 78)
print(f"Share of indicators in Healthcare-linked reports: {len(tagged):,} / {total:,} = {100 * len(tagged) / total:.1f}%")
