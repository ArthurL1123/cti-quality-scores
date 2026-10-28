"""
Check the reliability and actionability scores against outside evidence.

Fetches native indicators from OpenCTI (no sector filter), scores each one with
the pipeline's own functions, and checks every indicator value against the
MISP warninglists (github.com/MISP/misp-warninglists): public lists of values
that look like indicators but are usually harmless, such as public DNS
servers, private address ranges, sinkholes, research scanners and big
services' own ranges.

Two questions:
  1. Reliability: do indicators from a feed with a higher Admiralty grade hit
     the warninglists less often? A hit means blocking the indicator could
     block something harmless.
  2. Actionability: are indicators with a higher actionability score more often
     usable as they are? "Usable" here means: the STIX pattern is valid
     (OASIS stix2-patterns validator), it names one blockable value (IP,
     domain, hostname, URL or file hash), and the value is not on a harmless warninglist.
     Note: the score's IOC part (0.30) also rewards having a pattern, so that
     part overlaps with this check; the ATT&CK and mitigation parts do not.

Warninglist groups. MISP does not mark each list as harmless or not, so the
lists are split by name into three groups, and every list's hit count is
printed so the split can be checked:
  - hosting (ambiguous): things an attacker can also rent or use, such as
    cloud and datacenter servers, VPN and Tor exits, dynamic DNS, URL
    shorteners, parked domains, free email providers, GitHub, Telegram and
    university domains. A hit is not proof of a mistake. Reported, but not
    counted as harmless.
  - large popularity lists: lists with more than 100,000 entries (e.g. Tranco
    and Cisco top 1M sites). Long lists of popular sites can contain
    malicious ones. Reported, but not counted as harmless.
  - harmless: every other list. These values are harmless, or shared by many
    legitimate users at once (for example CDN addresses), so blocking them
    would block legitimate traffic. Includes private and reserved ranges,
    public DNS, sinkholes, research scanners, big services' own ranges and
    the two large lists of known-good file hashes (nioc-filehash,
    windows-binary-hashes).

Values are matched the way each list's type says: cidr (address inside a
range), hostname (the domain or any parent domain), string (exact),
substring (contained) and regex. URL indicators are matched as the full URL
only, not by their domain, because a malicious file on a popular site (for
example a cloud drive) is still a specific, usable indicator. Email and phone
lists are only applied to email and phone indicators.

The warninglist check is cheap and runs on every fetched indicator. The
actionability score needs several OpenCTI lookups per indicator, so it is
computed for a random sample of each feed (seed 42) and test 2 uses that
sample only.

To keep the load on OpenCTI low, the fetched indicators are saved to
output/validation_cache/ and reused on the next run (--refresh fetches them
again), lookups run one at a time with a short pause, and the run stops if a
single lookup takes longer than a minute.

Per-indicator results (OpenCTI id, feed, type, scores, list hits; no indicator
values) are saved to output/. Read-only: nothing is written to OpenCTI.

Usage:
    python validate_indicators.py                          # all indicators, 500 per feed for actionability
    python validate_indicators.py --limit 300 --sample-per-feed 20 --refresh   # quick test run
"""
import argparse
import bisect
import csv
import ipaddress
import json
import logging
import math
import random
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests
from stix2patterns.validator import run_validator

from healthcare_cti_pipeline import (
    Config,
    _fetch_related_entity_types,
    _get_actionability,
    _get_admiralty,
    _source_name,
    connect_opencti,
    fetch_native_indicators,
)

WARNINGLISTS_URL = "https://github.com/MISP/misp-warninglists/archive/refs/heads/main.zip"
DEFAULT_ZIP = Path("output/validation_cache/misp-warninglists.zip")
HOSTING = {
    # cloud, hosting and datacenter servers
    "alibaba-cloud", "amazon-aws", "coreweave", "datacenter-ipv4", "datacenter-ipv6", "digitalocean",
    "godaddy", "google-gcp", "hetzner", "huawei-cloud", "ibm-cloud", "leaseweb", "linode", "microsoft-azure",
    "microsoft-azure-china", "microsoft-azure-germany", "microsoft-azure-us-gov", "oracle-oci", "ovh-cluster",
    "rackspace", "scaleway", "tencent-cloud", "vultr",
    # anonymising and relay services
    "vpn-ipv4", "vpn-ipv6", "tor-exit-nodes", "icloud-private-relay",
    # services and names attackers commonly use or register
    "dynamic-dns", "url-shortener", "link-in-bio", "public-ipfs-gateways", "second-level-tlds",
    "parking-domain", "parking-domain-ns", "github", "telegram-ips", "university_domains",
    "disposable-email", "personal-email-domains",
}
LARGE = 100_000
KNOWN_GOOD_HASHES = {"nioc-filehash", "windows-binary-hashes"}
SEED = 42
SLOW = 60.0            # seconds; one lookup slower than this stops the run
ONLY_FOR = {"disposable-email": "email-addr", "personal-email-domains": "email-addr",
            "common-contact-emails": "email-addr", "phone_numbers": "phone"}
BLOCKABLE = {"ipv4-addr", "ipv6-addr", "domain-name", "hostname", "url", "file"}
PATTERN_RE = re.compile(r"\[\s*([a-z0-9-]+):([^\s=]+)\s*=\s*'([^']*)'\s*\]$", re.IGNORECASE)


def load_warninglists(path: Path) -> list[dict]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading MISP warninglists to {path} ...")
        path.write_bytes(requests.get(WARNINGLISTS_URL, timeout=300).content)
    lists = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            parts = name.split("/")
            if len(parts) == 4 and parts[1] == "lists" and parts[3] == "list.json":
                d = json.loads(z.read(name))
                lists.append({"id": parts[2], "type": d.get("type", "string"), "values": d.get("list", [])})
    for wl in lists:
        if wl["id"] in HOSTING:
            wl["group"] = "hosting"
        elif len(wl["values"]) > LARGE and wl["id"] not in KNOWN_GOOD_HASHES:
            wl["group"] = "large"
        else:
            wl["group"] = "harmless"
        _prepare(wl)
    return lists


def _prepare(wl: dict) -> None:
    t = wl["type"]
    if t == "cidr":
        ranges = {4: [], 6: []}
        for v in wl["values"]:
            try:
                net = ipaddress.ip_network(v.strip(), strict=False)
            except ValueError:
                continue
            ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
        wl["ranges"] = {}
        for ver, rs in ranges.items():
            rs.sort()
            merged = []
            for lo, hi in rs:
                if merged and lo <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            wl["ranges"][ver] = ([m[0] for m in merged], [m[1] for m in merged])
    elif t == "regex":
        wl["compiled"] = []
        for v in wl["values"]:
            try:
                wl["compiled"].append(re.compile(v, re.IGNORECASE))
            except re.error:
                pass
    else:
        wl["set"] = {v.strip().lower().rstrip(".") for v in wl["values"]}


def hits(kind: str, value: str, lists: list[dict]) -> list[str]:
    value = value.strip().lower().rstrip(".")
    ip = None
    if kind in ("ipv4-addr", "ipv6-addr"):
        try:
            ip = ipaddress.ip_address(value.split("/")[0])
        except ValueError:
            pass
    host = value if kind in ("domain-name", "hostname") else None
    out = []
    for wl in lists:
        t = wl["type"]
        if wl["id"] in ONLY_FOR and ONLY_FOR[wl["id"]] != kind:
            continue
        if t == "cidr":
            if ip is None:
                continue
            starts, ends = wl["ranges"][ip.version]
            i = bisect.bisect_right(starts, int(ip)) - 1
            if i >= 0 and int(ip) <= ends[i]:
                out.append(wl["id"])
        elif t == "hostname":
            if host:
                labels = host.split(".")
                if any(".".join(labels[j:]) in wl["set"] for j in range(len(labels) - 1)):
                    out.append(wl["id"])
        elif t == "string":
            if value in wl["set"]:
                out.append(wl["id"])
        elif t == "substring":
            if any(s and s in value for s in wl["set"]):
                out.append(wl["id"])
        elif t == "regex":
            if any(r.search(value) for r in wl["compiled"]):
                out.append(wl["id"])
    return out


def parse_pattern(pattern: str) -> tuple[bool, str | None, str | None]:
    """(valid STIX pattern, object type, value) for a single-comparison pattern."""
    pattern = (pattern or "").strip()
    valid = bool(pattern) and not run_validator(pattern)
    m = PATTERN_RE.match(pattern)
    if not m:
        return valid, None, None
    return valid, m.group(1).lower(), m.group(3)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def share(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k:>5}/{n:<5} {k / n:6.1%} [95% CI {lo:5.1%}-{hi:5.1%}]" if n else f"{k:>5}/{n:<5}   n/a"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None, help="Cap on native indicators to fetch (default: all).")
    ap.add_argument("--sample-per-feed", type=int, default=500,
                    help="Indicators per feed to score for actionability (random, seed 42).")
    ap.add_argument("--pause", type=float, default=0.2, help="Seconds to wait between OpenCTI lookups.")
    ap.add_argument("--refresh", action="store_true", help="Fetch indicators again instead of using the cache.")
    ap.add_argument("--warninglists", type=Path, default=DEFAULT_ZIP, help="MISP warninglists zip.")
    args = ap.parse_args()
    logging.disable(logging.INFO)

    lists = load_warninglists(args.warninglists)
    groups = Counter(wl["group"] for wl in lists)
    print(f"Loaded {len(lists)} warninglists: {dict(groups)}")
    group_of = {wl["id"]: wl["group"] for wl in lists}

    cfg = Config()
    cfg.FETCH_LIMIT = args.limit
    client = connect_opencti(cfg)
    cache = DEFAULT_ZIP.parent / f"indicators_{args.limit or 'all'}.json"
    if cache.exists() and not args.refresh:
        indicators = json.loads(cache.read_text(encoding="utf-8"))
        print(f"Using cached indicators from {cache} (--refresh to fetch again)")
    else:
        indicators = fetch_native_indicators(client, cfg)
        cache.write_text(json.dumps(indicators), encoding="utf-8")
    feed_ids = defaultdict(list)
    for ind in indicators:
        feed_ids[_source_name(ind)].append(ind["id"])
    rng = random.Random(SEED)
    sampled = set()
    for ids in feed_ids.values():
        sampled.update(rng.sample(sorted(ids), min(args.sample_per_feed, len(ids))))
    print(f"Fetched {len(indicators)} indicators; {len(sampled)} sampled for actionability. Checking...",
          flush=True)

    rows = []
    for n, ind in enumerate(indicators, 1):
        grade, reliability = _get_admiralty(ind, cfg)
        actionability = has_ttp = has_mit = None
        if ind["id"] in sampled:
            started = time.monotonic()
            related, ap_ids = _fetch_related_entity_types(client, ind["id"], cfg)
            actionability, _, has_ttp, has_mit = _get_actionability(ind, related, ap_ids, client, cfg)
            if time.monotonic() - started > SLOW:
                print(f"OpenCTI took over {SLOW:.0f} s for one lookup; stopping to avoid overloading it.")
                return 1
            time.sleep(args.pause)
        valid, kind, value = parse_pattern(ind.get("pattern"))
        found = hits(kind, value, lists) if value else []
        harmless = [h for h in found if group_of[h] == "harmless"]
        rows.append({
            "opencti_id": ind["id"],
            "sampled": ind["id"] in sampled,
            "feed": _source_name(ind),
            "grade": grade,
            "reliability": reliability,
            "actionability": actionability,
            "has_ttp": has_ttp,
            "has_mitigation": has_mit,
            "type": kind or "complex/other",
            "pattern_valid": valid,
            "blockable": kind in BLOCKABLE,
            "hit_harmless": bool(harmless),
            "hit_hosting": any(group_of[h] == "hosting" for h in found),
            "hit_large": any(group_of[h] == "large" for h in found),
            "usable": valid and kind in BLOCKABLE and not harmless,
            "lists": ";".join(found),
        })
        if n % 2000 == 0 or n == len(indicators):
            print(f"  checked {n} of {len(indicators)}", flush=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(cfg.OUTPUT_DIR) / f"validation_indicators_{ts}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print(f"\nRun {ts}, {len(rows)} indicators. Per-indicator results saved to {out}")
    feeds = sorted({(r["feed"], r["grade"], r["reliability"]) for r in rows}, key=lambda x: -(x[2] or 0))
    print("\nIndicator types per feed:")
    for feed, grade, _ in feeds:
        c = Counter(r["type"] for r in rows if r["feed"] == feed)
        print(f"  {feed[:28]:<28} grade {grade}: {dict(c.most_common())}")

    print("\n== 1. RELIABILITY: share of each feed's indicators on a warninglist")
    for feed, grade, rel in feeds:
        grp = [r for r in rows if r["feed"] == feed]
        print(f"  {feed[:28]:<28} grade {grade} ({rel})")
        for col, name in (("hit_harmless", "harmless lists"), ("hit_hosting", "hosting lists"),
                          ("hit_large", "large popularity lists")):
            print(f"      {name:<24} {share(sum(r[col] for r in grp), len(grp))}")

    print("\n== 2. ACTIONABILITY: share usable as-is, by actionability score (sampled indicators)")
    srows = [r for r in rows if r["sampled"]]
    for scope, grp in [("All feeds", srows)] + [(f, [r for r in srows if r["feed"] == f]) for f, _, _ in feeds]:
        print(f"  {scope}")
        for score in sorted({r["actionability"] for r in grp}, reverse=True):
            sub = [r for r in grp if r["actionability"] == score]
            print(f"      score {score:<5} {share(sum(r['usable'] for r in sub), len(sub))}")
    print("  Why not usable (sampled indicators, all feeds):")
    reasons = Counter()
    for r in srows:
        if not r["pattern_valid"]:
            reasons["pattern not valid"] += 1
        elif not r["blockable"]:
            reasons["not one blockable value"] += 1
        elif r["hit_harmless"]:
            reasons["on a harmless warninglist"] += 1
    for k, v in reasons.most_common():
        print(f"      {k:<28} {v}")

    print("\n== Hits per warninglist (all feeds)")
    per_list = Counter(h for r in rows for h in r["lists"].split(";") if h)
    by_feed = defaultdict(Counter)
    for r in rows:
        for h in filter(None, r["lists"].split(";")):
            by_feed[h][r["feed"]] += 1
    for h, v in per_list.most_common():
        print(f"  {h:<40} {group_of[h]:<9} {v:>5}  {dict(by_feed[h])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
