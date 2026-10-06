"""
Healthcare CTI pipeline - personal working script.
Ingest -> filter -> score (urgency/reliability/actionability) -> sanitise -> export.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import tlsh
from dotenv import load_dotenv
from pycti import OpenCTIApiClient
from stix2 import parse as stix2_parse
from stix2.exceptions import STIXError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cti_pipeline")


# ==============================================================================
#  CONFIGURATION
# ==============================================================================

class Config:
    """Single source of truth for all tuneable parameters."""

    # -- OpenCTI ---------------------------------------------------------------
    OPENCTI_URL: str   = os.getenv("OPENCTI_URL",   "http://localhost:8080")
    OPENCTI_TOKEN: str | None = os.getenv("OPENCTI_TOKEN")

    # -- Composite vulnerability scoring (CVSSv4 + EPSS v4 + KEV) --------------
    # SOLUTION: Composite score = w_epss*EPSS + w_cvss*(CVSS/10) + w_kev*KEV_flag
    #
    # ARCHITECTURAL NOTE: NATO Admiralty System source reliability is applied
    # independently to Indicators, NOT to Vulnerabilities (CVEs). CVEs are global
    # ground-truth objects; discounting a CVE's theoretical severity because it
    # was reported by an unreliable feed invalidates the threat model.
    #
    # Weights (tunable via env vars):
    #   0.35 EPSS + 0.25 CVSS + 0.40 KEV
    EPSS_WEIGHT:  float = float(os.getenv("EPSS_WEIGHT",  "0.35"))
    CVSS_WEIGHT:  float = float(os.getenv("CVSS_WEIGHT",  "0.25"))
    KEV_WEIGHT:   float = float(os.getenv("KEV_WEIGHT",   "0.40"))

    COMPOSITE_THRESHOLD: float = float(os.getenv("COMPOSITE_THRESHOLD", "0.10"))

    # -- Observable types eligible for promotion -------------------------------
    PROMOTABLE_TYPES: set[str] = {
        "IPv4-Addr", "IPv6-Addr", "Domain-Name",
        "Url", "StixFile", "Email-Addr", "Hostname",
    }

    # -- Healthcare sector keywords --------------------------------------------
    HEALTHCARE_LABELS: set[str] = {
        "healthcare", "health-sector", "health", "iomt", "medical",
        "hospital", "clinic", "pharmaceutical", 
        "ransomware", "phishing", "credential-theft"
    }
    STRICT_SECTOR_FILTER: bool = False

    # -- TLSH ------------------------------------------------------------------
    TLSH_MIN_INPUT_BYTES: int = 50

    # -- External APIs ---------------------------------------------------------
    EPSS_API_BASE: str     = "https://api.first.org/data/v1/epss"
    EPSS_BATCH_SIZE: int   = 50
    EPSS_RETRY_LIMIT: int  = 3
    EPSS_RETRY_DELAY: float = 2.0

    KEV_API_URL: str      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    KEV_RETRY_LIMIT: int  = 3
    KEV_RETRY_DELAY: float = 2.0

    # -- Pagination and Limits -------------------------------------------------
    PAGE_SIZE: int = 100
    FETCH_LIMIT: int | None = (
        int(os.getenv("FETCH_LIMIT")) if os.getenv("FETCH_LIMIT") else None
    )

    # -- Output ----------------------------------------------------------------
    OUTPUT_DIR: Path = Path(os.getenv("OUTPUT_DIR", "./output"))
    BUNDLE_FILENAME: str = "sanitised_healthcare_cti_{ts}.json"

    # -- NATO Admiralty System source reliability ------------------------------
    # Used exclusively for Indicators (Intelligence), not Vulnerabilities (Facts).
    # Reliability is now read directly from OpenCTI's native
    # `createdBy.x_opencti_reliability` field on the source Identity, instead
    # of being guessed from the source name. Set this via the OpenCTI UI/API
    # on each connector's Identity object.
    SKIP_ADMIRALTY: bool = False

    # OpenCTI stores reliability as a labelled string, e.g. "A - Completely reliable".
    # This maps the leading letter to a numeric score for the composite pipeline.
    # Fallback for indicators whose source Identity has no reliability set.
    ADMIRALTY_UNSET_GRADE: str   = "F"
    ADMIRALTY_UNSET_SCORE: float = 0.10

    ADMIRALTY_GRADE_SCORES: dict[str, float] = {
        "A": 1.00,
        "B": 0.85,
        "C": 0.70,
        "D": 0.50,
        "E": 0.30,
        "F": 0.10,
    }

    # -- Actionability scoring (IOC presence + TTP linkage + mitigation linkage)
    # Used exclusively for Indicators, same as Admiralty. Measures whether an
    # analyst can actually DO something with the artefact, independent of how
    # trustworthy the source is (Admiralty) or how urgent it is (composite
    # vulnerability score). Signals sourced via relationships on the Indicator:
    #   - IOC present:      the indicator has a concrete pattern value.
    #   - TTP linked:       related to an Attack-Pattern (MITRE ATT&CK) object.
    #   - Mitigation linked: related to a Course-Of-Action object.
    # TTP weighted higher than raw IOC presence per the Pyramid of Pain
    # (RFC 9424) - IOCs are trivial for an attacker to rotate, TTPs are not.
    SKIP_ACTIONABILITY: bool = False
    FETCH_RELATIONSHIPS: bool = True   # set False to skip the extra API call per indicator

    IOC_WEIGHT:        float = float(os.getenv("IOC_WEIGHT",        "0.30"))
    TTP_WEIGHT:        float = float(os.getenv("TTP_WEIGHT",        "0.40"))
    MITIGATION_WEIGHT: float = float(os.getenv("MITIGATION_WEIGHT", "0.30"))

    RELATIONSHIP_FETCH_LIMIT: int = 50

    # -- OPSEC: metadata fields to strip before export -------------------------
    STRIP_FIELDS: set[str] = {
        "created_by_ref", "external_references",
        "x_opencti_aliases", "x_opencti_stix_ids",
        "x_opencti_workflow_id", "x_opencti_linked_to",
        "connectors", "connector_id",
    }


# ==============================================================================
#  STEP 1 - CONNECT
# ==============================================================================

def connect_opencti(cfg: Config) -> OpenCTIApiClient:
    log.info("Connecting to OpenCTI at %s ...", cfg.OPENCTI_URL)
    client = OpenCTIApiClient(
        url=cfg.OPENCTI_URL,
        token=cfg.OPENCTI_TOKEN,
        log_level="error",
        ssl_verify=False,
    )
    log.info("Connection established.")
    return client


# ==============================================================================
#  STEP 2A - FETCH NATIVE INDICATORS
# ==============================================================================

def fetch_native_indicators(
    client: OpenCTIApiClient,
    cfg: Config,
) -> list[dict[str, Any]]:
    limit = cfg.FETCH_LIMIT
    if limit is not None:
        log.info("Fetching native Indicators from OpenCTI (limit=%d) ...", limit)
    else:
        log.info("Fetching native Indicator objects from OpenCTI (no limit) ...")

    indicators: list[dict] = []
    after_cursor: str | None = None
    page = 0

    while True:
        page += 1
        page_size = cfg.PAGE_SIZE
        if limit is not None:
            remaining = limit - len(indicators)
            if remaining <= 0:
                break
            page_size = min(page_size, remaining)

        result = client.indicator.list(
            first=page_size,
            after=after_cursor,
            withPagination=True,
            getAll=False,
            customAttributes="""
                id
                name
                pattern
                indicator_types
                valid_from
                confidence
                x_opencti_score
                objectLabel { value }
                createdBy {
                    ... on Identity {
                        id
                        name
                        x_opencti_reliability
                    }
                }
            """,
        )

        if result is None:
            break

        entities   = result.get("entities", result) if isinstance(result, dict) else result
        pagination = result.get("pagination", {})   if isinstance(result, dict) else {}

        if not entities:
            break

        indicators.extend(entities)
        log.info("  Page %d: %d indicators (total: %d)", page, len(entities), len(indicators))

        if limit is not None and len(indicators) >= limit:
            break

        if not pagination.get("hasNextPage") or not pagination.get("endCursor"):
            break
        after_cursor = pagination["endCursor"]

    return indicators


# ==============================================================================
#  STEP 2B - FETCH RAW OBSERVABLES
# ==============================================================================

def fetch_all_observables(
    client: OpenCTIApiClient,
    cfg: Config,
) -> list[dict[str, Any]]:
    limit = cfg.FETCH_LIMIT
    if limit is not None:
        log.info("Fetching raw Observables from OpenCTI (limit=%d) ...", limit)
    else:
        log.info("Fetching raw Observables from OpenCTI (page size=%d) ...", cfg.PAGE_SIZE)
    observables: list[dict] = []
    after_cursor: str | None = None
    page = 0

    while True:
        page += 1
        page_size = cfg.PAGE_SIZE
        if limit is not None:
            remaining = limit - len(observables)
            if remaining <= 0:
                break
            page_size = min(page_size, remaining)

        result = client.stix_cyber_observable.list(
            first=page_size,
            after=after_cursor,
            withPagination=True,
            getAll=False,
            customAttributes="""
                id
                entity_type
                observable_value
                objectLabel { value }
                x_opencti_description
            """
        )

        if result is None:
            break

        entities   = result.get("entities", result) if isinstance(result, dict) else result
        pagination = result.get("pagination", {})   if isinstance(result, dict) else {}

        if not entities:
            break

        observables.extend(entities)
        log.info("  Page %d: %d observables (total: %d)", page, len(entities), len(observables))

        if limit is not None and len(observables) >= limit:
            break

        if not pagination.get("hasNextPage") or not pagination.get("endCursor"):
            break
        after_cursor = pagination["endCursor"]

    return observables


# ==============================================================================
#  STEP 3 - SECTOR RELEVANCE FILTER
# ==============================================================================

def is_healthcare_relevant(obj: dict[str, Any], cfg: Config) -> bool:
    if not cfg.HEALTHCARE_LABELS:
        return True

    labels: list[dict] = obj.get("objectLabel", []) or []
    label_values = {lbl.get("value", "").lower() for lbl in labels}
    combined_text = " ".join([
        (obj.get("x_opencti_description") or obj.get("description") or obj.get("name") or ""),
        (obj.get("pattern") or ""),
    ]).lower()

    if not label_values and not cfg.STRICT_SECTOR_FILTER:
        return True 

    for keyword in cfg.HEALTHCARE_LABELS:
        if keyword in label_values or keyword in combined_text:
            return True

    return False


# ==============================================================================
#  STEP 4 - PROMOTE OBSERVABLES TO INDICATORS
# ==============================================================================

def promote_observables_to_indicators(
    client: OpenCTIApiClient,
    observables: list[dict[str, Any]],
    native_indicator_ids: set[str],
    cfg: Config,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    promoted: list[dict] = []
    skipped_type = skipped_sector = skipped_duplicate = errors = 0

    log.info("Promoting Observables to Indicators (candidates: %d) ...", len(observables))

    mutation = """
        mutation PromoteObservable($id: ID!) {
            stixCyberObservableEdit(id: $id) {
                promote {
                    id
                    standard_id
                    entity_type
                    parent_types
                    createdBy {
                        ... on Identity {
                            id
                            name
                            x_opencti_reliability
                        }
                    }
                }
            }
        }
    """

    for obs in observables:
        obs_type = obs.get("entity_type", "")
        obs_id   = obs.get("id", "")
        obs_val  = obs.get("observable_value", obs.get("value", "<unknown>"))

        if obs_type not in cfg.PROMOTABLE_TYPES:
            skipped_type += 1
            continue

        if not is_healthcare_relevant(obs, cfg):
            skipped_sector += 1
            continue

        if obs.get("indicators") or obs.get("indicatorsIds"):
            skipped_duplicate += 1
            continue

        if dry_run:
            stub = dict(obs)
            stub["_source_observable_value"] = obs_val
            stub["_source_observable_type"]  = obs_type
            stub["_source"]                  = "promoted"
            promoted.append(stub)
            continue

        try:
            result    = client.query(mutation, {"id": obs_id})
            indicator = result["data"]["stixCyberObservableEdit"]["promote"]

            if indicator:
                indicator["_source_observable_value"] = obs_val
                indicator["_source_observable_type"]  = obs_type
                indicator["_source"]                  = "promoted"
                promoted.append(indicator)
            else:
                errors += 1
        except Exception as exc:
            err_str = str(exc).lower()
            if "already exists" in err_str or "duplicate" in err_str:
                skipped_duplicate += 1
            else:
                errors += 1

    log.info("Promotion done. Promoted=%d Skip(type)=%d Skip(sector)=%d Skip(duplicate)=%d Errors=%d",
        len(promoted), skipped_type, skipped_sector, skipped_duplicate, errors)
    return promoted


# ==============================================================================
#  STEP 5 - DERIVE ADMIRALTY SOURCE RELIABILITY
# ==============================================================================
def _get_admiralty(indicator: dict[str, Any], cfg: Config) -> tuple[str | None, float | None]:
    """
    Derive a NATO Admiralty source reliability grade for an indicator by
    reading OpenCTI's native `createdBy.x_opencti_reliability` field on the
    source Identity - rather than guessing from the source/org name.

    OpenCTI stores this as a labelled string, e.g. "A - Completely reliable".
    We take the leading letter and map it to a numeric score.

    Returns (None, None) if SKIP_ADMIRALTY is active.
    Falls back to cfg.ADMIRALTY_UNSET_GRADE/SCORE if the source Identity has
    no reliability set (field is null/missing).
    """
    if getattr(cfg, "SKIP_ADMIRALTY", False):
        return None, None

    created_by = indicator.get("createdBy") or {}
    raw_reliability = created_by.get("x_opencti_reliability")

    if not raw_reliability:
        return cfg.ADMIRALTY_UNSET_GRADE, cfg.ADMIRALTY_UNSET_SCORE

    # Extract leading grade letter, e.g. "A" from "A - Completely reliable"
    grade = raw_reliability.strip()[0].upper()

    if grade not in cfg.ADMIRALTY_GRADE_SCORES:
        log.warning(
            "Unrecognised x_opencti_reliability value '%s' on source '%s' - "
            "falling back to grade %s.",
            raw_reliability, created_by.get("name", "unknown"),
            cfg.ADMIRALTY_UNSET_GRADE,
        )
        return cfg.ADMIRALTY_UNSET_GRADE, cfg.ADMIRALTY_UNSET_SCORE

    return grade, cfg.ADMIRALTY_GRADE_SCORES[grade]


# ==============================================================================
#  STEP 6 - DERIVE ACTIONABILITY (IOC / TTP / MITIGATION)
# ==============================================================================

def _fetch_related_entity_types(
    client: OpenCTIApiClient,
    indicator_id: str,
    cfg: Config,
) -> tuple[set[str], set[str]]:
    """
    Fetch the entity types of objects related to this indicator via any
    stixCoreRelationship (e.g. Attack-Pattern via 'indicates', Course-Of-Action
    via 'mitigates'). Used to derive TTP-linked and mitigation-linked signals.

    Returns (related_types, attack_pattern_ids) - the latter is needed for the
    two-hop mitigation check in _attack_pattern_has_mitigation(), since ATT&CK
    Course-Of-Action objects are typically linked to the Attack-Pattern
    (technique) rather than directly to the Indicator.

    One extra API call per indicator - can be disabled via cfg.FETCH_RELATIONSHIPS
    for faster/cheaper dry-runs, at the cost of TTP/mitigation always reading False.
    """
    if not getattr(cfg, "FETCH_RELATIONSHIPS", True):
        return set(), set()

    query = """
        query IndicatorRelations($id: [String], $first: Int) {
            asSource: stixCoreRelationships(fromId: $id, first: $first) {
                edges {
                    node {
                        relationship_type
                        to { ... on StixDomainObject { id entity_type } }
                    }
                }
            }
            asTarget: stixCoreRelationships(toId: $id, first: $first) {
                edges {
                    node {
                        relationship_type
                        from { ... on StixDomainObject { entity_type } }
                    }
                }
            }
        }
    """
    try:
        response = client.query(
            query, {"id": [indicator_id], "first": cfg.RELATIONSHIP_FETCH_LIMIT}
        )
        data = response.get("data", {})
        related_types: set[str] = set()
        attack_pattern_ids: set[str] = set()

        for edge in data.get("asSource", {}).get("edges", []):
            to_obj = (edge.get("node") or {}).get("to") or {}
            entity_type = to_obj.get("entity_type")
            if entity_type:
                related_types.add(entity_type)
                if entity_type == "Attack-Pattern" and to_obj.get("id"):
                    attack_pattern_ids.add(to_obj["id"])

        # mitigates: Course-Of-Action --(source)--> Indicator(target), so
        # these relationships must be found via toId, not fromId.
        for edge in data.get("asTarget", {}).get("edges", []):
            from_obj = (edge.get("node") or {}).get("from") or {}
            entity_type = from_obj.get("entity_type")
            if entity_type:
                related_types.add(entity_type)

        return related_types, attack_pattern_ids
    except Exception as exc:
        log.warning(
            "Failed to fetch relationships for indicator %s: %s - "
            "TTP/mitigation signals will default to False for this artefact.",
            indicator_id, exc,
        )
        return set(), set()


_coa_cache: dict[str, bool] = {}


def _attack_pattern_has_mitigation(
    client: OpenCTIApiClient,
    attack_pattern_id: str,
    cfg: Config,
) -> bool:
    """
    Two-hop mitigation check: does this Attack-Pattern (technique) have a
    Course-Of-Action mitigating it? ATT&CK mitigations are linked to
    techniques, not directly to indicators, so this closes the gap left by
    checking only direct Indicator<->Course-Of-Action relationships.

    Cached per attack_pattern_id for the life of the run - ATT&CK techniques
    repeat heavily across indicators, so this avoids redundant API calls.
    """
    if attack_pattern_id in _coa_cache:
        return _coa_cache[attack_pattern_id]

    query = """
        query AttackPatternMitigations($id: [String], $first: Int) {
            stixCoreRelationships(toId: $id, first: $first) {
                edges {
                    node {
                        relationship_type
                        from { ... on StixDomainObject { entity_type } }
                    }
                }
            }
        }
    """
    try:
        response = client.query(
            query, {"id": [attack_pattern_id], "first": cfg.RELATIONSHIP_FETCH_LIMIT}
        )
        edges = response.get("data", {}).get("stixCoreRelationships", {}).get("edges", [])
        has_mitigation = any(
            (edge.get("node") or {}).get("from", {}).get("entity_type") == "Course-Of-Action"
            for edge in edges
        )
    except Exception as exc:
        log.warning(
            "Failed to check mitigations for Attack-Pattern %s: %s - defaulting to False.",
            attack_pattern_id, exc,
        )
        has_mitigation = False

    _coa_cache[attack_pattern_id] = has_mitigation
    return has_mitigation


def _get_actionability(
    indicator: dict[str, Any],
    related_types: set[str],
    attack_pattern_ids: set[str],
    client: OpenCTIApiClient | None,
    cfg: Config,
) -> tuple[float, bool, bool, bool] | tuple[None, None, None, None]:
    """
    Derive an actionability score for an indicator from three independent
    signals - IOC presence, TTP linkage, mitigation linkage - kept separate
    from Admiralty (reliability) and the composite score (urgency), per
    Zibak et al. (2022) and Irwin & Mandel (2019): quality dimensions should
    be assessed independently, not blended into one number.

    Mitigation linkage checks both a direct Indicator<->Course-Of-Action
    relationship AND the two-hop path via the indicator's linked
    Attack-Pattern(s), since ATT&CK mitigations are typically attached to
    techniques rather than indicators directly.

    Returns (score, has_ioc, has_ttp, has_mitigation), or all-None if
    SKIP_ACTIONABILITY is active.
    """
    if getattr(cfg, "SKIP_ACTIONABILITY", False):
        return None, None, None, None

    pattern = (indicator.get("pattern") or "").strip()
    has_ioc = bool(pattern) and pattern != "[x-tlsh:hash = '']"

    has_ttp        = "Attack-Pattern"   in related_types
    has_mitigation = "Course-Of-Action" in related_types

    if not has_mitigation and client is not None and attack_pattern_ids:
        has_mitigation = any(
            _attack_pattern_has_mitigation(client, ap_id, cfg)
            for ap_id in attack_pattern_ids
        )

    score = (
        cfg.IOC_WEIGHT        * has_ioc
        + cfg.TTP_WEIGHT        * has_ttp
        + cfg.MITIGATION_WEIGHT * has_mitigation
    )

    return round(score, 4), has_ioc, has_ttp, has_mitigation

# ==============================================================================
#  STEP 7 - NORMALISE TO A COMMON SHAPE
# ==============================================================================

def normalise_indicator(
    indicator: dict[str, Any],
    source_tag: str,
) -> dict[str, Any]:
    raw_value = indicator.get("_source_observable_value")
    obs_type  = indicator.get("_source_observable_type")

    if not raw_value:
        pattern   = indicator.get("pattern") or ""
        match     = re.search(r"=\s*'([^']+)'", pattern)
        raw_value = match.group(1) if match else pattern

        if not obs_type:
            for prefix, name in [
                ("ipv4-addr", "IPv4-Addr"), ("ipv6-addr", "IPv6-Addr"),
                ("domain-name", "Domain-Name"), ("url:", "Url"),
                ("file:", "StixFile"), ("email-addr", "Email-Addr"),
            ]:
                if prefix in pattern:
                    obs_type = name
                    break
            else:
                obs_type = "Unknown"

    indicator["_source_observable_value"] = raw_value
    indicator["_source_observable_type"]  = obs_type
    indicator["_source"]                  = source_tag

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    indicator.setdefault("valid_from",      now)
    indicator.setdefault("confidence",      50)
    indicator.setdefault("indicator_types", ["malicious-activity"])
    indicator.setdefault("objectLabel",     [])
    indicator.setdefault("x_opencti_score", None)

    if not indicator.get("indicator_types") and indicator.get("indicatorTypes"):
        indicator["indicator_types"] = indicator["indicatorTypes"]

    return indicator


# ==============================================================================
#  STEP 8 - COMPOSITE VULNERABILITY SCORING
# ==============================================================================

def _fetch_kev_set(cfg: Config) -> set[str]:
    for attempt in range(1, cfg.KEV_RETRY_LIMIT + 1):
        try:
            resp = requests.get(cfg.KEV_API_URL, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            kev_ids = {
                entry.get("cveID", "").upper()
                for entry in data.get("vulnerabilities", [])
                if entry.get("cveID")
            }
            return kev_ids
        except requests.RequestException as exc:
            log.warning("KEV fetch attempt %d/%d failed: %s", attempt, cfg.KEV_RETRY_LIMIT, exc)
            if attempt < cfg.KEV_RETRY_LIMIT:
                time.sleep(cfg.KEV_RETRY_DELAY)
    log.error("KEV fetch failed after %d attempts - KEV flags will be unavailable.", cfg.KEV_RETRY_LIMIT)
    return set()


def _epss_batch_query(
    cve_ids: list[str],
    cfg: Config,
) -> dict[str, dict[str, float]]:
    results: dict[str, dict[str, float]] = {}
    url = f"{cfg.EPSS_API_BASE}?cve={','.join(cve_ids)}"

    for attempt in range(1, cfg.EPSS_RETRY_LIMIT + 1):
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            for entry in resp.json().get("data", []):
                cve = entry.get("cve", "").upper()
                if cve:
                    results[cve] = {
                        "epss":       float(entry.get("epss",       0.0)),
                        "percentile": float(entry.get("percentile", 0.0)),
                    }
            return results
        except requests.RequestException as exc:
            log.warning("EPSS fetch attempt %d/%d failed: %s", attempt, cfg.EPSS_RETRY_LIMIT, exc)
            if attempt < cfg.EPSS_RETRY_LIMIT:
                time.sleep(cfg.EPSS_RETRY_DELAY)
    log.error("EPSS fetch failed after %d attempts for this batch - EPSS scores will be unavailable.", cfg.EPSS_RETRY_LIMIT)
    return results


def enrich_vulnerabilities_with_epss(
    client: OpenCTIApiClient,
    cfg: Config,
) -> dict[str, dict]:
    kev_set = _fetch_kev_set(cfg)
    limit = getattr(cfg, "FETCH_LIMIT", None)
    
    if limit is not None:
        result = client.vulnerability.list(first=limit, getAll=False, withPagination=True)
        vulns = result.get("entities", result) if isinstance(result, dict) else result
        if not vulns:
            vulns = []
    else:
        vulns = client.vulnerability.list(getAll=True) or []
        
    cvss_map: dict[str, float] = {}
    cve_ids: list[str] = []
    for v in vulns:
        name = v.get("name", "")
        if not re.match(r"^CVE-\d{4}-\d+$", name, re.IGNORECASE):
            continue
        cve = name.upper()
        cve_ids.append(cve)
        
        raw_cvss = (
            v.get("x_opencti_cvss_base_score")
            or v.get("cvss")
            or v.get("base_score")
        )
        if raw_cvss is None:
            cvss_map[cve] = None   
        else:
            try:
                cvss_map[cve] = float(raw_cvss)
            except (TypeError, ValueError):
                cvss_map[cve] = None

    if not cve_ids:
        return {}

    epss_data: dict[str, dict[str, float]] = {}
    for i in range(0, len(cve_ids), cfg.EPSS_BATCH_SIZE):
        epss_data.update(_epss_batch_query(cve_ids[i : i + cfg.EPSS_BATCH_SIZE], cfg))
        time.sleep(0.3)

    enriched: dict[str, dict] = {}
    for cve in cve_ids:
        epss_raw   = epss_data.get(cve)    
        cvss_raw   = cvss_map.get(cve)    
        kev_listed = cve in kev_set

        epss_score = epss_raw.get("epss", None) if epss_raw else None
        epss_pct   = epss_raw.get("percentile", 0.0) if epss_raw else 0.0
        cvss_base  = (
            float(cvss_raw)
            if (cvss_raw is not None and cvss_raw != 0.0)
            else None
        )

        signal_count = sum([
            epss_score is not None,
            cvss_base  is not None,
            True,   
        ])

        both_continuous_missing = (epss_score is None and cvss_base is None)

        if both_continuous_missing:
            composite = cfg.KEV_WEIGHT * (1.0 if kev_listed else 0.0)
            w_epss_eff = 0.0
            w_cvss_eff = 0.0
            w_kev_eff  = cfg.KEV_WEIGHT
        else:
            weights = {}
            if epss_score is not None:
                weights["epss"] = cfg.EPSS_WEIGHT
            if cvss_base is not None:
                weights["cvss"] = cfg.CVSS_WEIGHT
            weights["kev"] = cfg.KEV_WEIGHT

            denom = sum(weights.values())   

            w_epss_eff = weights.get("epss", 0.0) / denom
            w_cvss_eff = weights.get("cvss", 0.0) / denom
            w_kev_eff  = weights["kev"] / denom

            composite = 0.0
            if epss_score is not None:
                composite += w_epss_eff * epss_score
            if cvss_base is not None:
                composite += w_cvss_eff * (cvss_base / 10.0)
            composite += w_kev_eff * (1.0 if kev_listed else 0.0)

        if composite < cfg.COMPOSITE_THRESHOLD and not kev_listed:
            continue

        parts = []
        if epss_score is not None:
            parts.append(f"EPSS={epss_score:.4f}(eff_w={w_epss_eff:.3f})")
        else:
            parts.append("EPSS=N/A")
        if cvss_base is not None:
            parts.append(f"CVSS={cvss_base:.1f}/10(eff_w={w_cvss_eff:.3f})")
        else:
            parts.append("CVSS=N/A")
        parts.append(f"KEV={'YES' if kev_listed else 'NO'}(eff_w={w_kev_eff:.3f})")

        enriched[cve] = {
            "epss_score":          epss_score if epss_score is not None else 0.0,
            "epss_percentile":     epss_pct,
            "cvss_base":           cvss_base  if cvss_base  is not None else 0.0,
            "kev_listed":          kev_listed,
            "composite_score":     round(composite, 4),
            "composite_breakdown": " + ".join(parts) + f" = {composite:.4f}",
            "epss_available":      epss_score is not None,
            "cvss_available":      cvss_base  is not None,
            "x_signal_count":      signal_count,
        }

    return enriched


# ==============================================================================
#  STEP 9 - TLSH SANITISATION ENGINE
# ==============================================================================

def _tlsh_hash_value(raw_value: str, cfg: Config) -> str | None:
    raw_bytes = raw_value.encode("utf-8")
    if len(raw_bytes) < cfg.TLSH_MIN_INPUT_BYTES:
        repeat    = (cfg.TLSH_MIN_INPUT_BYTES // len(raw_bytes)) + 2
        raw_bytes = (raw_value * repeat).encode("utf-8")[: cfg.TLSH_MIN_INPUT_BYTES * 2]
    try:
        h = tlsh.hash(raw_bytes)
        return h if (h and h != "TNULL") else None
    except Exception:
        return None


def sanitise_indicator(
    indicator: dict[str, Any],
    cfg: Config,
    client: OpenCTIApiClient | None = None,
) -> dict[str, Any] | None:
    raw_value = indicator.get("_source_observable_value", "")
    obs_type  = indicator.get("_source_observable_type", "Unknown")
    source    = indicator.get("_source", "unknown")

    adm_grade, adm_score = _get_admiralty(indicator, cfg)

    related_types: set[str] = set()
    attack_pattern_ids: set[str] = set()
    if client is not None and indicator.get("id"):
        related_types, attack_pattern_ids = _fetch_related_entity_types(
            client, indicator["id"], cfg
        )
    act_score, has_ioc, has_ttp, has_mitigation = _get_actionability(
        indicator, related_types, attack_pattern_ids, client, cfg
    )

    if not raw_value:
        return None

    tlsh_digest = _tlsh_hash_value(raw_value, cfg)
    if tlsh_digest is None:
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pipeline_id = "identity--" + str(
        uuid.uuid5(uuid.NAMESPACE_DNS, "healthcare-cti-pipeline")
    )

    sanitised: dict[str, Any] = {
        "type":         "indicator",
        "spec_version": "2.1",
        "id":           f"indicator--{uuid.uuid4()}",
        "name":         f"TLSH-sanitised {obs_type} indicator",
        "description": (
            f"OPSEC-safe indicator.  Observable type: {obs_type}.  "
            f"Behavioural signature preserved via TLSH; "
            f"source-identifying value and metadata destroyed."
        ),
        "pattern":      f"[x-tlsh:hash = '{tlsh_digest}']",
        "pattern_type": "stix",
        "valid_from":   indicator.get("valid_from") or now,
        "indicator_types": indicator.get("indicator_types") or ["malicious-activity"],
        "confidence":   indicator.get("confidence") or 50,
        "labels": ["healthcare", "opsec-sanitised", "tlsh-abstracted"],
        "x_tlsh_digest":              tlsh_digest,
        "x_original_observable_type": obs_type,
        "x_pipeline_source":          source,
        "x_opencti_score":            indicator.get("x_opencti_score"),
        "object_marking_refs": [
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
        ],
        "created":        now,
        "modified":       now,
        "created_by_ref": pipeline_id,
    }

    # Conditional inclusion of Admiralty grading
    if adm_grade is not None and adm_score is not None:
        sanitised["x_admiralty_grade"] = adm_grade
        sanitised["x_admiralty_score"] = adm_score

    # Conditional inclusion of actionability scoring
    if act_score is not None:
        sanitised["x_actionability_score"]     = act_score
        sanitised["x_ioc_present"]             = has_ioc
        sanitised["x_ttp_linked"]              = has_ttp
        sanitised["x_mitigation_linked"]       = has_mitigation

    for key in list(sanitised.keys()):
        if key.startswith("_") or key in cfg.STRIP_FIELDS:
            del sanitised[key]

    return sanitised


# ==============================================================================
#  STEP 10 - ASSEMBLE STIX 2.1 BUNDLE
# ==============================================================================

def build_stix_bundle(
    sanitised_indicators: list[dict[str, Any]],
    epss_scores: dict[str, float],
    cfg: Config,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pipeline_id = "identity--" + str(
        uuid.uuid5(uuid.NAMESPACE_DNS, "healthcare-cti-pipeline")
    )

    pipeline_identity = {
        "type": "identity", "spec_version": "2.1", "id": pipeline_id,
        "name": "Healthcare CTI Pipeline (CYBR7901)", "identity_class": "system",
        "description": "EPSS-prioritised, TLSH-sanitised CTI pipeline v2.1.",
        "created": now, "modified": now,
    }

    tlp_green = {
        "type": "marking-definition", "spec_version": "2.1",
        "id": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "definition": {"tlp": "green"},
    }

    vuln_objects = [
        {
            "type": "vulnerability", "spec_version": "2.1",
            "id": "vulnerability--" + str(uuid.uuid5(uuid.NAMESPACE_DNS, cve)),
            "name": cve, "created": now, "modified": now,
            "description": enrichment.get("composite_breakdown", ""),
            "x_epss_score":       enrichment.get("epss_score",      0.0),
            "x_epss_percentile":  enrichment.get("epss_percentile", 0.0),
            "x_cvss_base":        enrichment.get("cvss_base",       0.0),
            "x_kev_listed":       enrichment.get("kev_listed",      False),
            "x_composite_score":  enrichment.get("composite_score", 0.0),
            "x_signal_count":     enrichment.get("x_signal_count",  1),
            "object_marking_refs": [
                "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
            ],
            "created_by_ref": pipeline_id,
        }
        for cve, enrichment in sorted(
            epss_scores.items(),
            key=lambda x: -x[1].get("composite_score", 0.0)
        )
    ]

    return {
        "type": "bundle",
        "id":   f"bundle--{uuid.uuid4()}",
        "objects": [tlp_green, pipeline_identity] + vuln_objects + sanitised_indicators,
    }


def export_bundle(bundle: dict[str, Any], cfg: Config) -> Path:
    cfg.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = cfg.OUTPUT_DIR / cfg.BUNDLE_FILENAME.format(ts=ts)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)
    log.info("Bundle written -> %s", out_path)
    return out_path


# ==============================================================================
#  STEP 11 - STIX 2.1 VALIDATION
# ==============================================================================

def validate_bundle(bundle_path: Path) -> bool:
    log.info("Validating STIX 2.1 bundle ...")
    errors = 0
    with open(bundle_path, encoding="utf-8") as f:
        raw = json.load(f)

    for obj in raw.get("objects", []):
        try:
            stix2_parse(json.dumps(obj), allow_custom=True)
        except STIXError as exc:
            log.warning("  STIX warning [%s]: %s", obj.get("id", "?"), exc)
            errors += 1
        except Exception as exc:
            log.error("  Parse error [%s]: %s", obj.get("id", "?"), exc)
            errors += 1

    total = len(raw.get("objects", []))
    if errors == 0:
        log.info("  Validation PASSED - %d objects clean.", total)
    else:
        log.warning("  %d warning(s) across %d objects.", errors, total)
    return True


# ==============================================================================
#  STEP 12 - SUMMARY OUTPUT
# ==============================================================================

def print_summary(
    native_count: int,
    raw_obs_count: int,
    promoted_count: int,
    epss_vuln_count: int,
    sanitised_count: int,
    alienvault_in_output: int,
    promoted_in_output: int,
    bundle_path: Path,
    cfg: Config,
    quality_report: dict[str, Any] | None = None,
) -> None:
    total_input   = native_count + raw_obs_count
    reduction_pct = (
        100.0 * (1.0 - sanitised_count / total_input)
        if total_input > 0 else 0.0
    )
    W = 62
    print("\n" + "=" * W)
    print("  HEALTHCARE CTI PIPELINE  -  RUN SUMMARY")
    print("=" * W)
    print(f"  OpenCTI             : {cfg.OPENCTI_URL}")
    print(f"  Composite threshold : {cfg.COMPOSITE_THRESHOLD:.2f}  "
          f"(EPSS {cfg.EPSS_WEIGHT} / CVSS {cfg.CVSS_WEIGHT} / KEV {cfg.KEV_WEIGHT})")
    print(f"  Sector filter       : {'STRICT' if cfg.STRICT_SECTOR_FILTER else 'SOFT'}")
    print(f"  Admiralty grading   : {'disabled' if cfg.SKIP_ADMIRALTY else 'enabled'}")
    print(f"  Actionability       : {'disabled' if cfg.SKIP_ACTIONABILITY else 'enabled'}")

    print("\n  INPUT")
    print(f"    AlienVault indicators (native) : {native_count:>6}")
    print(f"    Raw observables (SCOs)         : {raw_obs_count:>6}")
    print(f"    Total input objects            : {total_input:>6}")

    print("\n  PROCESSING")
    print(f"    Observables promoted           : {promoted_count:>6}")
    print(f"    CVEs above composite threshold : {epss_vuln_count:>6}")
    print(f"    TLSH-sanitised indicators      : {sanitised_count:>6}")

    print("\n  OUTPUT BUNDLE")
    print(f"    From AlienVault (sanitised)    : {alienvault_in_output:>6}")
    print(f"    From promotion (sanitised)     : {promoted_in_output:>6}")
    print(f"    Vulnerability SDOs (EPSS)      : {epss_vuln_count:>6}")
    print(f"    Total indicators in bundle     : {sanitised_count:>6}")
    print(f"    Volume reduction               : {reduction_pct:>5.1f}%")

    if quality_report:
        qr = quality_report

        def _fmt(v: float | None) -> str:
            return f"{v:.3f}" if v is not None else "n/a"

        def _delta(before: float | None, after: float | None) -> str:
            if before is None or after is None:
                return ""
            change = after - before
            sign = "+" if change >= 0 else ""
            return f"  ({sign}{change:.3f})"

        print("\n  QUALITY: NATIVE INDICATORS, BEFORE vs. AFTER SECTOR FILTER")
        print(f"    Sample sizes                   : "
              f"before={qr['before_count']:>4}   after={qr['after_count']:>4}")
        print(f"    Avg reliability score          : "
              f"{_fmt(qr['before_avg_admiralty']):>6} -> {_fmt(qr['after_avg_admiralty']):>6}"
              f"{_delta(qr['before_avg_admiralty'], qr['after_avg_admiralty'])}")
        print(f"    Avg actionability score        : "
              f"{_fmt(qr['before_avg_actionability']):>6} -> {_fmt(qr['after_avg_actionability']):>6}"
              f"{_delta(qr['before_avg_actionability'], qr['after_avg_actionability'])}")
        print("    (covers native indicators only - vulnerabilities and")
        print("     promoted observables are not sector-filtered)")

    print(f"\n  Output -> {bundle_path}")
    print("=" * W + "\n")



# ==============================================================================
#  CLI & MAIN
# ==============================================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Healthcare CTI pipeline")
    p.add_argument("--dry-run",        action="store_true",
                   help="Preview without writing to OpenCTI.")
    p.add_argument("--threshold", type=float, default=None,
                   metavar="T",
                   help="Minimum composite score (0.0-1.0) a CVE must reach to be included.")
    p.add_argument("--output-dir",     type=str,   default=None,
                   help="Override output directory.")
    p.add_argument("--strict-filter",  action="store_true",
                   help="Drop unlabelled objects (strict healthcare filter).")
    p.add_argument("--skip-promote",   action="store_true",
                   help="Skip SCO promotion (use only native Indicators).")
    p.add_argument("--skip-native", action="store_true",
                   help="Skip native indicators (e.g. AlienVault).")
    p.add_argument("--skip-admiralty", action="store_true",
                   help="Disable NATO Admiralty System grading for demonstrative purposes.")
    p.add_argument("--skip-actionability", action="store_true",
                   help="Disable actionability scoring (IOC/TTP/mitigation) for demonstrative purposes.")
    p.add_argument("--no-relationships", action="store_true",
                   help="Skip the per-indicator relationship fetch (faster, but TTP/mitigation always False).")
    p.add_argument("--limit",        type=int, default=None,
                   metavar="N",
                   help="Fetch at most N objects per step.")
    return p.parse_args()


def _build_quality_comparison(all_scored: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Compare average reliability/actionability scores before vs. after the
    healthcare-relevance filter, as evidence the filter selects for quality
    rather than merely reducing volume.
    """
    def _avg(vals: list[float]) -> float | None:
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    before = all_scored
    after  = [s for s in all_scored if s["is_relevant"]]

    return {
        "before_count": len(before),
        "after_count":  len(after),
        "before_avg_admiralty":    _avg([s["admiralty_score"] for s in before]),
        "after_avg_admiralty":     _avg([s["admiralty_score"] for s in after]),
        "before_avg_actionability": _avg([s["actionability_score"] for s in before]),
        "after_avg_actionability":  _avg([s["actionability_score"] for s in after]),
    }


def main() -> int:
    args = parse_args()
    cfg  = Config()

    if args.threshold is not None:
        cfg.COMPOSITE_THRESHOLD = args.threshold
    if args.output_dir is not None:
        cfg.OUTPUT_DIR = Path(args.output_dir)
    if args.strict_filter:
        cfg.STRICT_SECTOR_FILTER = True
    if args.limit is not None:
        cfg.FETCH_LIMIT = args.limit
        log.info("Fetch limit set to %d objects per step (test mode).", args.limit)
    if args.skip_admiralty:
        cfg.SKIP_ADMIRALTY = True
        log.info("Admiralty grading disabled (--skip-admiralty).")
    if args.skip_actionability:
        cfg.SKIP_ACTIONABILITY = True
        log.info("Actionability scoring disabled (--skip-actionability).")
    if args.no_relationships:
        cfg.FETCH_RELATIONSHIPS = False
        log.info("Relationship fetch disabled (--no-relationships) - TTP/mitigation will default to False.")

    if args.dry_run:
        log.info("*** DRY-RUN - no mutations sent to OpenCTI ***")

    token = cfg.OPENCTI_TOKEN
    if not token or token == "REPLACE_WITH_YOUR_TOKEN" or len(token) < 20:
        log.error("OPENCTI_TOKEN is missing or invalid.")
        return 1

    client = connect_opencti(cfg)

    native_normalised = []
    native_count = 0
    native_ids = set()
    quality_report: dict[str, Any] = {}

    if not args.skip_native:
        native_indicators = fetch_native_indicators(client, cfg)
        native_count      = len(native_indicators)
        native_ids        = {ind.get("id") for ind in native_indicators}

        # Score EVERY fetched indicator (before sector-relevance filtering),
        # so we can compare quality before vs. after filtering - proof the
        # filter selects for quality, not just volume reduction.
        all_scored = []
        for ind in native_indicators:
            related_types, ap_ids = (
                _fetch_related_entity_types(client, ind["id"], cfg)
                if client is not None and ind.get("id") else (set(), set())
            )
            adm_grade, adm_score = _get_admiralty(ind, cfg)
            act_score, *_ = _get_actionability(ind, related_types, ap_ids, client, cfg)
            is_relevant = is_healthcare_relevant(ind, cfg)
            all_scored.append({
                "is_relevant": is_relevant,
                "admiralty_score": adm_score,
                "actionability_score": act_score,
            })
            if is_relevant:
                native_normalised.append(normalise_indicator(ind, source_tag="alienvault"))

        quality_report = _build_quality_comparison(all_scored)
    else:
        log.info("Native indicators skipped (--skip-native).")
        
    promoted_normalised: list[dict] = []
    raw_obs_count = 0

    if not args.skip_promote:
        raw_observables = fetch_all_observables(client, cfg)
        raw_obs_count   = len(raw_observables)
        promoted_raw    = promote_observables_to_indicators(
            client, raw_observables, native_ids, cfg, dry_run=args.dry_run
        )
        promoted_normalised = [
            normalise_indicator(ind, source_tag="promoted")
            for ind in promoted_raw
        ]
    else:
        log.info("Observable promotion skipped (--skip-promote).")

    epss_scores = enrich_vulnerabilities_with_epss(client, cfg)

    all_indicators                = native_normalised + promoted_normalised
    sanitised: list[dict]         = []
    alienvault_count = promoted_count_out = 0

    for ind in all_indicators:
        result = sanitise_indicator(ind, cfg, client=client)
        if result is None:
            continue
        sanitised.append(result)
        if result.get("x_pipeline_source") == "alienvault":
            alienvault_count += 1
        else:
            promoted_count_out += 1

    if not sanitised and not epss_scores:
        log.warning("Nothing to export. Check connectors have completed ingestion.")
        return 0

    bundle      = build_stix_bundle(sanitised, epss_scores, cfg)
    bundle_path = export_bundle(bundle, cfg)

    validate_bundle(bundle_path)

    print_summary(
        native_count         = native_count,
        raw_obs_count        = raw_obs_count,
        promoted_count       = len(promoted_normalised),
        epss_vuln_count      = len(epss_scores),
        sanitised_count      = len(sanitised),
        alienvault_in_output = alienvault_count,
        promoted_in_output   = promoted_count_out,
        bundle_path          = bundle_path,
        cfg                  = cfg,
        quality_report       = quality_report,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())