# Healthcare CTI quality pipeline

A Python pipeline on top of a local Docker [OpenCTI](https://www.opencti.io/) instance. It reads threat intelligence from AlienVault OTX, Abuse.ch ThreatFox and CISA KEV (through OpenCTI connectors), filters it for healthcare relevance, and scores it on three separate quality dimensions: **urgency**, **reliability** and **actionability**. The output is a sanitised STIX 2.1 bundle.

## What it does

1. **Fetch** native indicators and raw observables. Raw observables are promoted to indicators with OpenCTI's promote mutation.
2. **Sector filter.** An object passes if a healthcare keyword matches its labels or its name, description or pattern text. In soft mode (the default), unlabelled objects also pass. `--strict-filter` requires a keyword match.
3. **Urgency** (vulnerabilities): `0.35 EPSS + 0.25 CVSS + 0.40 KEV`. If a signal is missing, its weight is removed and the rest are rescaled. If both EPSS and CVSS are missing, the score is capped at the KEV weight (0.40).
4. **Reliability** (indicators): NATO Admiralty grade (A to F) from OpenCTI's `x_opencti_reliability`. If it's unset, the grade falls back to F (0.10).
5. **Actionability** (indicators): `0.30 IOC + 0.40 linked ATT&CK technique + 0.30 linked mitigation`. Mitigations are found through the linked Attack-Pattern, because ATT&CK mitigations link to techniques, not indicators.
6. **Sanitise:** TLSH hashing, new random IDs, metadata stripped, and a TLP:GREEN marking.
7. **Export:** vulnerabilities are sorted by composite score, highest first. Indicators are not sorted.

| File | Purpose |
|---|---|
| `healthcare_cti_pipeline.py` | Main pipeline |
| `compare_quality.py` | Re-scores all *unfiltered* indicators with the same scoring functions, as a cross-check on the filter's effect |
| `DEVLOG.md` | Development history: v1 vs v2, bugs fixed, decisions |

## Design decisions

- **Three urgency signals.** CVSS alone says how bad a flaw could be, but not how likely it is to be exploited. EPSS predicts exploitation and KEV confirms it.
- **KEV has the highest weight** because it records confirmed exploitation rather than a prediction.
- **TLSH instead of SHA-256.** A fuzzy hash keeps similar malware variants close together, so matching still works while the raw value is hidden.
- **TLP:GREEN on output.** After sanitisation, the output no longer carries the source network's identifiers.
- **Separate scores.** Urgency, reliability and actionability are never blended into one number. Urgency is a fact about a weakness, so it applies to vulnerabilities. Reliability and actionability are judgements about a source's claim, so they apply to indicators.
- **Grounding.** Reliability and actionability follow Zibak et al. (2022), a 7-dimension CTI quality taxonomy. Urgency is an extra dimension added for this project.
- **Project direction.** The supervisor moved the project away from OPSEC-safe sharing and towards CTI quality. The OPSEC sanitisation stage is still in the code, and whether it stays is undecided.

> **Note:** the pipeline adds a `healthcare` label to every sanitised indicator, so that label in the output bundle is not evidence of healthcare relevance.

## How to run

Requirements: Python 3.10+, a running OpenCTI instance with the connectors above, and an OpenCTI API token.

```bash
pip install pycti stix2 requests python-tlsh python-dotenv
```

Set the token in your environment, or in a `.env` file next to the scripts (it's git-ignored):

```
OPENCTI_TOKEN=<your-token>
OPENCTI_URL=http://localhost:8080
```

The token has no default. The scripts exit with an error if it isn't set.

```bash
python healthcare_cti_pipeline.py              # full run
python healthcare_cti_pipeline.py --dry-run    # preview, no writes to OpenCTI
python healthcare_cti_pipeline.py --limit 100  # quick test run
python compare_quality.py                      # unfiltered baseline scores
```

Flags: `--dry-run`, `--threshold T`, `--limit N`, `--strict-filter`, `--skip-promote`, `--skip-native`, `--skip-admiralty`, `--skip-actionability`, `--no-relationships`, `--output-dir DIR`. Run with `--help` for details.

You can override weights and settings with environment variables: `EPSS_WEIGHT`, `CVSS_WEIGHT`, `KEV_WEIGHT`, `IOC_WEIGHT`, `TTP_WEIGHT`, `MITIGATION_WEIGHT`, `COMPOSITE_THRESHOLD`, `FETCH_LIMIT`, `OUTPUT_DIR`.

## Results (latest run)

Sample: 298 indicators and 2,310 vulnerabilities in the bundle.

- 88.3% of indicators have a linked technique, and 52.0% have a linked mitigation.
- Filtering raised average reliability from 0.800 to 0.844 and average actionability from 0.593 to 0.795. `compare_quality.py` reproduced the unfiltered averages.
- The 40 KEV-listed vulnerabilities average a composite score of 0.816, against 0.188 for the rest.
- 138 vulnerabilities (6.0%) had no CVSS and were scored with dynamic normalisation. In the bundle, their `x_cvss_base` is 0.0 and the description says N/A.
- Sensitivity: across five other weight sets, the urgency ranking keeps a rank correlation of 0.907 or higher with the original.

## Open items and known limits

- OPSEC scope: waiting for the supervisor's answer.
- Critical review: add the schedule comment, and a conclusion tied back to the literature.
- Indicators have no ranking in the export.
- 97% of the sample comes from one feed (AlienVault OTX), so reliability barely varies.
- The sector filter only applies to native indicators. Vulnerabilities and promoted observables are not filtered.
- No user study with analysts has been done yet.
- `check_coa.py` (counts Course-of-Action objects) is listed in the dev log but isn't in this repo yet.
- ~~Remove the hardcoded OpenCTI token~~: done. The token is read from `OPENCTI_TOKEN` with no default.
