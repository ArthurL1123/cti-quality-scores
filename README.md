# Healthcare CTI quality pipeline

A pipeline on top of [OpenCTI](https://www.opencti.io/) that ingests threat intelligence, filters it for healthcare relevance, and scores it on three separate quality dimensions: **urgency**, **reliability** and **actionability**. The output is a sanitised STIX 2.1 bundle.

## What it does

1. **Ingest** native indicators and raw observables from OpenCTI. Raw observables are promoted to indicators with OpenCTI's own promote mutation.
2. **Filter** for healthcare relevance with a keyword filter (soft mode by default, `--strict-filter` for strict mode).
3. **Urgency** (vulnerabilities): composite score = `0.35 EPSS + 0.25 CVSS + 0.40 KEV`. If a signal is missing, its weight is dropped and the remaining weights are rescaled to sum to 1.
4. **Reliability** (indicators): NATO Admiralty grade read from OpenCTI's `createdBy.x_opencti_reliability`. If it's unset, the grade falls back to F (0.10).
5. **Actionability** (indicators): `0.30 IOC present + 0.40 linked to an ATT&CK technique + 0.30 linked to a mitigation`. Mitigations are found through the linked Attack-Pattern, because ATT&CK mitigations link to techniques, not indicators.
6. **Sanitise** with TLSH hashing, identity stripping and a TLP:GREEN marking.
7. **Export** a STIX 2.1 bundle to `output/`. The run summary prints a before/after quality comparison.

The three scores are kept separate on purpose and are never blended into one number. Urgency describes a weakness (a fact), while reliability and actionability are judgements about a source's claim. Reliability and actionability come from the CTI quality taxonomy in Zibak et al. (2022). Urgency is an extra dimension added for this project.

| File | Purpose |
|---|---|
| `healthcare_cti_pipeline.py` | Main pipeline |
| `compare_quality.py` | Re-scores all *unfiltered* indicators with the same scoring functions, as a cross-check on the filter's effect |
| `DEVLOG.md` | Development history, decisions and bug fixes |

## How to run

Requirements: Python 3.10+, a running OpenCTI instance, and an OpenCTI API token.

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

Useful flags: `--threshold T`, `--strict-filter`, `--skip-promote`, `--skip-native`, `--skip-admiralty`, `--skip-actionability`, `--no-relationships`, `--output-dir DIR`. Run with `--help` for details.

You can override weights and other settings with environment variables: `EPSS_WEIGHT`, `CVSS_WEIGHT`, `KEV_WEIGHT`, `IOC_WEIGHT`, `TTP_WEIGHT`, `MITIGATION_WEIGHT`, `COMPOSITE_THRESHOLD`, `FETCH_LIMIT`, `OUTPUT_DIR`.

## Results on the sample bundle

Sample: 298 indicators and 2,310 vulnerabilities.

- 88.3% of indicators have a linked technique, and 52.0% have a linked mitigation.
- Filtering raised average reliability from 0.800 to 0.844 and average actionability from 0.593 to 0.795. `compare_quality.py` reproduced the unfiltered averages to within rounding.
- The 40 KEV-listed vulnerabilities average a composite score of 0.816, against 0.188 for the rest.
- Sensitivity: across five other weight sets, the urgency ranking keeps a rank correlation of 0.907 or higher with the original.
- Only four actionability signal combinations occur, and they are nested, so any positive weights give the same ranking.

## Open items and known limits

- 97% of the sample indicators come from a single feed (AlienVault OTX), so reliability barely varies.
- The sector filter only applies to native indicators. Vulnerabilities and promoted observables are not filtered.
- No user study with analysts has been done yet.
- It's still undecided whether the OPSEC sanitisation stage belongs in the project.
- `check_coa.py` (counts Course-of-Action objects in OpenCTI) is mentioned in the dev log but isn't in this repo yet.
