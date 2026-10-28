# CTI quality scores

Code for the capstone thesis *From Volume to Value: Validating Quality Scores for Open Cyber Threat Intelligence* (University of Queensland, 2026).

A Python pipeline on top of a local OpenCTI instance. It scores open CTI on three separate quality dimensions:

- **Urgency** (vulnerabilities): `0.35 EPSS + 0.25 CVSS/10 + 0.40 KEV`, with the weights of a missing signal moved to the others
- **Reliability** (indicators): the NATO Admiralty grade from OpenCTI's own source reliability field
- **Actionability** (indicators): `0.30 IOC + 0.40 linked ATT&CK technique + 0.30 linked mitigation`

Each score is then checked against evidence from outside the pipeline: CISA KEV for urgency, the MISP warninglists for reliability, and the OASIS STIX pattern validator for actionability.

## Scripts

| Script | What it does | Report section |
|---|---|---|
| `healthcare_cti_pipeline.py` | The pipeline: fetch, keyword filter, score, export a STIX 2.1 bundle | Ch 4, 5.1 to 5.5 |
| `app.py` | Streamlit dashboard for the exported runs | 5.2 to 5.5 |
| `analyse_bundle.py` | Every Chapter 5 number from one bundle, including the weight sensitivity check | 5.2 to 5.5 |
| `check_significance.py` | Passed vs dropped indicators: permutation test and bootstrap, overall and per feed | 5.3 |
| `check_threshold.py` | What the 0.10 urgency threshold removes, by CVSS band | 5.5.2 |
| `backtest_urgency.py` | Back test of the urgency score against later KEV additions, 13 monthly dates | 5.6.1 |
| `check_backtest_significance.py` | Whether the back test lead over EPSS and CVSS is chance | 5.6.1 |
| `validate_indicators.py` | Warninglist check for reliability and usability check for actionability | 5.6.2, 5.6.3 |
| `make_validation_figures.py` | Draws the Section 5.6 figures from the saved results | 5.6 |

## Results

`results/` holds the outputs the report's numbers come from. They contain counts and CVE IDs only, no indicator values.

| File | From |
|---|---|
| `run_summary_20261009T042040Z.json` | The pipeline run on 5,000 indicators and 5,000 vulnerabilities, 9 October 2026 |
| `analyse_bundle_20261009.log` | `analyse_bundle.py` on that run's bundle |
| `significance_5000.log` | `check_significance.py --limit 5000` |
| `threshold_5000.log` | `check_threshold.py --limit 5000` |
| `backtest_summary_2025-04-01_to_2026-04-01.json` | `backtest_urgency.py --range 2025-04-01 2026-04-01` |
| `significance_2025-04-01_to_2026-04-01*.json` | `check_backtest_significance.py`, budgets of 10% and 15.5% |
| `validation_run.log` | `validate_indicators.py` on all 67,353 indicators, 25 October 2026 |

## Running

```bash
pip install pycti stix2 stix2-patterns requests python-dotenv pandas numpy matplotlib streamlit altair

export OPENCTI_TOKEN=<your-token>      # or put it in a .env file

python healthcare_cti_pipeline.py --limit 5000
python analyse_bundle.py output/healthcare_cti_<ts>.json
python check_significance.py --limit 5000
python check_threshold.py --limit 5000
python backtest_urgency.py --range 2025-04-01 2026-04-01
python check_backtest_significance.py --range 2025-04-01 2026-04-01
python check_backtest_significance.py --range 2025-04-01 2026-04-01 --budget 0.155
python validate_indicators.py
python make_validation_figures.py
streamlit run app.py
```

Run any script with `--help` for all options.

## Notes

- Needs a running OpenCTI with the AlienVault OTX, ThreatFox and CISA KEV connectors. The token is read from `OPENCTI_TOKEN` and has no default.
- All scripts only read from OpenCTI. Nothing is written back.
- EPSS, KEV, NVD and the MISP warninglists are downloaded from their public sources, so the scripts need internet access.
- The keyword filter was first built for the healthcare sector, which is why the pipeline keeps its original file name. The report uses it as one example of a topic filter.
- Bundles and per-indicator files contain real indicator values. They are written to `output/`, which is git-ignored. Do not commit them.
