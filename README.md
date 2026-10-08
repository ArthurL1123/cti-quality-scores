# Healthcare CTI quality pipeline

A Python script that runs on top of a local OpenCTI instance. It filters threat intelligence for healthcare relevance and scores it on three separate dimensions:

- **Urgency** (vulnerabilities): `0.35 EPSS + 0.25 CVSS + 0.40 KEV`
- **Reliability** (indicators): NATO Admiralty grade from OpenCTI's source reliability field
- **Actionability** (indicators): `0.30 IOC + 0.40 linked ATT&CK technique + 0.30 linked mitigation`

The output is a STIX 2.1 bundle of the filtered indicators with their scores, plus the scored vulnerabilities. Vulnerabilities are sorted by urgency, highest first. The run summary compares quality before and after the filter, overall and for each source feed.

## Sample commands

```bash
pip install pycti stix2 requests python-dotenv

export OPENCTI_TOKEN=<your-token>      # or put it in a .env file

python healthcare_cti_pipeline.py                  # full run
python healthcare_cti_pipeline.py --limit 2000     # the sample used in the report
python healthcare_cti_pipeline.py --threshold 0.25 --strict-filter
python compare_quality.py --limit 2000             # scores before filtering, as a consistency check
python label_hand_check.py                         # hand-label the filter sample in output/
```

## Demo dashboard

```bash
pip install streamlit
streamlit run app.py
```

Opens in the browser. Tabs: run the pipeline live against OpenCTI, compare indicators before and after the filter (volume and quality, per feed), ranked vulnerabilities with their score breakdown, and indicators with their reliability and actionability. The sidebar loads any saved run from `output/`. Each run also writes a `run_summary_*.json` next to its bundle, which the dashboard reads.

Run `--help` for all flags.

## Notes

- Needs a running OpenCTI with the AlienVault OTX, ThreatFox and CISA KEV connectors. The token is read from `OPENCTI_TOKEN` and has no default.
- The script only reads from OpenCTI. It does not write anything back.
- EPSS and KEV data are fetched directly from FIRST and CISA, so the script needs internet access.
- The filter uses two keyword lists: sector words from STIX 2.1 and ENISA, and threat words from ENISA. It checks labels, name and pattern, not the description.
- `--limit N` caps both indicators and vulnerabilities at N.
- Bundles contain real indicator values. They are written to `output/`, which is git-ignored. Do not commit them.
- Indicators are not sorted in the output.
- Weights can be changed with environment variables, for example `EPSS_WEIGHT` or `KEV_WEIGHT`.
- `DEVLOG.md` has the history, the decisions and the bugs that were fixed.
