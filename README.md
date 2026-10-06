# Healthcare CTI quality pipeline

A Python script that runs on top of a local OpenCTI instance. It filters threat intelligence for healthcare relevance and scores it on three separate dimensions:

- **Urgency** (vulnerabilities): `0.35 EPSS + 0.25 CVSS + 0.40 KEV`
- **Reliability** (indicators): NATO Admiralty grade from OpenCTI's source reliability field
- **Actionability** (indicators): `0.30 IOC + 0.40 linked ATT&CK technique + 0.30 linked mitigation`

The output is a sanitised STIX 2.1 bundle. Vulnerabilities are sorted by urgency, highest first.

## Sample commands

```bash
pip install pycti stix2 requests python-tlsh python-dotenv

export OPENCTI_TOKEN=<your-token>      # or put it in a .env file

python healthcare_cti_pipeline.py                  # full run
python healthcare_cti_pipeline.py --limit 100      # quick test run
python healthcare_cti_pipeline.py --dry-run        # no changes to OpenCTI
python healthcare_cti_pipeline.py --threshold 0.25 --strict-filter
python compare_quality.py                          # scores before filtering, for comparison
```

Run `--help` for all flags.

## Notes

- Needs a running OpenCTI with the AlienVault OTX, ThreatFox and CISA KEV connectors. The token is read from `OPENCTI_TOKEN` and has no default.
- EPSS and KEV data are fetched directly from FIRST and CISA, so the script needs internet access.
- `--dry-run` does not write to OpenCTI, but it still writes the bundle file.
- The pipeline adds a `healthcare` label to every output indicator, so that label does not show an indicator is relevant to healthcare.
- Indicators are not sorted in the output.
- Weights can be changed with environment variables, for example `EPSS_WEIGHT` or `KEV_WEIGHT`.
- `DEVLOG.md` has the history and the bugs that were fixed.
