# Original CIC-DDoS2019 dataset: download and execution status

## What was verified

- The official Canadian Institute for Cybersecurity page describes labelled CICFlowMeter-V3 CSVs and multiple DDoS families: <https://www.unb.ca/cic/datasets/ddos-2019.html>.
- The official page's download portal opened but displayed `Server error. Please try again later` during this attempt.
- A public Hugging Face mirror lists the original per-attack CSV filenames in `01-12/` and a total folder size of about 22.3 GB: <https://huggingface.co/datasets/baalajimaestro/CICDDoS2019/tree/main/01-12>.
- The default starter selection is `UDPLag.csv`, `Syn.csv`, and `DrDoS_NTP.csv` (approximately 1.44 GB combined by the mirror's listed file sizes).

## Why no real-data model is included

This execution environment cannot resolve external download hosts (outbound DNS/network is unavailable). Attempts to fetch the public Hugging Face CSV and the Zenodo mirror directly therefore failed. No full or partial original CIC-DDoS2019 CSV was available in the uploaded ZIP. Consequently, this package does **not** claim to have trained or evaluated a model on the original benchmark. Existing `artifacts/demo/` files remain synthetic-only smoke-test outputs.

## Download and run on a machine with Internet access

```bash
pip install -r requirements-download.txt
python scripts/download_cicddos2019.py
python scripts/preprocess_dataset.py --input data/raw/CICDDoS2019/01-12 --output data/processed/cicddos2019_flows.csv
python scripts/train.py --input data/processed/cicddos2019_flows.csv --output-dir artifacts/production --max-rows 100000
pytest -q
```

Use `python scripts/download_cicddos2019.py --all` to download all 11 CSVs (about 22.3 GB). Remove `--max-rows 100000` for a larger training run after confirming available RAM and disk space.

The preprocessing code converts the labelled flow CSVs into this project's seven-feature deployment schema. IPs, ports, timestamps, flow IDs, and datapath IDs are excluded from the model inputs and retained only as needed for group-aware split protection. The group-aware split will fail loudly rather than silently revert to a row split when it cannot keep groups separate.

## Required citation

Iman Sharafaldin, Arash Habibi Lashkari, Saqib Hakak, and Ali A. Ghorbani, “Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy,” IEEE 53rd International Carnahan Conference on Security Technology, 2019.
