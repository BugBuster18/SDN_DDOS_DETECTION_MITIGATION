# Dataset directory

- `raw/`: place original downloaded CICFlowMeter CSVs or your Mininet/Ryu captures here.
- `processed/`: output of `scripts/preprocess_dataset.py`; canonical schema has seven numeric features, a binary label, and a hashed `group_id` used only for group-aware evaluation.
- `demo/`: included synthetic smoke-test dataset and its dataset card. It is not a real traffic capture and its scores must not be used as research results.

## Recommended public dataset

Use **CIC-DDoS2019** for a DDoS-focused benchmark. The Canadian Institute for Cybersecurity documents benign traffic and multiple DDoS attack families, exports labelled flow CSVs via CICFlowMeter-V3, and permits redistribution with the required citation. Download the CSV archive from the official page:

https://www.unb.ca/cic/datasets/ddos-2019.html

The download page may request registration information. A public Hugging Face mirror with the 11 published per-attack CSVs is also available. Download a practical starter subset (about 1.44 GB) using:

```bash
pip install -r requirements-download.txt
python scripts/download_cicddos2019.py
```

Or fetch all attack CSVs (about 22.3 GB) with `python scripts/download_cicddos2019.py --all`. Then run:

```bash
python scripts/preprocess_dataset.py --input data/raw/CICDDoS2019/01-12 --output data/processed/cicddos2019_flows.csv
python scripts/train.py --input data/processed/cicddos2019_flows.csv --output-dir artifacts/production --max-rows 100000
```
The row cap can be removed for a full run. The trainer will not fall back to a row-wise split when a group key exists but cannot be separated safely.

Citation required by the dataset provider:

Iman Sharafaldin, Arash Habibi Lashkari, Saqib Hakak, and Ali A. Ghorbani, “Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy,” IEEE 53rd International Carnahan Conference on Security Technology, 2019.

An alternative is CIC-IDS2017. The preprocessing code keeps BENIGN and DoS/DDoS-like labels and ignores unrelated classes rather than silently treating every other attack type as DDoS:

https://www.unb.ca/cic/datasets/ids-2017.html

For datasets with numeric labels, check the source's convention before preprocessing. By default this project uses `0=BENIGN, 1=attack`. For the SNT-ddos dataset's published convention (benign=1, malicious=0), pass:

```bash
python scripts/preprocess_dataset.py --input /path/to/SNT-ddos.csv --numeric-label-meaning one_is_benign
```

The raw public datasets are not bundled because the uploaded repository did not contain them and the recommended CIC-DDoS2019 archive is distributed through its official download page. No external benchmark rows are fabricated or presented as real captures.
