# CIC-DDoS2019 training-pipeline patch

This patch updates the existing project without replacing your downloaded raw or processed dataset.

## Apply it

From the project root (`~/projects/ddos-cicddos2019-ready`), back up the files and extract this ZIP over the project:

```bash
cp ddos_ml/training.py ddos_ml/training.py.before_patch
cp ddos_ml/features.py ddos_ml/features.py.before_patch
cp tests/test_training.py tests/test_training.py.before_patch
unzip -o ~/Downloads/ddos-cicddos2019-training-patch.zip -d .
```

If the ZIP is saved somewhere else, change the ZIP path accordingly.

## What changed

- Makes a group-separated train/test split **before** sampling.
- Removes feature signatures that have contradictory labels (the reported 200 ambiguous feature combinations).
- Balances the training sample to 1:1 by class, sampling only from the training partition.
- Keeps the held-out test sample at its natural class prevalence, rather than balancing it.
- Limits the default training sample to 60,000 rows and test sample to 100,000 rows for a 16 GB RAM laptop.
- Reports attack and benign precision/recall/F1 separately, balanced accuracy, macro-F1, ROC-AUC, both-class average precision, and false-positive rate.
- Reports train/test flow-group overlap and duplicate feature-signature overlap explicitly.
- Fixes live inference for zero-duration flows: packet/byte rates and average packet size become missing and are handled by the model's fitted imputer, instead of producing artificially huge rates.

## Verify and train

```bash
source .venv/bin/activate
pytest -q

python scripts/train.py \
  --input data/processed/cicddos2019_flows.csv \
  --output-dir artifacts/production \
  --max-train-rows 60000 \
  --max-test-rows 100000
```

The command trains seven candidates on a balanced training sample. The held-out test sample is not balanced; it keeps the class prevalence present in the grouped test partition. Review `artifacts/production/metrics.csv` and `metrics.json` before choosing a deployment model. Random Forest is saved as the existing controller-compatible baseline, not automatically proven to be the best model.

The patch was tested with the included synthetic demo CSV and the project's automated test suite. It has **not** been run against your local 3.17-million-row CIC-DDoS2019 processed CSV, because that file is on your WSL machine and is not attached to this chat. Do not treat demo metrics as CIC-DDoS2019 results.
