# Extended CICFlowMeter experiment patch

This patch adds a **separate offline research pipeline** for the original CIC-DDoS2019 CICFlowMeter CSVs. It does not replace the existing seven-feature SDN/Ryu-compatible baseline or overwrite `artifacts/production`.

## Why there are two feature profiles

- Existing baseline: seven features currently extracted by the Ryu/OpenFlow path.
- Extended profile: 35 numeric CICFlowMeter features for offline experiments. The current Ryu flow-stat collector does not provide all of these measurements, so the extended model is **not** a drop-in live controller model.

The extended profile excludes Flow ID, IP addresses, ports, timestamps, `SimillarHTTP`, `Inbound`, labels and source metadata from model inputs. It also omits confirmed duplicate source columns (`Fwd Header Length.1`, `Avg Fwd Segment Size`, and Subflow counters that matched their original counters in the user's diagnostic).

## Apply

Extract this patch into the project root, preserving the `scripts/` and `tests/` directories. It adds:

- `scripts/extended_common.py`
- `scripts/preprocess_extended.py`
- `scripts/train_extended.py`
- `tests/test_extended_pipeline.py`

## Install/test

Use the existing activated virtual environment:

```bash
pytest -q tests/test_extended_pipeline.py
```

## Preprocess existing raw files

No additional dataset download is needed. The three current original CSVs are used:

```bash
python scripts/preprocess_extended.py \
  --input data/raw/CICDDoS2019/01-12 \
  --output data/processed/cicddos2019_extended.csv.gz \
  --chunksize 100000
```

The output is gzip-compressed to reduce disk use. It includes numeric features, `label` (0 benign, 1 attack), `attack_family`, `group_id`, and `source_file`. Identifiers are not included as model features.

Duration, IAT, Active and Idle measurements are converted from microseconds to seconds. Infinite rate values become missing and are imputed inside each model pipeline using training-only statistics.

## Train and evaluate

```bash
python scripts/train_extended.py \
  --input data/processed/cicddos2019_extended.csv.gz \
  --output-dir artifacts/extended_features \
  --max-train-rows 60000 \
  --max-test-rows 100000
```

Use `--max-test-rows 0` to evaluate the full group-separated holdout. KNN can become substantially slower with a full test set; use the default 100,000-row sample for the first run.

The trainer:

1. Splits by `group_id` before any sampling.
2. Detects exact feature signatures that have conflicting labels.
3. Purges from the **training partition only** any signatures that also occur in the test partition, enforcing zero exact-signature overlap.
4. Excludes contradictory signatures from model fitting but keeps their test records for a separately reported ambiguous subset.
5. Balances only the training sample by random under-sampling.
6. Leaves test prevalence natural and reports attack-family recall/precision/F1.
7. Saves each classifier separately under `artifacts/extended_features/models/` and writes JSON/CSV reports.

## Outputs

- `metrics.json`: full experiment metadata and train/test metrics.
- `model_comparison.csv`: main classifier comparison.
- `attack_family_metrics.csv`: test metrics by original family label.
- `models/*.joblib`: individual candidate pipelines.

## Important limitations

- This is an offline CICFlowMeter model experiment. It is not directly compatible with the current seven-feature Ryu controller.
- Exact feature signatures are hashed across the selected extended feature vector. Group splitting and training-only signature purging are both reported.
- A test subset with contradictory feature signatures is retained and reported separately; it is not silently removed from the test set.
- The existing baseline is preserved. Compare its metrics only after applying a comparable evaluation protocol; otherwise the two experiment reports are not directly comparable.
- No model should be used for automatic SDN mitigation until the feature schema, threshold, telemetry mapping, and live Mininet behavior have been validated.
