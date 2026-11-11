# Patch validation record

Validated in the build environment on 2026-11-11.

- Python compilation (`python -m compileall -q scripts tests`): passed.
- Patch-specific automated tests: **7 passed**.
- `scripts/preprocess_extended.py --help`: passed.
- `scripts/train_extended.py --help`: passed.
- Extended schema: **35 numeric features**.
- End-to-end synthetic CICFlowMeter-shaped CSV smoke test: preprocessing completed; the gzip dataset and summary JSON were written; all seven classifier pipelines trained; JSON, model comparison CSV, attack-family CSV and candidate model files were created.
- Smoke-test checks: zero flow-group overlap and zero exact feature-signature overlap after training-only purge.
- Test sampler was explicitly tested to return the requested sample size while retaining class proportions.

This validates software behavior only. The real CIC-DDoS2019 files supplied by the user were not available in this build environment, so no real-data metrics are claimed. The synthetic fixture is not part of the patch ZIP and is not a substitute for the original dataset.
