# Technical audit of the uploaded repository

## Findings in the uploaded archive

1. The top-level `FlowStatsfile.csv` was not present. The two files named `Codes/ml/FlowStatsfile.csv` and `Codes/controller/FlowStatsfile.csv` contained only the text `../../FlowStatsfile.csv`; they were broken link placeholders, not labelled data.
2. The README claimed a 10,000-flow dataset and a `generate_realistic_dataset.py` script. Neither existed in the upload.
3. Model scripts used positional CSV columns and trained on identifiers, IP-derived numeric strings, timestamps, and controller metadata.
4. Training used a row-wise random split, so repeated records of the same flow could occur in both partitions.
5. The live controller included a different number/order of columns from training and retrained from a local file at startup.
6. Rate calculations divided by `duration_sec` and `duration_nsec` independently; when seconds were zero but nanoseconds were non-zero the computed per-second rate was set to zero.
7. The Random Forest used only 10 unconstrained trees in the controller path, with no saved pipeline or train/test overfit-gap report.
8. The old README included headline accuracy values without a present dataset or reproducible run to support them.
9. The duplicated mitigation implementation could block a whole ingress port based on inference, even though the flow match did not consistently identify ingress ports.
10. `switch.py` and `switchm.py` tested `if buffer_id`, which mishandles a valid buffer ID of zero.

## Corrections in this package

- Added named-schema preprocessing for CICFlowMeter and OpenFlow collector CSVs.
- Added label normalization, numeric-label polarity option, NaN/Inf cleanup, duration/rate derivation, and hashed flow groups.
- Excluded timestamps, IP addresses, flow IDs, datapath IDs and ports from model features.
- Added group-aware evaluation, including bidirectional 5-tuple grouping where endpoint fields exist, train/test metrics, FPR, balanced accuracy, ROC-AUC, average precision, and comparison plots.
- Added a constrained Random Forest and serialized scikit-learn Pipeline shared with live inference.
- Updated Ryu collectors and the controller to use the same feature order and duration/rate formulas.
- Made mitigation opt-in, short-lived and exact-flow scoped.
- Removed the bundled virtual environment and repository internals from the new package.

## Validation status

The local validation performed for this package includes syntax compilation, preprocessing tests for both OpenFlow and CICFlowMeter-shaped rows, numeric label inversion, reverse-direction flow grouping, grouped split isolation, synthetic-demo training for all seven classifiers, model serialization/reload, and live-feature schema compatibility. The current automated suite passes 6 tests. The 10,000-row synthetic smoke test completed preprocessing, EDA, and seven-model comparison; its Random Forest test F1 was approximately 0.697 with an FPR of approximately 0.332. These synthetic metrics are included to demonstrate software execution only, not model effectiveness on real DDoS traffic.

The actual Ryu/Mininet/Open vSwitch integration was not run because Ryu, Mininet and Open vSwitch are not installed in the build environment. The recommended public CIC-DDoS2019 raw dataset was not present in the upload and is not bundled; the included demo dataset is synthetic and clearly marked as such.
