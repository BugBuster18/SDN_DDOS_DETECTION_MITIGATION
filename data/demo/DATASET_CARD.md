# Demo dataset card

`demo_flows_raw.csv` is generated deterministically by `scripts/generate_demo_dataset.py`.

- Purpose: smoke-test CSV preprocessing, model fitting, evaluation, export, and controller feature compatibility.
- Labels: `0 = BENIGN`, `1 = DoS/DDoS`.
- Origin: synthetic distributions generated in code; not a packet capture and not a public benchmark.
- Noise/overlap: includes low-rate synthetic attack rows, benign burst rows, and a small label-flip rate to test non-trivial behavior.
- Use: software validation only. Never quote its metrics as measured real-network detection accuracy and do not use its model for live mitigation.
