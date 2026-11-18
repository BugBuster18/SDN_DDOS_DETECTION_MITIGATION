"""Offline replay of source attribution on a detection-only session (who WOULD be blocked).

python experiments/large/attribution_replay.py large_test_det test_det
Compares the live configuration with and without baseline-aware attribution, per attack segment:
attackers attributed, legitimate clients attributed (collateral).
"""
import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ddos_ml.config import load_config  # noqa: E402
from ddos_ml.decision_engine import DecisionEngine  # noqa: E402
from ddos_ml.temporal_features import SOURCE_FEATURES, WINDOW_FEATURES  # noqa: E402


def run(campaign, session, factor):
    import os
    os.environ.pop("DDOS_MITIGATION_MODE", None)
    cfg = load_config(ROOT / "experiments/results/large" / session / "config.yaml")
    cfg["detection"]["window_model"] = "artifacts/experiments/large/window_model.json"
    cfg["detection"]["source_model"] = "artifacts/experiments/large/source_model.json"
    cfg["detection"]["attribution_baseline_factor"] = factor
    cfg["detection"]["new_source_corroborates"] = factor is not None
    cfg["detection"]["source_confirm_windows"] = int(os.environ.get("SRC_CONFIRM", "1"))
    cfg["mitigation"].update({"enabled": True, "dry_run": True})
    ses = json.loads((ROOT / "experiments/results/large" / session / "session.json").read_text())
    legit = {c["ip"] for c in ses["clients"].values()}
    t = ROOT / "experiments/results/raw" / campaign / "tables"
    dst = pd.read_csv(t / "dst_windows.csv")
    src = pd.read_csv(t / "src_windows.csv")
    eng = DecisionEngine.from_config(cfg, ROOT)   # one engine for the whole session (state carries over)
    out = []
    src_g = {k: g for k, g in src.groupby("ts")}
    for ts, w in dst.sort_values("ts").groupby("ts", sort=True):
        df = {r["dst"]: {f: r[f] for f in WINDOW_FEATURES} for r in w.to_dict("records")}
        sw = src_g.get(ts)
        sf = {} if sw is None else {(r["src"], r["dst"]): {f: r[f] for f in SOURCE_FEATURES} for r in sw.to_dict("records")}
        for d in eng.step(ts, df, sf):
            for s in d.attributed_sources:
                out.append((ts, d.dst, s))
    rows = []
    for g in ses["segments"]:
        atk = {e["src_ip"] for e in g["events"]}
        got = {(d, s) for ts, d, s in out if g["start"] - 1 <= ts <= g["end"] + 40}
        srcs = {s for d, s in got}
        rows.append({"kind": g["kind"], "attackers": len(atk - {"spoofed"}),
                     "attackers_attributed": len(srcs & atk), "legit_attributed": len(srcs & legit),
                     "legit_ips": ",".join(sorted(srcs & legit))[:60]})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    pd.set_option("display.width", 200)
    for f in (None, 3.0):
        print("=== baseline factor", f)
        print(run(sys.argv[1], sys.argv[2], f).to_string(index=False))
