"""Flow-level model: multi-dataset training, cross-dataset tests and significance tests.

Answers two review points:
  * "trained on CIC-DDoS2019 only"  -> train on CIC-DDoS2019, on CSE-CIC-IDS2018, and on both;
                                        test every model on BOTH datasets' group-disjoint holdouts
                                        (in-dataset and cross-dataset generalisation).
  * "the gap to KNN is too low"      -> McNemar test (paired, same test flows), cluster-free
                                        bootstrap CI of the balanced-accuracy difference,
                                        inference latency and model size.

Outputs  experiments/results/flow_multidataset/*.csv|json  and the deployable combined model in
artifacts/multidataset/ (same format as artifacts/production, loaded with DDOS_MODEL_DIR).
"""
from __future__ import annotations

import hashlib
import io
import json
import pickle
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.stats import chi2
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, f1_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ddos_ml.features import FEATURE_COLUMNS, canonicalize_frame  # noqa: E402
from ddos_ml.training import _pipeline, model_factories, split_indices  # noqa: E402

OUT = ROOT / "experiments" / "results" / "flow_multidataset"
ART = ROOT / "artifacts" / "multidataset"
P18 = ROOT / "data" / "processed" / "cic2018_flows.csv.gz"
P19 = ROOT / "data" / "processed" / "cicddos2019_flows.csv"
RNG = np.random.default_rng(42)
PER_CLASS = 20_000      # balanced training rows per class per dataset
TEST_ROWS = 60_000      # natural-ratio holdout rows per dataset

RENAME_18 = {"Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
             "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
             "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s"}


def prep_2018():
    if P18.exists():
        return pd.read_csv(P18)
    cols = ["Dst Port", "Protocol", "Timestamp", "Flow Duration"] + list(RENAME_18) + ["Label"]
    parts = []
    for f in sorted((ROOT / "data" / "raw" / "cic2018").glob("*.csv")):
        for chunk in pd.read_csv(f, usecols=cols, chunksize=400_000, low_memory=False, dtype=str):
            chunk = chunk[chunk["Label"] != "Label"].rename(columns=RENAME_18)
            ts = chunk["Timestamp"].str.slice(0, 16).fillna("")
            grp = (f.name + "|" + ts + "|" + chunk["Dst Port"].fillna("")).map(
                lambda v: hashlib.sha1(v.encode()).hexdigest()[:16])
            canon = canonicalize_frame(chunk.drop(columns=["Timestamp", "Dst Port"]).reset_index(drop=True))
            # canonicalize drops unlabelled rows; recompute group ids for the kept rows
            keep = chunk["Label"].str.lower().str.contains("benign|dos", regex=True, na=False).to_numpy()
            g = grp.to_numpy()[keep]
            if len(g) == len(canon):
                canon["group_id"] = g
            canon["source_file"] = f.name
            parts.append(canon)
        print("prepared", f.name, flush=True)
    df = pd.concat(parts, ignore_index=True)
    df.to_csv(P18, index=False)
    return df


def clean(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    h = pd.util.hash_pandas_object(df[FEATURE_COLUMNS], index=False).to_numpy()
    lab = df["label"].to_numpy()
    s = pd.DataFrame({"h": h, "y": lab}).groupby("h")["y"].nunique()
    bad = np.isin(h, s[s > 1].index.to_numpy())
    return df.loc[~bad].reset_index(drop=True), int(bad.sum())


def split(df, name):
    tr, te, how = split_indices(df["label"].reset_index(drop=True), df["group_id"].reset_index(drop=True))
    train, test = df.iloc[tr], df.iloc[te]
    parts = []
    for c in (0, 1):
        sub = train[train["label"] == c]
        parts.append(sub.sample(min(PER_CLASS, len(sub)), random_state=42))
    test = test.sample(min(TEST_ROWS, len(test)), random_state=42)
    print(f"{name}: train pool {len(train)}, balanced train {sum(len(p) for p in parts)}, test {len(test)} "
          f"(benign {int((test.label == 0).sum())}, attack {int((test.label == 1).sum())}) via {how}", flush=True)
    return pd.concat(parts), test


def metrics(y, p, prob):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"balanced_accuracy": balanced_accuracy_score(y, p), "attack_recall": tp / max(tp + fn, 1),
            "benign_recall": tn / max(tn + fp, 1), "fpr": fp / max(tn + fp, 1),
            "macro_f1": f1_score(y, p, average="macro"),
            "roc_auc": roc_auc_score(y, prob) if len(set(y)) > 1 else np.nan,
            "n_test": int(len(y)), "n_benign": int((y == 0).sum())}


def mcnemar(y, a, b):
    ca, cb = a == y, b == y
    n01 = int(np.sum(ca & ~cb))   # A right, B wrong
    n10 = int(np.sum(~ca & cb))
    stat = (abs(n01 - n10) - 1) ** 2 / max(n01 + n10, 1)
    return n01, n10, stat, float(chi2.sf(stat, 1))


def boot_diff(y, a, b, n=1000):
    """Bootstrap CI of balanced_accuracy(A) - balanced_accuracy(B), stratified by class."""
    i0, i1 = np.where(y == 0)[0], np.where(y == 1)[0]
    d = []
    for _ in range(n):
        s0, s1 = RNG.choice(i0, len(i0)), RNG.choice(i1, len(i1))
        ra = (np.mean(a[s0] == 0) + np.mean(a[s1] == 1)) / 2
        rb = (np.mean(b[s0] == 0) + np.mean(b[s1] == 1)) / 2
        d.append(ra - rb)
    return float(np.mean(d)), float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ART.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    d19 = pd.read_csv(P19)
    d18 = prep_2018()
    d19, amb19 = clean(d19)
    d18, amb18 = clean(d18)
    info = {"cic2019_rows": len(d19), "cic2019_benign": int((d19.label == 0).sum()), "cic2019_ambiguous_removed": amb19,
            "cic2018_rows": len(d18), "cic2018_benign": int((d18.label == 0).sum()), "cic2018_ambiguous_removed": amb18,
            "cic2018_benign_udp": int(((d18.label == 0) & (d18.protocol == 17)).sum()),
            "cic2019_benign_udp": int(((d19.label == 0) & (d19.protocol == 17)).sum())}
    print(info, flush=True)
    tr19, te19 = split(d19, "CIC-DDoS2019")
    tr18, te18 = split(d18, "CSE-CIC-IDS2018")
    trains = {"CIC-DDoS2019": tr19, "CSE-CIC-IDS2018": tr18, "Combined": pd.concat([tr19, tr18])}
    tests = {"CIC-DDoS2019": te19, "CSE-CIC-IDS2018": te18}
    rows, preds = [], {}
    for tname, tr in trains.items():
        for mname, est in model_factories().items():
            model = _pipeline(est)
            ts = time.time()
            model.fit(tr[FEATURE_COLUMNS], tr["label"])
            fit_s = time.time() - ts
            for sname, te in tests.items():
                X, y = te[FEATURE_COLUMNS], te["label"].to_numpy()
                ts = time.time()
                prob = model.predict_proba(X)[:, 1]
                inf_s = time.time() - ts
                p = (prob >= 0.5).astype(int)
                m = metrics(y, p, prob)
                m.update({"train": tname, "model": mname, "test": sname, "fit_s": round(fit_s, 2),
                          "infer_us_per_flow": round(1e6 * inf_s / len(y), 2)})
                rows.append(m)
                preds[(tname, mname, sname)] = p
            size = len(pickle.dumps(model))
            for r in rows[-2:]:
                r["model_bytes"] = size
            print(f"[{time.time()-t0:5.0f}s] train={tname:16s} {mname:22s} " + " | ".join(
                f"{r['test']}: BA={r['balanced_accuracy']:.4f} FPR={r['fpr']:.4f}" for r in rows[-2:]), flush=True)
            if tname == "Combined" and mname == "Hist Gradient Boosting":
                joblib.dump(model, ART / "hist_gradient_boosting.joblib")
    res = pd.DataFrame(rows)
    res.to_csv(OUT / "cross_dataset_metrics.csv", index=False)

    # Significance: deployed candidate (Combined training) HGB vs every other model, pooled test set
    y_all = np.concatenate([tests[s]["label"].to_numpy() for s in tests])
    sig = []
    for mname in model_factories():
        if mname == "Hist Gradient Boosting":
            continue
        a = np.concatenate([preds[("Combined", "Hist Gradient Boosting", s)] for s in tests])
        b = np.concatenate([preds[("Combined", mname, s)] for s in tests])
        n01, n10, stat, pv = mcnemar(y_all, a, b)
        mean, lo, hi = boot_diff(y_all, a, b)
        sig.append({"model_B": mname, "hgb_right_B_wrong": n01, "hgb_wrong_B_right": n10, "mcnemar_chi2": round(stat, 2),
                    "p_value": pv, "ba_diff_mean": mean, "ba_diff_lo": lo, "ba_diff_hi": hi})
    pd.DataFrame(sig).to_csv(OUT / "significance_combined.csv", index=False)

    meta = json.loads((ROOT / "artifacts" / "production" / "model_metadata.json").read_text())
    meta.update({"training_source": "CIC-DDoS2019 (01-12) + CSE-CIC-IDS2018 (4 days), balanced %d/class/dataset" % PER_CLASS,
                 "training_rows": int(len(trains["Combined"])), "datasets": info,
                 "ambiguous_rows_removed": amb19 + amb18})
    (ART / "model_metadata.json").write_text(json.dumps(meta, indent=2))
    (OUT / "dataset_info.json").write_text(json.dumps(info, indent=2))
    print(res.pivot_table(index=["train", "model"], columns="test", values=["balanced_accuracy", "fpr"]).round(4))
    print(pd.DataFrame(sig).round(5))
    print("done in %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
