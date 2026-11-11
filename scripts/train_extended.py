#!/usr/bin/env python3
"""Train/evaluate CICFlowMeter extended models with group/signature-aware holdout."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.metrics import (
    accuracy_score, balanced_accuracy_score, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
    average_precision_score,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.extended_common import FEATURE_COLUMNS

RANDOM_STATE = 42


def model_factories():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=140, max_depth=12, min_samples_split=25,
            min_samples_leaf=12, max_features=0.7,
            class_weight="balanced_subsample", n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=150, max_depth=14, min_samples_split=20,
            min_samples_leaf=10, max_features="sqrt",
            class_weight="balanced", n_jobs=-1,
            random_state=RANDOM_STATE,
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=10, min_samples_split=25, min_samples_leaf=12,
            class_weight="balanced", random_state=RANDOM_STATE,
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1200, class_weight="balanced", solver="lbfgs",
            random_state=RANDOM_STATE,
        ),
        "KNN": KNeighborsClassifier(
            n_neighbors=9, weights="distance", algorithm="kd_tree",
            leaf_size=40, n_jobs=-1,
        ),
        "Naive Bayes": GaussianNB(),
        "Hist Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=140, max_leaf_nodes=15, l2_regularization=2.0,
            learning_rate=0.08, random_state=RANDOM_STATE,
        ),
    }


def make_pipeline(estimator):
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median", add_indicator=True)),
        ("scaler", StandardScaler()),
        ("classifier", estimator),
    ])


def metrics(y_true, y_pred, y_prob):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    out = {
        "rows": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "attack_precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "attack_recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "attack_f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "benign_precision": float(precision_score(y_true, y_pred, pos_label=0, zero_division=0)),
        "benign_recall": float(recall_score(y_true, y_pred, pos_label=0, zero_division=0)),
        "benign_f1": float(f1_score(y_true, y_pred, pos_label=0, zero_division=0)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }
    try:
        out["roc_auc_attack"] = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        out["roc_auc_attack"] = None
    try:
        out["average_precision_attack"] = float(average_precision_score(y_true, y_prob))
    except ValueError:
        out["average_precision_attack"] = None
    try:
        out["average_precision_benign"] = float(average_precision_score(1 - np.asarray(y_true), 1 - y_prob))
    except ValueError:
        out["average_precision_benign"] = None
    return out


def split_and_purge(data: pd.DataFrame, feature_hash: np.ndarray, test_size: float = 0.20):
    """Group split; purge training signatures that appear in test; retain ambiguous test rows."""
    y = data["label"].reset_index(drop=True)
    groups = data["group_id"].astype("string").fillna("__MISSING_GROUP__").reset_index(drop=True)
    group_codes, unique_groups = pd.factorize(groups, sort=False)
    if len(unique_groups) < 3:
        raise ValueError("At least three distinct flow groups are required for a group holdout.")
    splitter = GroupShuffleSplit(n_splits=40, test_size=test_size, random_state=RANDOM_STATE)
    chosen = None
    for train_idx, test_idx in splitter.split(np.zeros(len(y)), y, group_codes):
        if y.iloc[train_idx].nunique() == 2 and y.iloc[test_idx].nunique() == 2:
            chosen = (train_idx, test_idx)
            break
    if chosen is None:
        raise ValueError("Unable to create a group-disjoint split containing both classes.")
    train_idx, test_idx = chosen

    group_overlap = np.intersect1d(np.unique(group_codes[train_idx]), np.unique(group_codes[test_idx])).size
    test_signatures = np.unique(feature_hash[test_idx])
    overlap_before = np.intersect1d(np.unique(feature_hash[train_idx]), test_signatures)
    keep_train = ~np.isin(feature_hash[train_idx], test_signatures)
    purged_idx = train_idx[~keep_train]
    train_idx = train_idx[keep_train]
    overlap_after = np.intersect1d(np.unique(feature_hash[train_idx]), test_signatures).size
    if group_overlap != 0 or overlap_after != 0:
        raise RuntimeError("Leakage purge failed: group or exact feature signature overlap remains.")
    return train_idx, test_idx, {
        "group_overlap": int(group_overlap),
        "feature_signature_overlap_before_purge": int(len(overlap_before)),
        "feature_signature_overlap_after_purge": int(overlap_after),
        "training_rows_purged_to_remove_test_signatures": int(len(purged_idx)),
        "train_group_count": int(np.unique(group_codes[train_idx]).size),
        "test_group_count": int(np.unique(group_codes[test_idx]).size),
    }


def sample_training(y: pd.Series, max_rows: int, seed: int = RANDOM_STATE):
    c0 = np.flatnonzero(y.to_numpy() == 0)
    c1 = np.flatnonzero(y.to_numpy() == 1)
    if min(len(c0), len(c1)) < 50:
        raise ValueError(f"Insufficient training class counts after leakage purge: benign={len(c0)}, attack={len(c1)}")
    per_class = min(len(c0), len(c1), max_rows // 2)
    rng = np.random.default_rng(seed)
    chosen = np.concatenate([
        rng.choice(c0, per_class, replace=False),
        rng.choice(c1, per_class, replace=False),
    ])
    rng.shuffle(chosen)
    return chosen


def stratified_test_sample(indices: np.ndarray, y: pd.Series, max_rows: int):
    if max_rows <= 0 or len(indices) <= max_rows:
        return indices
    sampled, _ = train_test_split(
        indices, train_size=max_rows, random_state=RANDOM_STATE,
        stratify=y.iloc[indices],
    )
    return np.asarray(sampled, dtype=int)


def main():
    parser = argparse.ArgumentParser(description="Train and compare extended CICFlowMeter classifiers.")
    parser.add_argument("--input", default="data/processed/cicddos2019_extended.csv.gz")
    parser.add_argument("--output-dir", default="artifacts/extended_features")
    parser.add_argument("--max-train-rows", type=int, default=60000,
                        help="Maximum balanced training rows; default 60000")
    parser.add_argument("--max-test-rows", type=int, default=100000,
                        help="Natural-prevalence test sample; use 0 for full grouped holdout")
    args = parser.parse_args()

    start = time.time()
    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Input not found: {path}. Run scripts/preprocess_extended.py first.")
    dtype = {c: "float32" for c in FEATURE_COLUMNS}
    dtype.update({"label": "int8", "group_id": "string", "attack_family": "string", "source_file": "string"})
    usecols = FEATURE_COLUMNS + ["label", "group_id", "attack_family", "source_file"]
    print(f"Loading {path} (numeric features as float32)...", flush=True)
    data = pd.read_csv(path, usecols=usecols, dtype=dtype, low_memory=False)
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data[data.label.isin([0, 1])].reset_index(drop=True)
    if data.label.nunique() != 2:
        raise ValueError("Input must contain both label 0=BENIGN and label 1=ATTACK.")

    X = data[FEATURE_COLUMNS]
    y = data.label.astype("int8")
    print("Computing exact feature signatures...", flush=True)
    signatures = pd.util.hash_pandas_object(X, index=False).to_numpy(dtype=np.uint64)
    sig_frame = pd.DataFrame({"signature": signatures, "label": y.to_numpy(dtype=np.int8)})
    conflicting = sig_frame.groupby("signature", sort=False)["label"].nunique()
    ambiguous_signatures = conflicting[conflicting > 1].index.to_numpy(dtype=np.uint64)
    ambiguous_mask = np.isin(signatures, ambiguous_signatures)

    train_idx, test_idx, split_report = split_and_purge(data, signatures)
    # Ambiguous signatures are not used for model fitting, but are retained in
    # the holdout so we can quantify how hard contradictory feature vectors are.
    train_before_ambiguity = len(train_idx)
    train_idx = train_idx[~ambiguous_mask[train_idx]]
    ambiguous_train_removed = train_before_ambiguity - len(train_idx)
    if data.label.iloc[train_idx].nunique() != 2:
        raise ValueError("Ambiguous-signature filtering removed one training class; inspect feature schema.")

    sampled_local = sample_training(data.label.iloc[train_idx].reset_index(drop=True), args.max_train_rows)
    sampled_train_idx = train_idx[sampled_local]
    sampled_test_idx = stratified_test_sample(test_idx, y, args.max_test_rows)
    X_train, y_train = X.iloc[sampled_train_idx], y.iloc[sampled_train_idx]
    X_test, y_test = X.iloc[sampled_test_idx], y.iloc[sampled_test_idx]
    test_ambiguous = ambiguous_mask[sampled_test_idx]

    out_dir = Path(args.output_dir)
    (out_dir / "models").mkdir(parents=True, exist_ok=True)
    report = {
        "experiment": "extended_CICFlowMeter_offline",
        "source_dataset": str(path),
        "demo_synthetic_data": False,
        "feature_profile": "extended_CICFlowMeter",
        "feature_count": len(FEATURE_COLUMNS),
        "feature_columns": FEATURE_COLUMNS,
        "excluded_from_features": ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp", "SimillarHTTP", "Inbound", "Label", "attack_family", "source_file", "group_id"],
        "unit_conversions": "Flow duration, IAT, Active and Idle values converted from microseconds to seconds.",
        "rows_loaded": int(len(data)),
        "class_counts_full": {str(int(k)): int(v) for k, v in y.value_counts().sort_index().items()},
        "attack_family_counts_full": {str(k): int(v) for k, v in data.attack_family.value_counts(dropna=False).items()},
        "ambiguous_feature_signature_count": int(len(ambiguous_signatures)),
        "ambiguous_rows_full": int(ambiguous_mask.sum()),
        "ambiguous_rows_in_test_sample": int(test_ambiguous.sum()),
        "ambiguous_rows_removed_from_training_partition": int(ambiguous_train_removed),
        "split_strategy": "GroupShuffleSplit by bidirectional 5-tuple group, followed by training-only purge of exact feature signatures found in test",
        **split_report,
        "train_rows_before_sampling": int(len(train_idx)),
        "test_holdout_rows_before_sampling": int(len(test_idx)),
        "train_rows": int(len(sampled_train_idx)),
        "test_rows": int(len(sampled_test_idx)),
        "train_class_counts": {str(int(k)): int(v) for k, v in y_train.value_counts().sort_index().items()},
        "test_class_counts": {str(int(k)): int(v) for k, v in y_test.value_counts().sort_index().items()},
        "training_sampling": "Equal-class random under-sampling from training partition only.",
        "test_sampling": "Natural-prevalence stratified-size sample from untouched group holdout.",
    }

    model_results = {}
    attack_family_results = []
    for name, estimator in model_factories().items():
        print(f"Training {name}...", flush=True)
        model = make_pipeline(clone(estimator))
        t0 = time.time()
        model.fit(X_train, y_train)
        train_pred = model.predict(X_train)
        test_pred = model.predict(X_test)
        train_prob = model.predict_proba(X_train)[:, 1]
        test_prob = model.predict_proba(X_test)[:, 1]
        train_m = metrics(y_train, train_pred, train_prob)
        test_m = metrics(y_test, test_pred, test_prob)
        model_results[name] = {
            "train": train_m,
            "test": test_m,
            "train_test_attack_f1_gap": train_m["attack_f1"] - test_m["attack_f1"],
            "train_test_benign_f1_gap": train_m["benign_f1"] - test_m["benign_f1"],
            "fit_seconds": round(time.time() - t0, 3),
        }
        # Separate unambiguous/ambiguous test metrics; retain the overall result.
        for subset_name, mask in (("unambiguous", ~test_ambiguous), ("ambiguous", test_ambiguous)):
            if mask.sum() and np.unique(y_test.to_numpy()[mask]).size == 2:
                subset_m = metrics(y_test.to_numpy()[mask], test_pred[mask], test_prob[mask])
            else:
                subset_m = None
            model_results[name].setdefault("test_subsets", {})[subset_name] = subset_m

        family_col = data.attack_family.iloc[sampled_test_idx].astype(str).to_numpy()
        for family in sorted(set(family_col)):
            if family.strip().upper() in {"BENIGN", "NORMAL", "LEGITIMATE"}:
                continue
            mask = family_col == family
            attack_family_results.append({
                "model": name,
                "attack_family": family,
                "rows": int(mask.sum()),
                "attack_recall": float(recall_score(y_test.to_numpy()[mask], test_pred[mask], pos_label=1, zero_division=0)),
                "attack_precision": float(precision_score(y_test.to_numpy()[mask], test_pred[mask], pos_label=1, zero_division=0)),
                "attack_f1": float(f1_score(y_test.to_numpy()[mask], test_pred[mask], pos_label=1, zero_division=0)),
            })

        safe = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        joblib.dump(model, out_dir / "models" / f"{safe}.joblib", compress=3)
        print(
            f"  balanced-acc={test_m['balanced_accuracy']:.4f} | macro-F1={test_m['macro_f1']:.4f} | "
            f"attack-recall={test_m['attack_recall']:.4f} | benign-recall={test_m['benign_recall']:.4f} | "
            f"FPR={test_m['false_positive_rate']:.4f} | fit={model_results[name]['fit_seconds']:.1f}s",
            flush=True,
        )
        del model

    report["models"] = model_results
    report["warning"] = (
        "Offline CICFlowMeter experiment only. This feature profile is not directly compatible with the current seven-feature Ryu controller. "
        "Do not use the model for live mitigation without matching telemetry and a separate deployment validation."
    )
    report["elapsed_seconds"] = round(time.time() - start, 3)
    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    summary_rows = []
    for name, result in model_results.items():
        summary_rows.append({
            "model": name,
            **result["test"],
            "train_attack_f1": result["train"]["attack_f1"],
            "train_benign_f1": result["train"]["benign_f1"],
            "train_test_attack_f1_gap": result["train_test_attack_f1_gap"],
            "train_test_benign_f1_gap": result["train_test_benign_f1_gap"],
            "fit_seconds": result["fit_seconds"],
        })
    pd.DataFrame(summary_rows).to_csv(out_dir / "model_comparison.csv", index=False)
    pd.DataFrame(attack_family_results).to_csv(out_dir / "attack_family_metrics.csv", index=False)
    print("\nCompleted extended-feature experiment.")
    print(f"Flow-group overlap: {split_report['group_overlap']}")
    print(f"Exact feature-signature overlap before purge: {split_report['feature_signature_overlap_before_purge']}")
    print(f"Exact feature-signature overlap after purge: {split_report['feature_signature_overlap_after_purge']}")
    print(f"Training rows purged to remove test signatures: {split_report['training_rows_purged_to_remove_test_signatures']:,}")
    print(f"Ambiguous signatures: {len(ambiguous_signatures):,}; ambiguous rows retained in test: {int(test_ambiguous.sum()):,}")
    print(f"Saved reports/models under: {out_dir}")
    print("NOTE: These extended CICFlowMeter models are offline research candidates, not drop-in Ryu models.")


if __name__ == "__main__":
    main()
