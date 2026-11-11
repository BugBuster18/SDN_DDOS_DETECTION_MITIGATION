import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from scripts.extended_common import FEATURE_COLUMNS, canonicalize_extended_chunk
from scripts.train_extended import split_and_purge, stratified_test_sample


def make_raw(labels=("BENIGN", "Syn", "DrDoS_NTP")):
    rows = []
    for i, label in enumerate(labels):
        rows.append({
            "Flow ID": f"10.0.0.{i}-1234-10.0.1.{i}-80-6",
            "Source IP": f"10.0.0.{i}",
            "Source Port": 1234,
            "Destination IP": f"10.0.1.{i}",
            "Destination Port": 80,
            "Protocol": 6,
            "Timestamp": "2019-01-01 00:00:00",
            "Flow Duration": 1_000_000,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 1000,
            "Total Length of Bwd Packets": 200,
            "Fwd Packet Length Max": 100,
            "Fwd Packet Length Min": 100,
            "Fwd Packet Length Mean": 100,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 100,
            "Bwd Packet Length Min": 100,
            "Bwd Packet Length Mean": 100,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": 1200,
            "Flow Packets/s": 12,
            "Flow IAT Mean": 1000,
            "Flow IAT Std": 100,
            "Flow IAT Max": 2000,
            "Flow IAT Min": 100,
            "Fwd IAT Mean": 1000,
            "Fwd IAT Std": 100,
            "Bwd IAT Mean": 1000,
            "Bwd IAT Std": 100,
            "Fwd Packets/s": 10,
            "Bwd Packets/s": 2,
            "Fwd Header Length": 40,
            "Fwd Header Length.1": 40,
            "Bwd Header Length": 8,
            "Min Packet Length": 100,
            "Max Packet Length": 100,
            "Packet Length Mean": 100,
            "Packet Length Std": 0,
            "FIN Flag Count": 0,
            "SYN Flag Count": 1,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 1,
            "URG Flag Count": 0,
            "Down/Up Ratio": 0.2,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 4096,
            "act_data_pkt_fwd": 9,
            "min_seg_size_forward": 20,
            "Active Mean": 1000,
            "Active Std": 10,
            "Idle Mean": 1000,
            "Idle Std": 10,
            "Avg Fwd Segment Size": 100,
            "Subflow Fwd Packets": 10,
            "Subflow Fwd Bytes": 1000,
            "Label": label,
        })
    return pd.DataFrame(rows)


def test_extended_schema_excludes_identifiers_and_duplicate_features():
    forbidden = {"Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp", "Label", "attack_family", "group_id"}
    assert len(FEATURE_COLUMNS) == 35
    assert not forbidden.intersection(FEATURE_COLUMNS)
    assert "fwd_header_length" not in FEATURE_COLUMNS


def test_canonicalization_maps_labels_and_converts_microseconds():
    frame = make_raw()
    result = canonicalize_extended_chunk(frame, "unit.csv")
    assert result.label.tolist() == [0, 1, 1]
    assert result.loc[0, "flow_duration_sec"] == 1.0
    assert result.loc[0, "flow_iat_mean_sec"] == 0.001
    assert result.loc[0, "active_mean_sec"] == 0.001
    assert result.attack_family.tolist() == ["BENIGN", "Syn", "DrDoS_NTP"]
    assert result.source_file.eq("unit.csv").all()


def test_canonicalization_does_not_emit_duplicate_or_identity_columns():
    result = canonicalize_extended_chunk(make_raw(), "unit.csv")
    for col in ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Timestamp", "Fwd Header Length.1", "Avg Fwd Segment Size", "Subflow Fwd Packets"]:
        assert col not in result.columns


def test_group_hash_is_bidirectional():
    raw = make_raw(("BENIGN", "BENIGN"))
    raw.loc[1, ["Source IP", "Destination IP"]] = raw.loc[0, ["Destination IP", "Source IP"]].values
    raw.loc[1, ["Source Port", "Destination Port"]] = raw.loc[0, ["Destination Port", "Source Port"]].values
    result = canonicalize_extended_chunk(raw)
    assert result.group_id.iloc[0] == result.group_id.iloc[1]


def test_split_and_purge_has_zero_group_and_signature_overlap():
    n_groups = 100
    per_group = 4
    rows = []
    for g in range(n_groups):
        label = g % 2
        for j in range(per_group):
            rows.append({
                "label": label,
                "group_id": f"g{g}",
                "feature": float(g),
            })
    df = pd.DataFrame(rows)
    sig = pd.util.hash_pandas_object(df[["feature"]], index=False).to_numpy(dtype=np.uint64)
    train, test, report = split_and_purge(df, sig)
    assert report["group_overlap"] == 0
    assert report["feature_signature_overlap_after_purge"] == 0
    assert len(train) > 0 and len(test) > 0
    assert not (set(df.group_id.iloc[train]) & set(df.group_id.iloc[test]))


def test_signature_purge_removes_training_duplicates_only():
    rows = []
    for group_no in range(200):
        pair_no = group_no // 2
        label = pair_no % 2
        rows.append({
            "label": label,
            "group_id": f"g{group_no}",
            "feature": float(pair_no),
        })
    df = pd.DataFrame(rows)
    sig = pd.util.hash_pandas_object(df[["feature"]], index=False).to_numpy(dtype=np.uint64)
    train, test, report = split_and_purge(df, sig)
    assert report["feature_signature_overlap_before_purge"] > 0
    assert report["feature_signature_overlap_after_purge"] == 0
    assert report["training_rows_purged_to_remove_test_signatures"] > 0
    assert len(test) > 0
    assert len(train) > 0


def test_test_sampler_returns_requested_size_and_keeps_class_prevalence():
    y = pd.Series([0] * 100 + [1] * 900)
    indices = np.arange(len(y))
    sampled = stratified_test_sample(indices, y, 200)
    assert len(sampled) == 200
    sampled_counts = y.iloc[sampled].value_counts(normalize=True)
    assert abs(float(sampled_counts.loc[0]) - 0.10) < 0.02
