import numpy as np
import pandas as pd

from ddos_ml.features import FEATURE_COLUMNS, canonicalize_frame, live_flow_features


def test_openflow_schema_and_labels():
    raw = pd.DataFrame({
        "timestamp": [1, 2, 3],
        "datapath_id": [1, 1, 1],
        "flow_id": ["a", "b", "c"],
        "ip_src": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "ip_dst": ["10.0.0.4", "10.0.0.4", "10.0.0.4"],
        "ip_proto": [6, 17, 1],
        "flow_duration_sec": [1, 0, 2],
        "flow_duration_nsec": [0, 500_000_000, 0],
        "packet_count": [10, 50, 5],
        "byte_count": [1000, 5000, 300],
        "packet_count_per_second": [10, 100, 2.5],
        "byte_count_per_second": [1000, 10000, 150],
        "label": [0, 1, 0],
    })
    out = canonicalize_frame(raw)
    assert list(out.columns) == FEATURE_COLUMNS + ["label", "group_id"]
    assert out["label"].tolist() == [0, 1, 0]
    assert out.loc[1, "duration_sec"] == 0.5
    assert "ip_src" not in out.columns and "flow_id" not in out.columns


def test_cicflowmeter_fields_and_unrelated_attack_removed():
    raw = pd.DataFrame({
        "Flow ID": ["x", "y", "z"],
        "Source IP": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "Destination IP": ["4.4.4.4", "5.5.5.5", "6.6.6.6"],
        "Protocol": [6, 17, 6],
        "Flow Duration": [1_000_000, 500_000, 100_000],
        "Total Fwd Packets": [10, 20, 4],
        "Total Backward Packets": [5, 0, 2],
        "Total Length of Fwd Packets": [1000, 2000, 400],
        "Total Length of Bwd Packets": [500, 0, 200],
        "Flow Packets/s": [15, 40, 60],
        "Flow Bytes/s": [1500, 4000, 6000],
        "Label": ["BENIGN", "DrDoS_DNS", "PortScan"],
    })
    out = canonicalize_frame(raw)
    assert len(out) == 2
    assert out["label"].tolist() == [0, 1]
    assert np.isclose(out.loc[0, "duration_sec"], 1.0)
    assert out.loc[1, "packet_count"] == 20
    assert out.loc[1, "byte_count"] == 2000


def test_numeric_label_inversion_for_snt_dataset():
    raw = pd.DataFrame({
        "protocol": [6, 17], "duration_sec": [1, 1],
        "packet_count": [10, 20], "byte_count": [100, 200],
        "label": [1, 0],
    })
    out = canonicalize_frame(raw, numeric_label_meaning="one_is_benign")
    assert out["label"].tolist() == [0, 1]


def test_live_feature_schema_matches_training_features():
    live = live_flow_features({
        "ip_proto": 17, "duration_sec": 1, "duration_nsec": 500_000_000,
        "packet_count": 15, "byte_count": 1500,
    })
    assert list(live) == FEATURE_COLUMNS
    assert np.isclose(live["duration_sec"], 1.5)
    assert np.isclose(live["packet_rate"], 10)
    assert np.isclose(live["byte_rate"], 1000)


def test_reverse_direction_rows_share_group_for_leakage_control():
    raw = pd.DataFrame({
        "Source IP": ["10.0.0.1", "10.0.0.2"],
        "Destination IP": ["10.0.0.2", "10.0.0.1"],
        "Source Port": [12345, 443],
        "Destination Port": [443, 12345],
        "Protocol": [6, 6],
        "Flow Duration": [1_000_000, 1_000_000],
        "Total Fwd Packets": [10, 8],
        "Total Backward Packets": [8, 10],
        "Total Length of Fwd Packets": [1000, 800],
        "Total Length of Bwd Packets": [800, 1000],
        "Label": ["BENIGN", "BENIGN"],
    })
    out = canonicalize_frame(raw)
    assert len(out) == 2
    assert out.loc[0, "group_id"] == out.loc[1, "group_id"]
