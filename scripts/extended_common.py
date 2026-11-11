"""Shared CICFlowMeter extended-feature schema and preprocessing helpers.

This is an offline CICFlowMeter experiment. Its feature vector is deliberately
separate from the seven-feature OpenFlow/Ryu-compatible production baseline.
"""
from __future__ import annotations

import re
from typing import Iterable

import numpy as np
import pandas as pd

# Raw CICFlowMeter column -> canonical numeric feature. Redundant columns such
# as Fwd Header Length.1, Avg Fwd Segment Size, and Subflow counters are omitted.
# Duration / IAT / Active / Idle fields are converted from microseconds to sec.
FEATURE_SPECS: dict[str, tuple[tuple[str, ...], float]] = {
    "protocol": (("Protocol",), 1.0),
    "flow_duration_sec": (("Flow Duration",), 1e-6),
    "total_fwd_packets": (("Total Fwd Packets",), 1.0),
    "total_backward_packets": (("Total Backward Packets",), 1.0),
    "total_length_fwd_packets": (("Total Length of Fwd Packets",), 1.0),
    "total_length_bwd_packets": (("Total Length of Bwd Packets",), 1.0),
    "fwd_packet_length_max": (("Fwd Packet Length Max",), 1.0),
    "fwd_packet_length_min": (("Fwd Packet Length Min",), 1.0),
    "fwd_packet_length_mean": (("Fwd Packet Length Mean",), 1.0),
    "fwd_packet_length_std": (("Fwd Packet Length Std",), 1.0),
    "bwd_packet_length_max": (("Bwd Packet Length Max",), 1.0),
    "bwd_packet_length_min": (("Bwd Packet Length Min",), 1.0),
    "bwd_packet_length_mean": (("Bwd Packet Length Mean",), 1.0),
    "bwd_packet_length_std": (("Bwd Packet Length Std",), 1.0),
    "flow_bytes_per_sec": (("Flow Bytes/s", "Flow Bytes/s "), 1.0),
    "flow_packets_per_sec": (("Flow Packets/s", "Flow Packets/s "), 1.0),
    "flow_iat_mean_sec": (("Flow IAT Mean",), 1e-6),
    "flow_iat_std_sec": (("Flow IAT Std",), 1e-6),
    "fwd_iat_mean_sec": (("Fwd IAT Mean",), 1e-6),
    "bwd_iat_mean_sec": (("Bwd IAT Mean",), 1e-6),
    "min_packet_length": (("Min Packet Length",), 1.0),
    "max_packet_length": (("Max Packet Length",), 1.0),
    "packet_length_mean": (("Packet Length Mean",), 1.0),
    "packet_length_std": (("Packet Length Std",), 1.0),
    "fin_flag_count": (("FIN Flag Count",), 1.0),
    "syn_flag_count": (("SYN Flag Count",), 1.0),
    "rst_flag_count": (("RST Flag Count",), 1.0),
    "psh_flag_count": (("PSH Flag Count",), 1.0),
    "ack_flag_count": (("ACK Flag Count",), 1.0),
    "urg_flag_count": (("URG Flag Count",), 1.0),
    "down_up_ratio": (("Down/Up Ratio",), 1.0),
    "init_win_bytes_forward": (("Init_Win_bytes_forward",), 1.0),
    "init_win_bytes_backward": (("Init_Win_bytes_backward",), 1.0),
    "active_mean_sec": (("Active Mean",), 1e-6),
    "idle_mean_sec": (("Idle Mean",), 1e-6),
}

FEATURE_COLUMNS = list(FEATURE_SPECS)
OUTPUT_COLUMNS = FEATURE_COLUMNS + ["label", "attack_family", "group_id", "source_file"]

# Raw identifiers are used only to build a group key, never as model inputs.
GROUP_COLUMNS = (
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Destination Port", "Protocol",
)
LABEL_COLUMN = "Label"


def normalize_column(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def map_columns(columns: Iterable[object]) -> dict[str, str]:
    """Map normalized header name to its original spelling."""
    return {normalize_column(c): str(c) for c in columns}


def resolve_raw_columns(columns: Iterable[object]) -> dict[str, str | None]:
    mapping = map_columns(columns)
    resolved: dict[str, str | None] = {}
    for feature, (aliases, _scale) in FEATURE_SPECS.items():
        resolved[feature] = next(
            (mapping[normalize_column(alias)] for alias in aliases
             if normalize_column(alias) in mapping),
            None,
        )
    for raw_name in GROUP_COLUMNS + (LABEL_COLUMN,):
        resolved[raw_name] = mapping.get(normalize_column(raw_name))
    return resolved


def _stable_group_ids(raw: pd.DataFrame, resolved: dict[str, str | None], features: pd.DataFrame) -> pd.Series:
    src_ip = resolved.get("Source IP")
    dst_ip = resolved.get("Destination IP")
    src_port = resolved.get("Source Port")
    dst_port = resolved.get("Destination Port")
    protocol_col = resolved.get("Protocol")
    flow_id = resolved.get("Flow ID")

    if src_ip and dst_ip and src_port and dst_port:
        src = raw[src_ip].fillna("").astype(str).str.strip() + ":" + raw[src_port].fillna("").astype(str).str.strip()
        dst = raw[dst_ip].fillna("").astype(str).str.strip() + ":" + raw[dst_port].fillna("").astype(str).str.strip()
        src_ip_values = raw[src_ip].fillna("").astype(str).str.strip()
        dst_ip_values = raw[dst_ip].fillna("").astype(str).str.strip()
        src_port_values = raw[src_port].fillna("").astype(str).str.strip()
        dst_port_values = raw[dst_port].fillna("").astype(str).str.strip()
        valid_tuple = (
            src_ip_values.ne("") & dst_ip_values.ne("")
            & src_port_values.ne("") & dst_port_values.ne("")
        )
        left = src.where(src <= dst, dst)
        right = dst.where(src <= dst, src)
        proto = raw[protocol_col].fillna("").astype(str).str.strip() if protocol_col else ""
        key = left + "|" + right + "|proto=" + proto
        if flow_id:
            fallback = raw[flow_id].fillna("").astype(str).str.strip()
            key = key.where(valid_tuple, "flow=" + fallback)
        else:
            sig = pd.util.hash_pandas_object(features, index=False).astype("uint64").astype(str)
            key = key.where(valid_tuple, "feature=" + sig)
    elif flow_id:
        key = "flow=" + raw[flow_id].fillna("").astype(str).str.strip()
    else:
        # Conservative fallback: identical feature signatures are kept together.
        key = "feature=" + pd.util.hash_pandas_object(features, index=False).astype("uint64").astype(str)

    return pd.util.hash_pandas_object(key, index=False).map(lambda x: f"{int(x):016x}")


def canonicalize_extended_chunk(raw: pd.DataFrame, source_file: str = "unknown") -> pd.DataFrame:
    """Convert a raw CICFlowMeter chunk to leakage-conscious extended features."""
    if raw.empty:
        return pd.DataFrame(columns=OUTPUT_COLUMNS)
    raw = raw.copy()
    raw.columns = [str(c).strip() for c in raw.columns]
    resolved = resolve_raw_columns(raw.columns)
    label_col = resolved.get(LABEL_COLUMN)
    if not label_col:
        raise ValueError("CICFlowMeter input needs a Label column")

    raw_labels = raw[label_col].astype("string").str.strip()
    raw_labels = raw_labels.fillna("")
    upper = raw_labels.str.upper()
    numeric = pd.to_numeric(raw_labels, errors="coerce")
    is_numeric_binary = numeric.isin([0, 1])
    is_benign = upper.str.contains(r"BENIGN|NORMAL|LEGITIMATE", regex=True, na=False)
    is_benign = is_benign | (is_numeric_binary & numeric.eq(0))
    is_attack = (raw_labels != "") & ~is_benign
    labels = pd.Series(np.where(is_benign, 0, np.where(is_attack, 1, -1)), index=raw.index, dtype="int8")

    features = pd.DataFrame(index=raw.index)
    for feature, (aliases, scale) in FEATURE_SPECS.items():
        raw_col = resolved.get(feature)
        if raw_col is None:
            features[feature] = np.nan
        else:
            values = pd.to_numeric(raw[raw_col], errors="coerce")
            values = values.replace([np.inf, -np.inf], np.nan)
            features[feature] = (values * scale).astype("float32")

    # Negative values are invalid for counters/timing/lengths. Initial TCP
    # window values can legitimately use -1 as an unavailable sentinel.
    allow_negative = {"init_win_bytes_forward", "init_win_bytes_backward"}
    for col in FEATURE_COLUMNS:
        if col not in allow_negative:
            features.loc[features[col] < 0, col] = np.nan
    features.loc[~features["protocol"].between(0, 255), "protocol"] = np.nan

    group_id = _stable_group_ids(raw, resolved, features)
    attack_family = raw_labels.str.replace(r"\s+", " ", regex=True).str.strip()
    valid = labels.isin([0, 1]) & features.notna().any(axis=1)
    result = features.loc[valid].copy()
    result["label"] = labels.loc[valid].astype("int8")
    result["attack_family"] = attack_family.loc[valid].astype(str)
    result["group_id"] = group_id.loc[valid].astype(str)
    result["source_file"] = str(source_file)
    return result[OUTPUT_COLUMNS].reset_index(drop=True)
