"""Map CICFlowMeter and OpenFlow flow records to one leakage-resistant schema."""
from __future__ import annotations

import hashlib
import re
from typing import Iterable

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "protocol",
    "duration_sec",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
]
OUTPUT_COLUMNS = FEATURE_COLUMNS + ["label", "group_id"]


def _norm(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def _find_col(df: pd.DataFrame, aliases: Iterable[str]) -> str | None:
    lookup = {_norm(c): c for c in df.columns}
    for alias in aliases:
        key = _norm(alias)
        if key in lookup:
            return lookup[key]
    return None


def _numeric(series: pd.Series | None, index: pd.Index, default=np.nan) -> pd.Series:
    if series is None:
        return pd.Series(default, index=index, dtype="float64")
    return pd.to_numeric(series, errors="coerce").replace([np.inf, -np.inf], np.nan)


def _label_values(series: pd.Series, numeric_label_meaning: str) -> pd.Series:
    """Return binary labels: 0=BENIGN, 1=DoS/DDoS; drop unrelated classes."""
    if numeric_label_meaning not in {"zero_is_benign", "one_is_benign"}:
        raise ValueError("numeric_label_meaning must be zero_is_benign or one_is_benign")

    numeric = pd.to_numeric(series, errors="coerce")
    result = pd.Series(np.nan, index=series.index, dtype="float64")
    numeric_mask = numeric.isin([0, 1])
    if numeric_label_meaning == "zero_is_benign":
        result.loc[numeric_mask] = numeric.loc[numeric_mask]
    else:
        result.loc[numeric_mask] = 1 - numeric.loc[numeric_mask]

    text_mask = ~numeric_mask
    texts = series.loc[text_mask].astype(str).str.strip().str.lower()
    benign = texts.str.contains(r"\b(?:benign|normal|legitimate)\b", regex=True, na=False)
    attack = texts.str.contains(
        r"(?:ddos|\bdos\b|flood|syn|udplag|udp-lag|drdos|portmap|netbios|mssql|ldap|ntp|snmp|ssdp|tftp|webddos|hulk|slowloris|slowhttptest)",
        regex=True,
        na=False,
    )
    result.loc[text_mask & benign.reindex(series.index, fill_value=False)] = 0
    result.loc[text_mask & attack.reindex(series.index, fill_value=False)] = 1
    return result


def _hash_group(values: pd.Series) -> pd.Series:
    def digest(v: object) -> str:
        return hashlib.sha1(str(v).encode("utf-8", "ignore")).hexdigest()[:16]
    return values.fillna("missing").map(digest)


def canonicalize_frame(
    raw: pd.DataFrame,
    *,
    numeric_label_meaning: str = "zero_is_benign",
) -> pd.DataFrame:
    """Convert one labelled CSV chunk to the fixed model schema.

    IP addresses, timestamps, flow IDs, datapath IDs and ports are used at most
    for grouping/diagnostics; they are never passed as model features.
    CICFlowMeter's Flow Duration is microseconds. Explicit *_sec columns remain
    seconds; *_nsec is combined with duration seconds for OpenFlow records.
    """
    if raw.empty:
        return pd.DataFrame(columns=OUTPUT_COLUMNS)
    df = raw.copy()
    df.columns = [str(c).strip() for c in df.columns]

    label_col = _find_col(df, ["label", "class", "traffic_label", "attack_label", "is_attack"])
    if label_col is None:
        raise ValueError("No label column found. Expected Label, label, class, or is_attack.")
    labels = _label_values(df[label_col], numeric_label_meaning)

    protocol_col = _find_col(df, ["ip_proto", "protocol", "protocol_type", "ip protocol"])
    duration_sec_col = _find_col(df, ["flow_duration_sec", "duration_sec", "flow duration seconds"])
    duration_col = _find_col(df, ["flow duration", "flow_duration", "duration", "dur"])
    duration_nsec_col = _find_col(df, ["flow_duration_nsec", "duration_nsec"])

    if duration_sec_col:
        duration = _numeric(df[duration_sec_col], df.index)
        if duration_nsec_col:
            duration += _numeric(df[duration_nsec_col], df.index, 0).fillna(0) / 1_000_000_000.0
    elif duration_col:
        # CICFlowMeter uses microseconds; a generic `duration` field is assumed
        # to be seconds only when its name explicitly says so above.
        duration = _numeric(df[duration_col], df.index) / 1_000_000.0
    else:
        duration = pd.Series(np.nan, index=df.index, dtype="float64")

    packet_col = _find_col(df, ["packet_count", "total_packets", "packets", "tot_packets"])
    fwd_packets_col = _find_col(df, ["total_fwd_packets", "total_fwd_packet", "subflow_fwd_packets"])
    bwd_packets_col = _find_col(df, ["total_backward_packets", "total_bwd_packets", "total_bwd_packet", "subflow_bwd_packets"])
    if packet_col:
        packets = _numeric(df[packet_col], df.index)
    elif fwd_packets_col or bwd_packets_col:
        packets = _numeric(df[fwd_packets_col] if fwd_packets_col else None, df.index, 0).fillna(0)
        packets += _numeric(df[bwd_packets_col] if bwd_packets_col else None, df.index, 0).fillna(0)
    else:
        raise ValueError("Packet count not found. Expected packet_count or CICFlowMeter Fwd/Bwd packet fields.")

    byte_col = _find_col(df, ["byte_count", "total_bytes", "bytes"])
    fwd_bytes_col = _find_col(df, ["total_length_of_fwd_packets", "total_length_of_fwd_packet", "subflow_fwd_bytes"])
    bwd_bytes_col = _find_col(df, ["total_length_of_bwd_packets", "total_length_of_bwd_packet", "subflow_bwd_bytes"])
    if byte_col:
        byte_count = _numeric(df[byte_col], df.index)
    elif fwd_bytes_col or bwd_bytes_col:
        byte_count = _numeric(df[fwd_bytes_col] if fwd_bytes_col else None, df.index, 0).fillna(0)
        byte_count += _numeric(df[bwd_bytes_col] if bwd_bytes_col else None, df.index, 0).fillna(0)
    else:
        raise ValueError("Byte count not found. Expected byte_count or CICFlowMeter Fwd/Bwd byte fields.")

    packet_rate_col = _find_col(df, ["packet_count_per_second", "packet_rate", "flow_packets/s", "flow packets/s", "total packets/s"])
    byte_rate_col = _find_col(df, ["byte_count_per_second", "byte_rate", "flow_bytes/s", "flow bytes/s"])
    packet_rate = _numeric(df[packet_rate_col], df.index) if packet_rate_col else packets / duration.replace(0, np.nan)
    byte_rate = _numeric(df[byte_rate_col], df.index) if byte_rate_col else byte_count / duration.replace(0, np.nan)
    protocol = _numeric(df[protocol_col], df.index, -1).fillna(-1) if protocol_col else pd.Series(-1.0, index=df.index)
    avg_size = byte_count / packets.replace(0, np.nan)

    out = pd.DataFrame({
        "protocol": protocol,
        "duration_sec": duration,
        "packet_count": packets,
        "byte_count": byte_count,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "avg_packet_size": avg_size,
        "label": labels,
    }, index=df.index)

    # Guard against impossible/invalid counters. Remaining missing rates are
    # imputed inside the fitted sklearn Pipeline, never using test-set statistics.
    for col in FEATURE_COLUMNS:
        out[col] = pd.to_numeric(out[col], errors="coerce").replace([np.inf, -np.inf], np.nan)
    for col in ["duration_sec", "packet_count", "byte_count", "packet_rate", "byte_rate", "avg_packet_size"]:
        out.loc[out[col] < 0, col] = np.nan
    out.loc[out["protocol"] < -1, "protocol"] = -1
    out.loc[out["protocol"] > 255, "protocol"] = -1

    # Group repeated rows from the same flow/capture tuple to prevent the same
    # conversation leaking into both train and test splits.
    flow_id_col = _find_col(df, ["flow_id", "flowid", "flow_key"])
    src_ip_col = _find_col(df, ["ip_src", "src_ip", "source_ip", "source address"])
    dst_ip_col = _find_col(df, ["ip_dst", "dst_ip", "destination_ip", "destination address"])
    src_port_col = _find_col(df, ["tp_src", "src_port", "source_port"])
    dst_port_col = _find_col(df, ["tp_dst", "dst_port", "destination_port"])
    if flow_id_col:
        flow_ids = df[flow_id_col].astype(str).str.strip()
        has_flow_id = df[flow_id_col].notna() & ~flow_ids.str.lower().isin(["", "nan", "none", "null"])
    else:
        flow_ids = pd.Series("", index=df.index, dtype="object")
        has_flow_id = pd.Series(False, index=df.index)
    if src_ip_col and dst_ip_col:
        # Treat the 5-tuple as bidirectional for grouping: reverse-direction
        # records for the same conversation must not be split across train/test.
        src_endpoint = df[src_ip_col].fillna("").astype(str)
        dst_endpoint = df[dst_ip_col].fillna("").astype(str)
        if src_port_col:
            src_endpoint = src_endpoint + ":" + df[src_port_col].fillna("").astype(str)
        if dst_port_col:
            dst_endpoint = dst_endpoint + ":" + df[dst_port_col].fillna("").astype(str)
        ordered_endpoints = pd.DataFrame({"left": src_endpoint, "right": dst_endpoint}).apply(
            lambda row: "|".join(sorted((row["left"], row["right"]))), axis=1
        )
        if protocol_col:
            ordered_endpoints = ordered_endpoints + "|proto=" + df[protocol_col].fillna("-1").astype(str)
        group_seed = ordered_endpoints
    elif flow_id_col:
        # Flow IDs are useful only when source/destination fields are absent.
        group_seed = flow_ids.where(has_flow_id, out[FEATURE_COLUMNS].round(6).astype(str).agg("|".join, axis=1))
    else:
        group_seed = out[FEATURE_COLUMNS].round(6).astype(str).agg("|".join, axis=1)
    out["group_id"] = _hash_group(group_seed)

    # Keep only rows with a recognized binary label and at least one usable
    # traffic statistic; invalid feature values are imputed during training.
    valid = out["label"].isin([0, 1]) & out[["packet_count", "byte_count", "duration_sec"]].notna().any(axis=1)
    out = out.loc[valid, OUTPUT_COLUMNS].copy()
    out["label"] = out["label"].astype("int8")
    return out.reset_index(drop=True)


def live_flow_features(row: dict) -> dict:
    """Create exactly the seven training features from one Ryu flow-stat row.

    Zero-duration flows produce missing rates in preprocessing. Keep live
    inference consistent: return NaN so the saved pipeline's fitted imputer
    handles these rows, rather than inventing enormous rates using 1e-9 sec.
    """
    duration = float(row.get("duration_sec", 0) or 0) + float(row.get("duration_nsec", 0) or 0) / 1_000_000_000.0
    packets = float(row.get("packet_count", 0) or 0)
    byte_count = float(row.get("byte_count", 0) or 0)
    if duration > 0:
        packet_rate = packets / duration
        byte_rate = byte_count / duration
    else:
        packet_rate = np.nan
        byte_rate = np.nan
    avg_packet_size = byte_count / packets if packets > 0 else np.nan
    return {
        "protocol": float(row.get("ip_proto", -1) if row.get("ip_proto") is not None else -1),
        "duration_sec": duration,
        "packet_count": packets,
        "byte_count": byte_count,
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "avg_packet_size": avg_packet_size,
    }
