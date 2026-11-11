"""Configuration loading for the hybrid detector (YAML, with safe defaults).

Mitigation is disabled and dry-run by default. Nothing is blocked unless the
configuration explicitly sets ``mitigation.enabled: true`` AND
``mitigation.dry_run: false``.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path

DEFAULTS = {
    "detection": {
        "enabled": True,
        "mode": "observation",        # observation | enforce
        "method": "hybrid",           # hybrid (linear window model) | rule
        "window_model": None,         # path relative to project root
        "source_model": None,
        "rule": {"min_pps": 1.0e9, "min_sources": 1, "min_new_flow_rate": None},
        "ml_threshold": 0.5,
        "confirm_k": 2,
        "confirm_n": 3,
        "recovery_windows": 3,
        "cooldown_windows": 3,
        "min_source_pps": 0.0,
        "min_source_pps_strict": False,     # True: floor also applies to sources opening new flows
        "source_min_attribute_pps": None,   # rate-based attribution fallback (None = ML only)
        "rate_requires_corroboration": False,  # fallback also needs flow-ML flag or new-flow churn
        "corroboration_ml_prob": 0.5,
        "corroboration_new_flows": 10.0,
    },
    "mitigation": {
        "mode": None,                 # DETECTION_ONLY | DRY_RUN | MITIGATION_ENABLED (overrides flags)
        "enabled": False,
        "dry_run": True,
        "priority": 200,
        "hard_timeout_seconds": 120,
        "max_rules_per_window": 20,
        "max_sources_per_destination": 32,
        "drop_rate_threshold_pps": 50.0,
        "allowlist": [],
        "kill_switch_file": "experiments/MITIGATION_DISABLE",
    },
    "monitoring": {
        "polling_interval_seconds": 5.0,
        "reply_timeout_seconds": 3.0,
        "ml_api_url": "http://127.0.0.1:8765/predict",
        "ml_api_timeout_seconds": 3.0,
        "ml_batch_size": 2000,
        "max_ml_flows_per_poll": 20000,
        "flow_expire_seconds": 30.0,
        "log_jsonl": None,            # per-poll JSONL telemetry (path)
    },
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def resolve_mitigation_mode(cfg: dict, env_mode: str | None = None) -> str:
    """Decide the startup mitigation mode and write it back into cfg.

    Precedence: env_mode (DDOS_MITIGATION_MODE) > mitigation.mode > legacy
    enabled/dry_run flags. MITIGATION_ENABLED additionally requires
    detection.mode == "enforce" (double opt-in, isolated lab only).
    """
    from ddos_ml.mitigation import MITIGATION_ENABLED, flags_from_mode, mode_from_flags, normalize_mode

    mit = cfg["mitigation"]
    if env_mode:
        mode = normalize_mode(env_mode)
    elif mit.get("mode"):
        mode = normalize_mode(mit["mode"])
    else:
        mode = mode_from_flags(bool(mit["enabled"]), bool(mit["dry_run"]))
    if mode == MITIGATION_ENABLED and cfg["detection"].get("mode") != "enforce":
        raise ValueError("Real mitigation requires detection.mode: enforce (explicit opt-in).")
    mit["enabled"], mit["dry_run"] = flags_from_mode(mode)
    mit["mode"] = mode
    return mode


def load_config(path: str | os.PathLike | None = None) -> dict:
    path = path or os.environ.get("DDOS_CONFIG")
    if not path:
        cfg = copy.deepcopy(DEFAULTS)
    else:
        import yaml  # PyYAML is available in both environments
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cfg = _merge(DEFAULTS, data)
    resolve_mitigation_mode(cfg, os.environ.get("DDOS_MITIGATION_MODE"))
    return cfg
