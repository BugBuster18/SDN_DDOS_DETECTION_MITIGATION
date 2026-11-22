"""Deep Review round 2: offline analyses on logged telemetry (no new emulation).

 (a) CUSUM baseline: S_d(t) = max(0, S_d(t-1) + s_d(t) - eta); alarm while S_d >= h. h is chosen on the
     calibration session so CUSUM's false-alarm episodes per hour match the proposed 2-of-3+fast rule's.
 (b) Per-role thresholds: eta_server / eta_client = (1 - eps) quantiles of calibration benign windows of
     servers (h198-h200) and clients separately (eps = 0.3 % each), 2-of-3 confirmation.
 (c) Fast path from a stricter quantile eps_f = 0.1 % (so eta_f > eta by construction), both calibrations.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments" / "large"))
import large_eval as E  # noqa: E402

SERVERS = {"10.0.0.198", "10.0.0.199", "10.0.0.200"}
EPS, EPS_F = 0.003, 0.001


def load(camp, model):
    t = E.RAW / camp / "tables"
    d = E.add_baseline_scores(pd.read_csv(t / "dst_windows.csv"), pd.read_csv(t / "src_windows.csv"), model)
    man = {}
    for dd in (E.RAW / camp).iterdir():
        if (dd / "manifest.json").exists():
            m = json.loads((dd / "manifest.json").read_text())
            man[(m["scenario"], m["seed"])] = m
    return d, man


def cusum_events(d, man, eta, h):
    rows = []
    for (scn, seed), g in d.groupby(["scenario", "seed"]):
        m = man[(scn, seed)]
        atk = [(e["epoch_start"], e["epoch_start"] + e["duration"]) for e in m["events"] if e.get("role") == "attack"]
        a0, a1 = (min(a for a, _ in atk), max(b for _, b in atk)) if atk else (None, None)
        S, on, first, fa = {}, {}, None, 0
        for ts, w in g.sort_values("ts").groupby("ts", sort=True):
            for dst, s in zip(w.dst, w.hybrid):
                S[dst] = max(0.0, S.get(dst, 0.0) + s - eta)
                alarm = S[dst] >= h
                if alarm and not on.get(dst):
                    if atk and dst == m["victim_ip"] and a0 - 0.1 <= ts <= a1 + 12:
                        pass
                    else:
                        fa += 1
                if alarm and atk and dst == m["victim_ip"] and a0 - 0.1 <= ts <= a1 + 4 and first is None:
                    first = ts
                on[dst] = alarm
            for dst in set(S) - set(w.dst):      # silent destination: decay to zero
                S[dst] = 0.0
                on[dst] = False
        rows.append({"has_attack": int(bool(atk)), "detected": int(first is not None) if atk else None,
                     "latency_s": (first - a0) if first is not None else None, "episode_s": (a1 - a0) if atk else None,
                     "false_alarm_episodes": fa, "hours": (g.ts.max() - g.ts.min() + 2) / 3600})
    return pd.DataFrame(rows)


def summ(ev, label):
    a = ev[ev.has_attack == 1]
    lat = a.latency_s.clip(lower=0)
    return {"config": label, "detected": f"{int(a.detected.sum())}/{len(a)}", "lat": round(lat.mean(), 2),
            "lat_pen": round(lat.fillna(a.episode_s).mean(), 2),
            "FA_per_h": round(ev.false_alarm_episodes.sum() / ev.hours.sum(), 1)}


def run(calib, model_dir, tests, tag):
    model = json.loads((ROOT / model_dir / "window_model.json").read_text())
    eta = model["threshold"]
    cd, cman = load(calib, model)
    ben = cd[cd.label == 0]
    out = []
    # proposed reference on calibration (for CUSUM h matching)
    ref_cfg = {"p": ("hybrid", 2, 3, 0.97)}
    ref = E.event_metrics(cd, {"hybrid": eta}, cman, ref_cfg)
    target = ref.false_alarm_episodes.sum() / ref.hours.sum()
    best = None
    for h in np.arange(0.02, 3.0, 0.02):
        r = cusum_events(cd, cman, eta, h)
        fah = r.false_alarm_episodes.sum() / r.hours.sum()
        if fah <= target:
            best = h
            break
    # per-role and quantile-fast thresholds
    eta_srv = E.thr_at_fpr(ben[ben.dst.isin(SERVERS)].hybrid, EPS)
    eta_cli = E.thr_at_fpr(ben[~ben.dst.isin(SERVERS)].hybrid, EPS)
    eta_f = max(E.thr_at_fpr(ben.hybrid, EPS_F), eta + 1e-6)
    E.METHODS["hybrid_role"] = "hybrid_role"
    res = {"tag": tag, "eta": round(eta, 4), "eta_f_quantile": round(eta_f, 4), "eta_server": round(eta_srv, 4),
           "eta_client": round(eta_cli, 4), "cusum_h": None if best is None else round(float(best), 2),
           "calib_FA_per_h_target": round(target, 1)}
    rows = []
    role_rows = []
    for camp in tests:
        d, man = load(camp, model)
        d["hybrid_role"] = d.hybrid / np.where(d.dst.isin(SERVERS), eta_srv, eta_cli)
        cfg = {"proposed 2-of-3 + fast 0.97": ("hybrid", 2, 3, 0.97),
               "proposed 2-of-3 + quantile fast": ("hybrid", 2, 3, eta_f),
               "per-role thresholds 2-of-3": ("hybrid_role", 2, 3, None)}
        ev = E.event_metrics(d, {"hybrid": eta, "hybrid_role": 1.0}, man, cfg)
        for c in cfg:
            rows.append(dict(summ(ev[ev.config == c], c), session=camp))
        if best is not None:
            rows.append(dict(summ(cusum_events(d, man, eta, best), "CUSUM on s_d (h=%.2f)" % best), session=camp))
        for name, col, thr in [("pooled", "hybrid", eta), ("per-role", "hybrid_role", 1.0)]:
            p = d[col] >= thr
            y = d.label == 1
            tp, fp, fn = int((p & y).sum()), int((p & ~y).sum()), int((~p & y).sum())
            vb = (~y) & (d.dst == "10.0.0.200")
            role_rows.append({"session": camp, "threshold": name, "recall": round(tp / max(tp + fn, 1), 3),
                              "precision": round(tp / max(tp + fp, 1), 3), "f1": round(2 * tp / max(2 * tp + fp + fn, 1), 3),
                              "victim_benign_fpr": round(float(p[vb].mean()), 3),
                              "client_fpr": round(float(p[(~y) & ~d.dst.isin(SERVERS)].mean()), 4)})
    print(json.dumps(res))
    print(pd.DataFrame(rows).to_string(index=False))
    print(pd.DataFrame(role_rows).to_string(index=False))
    return res, pd.DataFrame(rows), pd.DataFrame(role_rows)


if __name__ == "__main__":
    out = ROOT / "experiments" / "results" / "processed" / "round2"
    out.mkdir(parents=True, exist_ok=True)
    tests = ["large_test_det", "large_test_det2", "large_test3_det"]
    for calib, md, tag in [("large_calib", "artifacts/experiments/large", "calib50"),
                           ("large_calib25", "artifacts/experiments/large25", "calib25")]:
        res, ev, role = run(calib, md, tests, tag)
        json.dump(res, open(out / f"{tag}_thresholds.json", "w"), indent=1)
        ev.to_csv(out / f"{tag}_events.csv", index=False)
        role.to_csv(out / f"{tag}_roles.csv", index=False)
