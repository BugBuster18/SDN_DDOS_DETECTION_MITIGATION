"""HTML tables for the revised report, pooled over the two held-out large-testbed replicates."""
import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
P = ROOT / "experiments/results/processed"
REPS = ["large_test", "large_test2"]
NAMES = {"pps_threshold": "pps per destination", "src_entropy": "Source-IP entropy",
         "dst_entropy": "Destination-IP entropy", "flow_ml_only": "Flow-ML only (combined model)",
         "hybrid": "Proposed hybrid"}
CFG = {"pps_threshold": "pps_threshold k2/3", "src_entropy": "src_entropy k2/3", "dst_entropy": "dst_entropy k2/3",
       "flow_ml_only": "flow_ml_only k2/3", "hybrid": "hybrid k2/3", "hybrid_fast": "hybrid k2/3+fast"}


def main():
    wm = pd.concat([pd.read_csv(P / r / "window_metrics.csv").assign(rep=r) for r in REPS])
    wm = wm[wm.part == "all"]
    ev = pd.concat([pd.read_csv(P / r / "event_metrics.csv").assign(rep=r) for r in REPS])
    hours = ev.drop_duplicates(["rep", "scenario", "seed"]).groupby("config").hours.sum().max() if False else \
        ev[ev.config == "hybrid k2/3"].hours.sum()
    rows = []
    for key in ["pps_threshold", "src_entropy", "dst_entropy", "flow_ml_only", "hybrid", "hybrid_fast"]:
        m = "hybrid" if key == "hybrid_fast" else key
        w = wm[wm.method == m]
        tp, fp = w.tp.sum(), w.fp.sum()
        n_att = w.n_attack.sum()
        n_ben = (w.n - w.n_attack).sum()
        rec, fpr, prec = tp / n_att, fp / n_ben, tp / (tp + fp)
        f1 = 2 * prec * rec / (prec + rec)
        e = ev[(ev.config == CFG[key]) & (ev.has_attack == 1)]
        fa = ev[ev.config == CFG[key]].false_alarm_episodes.sum()
        name = NAMES[m] + (" (2-of-3 + fast confirmation)" if key == "hybrid_fast" else (" (2-of-3)" if key == "hybrid" else ""))
        rows.append((key, name, rec, fpr, prec, f1, int(e.detected.sum()), len(e), e.latency_s.clip(lower=0).mean(),
                     int(fa), fa / hours))
    html = []
    for key, name, rec, fpr, prec, f1, det, n, lat, fa, fah in rows:
        cls = ' class="hl"' if key == "hybrid_fast" else ""
        html.append(f'<tr{cls}><td>{name}</td><td class="n">{rec:.2f}</td><td class="n">{100*fpr:.2f}&nbsp;%</td>'
                    f'<td class="n">{prec:.2f}</td><td class="n">{f1:.2f}</td><td class="n">{det} / {n}</td>'
                    f'<td class="n">{lat:.1f}&nbsp;s</td><td class="n">{fa} ({fah:.0f}/h)</td></tr>')
    print("\n".join(html))
    # per attack type: detected reps and mean latency
    order = ["udp", "syn", "icmp", "lowrate", "pulsing", "spoof", "mixed", "protoswitch", "reattack"]
    label = {"udp": "UDP flood (40 sources)", "syn": "TCP SYN flood", "icmp": "ICMP flood",
             "lowrate": "Low-rate UDP (25&ndash;45 pps each)", "pulsing": "Pulsing (6&nbsp;s on / 10&nbsp;s off)",
             "spoof": "Spoofed sources", "mixed": "Mixed UDP + SYN", "protoswitch": "Protocol switching UDP&rarr;ICMP&rarr;SYN",
             "reattack": "Re-attack (first burst)"}
    cols = ["hybrid_fast", "dst_entropy", "pps_threshold", "src_entropy", "flow_ml_only"]
    print()
    means = {c: [] for c in cols}
    for s in order:
        cells = []
        for c in cols:
            e = ev[(ev.config == CFG[c]) & (ev.scenario == s)]
            d = int(e.detected.sum())
            lat = e.latency_s.dropna().clip(lower=0)
            means[c] += list(lat)
            cells.append(f'<td class="n">{"&ndash;" if d == 0 else ("%.1f" % lat.mean()) + ("" if d == 2 else " (1/2)")}</td>')
        print(f"<tr><td>{label[s]}</td>{''.join(cells)}</tr>")
    print('<tr class="hl"><td>Mean over detected</td>' + "".join(
        f'<td class="n">{pd.Series(means[c]).mean():.1f}</td>' for c in cols) + "</tr>")
    print("\nhours", hours, "windows", (wm[wm.method == "hybrid"].n).sum(), "attack windows", wm[wm.method == "hybrid"].n_attack.sum())


if __name__ == "__main__":
    main()
