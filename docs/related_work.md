# Related Work and Research-Gap Analysis

Verification note: entries marked **[full-text verified]** were read from the
publisher/PMC page (title, authors, DOI and reported numbers confirmed). Entries
marked **[bibliographic]** had their title/venue/DOI confirmed from indexing
records (DOAJ/IEEE/publisher) but the methods/metrics come from the
abstract/record, not a full read. Nothing here is invented; where a detail was
not confirmed it is left blank. Metrics are the authors' own reported figures.

## 1. Comparison matrix (primary references)

| # | Title (short) | Authors | Year | Venue / DOI | Dataset | Controller | Testbed | Features | Detector | Mitigation | Reported | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | A hybrid ML approach for detecting DDoS in SDN | Mahar, Aziz, Chakrabarti, Ahmed, Ladan, Javed | 2026 | Sci. Reports 16:6533, 10.1038/s41598-026-35458-w | Custom SDN (99,225×22), flow+port stats | Ryu | Mininet, single OVS | duration, pkt/byte counts, rates, TX/RX kbps, APPF, ABPF | **RF + XGBoost** hybrid | Proposed only (flow-drop/blacklist/rate-limit as future work) | Acc 99.36%, P/R/F1 0.99 | [full-text verified] |
| 2 | HSF: Hybrid SVM-RF for dual-plane DDoS detection & mitigation in SDN | Hirsi, Audah, Alhartomi, Salh, Ansa, Hamdi, Saputri, Ahmed, Farah | 2025 | IEEE Access 13:112303–112323, 10.1109/ACCESS.2025.3583712 | — | — | SDN (data+control plane) | data-plane + control-plane monitors | **SVM + RF** | Yes (framework) | Detection rate >99% both planes | [bibliographic] |
| 3 | Enhancing DDoS detection & mitigation in SDN using an ensemble online ML model | Alashhab, Zahid, Isyaku, Elnour, Nagmeldin, Abdelmaboud, Abdullah, Maiwada | 2024 | IEEE Access 12:51630–51649, 10.1109/ACCESS.2024.3384398 | Custom + CICDDoS2019, InSDN, slow-read | Ryu | Mininet | flow stats (online) | **Online ensemble** (incremental) | Yes | Detection rate 99.2% | [bibliographic] |
| 4 | An entropy and ML based approach for DDoS detection in SDN | Hassan, Abd El Reheem, Guirguis | 2024 | Sci. Reports 14:18159, 10.1038/s41598-024-67984-w | CIC-IDS2017 (+ CSE-CIC-2018, CICDDoS2019 bench) | — | — | per-user request entropy | **Shannon entropy + K-means (k=3)** | Blocks flagged users' requests | Acc 0.9994 / FPR 0.0 (2017) | [full-text verified] |
| 5 | A DDoS detection method based on feature engineering and ML in SDN | — (PMC10346601) | 2023 | Sensors, PMC10346601 | — | — | SDN | engineered flow features | ML ensemble | — | — | [bibliographic] |
| 6 | When Time Meets Space: entropy integration & dynamic threshold for adaptive DDoS detection in SDN | — | 2026 | arXiv:2608.15642 | CICDDoS2019 | Ryu 4.30 | Mininet 2.3.0, OF1.3 | spatial + temporal entropy | entropy + adaptive threshold | — | — | [bibliographic] |
| 7 | Entropy/deep-learning on suspicious OpenFlow switches | Narayan et al. | 2024 | J. Telecom. Inf. Tech. (JTIT) | Mininet-generated | Ryu | Mininet | OpenFlow stats → LSTM | entropy gate + **LSTM** | — | Acc 99.83% (LSTM) | [bibliographic] |
| 8 | Rényi-entropy low-rate DDoS detection | Siam et al. | 2025 | Research Square preprint | — | Ryu | Mininet-WiFi | packet-timing intervals | Rényi entropy | — | ~80% acc | [bibliographic, preprint] |
| 9 | Low-rate DDoS vs SDN controller, dynamic threshold | — | 2022 | Comput. Mater. Contin. (CMC) | — | — | SDN | controller-targeted stats | dynamic threshold | — | FPR 3.33–8.17% | [bibliographic] |
| 10 | Packet-based sliding-window, source-IP aggregation | — | 2024 | NOMS 2024 | — | — | — | inter-window source-IP stats | window statistics | — | — | [bibliographic] |
| 11 | Destination-IP entropy, dynamic window threshold | — | 2022 | J. Sci. Research (BHU) | — | — | SDN | destination-IP entropy | dynamic per-window threshold | — | — | [bibliographic] |
| 12 | Controller-targeted DDoS detection & mitigation in SD-IoV | Alemu Jorgi et al. | 2023 | ResearchGate / journal | — | — | SD-IoV | control-plane stats | ML | Yes | — | [bibliographic] |
| 13 | Evaluating ML models for DDoS detection in SDNs | — (Samsun Univ.) | 2024 | avesis record | InSDN etc. | — | SDN | flow features | ML comparison | — | — | [bibliographic] |
| 14 | Hybrid ML+DL for efficient DDoS detection in SDN | — (XJTLU/ITU) | 2024/25 | repository record | — | — | SDN | flow features | ML+DL hybrid | — | — | [bibliographic] |
| 15 | Feature selection (grey-wolf) XGBoost/RF/NB/HMM | Tonkal, Mgungile | 2026 | J. Adv. Inf. Tech. | LR-HR DDoS 2024, InSDN | — | — | selected flow features | XGBoost (best) | — | — | [bibliographic] |
| 16 | CNN-LSTM with RF/PCA/chi-square selection | Butt et al. | 2025/26 | CISTI 2025 / Springer LNNS | — | — | — | selected features | CNN-LSTM | — | — | [bibliographic] |

## 2. Thematic reading

- **Flow-level ML dominates and reports near-perfect accuracy.** Refs 1,3,7,13–16 all report ≥99% on their datasets. These numbers are produced on CSVs with known leakage risks (random splits, repeated flows, contradictory signatures). Our own audit found 1.3M contradictory 7-feature signatures in CIC-DDoS2019 — so high flow-level accuracy there is partly an artefact. This motivates our group-aware evaluation and our refusal to headline a leaked-accuracy figure.
- **Entropy / statistical detectors** (refs 4,6,8,9,11) are the main non-ML family. Their recognised weakness is **false positives under legitimate bursts / flash crowds** and **fixed-threshold brittleness**; several 2022–2026 works add dynamic or adaptive thresholds. Entropy is destination/ source *distributional* but is usually computed on packet or request counts, not on **counter-delta interval rates**.
- **Hybrid (ML + statistical / dual-plane)** (refs 1,2,3) is the current frontier. HSF (ref 2) monitors both planes; the RF-XGB hybrid (ref 1) explicitly leaves mitigation as future work and uses a single OVS (no multi-switch path de-duplication). The online ensemble (ref 3) adds incremental learning.
- **Mitigation + recovery is under-evaluated.** Most works stop at detection or describe mitigation without measuring legitimate-user impact, rollback, or recovery time. Ref 1 (the closest, same Ryu/OVS/Mininet stack) does not implement mitigation at all.

## 3. Research gap

Across refs 1–16, we did **not** find a work that combines **all** of:

1. **Counter-delta interval rates** (OpenFlow cumulative counters differenced across polls) rather than lifetime-average `bytes/duration` or packet-count entropy.
2. Explicit handling of **legitimate high-volume, large-packet UDP** as a first-class benign class, with evaluation under **benign/attack rate overlap** (our Scenario A-high and Scenario F), rather than assuming "high volume ⇒ attack".
3. **Destination-centric** aggregation with **per-source attribution** feeding **scoped, reversible** mitigation (block (src→victim, proto), not whole host), with measured **rollback and recovery**.
4. **Multi-switch path de-duplication** (the same conversation seen on several switches counted once) — most single-OVS testbeds never face this.
5. A transparent, logged **evidence vector** (per-feature contribution) behind every state transition and mitigation action.
6. Strict **train/test separation** where the flow model, the temporal models, their thresholds, and the final Mininet test runs are all disjoint.

The entropy family (4,6,11) overlaps with (2) conceptually but uses distributional entropy on counts, not counter-delta rates, and does not evaluate scoped reversible mitigation with recovery. The hybrid family (1,2,3) overlaps with the ML+statistics idea but on single-plane/flow features without counter-delta temporal rates or legitimate-large-UDP stress tests.

## 4. Recommended contribution (honest framing)

> A **false-positive-aware, destination-centric temporal** detection and
> **staged, reversible** mitigation framework for SDN, in which per-flow ML
> evidence is combined with **counter-delta multi-source traffic behaviour** and
> a transparent k-of-n state machine, **validated under concurrent legitimate
> high-volume UDP and DDoS workloads** with measured mitigation **recovery** and
> **control-plane overhead**.

This is a **systems + methodology** contribution, not a new ML algorithm. Its
defensibility rests on the experimental protocol (leakage control, benign/attack
overlap, counter-delta correctness, reproducible scenarios, recovery
measurement), not on beating 99.x% accuracy. If a reviewer requires an
algorithmic novelty, the strongest candidate is the **counter-delta temporal
feature set + per-source attribution model** and its demonstrated reduction of
large-packet-benign-UDP false positives relative to a flow-level baseline — a
claim we can support with the ablation study, or retract if the ablation does
not show it.

**Honesty check:** the individual ingredients (SDN+ML, Ryu+Mininet, entropy,
hybrid detection, OpenFlow mitigation) are each well-precedented. We do **not**
claim any single ingredient is novel. The contribution is the specific, fully
measured combination and the false-positive-focused evaluation. This is suitable
for a strong student project or a conference/workshop submission; a top-tier
journal would likely require a larger/physical testbed and more attack diversity
(see `docs/limitations.md`).
