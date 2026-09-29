# Rogue advertiser detection — software integration and measured results

The dashboard now defaults to `backend/models/rogue_advertiser_v6/trained_ensemble.joblib`.
SHA256: `f37d7a9947d0562583edc9f79dcc75c40f84f5d9e64f9437501f2608e11c5b9c`.
The previous v2 model remains available for rollback through `WIDS_MODEL_PATH`.

## What changed

The target is AP impersonation advertisements: evil twin, cafe-latte and Hirte,
following AWID's impersonation taxonomy. Classification applies to beacons and
probe responses only. All preceding traffic still contributes causal temporal
and AP behavior features. Non-advertising frames are **not evaluated**, not benign.
Only positive advertisements with valid unicast BSSIDs create suspected AP entries.
This detects suspicious behavior; it cannot establish administrative authorization.

Four forest/boosting candidates used two numeric feature sets. Development-only
threshold selection prioritized per-family recall with precision and normal-FPR
constraints. The selected model is histogram gradient boosting with AP behavior,
threshold 0.9990183341199669. Scores are model scores, not calibrated certainty.
Raw MACs, BSSIDs, labels and absolute timestamps are not estimator inputs.

The API, packet filters, JSON/CSV exports and dashboard carry the new scope.
Captures with no eligible frames show Unknown threat level. Saved captures retain
their model hash and display a reanalysis notice when the active model changes.

## Like-for-like advertising-frame comparison

Both models were scored on identical rows with the same broader positive labels.
The older evil-twin-only 57.58% F1 is not comparable to this task.

| AWID diagnostic, 59,909 advertisements | Previous v2 | Deployed v6 |
|---|---:|---:|
| Precision | 97.85% | 99.52% |
| Recall | 92.91% | 98.84% |
| F1 | 95.31% | 99.18% |
| Detected positive advertisements | 1,363 | 1,450 |
| Missed positive advertisements | 104 | 17 |
| False-positive advertisements | 30 | 7 |

V6 recall by family: evil twin 601/611 (98.36%), cafe-latte 372/379 (98.15%),
Hirte 477/477 (100%). Hirte was absent from training, but shares capture/device
conditions; this is not evidence of universal unseen-attack generalization.

AWID contains **one labeled positive advertising BSSID**. V6 detected it, but also
flagged one other BSSID. Thus high frame precision does not imply high AP-level
precision: this small diagnostic has 1 true and 1 false AP alert. BSSIDs are not
independently verified physical devices.

WPA3 blocked holdout: 1,656 advertisements, 527 positive; F1 99.62% -> 100%,
misses 4 -> 0, false positives 0 -> 0. Its one labeled positive BSSID was found.
Negative control: 8,530 advertisements, false positives 6 -> 0; zero AP alerts.
Negative-only F1/recall are not meaningful.

The AWID source had 575,643 frames (515,734 context-only); WPA3 holdout had 96,675
(95,019 context-only); negative control had 722,606 (714,076 context-only).

Classifier-only median scoring time on AWID advertisements was 0.218s for v6 vs
0.105s for v2, three repetitions. This excludes parsing and feature extraction;
v6 is not claimed to improve throughput. Raw deployment features matched cached
evaluation features for 2,000 consecutive AWID CSV frames.

## Limitations and rejected work

The preceding all-frame v5 model was rejected: AWID broad-target recall 8.91%,
F1 15.52%, with most Hirte data frames missed. Its reports remain in `rogue_v5`.
V6 does not fix arbitrary data-frame classification; it explicitly focuses on
AP advertising evidence. A capture without relevant advertising frames cannot
support this detector, and a quiet or behaviorally indistinguishable rogue AP
may be missed. This is a research detector, not guaranteed rogue discovery.

All test captures were previously examined. The scope change was informed by
those diagnostics, although fitting and threshold selection used development
partitions only. These results are exploratory and **not an untouched final
test**. WPA3 partitions share sessions/devices; AWID has very limited positive
advertiser identity diversity. New independently labeled capture sessions and
devices are needed to establish generalization. No hardware changes or automatic
network enforcement were added. Evasion tags remain heuristic evidence.

## Reproduction

From the project root, use the existing audited feature caches:

```powershell
.venv/Scripts/python.exe -m backend.train_rogue backend/models/new_run --advertisements
.venv/Scripts/python.exe -m backend.finalize_precision backend/models/new_run
.venv/Scripts/python.exe -m backend.benchmark_detection backend/models/new_run/trained_ensemble.joblib data/processed/behavior_awid_test.joblib backend/models/new_run/awid_diagnostic.json --baseline backend/models/detection_multisource_v2/trained_ensemble.joblib
```

Repeat evaluation with `behavior_wpa3_holdout.joblib` and `behavior_negative.joblib`.
The artifact directory contains experiments, protocol, frozen hash, validation
tradeoffs, three full comparisons, prediction arrays, and AP coverage counts.
See [the protocol](rogue-detection-protocol.md) for the recorded task change.

Validation: 94 existing backend tests plus 3 new scope/provenance tests passed;
all 5 Playwright browser scenarios passed; production frontend build passed.
The running local API's model hash and scope were verified against this artifact.
