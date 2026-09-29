# Refined v7: training, regression results and dashboard release

Trained 40 configurations across two passes, then compared 735 confirmation/recovery operating points. Selected `v7-refined-confirmed-ensemble` using validation data only.
Decision threshold: 0.50000000. SHA256: `92750d55527c8ca5a2558eb84d4e15700523aa8be1e5deda2142e7f2150fc7b8`.

The user requested refined v7 as the final local dashboard default. Integration is not a certification of production detection quality.
Original v7 and v6 are preserved. No hardware, live scanning or automatic mitigation changes were made.

**Outcome: marginal improvement only. RogueAP misses fell by one; false-alert counts are unchanged. The requested substantive reduction in both false alerts and misses was not achieved.**

## Like-for-like regression results

All counts below concern evaluated beacons/probe responses, not unique confirmed rogue APs.
Each original/refined pair uses identical rows and publisher labels. None of these test rows was fitted.
These captures were previously inspected; results are regression evidence, not fresh independent-device testing.
A precision-heavy candidate reduced false alerts but increased misses. A recall-constrained candidate increased false alerts sharply. Both were rejected as standalone defaults. The final model confirms original-v7 alerts with the behavior model and permits strong behavior scores to recover missed alerts. Its validation minimum family recall must match or exceed original v7. This is adaptive model development, not a blind final test.

| Capture | Version | Precision | Recall | F1 | False alerts | Missed targets |
|---|---|---:|---:|---:|---:|---:|
| RogueAP blocked capture | Original v7 | 72.28% | 85.99% | 78.54% | 186 / 379 | 79 / 564 |
| RogueAP blocked capture | Refined v7 | 72.32% | 86.17% | 78.64% | 186 / 379 | 78 / 564 |
| BeaconFlood blocked capture | Original v7 | N/A | N/A | N/A | 1 / 2499 | 0 / 0 |
| BeaconFlood blocked capture | Refined v7 | N/A | N/A | N/A | 1 / 2499 | 0 / 0 |
| AWID advertising diagnostic | Original v7 | 97.48% | 100.00% | 98.72% | 38 / 58442 | 0 / 1467 |
| AWID advertising diagnostic | Refined v7 | 97.48% | 100.00% | 98.72% | 38 / 58442 | 0 / 1467 |
| Earlier WPA3 evil-twin capture | Original v7 | 99.81% | 100.00% | 99.91% | 1 / 1129 | 0 / 527 |
| Earlier WPA3 evil-twin capture | Refined v7 | 99.81% | 100.00% | 99.91% | 1 / 1129 | 0 / 527 |
| Deauthentication negative control | Original v7 | N/A | N/A | N/A | 1283 / 8530 | 0 / 0 |
| Deauthentication negative control | Refined v7 | N/A | N/A | N/A | 1283 / 8530 | 0 / 0 |

## Inference timing

Median of three runs on the same extracted advertisements. Parsing and UI work are excluded.

| Capture | Original v7 | Refined v7 |
|---|---:|---:|
| RogueAP blocked capture | 0.0116 s | 0.0272 s |
| BeaconFlood blocked capture | 0.0149 s | 0.0368 s |
| AWID advertising diagnostic | 0.2028 s | 0.4728 s |
| Earlier WPA3 evil-twin capture | 0.0154 s | 0.0357 s |
| Deauthentication negative control | 0.0461 s | 0.1094 s |

## Remaining limitations

- Publisher RogueAP labels describe attack periods, including an AP also seen in normal periods; they do not certify AP identities.
- Training and blocked WPA3 tests share sessions/devices. Detection on unseen networks remains unproven.
- No alerts means no model detections within scope, not a safe network.

## What changed

- All normal development advertisements retained, instead of substantial negative undersampling.
- Compared positive weights, tree complexity, AP behavior, feature ablations and multiclass family classification.
- Validation selection explicitly penalizes false alerts and precision/recall deficits.
- Dashboard model insights include the difficult RogueAP and negative-control checks, with hash-verified metrics.
- Active artifact is `backend/models/final_v7/trained_ensemble.joblib`. Restart the server and re-upload old captures.

## Reproduction and rollback

Training requires the separately retained development caches. Output directories are write-once; preserve a release before retraining.
Training trials: `python -m backend.refine_v7`, `python -m backend.extend_v7_multiclass`, and `python -m backend.refine_v7_recall`.
Final selection: `python -m backend.select_confirmed_v7`. Evaluation: call `backend.evaluate_refined_v7.run` with `backend/models/final_v7`.
Set `WIDS_MODEL_PATH` to `backend/models/rogue_advertiser_v6/trained_ensemble.joblib` before starting the server to restore v6.
The original v7 remains at `backend/models/additional_captures_v7/trained_ensemble.joblib`.
See `refined-v7-protocol.md` and the saved JSON trial/evaluation reports for selection and data provenance.

## Software verification

The 105-test backend suite and the added confirmation-boundary test passed (106 distinct tests). The frontend production build succeeded. All five browser scenarios passed. All five packaged PCAPs completed twice through the upload API, with matching prediction digests. See `data/dashboard-round2-heldout/final-v7-upload-results.json` for exact counts and artifact hashes.
