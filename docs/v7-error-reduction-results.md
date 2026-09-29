# v7 error reduction release

Artifact SHA-256: `2eed9cb24f21fbb453f18ea11924712b15d66fac0e8e8ab1fd4fcd75cf7d66ac`.

Default artifact: `backend/models/v7_error_reduction_final/trained_ensemble.joblib`. Previous deployed model: `backend/models/v7_advertiser_combined/trained_ensemble.joblib` (retained for rollback).

| Regression | Precision before / after | Recall before / after | F1 before / after | False flags before / after | Misses before / after |
|---|---:|---:|---:|---:|---:|
| new_rogue | 73.86% / 75.21% | 92.20% / 94.15% | 82.02% / 83.62% | 184 / 175 | 44 / 33 |
| new_beacon | N/A (negative only) | N/A (negative only) | N/A (negative only) | 1 / 1 | 0 / 0 |
| awid_diagnostic | 97.35% / 97.35% | 100.00% / 100.00% | 98.66% / 98.66% | 40 / 40 | 0 / 0 |
| test_metrics | 99.81% / 99.81% | 100.00% / 100.00% | 99.91% / 99.91% | 1 / 1 | 0 / 0 |
| negative_control | N/A (negative only) | N/A (negative only) | N/A (negative only) | 1080 / 928 | 0 / 0 |

RogueAP misses decrease 25%, RogueAP false flags decrease 4.9%, and Deauth-control false flags decrease 14.1%. No FP/FN count increases on any of the five regression sets. These improvements do not make the remaining errors negligible.

## What changed

- Sixteen training configurations: eight source-balanced binary/family boosting models, four Extra Trees models, and four boosting models with new short-window features. Models fit development training rows only.
- Five- and twenty-advertisement windows describe RSSI variation, RSSI displacement from the recent mean, beacon interval variation and sequence-gap behavior. They supplement the older 100-frame features. A five-second silence resets the short history.
- The final classifier uses the selected short-window confirmer with the previous v7. A causal nine-advertisement score window combines 75% current score with 25% recent mean, separately for each AP, and resets after five seconds. No future packets or labels enter inference.
- A zero confirmation threshold now safely means no confirmation gate; exact-zero classifier output no longer risks division by zero in experimental tree models.
- Conservative recovery tie-breaking was investigated and tested. The final release uses the validation-selected multiscale model plus history; the standalone family/recovery variants were rejected.

## Selection and limits

Training and threshold/history selection are separate. Each validation source must retain at least baseline true positives with no additional false positives. A frozen candidate is evaluated across five regression sources; release requires no FP/FN increase anywhere and strict reductions of both RogueAP error counts.

These are adaptively examined, same-session regression datasets. No regression rows were fitted or used for numerical threshold search, but observed failures informed later development. Therefore these are not independent-device accuracy estimates. Rejected candidates and their full metrics remain in backend/models. No labels were changed and no MAC/SSID identities were model inputs; BSSID only groups temporal history.

The score smoothing improves deployed decisions at the selected threshold but does not improve every ranking metric: AWID average precision decreases from approximately 0.9787 to 0.9699, although its FP/FN counts are unchanged. Scores are uncalibrated and must not be shown as probabilities.

The feature audit found all RogueAP validation mistakes on a BSSID carrying both normal and attack-period labels. Overlapping observable behavior and ambiguous attack-period identity labels limit further improvement. The model evaluates AP beacons/probe responses, not every Wi-Fi attack or every traffic packet.

## Deployment and testing

Restart the server and re-upload prior captures; stored results remain tied to their original artifact hash. Use WIDS_MODEL_PATH pointing to the previous model to roll back. The dashboard exposes updated benchmark and additional detection-check results. The GitHub-ready package is refreshed with code, model and expected upload outcomes.

Verification logs: `tmp/v7-error-reduction-final-tests.log`, `tmp/v7-error-reduction-api.log`, and `tmp/v7-error-reduction-new-captures.log`. Five labelled PCAPs are uploaded twice through the API; repeated prediction digests must match. Compatibility checks retain unsupported/non-Wi-Fi failures rather than treating them as benign.

## Inference timing

| Source | Previous median seconds | New median seconds |
|---|---:|---:|
| new_rogue | 0.0461 | 0.0676 |
| awid_diagnostic | 0.8210 | 1.9053 |

Timing includes cached-input classifier prediction and score-history processing, excludes parsing/feature construction, and was measured during concurrent work. The new confirmer and history add work; this release improves detection errors, not processing speed.

Final backend suite: 119 tests passed. All five labelled PCAP examples completed twice through the actual upload API with identical packet-result digests. Live localhost:8000 reports the released model hash.

Real-PCAP versus cached-regression parity passed on all five files: every extracted model feature, score and prediction matched. Seven external capture checks completed: five readable Wi-Fi inputs succeeded, and the non-Wi-Fi and invalid-signature files failed explicitly. Packaged-app smoke checks passed, including native PCAP upload.
