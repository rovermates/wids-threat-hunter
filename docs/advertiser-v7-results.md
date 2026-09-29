# v7 advertiser correction: measured results

Default: `backend/models/v7_advertiser_combined/trained_ensemble.joblib`. Previous `final_v7` is retained for rollback.

| Regression | Precision before / after | Recall before / after | F1 before / after | False flags before / after | Misses before / after |
|---|---:|---:|---:|---:|---:|
| new_rogue | 72.32% / 73.86% | 86.17% / 92.20% | 78.64% / 82.02% | 186 / 184 | 78 / 44 |
| awid_diagnostic | 97.48% / 97.35% | 100.00% / 100.00% | 98.72% / 98.66% | 38 / 40 | 0 / 0 |
| test_metrics | 99.81% / 99.81% | 100.00% / 100.00% | 99.91% / 99.91% | 1 / 1 | 0 / 0 |
| new_beacon | N/A (negative only) | N/A (negative only) | N/A (negative only) | 1 / 1 | 0 / 0 |
| negative_control | N/A (negative only) | N/A (negative only) | N/A (negative only) | 1283 / 1080 | 0 / 0 |

RogueAP missed advertisements decrease 43.6%; Deauth false flags decrease 15.8%. AWID increases by two false flags. The revision is deployed for the overall improvement, not because it dominates every dataset.

These are previously examined capture regressions. No test rows were fitted; model and threshold selection used development validation. Prior regression findings informed development, so these are not independent final-test results.

Sixteen training trials tested corrected and hybrid features. Standalone precision and recall candidates were rejected. The final confirmation/recovery search required no source-level validation false-positive increase or true-positive decrease before maximizing mean F1.

| Inference-only timing | Previous median seconds | New median seconds |
|---|---:|---:|
| new_rogue | 0.0301 | 0.0469 |
| awid_diagnostic | 0.4909 | 0.8131 |

Timings exclude parsing and feature extraction and were measured during concurrent work. The additional model costs compute; no throughput improvement is claimed.

See [investigation and dataset audit](advertiser-feature-investigation.md) for reproduced defects, new downloads and label limitations. Full experiment and regression JSON files are alongside each model artifact.

## Verification

109 distinct backend tests passed after updating the default-model expectation; the seven-test model suite was rerun after that change. Five labelled PCAP examples passed two actual API uploads each with matching packet-result hashes. New independent captures were also tested through the upload API, with unsupported/corrupt inputs rejected explicitly. The running localhost dashboard reports the deployed artifact hash; existing results request reanalysis.

All seven new capture upload checks completed: five readable Wi-Fi captures succeeded, the non-Wi-Fi capture and invalid-signature capture failed explicitly. New-source expected counts are in `data/dashboard-independent-round3/manifest.json`. The shareable package also passed its sample and native-PCAP smoke checks.
