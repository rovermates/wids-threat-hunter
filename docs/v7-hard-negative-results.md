# V7 hard-negative training and full-pipeline evaluation

Date: 2026-09-29

## Outcome

The requested low-error target has **not been reached**. The deployed dashboard
model is unchanged. The best new development-selected candidate reduced misses
but increased incorrect RogueAP advertisement flags and failed the release gate.
No rejected candidate was put into production.

| Advertisement evaluation | Current incorrect flags | Candidate incorrect flags | Current misses | Candidate misses |
|---|---:|---:|---:|---:|
| RogueAP regression (943 ads; 564 positive) | 175 | 194 | 33 | 27 |
| AWID regression (59,909 ads) | 40 | 40 | 0 | 0 |
| Earlier WPA3 regression (1,656 ads) | 1 | 1 | 0 | 0 |
| Beacon flooding control (2,499 ads) | 1 | 0 | N/A | N/A |
| Deauthentication control (8,530 ads) | 928 | 538 | N/A | N/A |
| New disassociation reserved blocks (1,257 ads) | 94 | 62 | N/A | N/A |
| New aggregation complete capture (11,221 ads) | 773 | 438 | N/A | N/A |

RogueAP precision declined from 75.21% to 73.46%; recall increased from 94.15%
to 95.21%; F1 declined from 83.62% to 82.93%. Its candidate false-positive rate
is 194/379 = 51.19% and false-negative rate is 27/564 = 4.79%. Low misses alone
do not establish a useful detector. Control sets contain no positive rogue
advertisements and cannot establish recall.

## Work performed

- Downloaded Disasso.pcap, Disasso.csv, Aggreattack.pcap and Aggreattack.csv
  (about 284 MB) from the publisher's WPA3 dataset version 2. Verified all four
  files against publisher SHA-256 hashes and lengths. Source:
  https://data.mendeley.com/datasets/cxx5t5nw7z/2 (CC BY 4.0).
- Matched advertisement packet numbers and packet lengths to CSV labels;
  retained original label names. Disassociation supplied 4,187 training and
  1,293 validation advertisements, all labelled normal. Its disassociation and
  deauthentication attack frames are outside advertisement-only model scope.
- Reserved 1,257 disassociation advertisements and the complete aggregation
  capture from fitting and threshold selection. Features reset at temporal
  split boundaries, with one-second guard regions.
- Trained nine CatBoost variants on existing development sources, then six on
  development sources plus the new disassociation negatives. Varied depth and
  source weighting. Selected confirmation/recovery settings and, in the second
  round, decision thresholds using validation data through the full causal
  score-history pipeline. No MAC addresses or capture timestamps were fed as
  numeric identity predictors.
- The first round left RogueAP errors unchanged, removed the one beacon false
  flag and reduced deauthentication false flags from 928 to 917. It was rejected.
- Froze the second candidate before evaluating regression and new control sets.
  The new control results were not used to refit this candidate.

## Reproducibility

Current artifact: `backend/models/v7_error_reduction_final/trained_ensemble.joblib`

SHA-256: `2eed9cb24f21fbb453f18ea11924712b15d66fac0e8e8ab1fd4fcd75cf7d66ac`

Rejected candidate: `backend/models/v7_hard_negatives/trained_ensemble.joblib`

SHA-256: `8e76d182a3a22efddea1508c0203e72a190657ba0ee0205b8f2d5e777d4030be`

The candidate folder contains protocol.json, experiments.json, FROZEN.json,
release_decision.json, five regression reports and fresh_disasso.json /
fresh_aggregation.json. Reports include confusion counts, inference timing and
prediction arrays. Acquisition provenance is in
`data/raw/wpa3/hard-negative-acquisition.json`.

Training-only dependency: `backend/requirements-training.txt`.

Validation: all 122 backend tests passed, plus two training threshold-selection
tests. The new tests check exact agreement between vectorized selection and
streaming score history, reset/missing-ID behavior, preservation of disabled
refinement scores, and threshold constraints against brute-force enumeration.
No fresh browser deployment test was warranted because no model was deployed.

## What the evidence permits

The five older regression datasets have been inspected repeatedly and are
adaptive regression evidence, not independent generalization estimates. New
disassociation blocks share a session with training. The untouched aggregation
capture is a new negative control from the same publisher/testbed, not an
independent positive rogue-AP test.

Publisher labels describe packet/scenario categories; they do not provide an
independently verified authorized/rogue AP inventory over time. Existing audits
found the same BSSID with normal and rogue labels in different periods. This
does not prove labels are wrong, but does limit conclusions about physical AP
identity. A low packet error count is also not an AP-level detection rate.

Further reliable improvement needs distinguishing evidence: more independently
labelled positive rogue sessions and benign sessions with similar behavior,
plus an audit of per-AP labels and available security/clock behavior. Repeating
threshold searches on the already inspected tests would make reported numbers
less trustworthy. The next iteration must preserve a new final evaluation set;
these newly evaluated controls are now consumed.
