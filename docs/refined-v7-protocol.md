# V7 refinement and dashboard integration

## Scope

The requested release replaces the default offline dashboard detector with a refined v7.
PCAP and AWID CSV uploads remain supported. This release does not add live capture,
network enforcement, or confirmed AP identity claims. The original v7 and v6 artifacts
are preserved as rollback baselines.

## Fitting and selection

Use only the existing `train` partitions in `behavior_train`, `behavior_wpa3`,
`round2_rogue`, and `round2_beacon`. Retain all development advertisements instead
of discarding most normal AWID advertisements. Labels, BSSIDs, timestamps, source
identities and packet numbers are never model features. Retain beacon-flood and
other non-target attacks as negatives for the rogue-advertisement classifier.

Evaluate 24 configurations: three feature sets (portable, AP behavior, and an
ablation excluding absolute RSSI, channel and two length features), each with six
gradient-boosting configurations and two Extra Trees configurations. Positive
sample weights and tree complexity vary. Use seed 73 and four computation threads.

Before viewing regression results, add four multiclass boosting configurations
with AP behavior, 180 iterations, 15/31 leaves and positive weights 1/3. Preserve
the original attack-family labels during fitting and sum the target-family
probabilities for inference. These use the same validation selection objective,
bringing the total to 28 configurations.

### Recall-constrained follow-up

The first selected candidate reduced negative-control false alerts from 1,283 to
zero but increased RogueAP misses from 79 to 237. Reject it as the final model.
Preserve its artifact/reports in `backend/models/refined_v7` for the audit trail.
This observed regression motivates an adaptive second pass; it must not be
described as a blind test or fresh generalization evidence.

Train 12 further AP-behavior models in `backend/models/refined_v7_balanced`:
10 boosting configurations varying iterations (240/400/600), leaves (15/31/63)
and positive weights (1/3), plus two 240-tree Extra Trees configurations. Use the
same development partitions, retaining all negatives and excluding all test rows.
Require **at least 90% validation recall for each observed target family** and
then maximize mean source F1 minus 0.2 maximum source false-positive rate. This
constraint prevents a precision-only winner from suppressing too many detections.
Only the selected frozen winner is evaluated against the consumed test captures.
Total training configurations across both passes: 40.

### Final confirmation model

The recall-constrained winner increased false alerts and is rejected as a
standalone default. The final selection combines original v7 with the behavior
model from the first pass: accept an original alert only with behavior support,
or recover a detection when the behavior score exceeds a stronger threshold.
All confirmation/recovery thresholds are chosen on validation rows, retaining
the original v7 minimum target-family validation recall (84.98%). No additional
test rows are fitted. Store this model and its complete search in `final_v7`.

The resulting regression improvement is marginal: one fewer RogueAP miss,
with false-alert counts unchanged. This does not meet the desired substantive
reduction in both types of error. It is integrated as the user's requested v7
default, with known limits and rollback models, not certified production quality.

Select the model and threshold solely on existing validation partitions. The
objective is mean source F1 minus 0.6 times maximum source false-positive rate,
minus 0.25 times the minimum-source precision deficit below 90%, minus 0.25 times
the minimum-source recall deficit below 85%. Those targets are preferences in an
explicit utility function, not claims that the trained model satisfies them.

Compute permutation importance on validation data and freeze the final artifact
before evaluating regression captures. Save every trial, threshold, selected
configuration and SHA256. No test rows are fitted or used to select a threshold.

## Evaluation limits

The five existing evaluation caches are previously inspected captures. Results
are reproducible regression comparisons, not new independent evidence. The WPA3
splits share capture sessions/devices with training. RogueAP publisher labels
identify attack periods and do not independently confirm every transmitting AP
as malicious. Packet precision and recall must not be described as AP identity
accuracy. Do not relabel ambiguous packets to inflate scores.

## Integration verification

Run backend tests, the frontend build and browser integration tests, and upload
all five round-two PCAPs through the actual API with isolated state. Repeat those
uploads to verify deterministic predictions. Display additional regression
results in the model panel and hash-check all displayed benchmark reports.

Preserve the original models. Previously saved dashboard analyses must retain
their model hash and request reanalysis when the active model changes.
