# Rogue-AP scope correction

The SRAS objective is evasive rogue access points, MAC spoofing and beacon anomalies,
not exclusively discrimination of evil twins from all other impersonation attacks.
The [AWID paper](https://www.icsd.aegean.gr/publication_files/957971820.pdf) describes
impersonation attacks as introducing an additional AP; its taxonomy groups evil twin,
cafe-latte and hirte together. This experiment explicitly targets that category.
It does not label all attacks positive or claim every unauthorized AP is detectable.

Positive labels: `evil_twin`, `cafe_latte`, `hirte`. Other labels remain negative.
No raw identity or ground-truth field is an estimator input. Existing development
partitions and held-out captures remain separate; no test rows are fitted. Hirte is
absent from training and is reported individually on the diagnostic test.

Compare four RF/boosting candidates and two feature sets on development only.
Select thresholds requiring >=95% precision per source, >=90% recall for every
positive family present in validation, and <=0.01% false positives on normal traffic.
Freeze and hash the selected artifact before test scoring.

The earlier evil-twin-only 57.58% F1 is NOT the baseline for this broader target.
Rescore the old model and the candidate on identical rows with the same new labels.
Retain old artifacts/results and report each attack family's recall separately.
Available tests have been examined previously; they remain consumed diagnostics.

Deployment requires broad diagnostic precision and recall >=95% and >=90%,
each test positive family's recall >=90%, WPA3 F1 >=95%, and negative-control FPR
<=0.01%. If those checks fail, keep the previous default and report the limitation.

Packet-level impersonation activity is distinct from identifying a rogue advertiser.
Only positive beacon/probe-response frames with valid unicast BSSIDs enter the new
mode's AP feed. Data frames may identify victims/clients and are retained as activity
evidence rather than automatically naming their BSSID a rogue AP. BSSIDs and dataset
labels are not independently verified physical-device identities. Report advertising
BSSID coverage separately, with that limitation.

## Advertisement-only follow-up (v6)

The all-frame v5 experiment failed: AWID recall was 8.91%, including 4.20%
Hirte recall. It is rejected for deployment. Its advertising-frame diagnostic
motivated a separate, explicitly scoped classifier, v6. This is a task change,
not a claim that all-frame detection has been solved.

V6 trains and evaluates only beacons/probe responses (type 0, subtype 8/5),
while causal features retain preceding traffic context. Other frames are marked
not evaluated, not benign. The four development candidates and selection gates
above are unchanged. Deployment gates above apply to advertising rows only;
report excluded row counts and unique labeled/alerted BSSIDs alongside metrics.
The same previously consumed tests inform this scope choice, so results are
exploratory diagnostics, not an untouched final test or independent-device proof.
