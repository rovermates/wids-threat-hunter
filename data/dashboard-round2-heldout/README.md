# Current default: v7 error reduction release

Run `start.cmd` and upload these files individually. Each file was tested twice, with identical packet-result hashes. Re-upload previously saved analyses.

| File | Processed | Evaluated advertisements | Flagged | Suspected APs |
|---|---:|---:|---:|---:|
| round2_rogue-attack-block24.pcap | 14541 | 119 | 118 | 2 |
| round2_rogue-attack-second-block14.pcap | 13421 | 353 | 321 | 2 |
| round2_rogue-normal-block4.pcap | 16049 | 133 | 31 | 1 |
| round2_beacon-attack-block9.pcap | 20019 | 1428 | 0 | 0 |
| round2_beacon-normal-block4.pcap | 24451 | 187 | 1 | 1 |

The normal-period false alert remains, but flagged advertisements decrease from 34 to 31. Full before/after results: `docs/v7-error-reduction-results.md`. Everything below is historical comparison, not the active model.
---
# New held-out PCAP tests - 29 September 2026

## Start here

1. For the existing detector, open your normal dashboard on http://127.0.0.1:8000.
2. To try the newly trained experimental model, extract this supplemental ZIP into your project root (the folder containing backend and frontend), then run start-experimental-v7.cmd. Open http://127.0.0.1:8001. Keep the terminal running. Existing Python environment and built dashboard are required.
3. Upload the .pcap files in data/dashboard-round2-heldout/ one at a time. Do not upload the .labels.csv sidecars; they are for evaluation, not AWID-format inputs.
4. Compare with the table below. Clear filters first and wait for analysis completion.

Experimental v7 was NOT promoted: it improves recall against new publisher labels but produces excessive false alerts on normal/negative-control traffic. Port 8001 uses separate local state; the default model and port-8000 results remain unchanged. This supplemental pack can also be added to the GitHub-ready local distribution.

## Expected results from actual upload API tests

All five files completed with both models. Active v6 was tested twice per file and every packet-result hash matched. Experimental v7 was tested once per file. No Wi-Fi interface was opened; all tests read saved PCAP files.

| PCAP filename | Processed / evaluated | v6 flagged / suspected APs | v7 flagged / suspected APs |
|---|---:|---:|---:|
| round2_rogue-attack-block24.pcap | 14,541 / 119 | 63 / 1 | 113 / 2 |
| round2_rogue-attack-second-block14.pcap | 13,421 / 353 | 88 / 1 | 290 / 2 |
| round2_rogue-normal-block4.pcap | 16,049 / 133 | 0 / 0 | 34 / 1 |
| round2_beacon-attack-block9.pcap | 20,019 / 1,428 | 0 / 0 | 0 / 0 |
| round2_beacon-normal-block4.pcap | 24,451 / 187 | 0 / 0 | 1 / 1 |

Counts mean model predictions, not confirmed rogue identities. The RogueAP normal block is a useful false-alert check: v7 flags an AP despite the normal publisher labels. Beacon-flood traffic is a separate attack family, not a positive target for this impersonation classifier; zero rogue alerts does not imply there was no beacon-flood attack.

The Accuracy/F1 strip shows stored benchmark metrics, not accuracy on these uploads. Evaluation covers only beacons/probe responses; remaining packets provide context. Both model versions use the same narrow scope.

## New data and split provenance

These real packet bytes come from newly downloaded RogueAP and BeaconFlood scenarios in WPA3 Attacks Dataset v2. The five upload files are new contiguous excerpts from heldout 30-second blocks, with one-second guards. They were selected before model inference from labels/size, not from favorable predictions. None of their rows was fitted or used to choose thresholds. However, training/validation/test share capture sessions and devices; these are not independent-device tests.

The original sources exceed the default 64 MB upload limit. Each excerpt here is below 11 MB, with original packet bytes and timestamps. manifest.json records hashes, original packet ranges, label counts and block IDs. Sidecar CSVs map local packet numbers to original packet numbers and publisher labels.

The BeaconFlood companion CSV labels only packets 1..364201 of the longer PCAP. Unlabelled tail packets were excluded, not guessed as normal. RogueAP row labels cover both an AP also seen during normal periods and another advertising BSSID, so attack labels should not be equated with verified rogue identities. The publisher README also has a contradictory RogueAP/EvilTwin filename mapping; exact filenames and row labels are retained.

## Source and attribution

Asmaa Halbouni, Lee-Yeng Ong and Meng-Chew Leow, WPA3 Attacks Dataset, version 2, DOI 10.17632/cxx5t5nw7z.2. Source: https://data.mendeley.com/datasets/cxx5t5nw7z/2 . License: Creative Commons Attribution 4.0, https://creativecommons.org/licenses/by/4.0/ . Modifications: labelled-prefix selection and contiguous heldout packet extraction, plus separate label mappings; authors do not endorse this application.

The two full PCAP originals and publisher labels remain in data/raw/wpa3/ in the development workspace. They are not copied into this smaller download pack. See docs/additional-capture-training-results.md for all 12 trials, heldout metrics, regressions and the release decision.