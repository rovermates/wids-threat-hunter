# New dashboard PCAP comparison pack

These files were first introduced to this project for this test. None was used to train or tune the active detector. Three are existing public Wireshark captures newly downloaded here; one was generated offline for this test. They are not newly collected live captures. No model or parser changes were made to improve these outcomes.

## Reproduce

1. Open http://127.0.0.1:8000 and upload one .pcap at a time.
2. Wait for Analysis complete or the error message. Clear packet filters before comparing.
3. Compare counts below. An upload replaces the displayed capture; failed uploads preserve the preceding results.
4. The Accuracy/F1 strip is a saved benchmark, NOT accuracy measured on these files. It should remain 99.96% / 99.18%.
5. Model SHA256 must be f37d7a9947d0562583edc9f79dcc75c40f84f5d9e64f9437501f2608e11c5b9c. Different models may produce different results.

Tests used the actual browser upload UI against the same application/build on isolated port 8012, preserving your port-8000 results. Each file was tested twice. Full packet-result hashes matched for all successful uploads; the rejection repeated too. Analysis IDs/completion times naturally differ. No browser JavaScript errors occurred.

| File | Processed Wi-Fi packets | Evaluated advertisements | Flagged packets | Suspected APs | Level |
|---|---:|---:|---:|---:|---|
| Network_Join_Nokia_Mobile.pcap | 1180 | 684 | 195 | 1 | high |
| wpa-Induction.pcap | Rejected | — | — | — | Error |
| mesh.pcap | 780 | 450 | 0 | 0 | low |
| synthetic-ssid-impersonation.pcap | 1000 | 1000 | 0 | 0 | low |

## What these results mean

- Nokia network join: the model flagged an AP in a sample described by Wireshark as network joining/authentication. This is a suspected false alert, not a verified rogue detection; the source provides no rogue-AP ground truth.
- Mesh: no alerts. This does not prove that all devices are authorized.
- Synthetic impersonation: deliberately contains legitimate BSSID 02:aa:00:00:00:01 and an impersonator 02:aa:00:00:00:02 advertising the same Fresh-Lab-Network SSID with different privacy, signal and sequence behavior. The model missed the constructed impersonator. This demonstrates a synthetic coverage gap, not a measured real-world attack recall.
- WPA induction: parser error is exactly `Wi-Fi output lacks packet number or frame type`. This is a reproducible ingestion limitation, not a successful negative detection. The previous capture remains visible.

The high earlier benchmark numbers do not resolve these newly observed gaps. This pack is a reproducibility/functional test, not a labeled independent accuracy benchmark.

## Alert details
- Network_Join_Nokia_Mobile.pcap: BSSID `00:01:e3:41:bd:6e`, 195 flagged packets, severity high, evidence tags: Sequence gap.

## Sources and integrity

Public captures: https://wiki.wireshark.org/SampleCaptures . Original files retained byte-for-byte. See sources.json for exact download URLs, sizes and SHA256 hashes. Public samples do not include authoritative benign/rogue labels. The synthetic capture is generated packet bytes only; no transmission occurred.

For each successful file, `<name>.results.json` contains the full packet export. `<name>.png` shows the dashboard. `dashboard-results.json` records both runs, alert details, model hash and matching packet-result digests.