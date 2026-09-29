# v7 feature and dataset investigation

Measured before/after results and the deployment decision: [v7 correction results](advertiser-v7-results.md).

## Reproduced software issue

The original temporal histories group every frame by BSSID. Client transmissions and AP advertisements therefore share RSSI and sequence history. A regression fixture with two steady -40 dBm AP beacons and one -90 dBm client frame produces over 20 dB apparent RSSI variance and a sequence gap over 1,000. Advertisement-only histories preserve zero RSSI variance and consecutive advertisement sequence numbers in that fixture.

New `ad_` features maintain separate advertisement-only history, causal across chunks. Existing model features retain their old meaning to avoid silently changing deployed inference. Skipped AP management/data frames can still create legitimate gaps between advertisements; sequence gaps alone do not establish an attack.

The parser also now preserves Wi-Fi frames with an undecodable frame type as malformed context rather than rejecting an otherwise readable capture. Native decoder errors still fail the upload.

## New independent sources acquired

- UAV-NIDD: https://doi.org/10.6084/m9.figshare.25486462, CC BY 4.0. Author repository: https://github.com/CyberSaR-KAUST/UAV-Intrusion-Detection-Dataset. Selected complete ZIP members downloaded with CRC validation; paths and SHA-256 hashes in `data/raw/uav_nidd/acquisition.json`.
- Wireshark reference captures: https://wiki.wireshark.org/SampleCaptures. Three protocol examples; URLs and hashes in `data/raw/independent_wifi/manifest.json`.

Audit results are in `new-capture-audit.json`; actual dashboard upload outcomes are in `new-capture-upload-results.json`.

UAV-NIDD eviltwin-01.cap contains 299,785 packets, including 299,618 deauthentication frames but only one AP advertisement. Deauthentication.pcap also contains just one advertisement. Normal traffic.pcap contains no decoded 802.11 frames. MITM-AP.pcap fails native decoding with an invalid record length despite successful ZIP CRC validation. These files cannot support a trustworthy new supervised AP-advertisement benchmark.

The author's separate labelled CSV contains 631,356 records with 11 attack/normal categories. Its frame numbers are not proven to align uniquely with the downloaded captures; it has no BSSID/SSID columns. It is retained for research, not silently joined by row position or fitted into this model. A filename is not a packet-level target label.

The three Wireshark captures provide protocol compatibility checks, not ground-truth rogue-AP accuracy: only wpa2-linkup has advertisements (two). The other two have none.

## Evaluation protocol

Corrected caches keep the same existing train/validation/test partitions and original features for paired comparisons. Each source block starts with fresh feature state. No test rows are fitted. The existing regression captures have been inspected in earlier development and are not independent final-test evidence.

Eight models compare corrected-only and hybrid feature sets, two tree sizes and two positive-class weights. A second eight-model pass requires minimum validation-source recall at least 724/852 (current RogueAP validation recall) before optimizing mean source F1 minus 0.15 times maximum source false-positive rate. Test predictions are not used for threshold tuning. Candidate artifacts and experiment logs are retained separately from the deployed final_v7.
