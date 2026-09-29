# Independent capture upload checks

Upload these five PCAP files individually. Expected results and model hash are in manifest.json. These are new independent-source files, not synthetic attacks or training extracts. They have not been fitted.

UAV-NIDD eviltwin-01.pcap has 299,785 frames but only one AP advertisement. A zero alert result does NOT establish that this attack capture is safe: the model evaluates beacons/probe responses, not deauthentication attacks. Wireshark HTTP and EAP captures have no eligible advertisements and should show unknown threat level.

Sources: https://doi.org/10.6084/m9.figshare.25486462 (CC BY 4.0) and https://wiki.wireshark.org/SampleCaptures. Full provenance is in data/raw/uav_nidd/acquisition.json and data/raw/independent_wifi/manifest.json in the research workspace. The .cap file is copied byte-for-byte with a .pcap extension.
