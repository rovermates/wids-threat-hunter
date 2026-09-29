"""Public independent Wireshark examples, reserved for external robustness checks."""
import gzip,hashlib,json
from pathlib import Path
import requests

SOURCES={
 'wpa-eap-tls.pcap':'https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/wpa-eap-tls.pcap.gz',
 'http_PPI.pcap':'https://wiki.wireshark.org/uploads/e8cebabd278b76e3bc9edbd484c4d293/http_PPI.cap',
 'wpa2-linkup.pcap':'https://wiki.wireshark.org/uploads/0ad8934c433f71607d8dc9c3b7a14718/wpa2linkuppassphraseiswireshark.pcap'}

def run():
    root=Path('data/raw/independent_wifi');root.mkdir(exist_ok=True);manifest=[]
    for name,url in SOURCES.items():
        r=requests.get(url,timeout=90);r.raise_for_status()
        data=gzip.decompress(r.content) if url.endswith('.gz') else r.content
        if data[:4] not in [b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x0a\x0d\x0d\x0a']:
            raise ValueError('Expected a packet capture, not an HTML download page')
        (root/name).write_bytes(data)
        manifest.append({'file':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'url':url,'source':'https://wiki.wireshark.org/SampleCaptures',
            'role':'External protocol example; not fitted; no independently verified rogue-AP labels'})
        print('Downloaded',name,len(data),flush=True)
    (root/'manifest.json').write_text(json.dumps(manifest,indent=2))

if __name__=='__main__':run()
