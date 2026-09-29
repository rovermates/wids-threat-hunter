"""Record actual protocol coverage, rather than assuming attack names are labels."""
import collections,json,subprocess
from pathlib import Path
from backend.core.pcap_parser import resolve_tshark

def run():
    out={}
    for folder in ['uav_nidd','independent_wifi']:
        for path in (Path('data/raw')/folder).iterdir():
            if path.suffix not in {'.pcap','.cap'}:continue
            result=subprocess.run([resolve_tshark(),'-r',str(path),'-T','fields','-e','wlan.fc.type_subtype','-e','wlan.bssid'],capture_output=True,text=True)
            types=collections.Counter();advertisers=collections.Counter()
            for line in result.stdout.splitlines():
                subtype,_,bssid=line.partition('\t');types[subtype]+=1
                if subtype in {'0x0008','0x0005','8','5'}:advertisers[bssid]+=1
            out[str(path)]={'complete':result.returncode==0,'error':result.stderr if result.returncode else None,'subtypes':dict(types),'advertisements_by_bssid':dict(advertisers)}
            print(path.name,json.dumps(out[str(path)]),flush=True)
    Path('docs/new-capture-audit.json').write_text(json.dumps(out,indent=2))

if __name__=='__main__':run()
