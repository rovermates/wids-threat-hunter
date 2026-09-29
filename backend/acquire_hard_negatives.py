"""Download publisher-verified new development and untouched control captures."""
import hashlib,json
from pathlib import Path
import requests
from concurrent.futures import ThreadPoolExecutor

def run():
    root=Path('data/raw/wpa3');meta=json.loads((root/'source-metadata.json').read_text())
    names=['Disasso.pcap','Disasso.csv','Aggreattack.pcap','Aggreattack.csv'];records=[]
    for name in names:
        info=next(f for f in meta['files'] if f['filename']==name);details=info['content_details'];path=root/name
        expected=details['sha256_hash']
        if not path.exists():
            partial=path.with_suffix(path.suffix+'.partial')
            span=1024*1024
            def fetch(start):
                end=min(start+span,info['size'])-1
                for attempt in range(4):
                    try:
                        r=requests.get(details['download_url'],headers={'Range':f'bytes={start}-{end}'},timeout=120)
                        r.raise_for_status()
                        if r.status_code!=206 or not r.headers.get('Content-Range','').startswith(f'bytes {start}-{end}/') or len(r.content)!=end-start+1:
                            raise ValueError('Incomplete or unhonored byte range')
                        return r.content
                    except requests.RequestException:
                        if attempt==3:raise
            with ThreadPoolExecutor(max_workers=8) as pool,partial.open('wb') as f:
                for chunk in pool.map(fetch,range(0,info['size'],span)):f.write(chunk)
            if partial.stat().st_size!=info['size'] or hashlib.sha256(partial.read_bytes()).hexdigest()!=expected:raise ValueError('Publisher hash mismatch')
            partial.replace(path)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==expected
        records.append({'file':name,'sha256':expected,'bytes':path.stat().st_size,'url':details['download_url'],
            'role':'development (partition before fitting)' if name.startswith('Disasso') else 'untouched final negative control; never fitted or tuned'})
        print('Verified',name,flush=True)
    (root/'hard-negative-acquisition.json').write_text(json.dumps({'source':'https://data.mendeley.com/datasets/cxx5t5nw7z/2','license':'CC BY 4.0','files':records},indent=2))

if __name__=='__main__':run()
