"""Inspect/download public UAV-NIDD ZIP members with byte-range integrity checks."""
import io,json,hashlib,zipfile
from pathlib import Path
import requests

ROOT=Path('data/raw/uav_nidd')

class RemoteZip(io.RawIOBase):
    def __init__(self,url,size):self.url=url;self.size=size;self.position=0;self.session=requests.Session()
    def seekable(self):return True
    def readable(self):return True
    def tell(self):return self.position
    def seek(self,offset,whence=0):
        self.position=offset if whence==0 else self.position+offset if whence==1 else self.size+offset
        return self.position
    def read(self,size=-1):
        end=self.size if size<0 else min(self.position+size,self.size)
        if end<=self.position:return b''
        for attempt in range(4):
            try:
                r=self.session.get(self.url,headers={'Range':f'bytes={self.position}-{end-1}'},timeout=120)
                r.raise_for_status();break
            except requests.RequestException:
                if attempt==3:raise
        r.raise_for_status()
        expected=f'bytes {self.position}-{end-1}/'
        if r.status_code!=206 or not r.headers.get('Content-Range','').startswith(expected):
            raise ValueError('Server did not honor byte range')
        if len(r.content)!=end-self.position:raise ValueError('Truncated range')
        self.position=end;return r.content

def run(names=None):
    metadata=json.loads((ROOT/'metadata.json').read_text());source=metadata['files'][0]
    with zipfile.ZipFile(RemoteZip(source['download_url'],source['size'])) as archive:
        listing=[{'name':i.filename,'bytes':i.file_size,'compressed':i.compress_size,'crc32':i.CRC} for i in archive.infolist()]
        (ROOT/'zip-listing.json').write_text(json.dumps(listing,indent=2))
        if not names:
            print(json.dumps(listing,indent=2));return
        manifest=json.loads((ROOT/'acquisition.json').read_text()) if (ROOT/'acquisition.json').exists() else []
        for name in names:
            info=archive.getinfo(name);target=ROOT/Path(name).name
            if info.file_size>512*1024*1024:raise ValueError('Member exceeds memory/download bound')
            contents=archive.read(info)
            partial=target.with_suffix(target.suffix+'.partial');partial.write_bytes(contents);partial.replace(target)
            # ZipFile checks CRC32 when consuming each complete member.
            manifest=[f for f in manifest if f['file']!=target.name]
            manifest.append({'file':target.name,'source_member':name,'source':source['download_url'],
                'bytes':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'zip_crc32_verified':True})
            (ROOT/'acquisition.json').write_text(json.dumps(manifest,indent=2))
            print('Downloaded',target.name,target.stat().st_size,flush=True)

if __name__=='__main__':
    import sys
    run(sys.argv[1:])
