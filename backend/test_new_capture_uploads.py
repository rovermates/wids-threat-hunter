"""Run new external captures through the upload API; no assumed packet labels."""
import json, tempfile, time
from pathlib import Path
from fastapi.testclient import TestClient
from threadpoolctl import threadpool_limits
from backend.app import create_app
from backend.config import DashboardSettings

def run():
    results=[]
    paths=list(Path('data/raw/independent_wifi').glob('*.pcap'))
    paths += [Path('data/raw/uav_nidd')/n for n in ['Normal traffic.pcap','Deauthentication.pcap','eviltwin-01.cap','MITM-AP.pcap']]
    with tempfile.TemporaryDirectory() as state, threadpool_limits(limits=4), TestClient(create_app(DashboardSettings(state_dir=Path(state)))) as client:
        for path in paths:
            response=client.post('/api/upload',files={'file':(path.stem+'.pcap',path.read_bytes())})
            response.raise_for_status()
            deadline=time.monotonic()+900
            while time.monotonic()<deadline:
                status=client.get(response.json()['status_url']).json()
                if status['status'] in ['failed','completed']:break
                time.sleep(.2)
            if status['status'] not in ['failed','completed']:
                raise TimeoutError(f'Upload did not finish: {path}')
            record={'file':str(path),'status':status['status'],'error':status.get('error')}
            if status['status']=='completed':
                m=client.get('/api/metrics').json()
                record.update(capture=m['capture'],model_sha256=m['model']['artifact_sha256'])
            results.append(record)
            Path('docs/new-capture-upload-results.json').write_text(json.dumps(results,indent=2))
            print(json.dumps(record),flush=True)

if __name__=='__main__':run()
