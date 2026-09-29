"""Exercise packaged heldouts through the real upload API with isolated state."""
import hashlib,json,tempfile,time
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.config import DashboardSettings,PROJECT_ROOT
from threadpoolctl import threadpool_limits

def run(models=None, output='upload-results.json'):
 folder=Path('data/dashboard-round2-heldout');files=json.loads((folder/'manifest.json').read_text());allresults=[]
 with threadpool_limits(limits=4):
  for name,repeats in (models or [('rogue_advertiser_v6',2),('additional_captures_v7',1)]):
   with tempfile.TemporaryDirectory() as state,TestClient(create_app(DashboardSettings(state_dir=Path(state),model_path=PROJECT_ROOT/f'backend/models/{name}/trained_ensemble.joblib'))) as client:
    for f in files:
     path=folder/f['file'];runs=[]
     for _ in range(repeats):
      response=client.post('/api/upload',files={'file':(path.name,path.read_bytes())});response.raise_for_status();deadline=time.monotonic()+240
      while time.monotonic()<deadline:
       status=client.get(response.json()['status_url']).json()
       if status['status'] in ['failed','completed']:break
       time.sleep(.2)
      record={'status':status['status'],'error':status.get('error')}
      if status['status']=='completed':
       m=client.get('/api/metrics').json();record['capture']=m['capture'];record['model_sha256']=m['model']['artifact_sha256'];record['threats']=client.get('/api/threats').json()['items'];payload=client.get('/api/export',params={'analysis_id':status['id'],'format':'json'}).json();record['prediction_sha256']=hashlib.sha256(json.dumps(payload['packets'],sort_keys=True).encode()).hexdigest()
      runs.append(record)
     result={'file':f['file'],'model':name,'runs':runs,'repeat_matches':len(runs)==2 and runs[0].get('prediction_sha256')==runs[1].get('prediction_sha256')};allresults.append(result);(folder/output).write_text(json.dumps(allresults,indent=2));print(name,f['file'],runs[0].get('capture',record),flush=True)
     assert all(r['status']=='completed' for r in runs), result
     if repeats==2: assert result['repeat_matches'], result
if __name__=='__main__':run()
