"""Check the bundled model, frontend and actual upload API in temporary state."""
import hashlib
import tempfile
import time
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app import create_app
from backend.config import DashboardSettings, PROJECT_ROOT


def wait(client, response):
    response.raise_for_status()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        job = client.get(response.json()['status_url']).json()
        if job['status'] == 'failed':
            raise RuntimeError(job['error'])
        if job['status'] == 'completed':
            return job
        time.sleep(.1)
    raise RuntimeError('Analysis timed out')


with tempfile.TemporaryDirectory() as folder:
    settings = DashboardSettings(state_dir=Path(folder))
    digest = hashlib.sha256(settings.model_path.read_bytes()).hexdigest()
    assert digest == '2eed9cb24f21fbb453f18ea11924712b15d66fac0e8e8ab1fd4fcd75cf7d66ac', 'Unexpected model hash'
    with TestClient(create_app(settings)) as client:
        assert client.get('/').status_code == 200, 'Built frontend missing'
        health = client.get('/api/health').json()
        assert health['model_ready'], 'Model could not be loaded'
        job = wait(client, client.post('/api/sample'))
        assert job['processed_packets'] == 100
        metrics = client.get('/api/metrics').json()
        assert metrics['model']['scope'] == 'ap_advertisements'
        assert not metrics['needs_reanalysis']
        assert client.get('/api/packets').json()['total'] == 100
        result = client.get('/api/export', params={'analysis_id':job['id'],'format':'json'})
        assert len(result.json()['packets']) == 100
        if health['pcap_available']:
            path = PROJECT_ROOT / 'data/sample_wifi.pcap'
            job = wait(client, client.post('/api/upload', files={'file':(path.name,path.read_bytes())}))
            assert job['processed_packets'] > 0
            print('PASS: PCAP upload and processing')
        else:
            print('PCAP check skipped: install tshark 4.4+ to enable PCAP uploads.')
print('PASS: bundled model, frontend, sample analysis, packet API and export')
