"""Download a version-pinned, checksum-verified external Wi-Fi dataset subset."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import requests
from concurrent.futures import ThreadPoolExecutor

from backend.config import DATA_DIR


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def acquire(names):
    root = DATA_DIR / 'raw/wpa3'
    root.mkdir(parents=True, exist_ok=True)
    url = 'https://data.mendeley.com/public-api/datasets/cxx5t5nw7z'
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    metadata = response.json()
    if metadata['version'] != 2:
        raise ValueError('Dataset version changed; review before downloading')
    (root / 'source-metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    entries = {item['filename']: item for item in metadata['files']}
    manifest = {'source': 'https://data.mendeley.com/datasets/cxx5t5nw7z/2',
                'doi': '10.17632/cxx5t5nw7z.2', 'version': 2,
                'license': metadata['data_licence'],
                'retrieved_at': datetime.now(timezone.utc).isoformat(), 'files': []}
    for name in names:
        if Path(name).name != name or name not in entries:
            raise ValueError('Unknown or unsafe dataset filename')
        item = entries[name]
        details = item['content_details']
        destination = root / name
        if not destination.is_file() or digest(destination) != details['sha256_hash']:
            temporary = destination.with_suffix(destination.suffix + '.partial')
            print('Downloading', name, f"({item['size'] / 1e6:.1f} MB)", flush=True)
            # Independent bounded ranges can retry without restarting a large capture.
            part_dir = root / (name + '.parts')
            part_dir.mkdir(exist_ok=True)
            span = 8 * 1024 * 1024
            def fetch(start):
                end = min(start + span, item['size']) - 1
                part = part_dir / str(start)
                if part.exists() and part.stat().st_size == end - start + 1:
                    return part
                for attempt in range(8):
                    try:
                        r = requests.get(details['download_url'], headers={'Range': f'bytes={start}-{end}'}, timeout=120)
                        r.raise_for_status()
                        if r.status_code != 206 or not r.headers.get('Content-Range', '').startswith(f'bytes {start}-{end}/') or len(r.content) != end - start + 1:
                            raise ValueError('Server did not return the requested range')
                        part.write_bytes(r.content)
                        return part
                    except requests.RequestException:
                        if attempt == 7:
                            raise
            with ThreadPoolExecutor(max_workers=8) as pool:
                parts = list(pool.map(fetch, range(0, item['size'], span)))
            with temporary.open('wb') as stream:
                for part in parts:
                    stream.write(part.read_bytes())
            if temporary.stat().st_size != item['size'] or digest(temporary) != details['sha256_hash']:
                raise ValueError(f'Integrity check failed: {name}')
            temporary.replace(destination)
            for part in parts:
                part.unlink()
            part_dir.rmdir()
        manifest['files'].append({'name': name, 'bytes': destination.stat().st_size,
                                  'sha256': digest(destination), 'url': details['download_url']})
        (root / 'acquisition-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        print('Verified', name, flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('files', nargs='*', default=['Readme.txt', 'FeatureListTable.pdf', 'EvilTwin.csv', 'evilTwin.pcap', 'Deauth.csv', 'Deauth.pcap'])
    acquire(p.parse_args().files)
