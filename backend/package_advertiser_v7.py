"""Refresh the shareable package with the deployed revision and audit evidence."""
import hashlib,json,shutil,zipfile
from pathlib import Path

def run():
    root=Path(__file__).resolve().parents[1];dest=root.parent/'github-upload/wids-threat-hunter'
    model='v7_advertiser_combined'
    for sub in ['backend/core','backend/dashboard']:
        for p in (root/sub).glob('*.py'):shutil.copy2(p,dest/sub/p.name)
    names=['backend/config.py','docs/advertiser-v7-results.md','docs/advertiser-feature-investigation.md',
           'docs/new-capture-audit.json','docs/new-capture-upload-results.json','docs/new-capture-upload-baseline.json']
    for pattern in ['*advertiser*.py','acquire_*.py','audit_new_captures.py','test_new_capture_uploads.py']:
        names += [str(p.relative_to(root)) for p in (root/'backend').glob(pattern)]
    for name in names:
        target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/name,target)
    for folder in [f'backend/models/{model}','data/dashboard-independent-round3','data/dashboard-round2-heldout']:
        shutil.copytree(root/folder,dest/folder,dirs_exist_ok=True)
    sha=hashlib.sha256((root/f'backend/models/{model}/trained_ensemble.joblib').read_bytes()).hexdigest()
    readme=dest/'README.md';text=readme.read_text(encoding='utf8');start=text.index('The active artifact is ');end=text.index('\n## What is included',start)
    text=text[:start]+f'''The active artifact is `backend/models/{model}/trained_ensemble.joblib`.
SHA256: `{sha}`.
The corrected v7 reduces RogueAP regression misses from 78 to 44 and raises F1
from 78.64% to 82.02%. AWID false flags increase from 38 to 40; other results and
limitations are in `docs/advertiser-v7-results.md`. These are previously examined
capture regressions, not independent production accuracy claims.

Restart the server and re-upload existing captures after updating. Previous v7
is retained at `backend/models/final_v7/trained_ensemble.joblib` for rollback using
`WIDS_MODEL_PATH`. Five new external PCAP compatibility checks are in
`data/dashboard-independent-round3`; these do not have verified rogue labels.
The older labelled tests in `data/dashboard-round2-heldout` have updated expected
counts. Full raw research datasets are excluded from this package.
'''+text[end:];readme.write_text(text,encoding='utf8')
    smoke=dest/'smoke_check.py';s=smoke.read_text();s=s.replace('92750d55527c8ca5a2558eb84d4e15700523aa8be1e5deda2142e7f2150fc7b8',sha);smoke.write_text(s)
    files=sorted(p for p in dest.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
    manifest={'files':len(files),'bytes':sum(p.stat().st_size for p in files),'sha256':{p.relative_to(dest).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    (dest.parent/'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest,indent=2))
    archive=dest.parent/'wids-threat-hunter-github-ready.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in files:z.write(p,Path(dest.name)/p.relative_to(dest))
    with zipfile.ZipFile(archive) as z:assert z.testzip() is None
    print(json.dumps({'files':len(files),'bytes':archive.stat().st_size,'model_sha256':sha}))

if __name__=='__main__':run()
