"""Refresh the shareable package with the deployed revision and audit evidence."""
import hashlib,json,shutil,zipfile
from pathlib import Path

def run():
    root=Path(__file__).resolve().parents[1];dest=root.parent/'github-upload/wids-threat-hunter'
    model='v7_error_reduction_final'
    for sub in ['backend/core','backend/dashboard','backend/tests']:
        (dest/sub).mkdir(parents=True,exist_ok=True)
        for p in (root/sub).glob('*.py'):shutil.copy2(p,dest/sub/p.name)
    names=['backend/config.py','backend/requirements.txt','backend/requirements-training.txt','docs/v7-hard-negative-results.md','docs/v7-error-reduction-capture-parity.json','docs/advertiser-v7-results.md','docs/advertiser-feature-investigation.md',
           'docs/v7-error-reduction-results.md','docs/v7-residual-validation-audit.json','docs/new-capture-audit.json','docs/new-capture-upload-results.json','docs/new-capture-upload-baseline.json']
    for pattern in ['*.py']:
        names += [str(p.relative_to(root)) for p in (root/'backend').glob(pattern)]
    for name in names:
        target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/name,target)
    for folder in [f'backend/models/{model}','data/dashboard-independent-round3','data/dashboard-round2-heldout']:
        shutil.copytree(root/folder,dest/folder,dirs_exist_ok=True)
    for experiment in ['v7_full_pipeline','v7_hard_negatives']:
        target=dest/'docs/experiments'/experiment;target.mkdir(parents=True,exist_ok=True)
        for p in (root/'backend/models'/experiment).glob('*.json'):
            shutil.copy2(p,target/p.name)
    sha=hashlib.sha256((root/f'backend/models/{model}/trained_ensemble.joblib').read_bytes()).hexdigest()
    readme=dest/'README.md';text=readme.read_text(encoding='utf8');start=text.index('The active artifact is ');end=text.index('\n## What is included',start)
    text=text[:start]+f'''The active artifact is `backend/models/{model}/trained_ensemble.joblib`.
SHA256: `{sha}`.
This v7 reduces RogueAP misses from 44 to 33 and false flags from 184 to 175.
F1 rises from 82.02% to 83.62%. No FP/FN counts increase across the five
regression sets. Full results and limits are in `docs/v7-error-reduction-results.md`. These are previously examined
capture regressions, not independent production accuracy claims.

Restart the server and re-upload existing captures after updating. Previous v7
is retained at `backend/models/v7_advertiser_combined/trained_ensemble.joblib` for rollback using
`WIDS_MODEL_PATH`. Five new external PCAP compatibility checks are in
`data/dashboard-independent-round3`; these do not have verified rogue labels.
The older labelled tests in `data/dashboard-round2-heldout` have updated expected
counts. Full raw research datasets are excluded from this package.

Latest development update (2026-09-29): 15 additional training runs and new
control captures were evaluated. The candidate increased RogueAP false flags
and was rejected; the deployed model above is unchanged. See
`docs/v7-hard-negative-results.md` and `docs/experiments/` for results.
Experimental training scripts are included, with optional dependencies in
`backend/requirements-training.txt`. Reproducing training requires the external
datasets and feature caches described in the report; they are not bundled.
'''+text[end:];readme.write_text(text,encoding='utf8')
    smoke=dest/'smoke_check.py';s=smoke.read_text();s=s.replace('eb12ac5d811bb94d6e03fd36e33998a905ace2574598afaa3de61cf936139313',sha);smoke.write_text(s)
    files=sorted(p for p in dest.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
    manifest={'files':len(files),'bytes':sum(p.stat().st_size for p in files),'sha256':{p.relative_to(dest).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    (dest.parent/'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest,indent=2))
    archive=dest.parent/'wids-threat-hunter-github-ready.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in files:z.write(p,Path(dest.name)/p.relative_to(dest))
    with zipfile.ZipFile(archive) as z:assert z.testzip() is None
    print(json.dumps({'files':len(files),'bytes':archive.stat().st_size,'model_sha256':sha}))

if __name__=='__main__':run()
