"""Update the existing shareable local distribution without copying private state."""
import hashlib,json,shutil,zipfile
from pathlib import Path

def run():
    root=Path(__file__).resolve().parents[1]
    destination=root.parent/'github-upload'/'wids-threat-hunter'
    model=root/'backend/models/final_v7'
    metadata=json.loads((model/'metadata.json').read_text())
    paths=['backend/config.py','backend/dashboard/model_info.py','backend/core/target_classifier.py','backend/core/confirmed_classifier.py',
           'backend/refine_v7.py','backend/refine_v7_recall.py','backend/extend_v7_multiclass.py',
           'backend/evaluate_refined_v7.py','backend/report_refined_v7.py','backend/train_additional_captures.py','backend/select_confirmed_v7.py',
           'frontend/src/components/ModelPerformance.jsx','docs/refined-v7-results.md',
           'docs/refined-v7-protocol.md','start.cmd','start-experimental-v7.cmd']
    for name in paths:
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/name,target)
    for folder in ['frontend/dist','data/dashboard-round2-heldout']:
        shutil.copytree(root/folder,destination/folder,dirs_exist_ok=True)
    for folder in ['final_v7','refined_v7_balanced','refined_v7','additional_captures_v7']:
        source=root/'backend/models'/folder;target=destination/'backend/models'/folder;target.mkdir(parents=True,exist_ok=True)
        for path in source.iterdir():
            if path.suffix in {'.json','.joblib'}:shutil.copy2(path,target/path.name)
    readme=destination/'README.md';text=readme.read_text(encoding='utf8')
    start=text.index('The active artifact is ');end=text.index('\n## What is included',start)
    text=text[:start]+f'''The active artifact is `backend/models/final_v7/trained_ensemble.joblib`.
SHA256: `{metadata['artifact_sha256']}`.
This refined v7 is the requested final local dashboard default after 40 training
configurations. See `docs/refined-v7-results.md` for every before/after result,
including remaining false alerts and missed targets. These are previously examined
capture regressions, not independent-device or production-quality guarantees.

Upload the five files in `data/dashboard-round2-heldout/` and compare with its
README. The dashboard's **Additional detection checks** exposes the more difficult
RogueAP and negative-control results. Restart the server after updating and
re-upload old captures. To roll back, set `WIDS_MODEL_PATH` to
`backend/models/rogue_advertiser_v6/trained_ensemble.joblib` before starting.
The original experimental v7 is also retained for comparison.
'''+text[end:]
    text=text.replace('The current model raises an unverified alert on the Nokia sample, misses the',
                      'Historical v6 testing raised an unverified alert on the Nokia sample, missed the')
    text=text.replace('synthetic impersonator, and rejects','synthetic impersonator, and rejected')
    text=text.replace('Excluded: training datasets/caches, historical model variants, full development',
                      'Excluded: training datasets/caches, most historical model variants, full development')
    readme.write_text(text,encoding='utf8')
    smoke=destination/'smoke_check.py';text=smoke.read_text()
    text=text.replace('f37d7a9947d0562583edc9f79dcc75c40f84f5d9e64f9437501f2608e11c5b9c',metadata['artifact_sha256'])
    smoke.write_text(text)
    guide=destination.parent/'UPLOAD-INSTRUCTIONS.txt';text=guide.read_text()
    text=text.replace('backend/models/rogue_advertiser_v6/trained_ensemble.joblib','backend/models/final_v7/trained_ensemble.joblib')
    text=text.replace('package fits these limits. If your browser refuses the folder drag, upload the',
                      'package now exceeds 100 files: upload in batches of fewer than 100 files. Upload the')
    guide.write_text(text)
    files=sorted(p for p in destination.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc')
    manifest={'files':len(files),'bytes':sum(p.stat().st_size for p in files),
              'sha256':{p.relative_to(destination).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}
    (destination.parent/'PACKAGE-MANIFEST.json').write_text(json.dumps(manifest,indent=2))
    archive=destination.parent/'wids-threat-hunter-github-ready.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for path in files:z.write(path,Path(destination.name)/path.relative_to(destination))
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        name='wids-threat-hunter/backend/models/final_v7/trained_ensemble.joblib'
        assert hashlib.sha256(z.read(name)).hexdigest()==metadata['artifact_sha256']
    print(json.dumps({'files':len(files),'zip_bytes':archive.stat().st_size,'model_sha256':metadata['artifact_sha256']}))

if __name__=='__main__':run()
