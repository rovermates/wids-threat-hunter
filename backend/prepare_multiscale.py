"""Enrich existing partitions without changing labels or split membership."""
from pathlib import Path
import joblib
from backend.core.multiscale_features import enrich_cache

def run():
    for p in Path('data/processed').glob('ad_*.joblib'):
        out=p.with_name('multi_'+p.name[3:])
        if out.exists():continue
        bundle=joblib.load(p)
        bundle['data']={part:enrich_cache(frame) for part,frame in bundle['data'].items()}
        bundle['metadata']={**bundle['metadata'],'short_windows':[5,20],'gap_reset_ns':5000000000}
        joblib.dump(bundle,out,compress=3);print(out,flush=True)

if __name__=='__main__':run()
