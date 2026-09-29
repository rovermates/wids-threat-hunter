"""Compare actual PCAP extraction/inference with the frozen regression caches."""
import json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from threadpoolctl import threadpool_limits
from backend.config import DashboardSettings
from backend.core.ml_engine import InferenceSession
from backend.core.pcap_parser import iter_pcap_chunks
from backend.benchmark_detection import score_bundle

def run():
    folder=Path('data/dashboard-round2-heldout');manifest=json.loads((folder/'manifest.json').read_text())
    path=DashboardSettings().model_path;bundle=joblib.load(path);results=[]
    with threadpool_limits(limits=4):
        for item in manifest:
            cache='round2_rogue_holdout' if item['source']=='RogueAP.pcap' else 'round2_beacon_holdout'
            frame=joblib.load(f'data/processed/multi_{cache}.joblib')['data']['test']
            lo,hi=item['source_packet_range'];frame=frame.loc[frame.packet_number.between(lo,hi)].copy()
            expected,scores=score_bundle(bundle,frame)
            session=InferenceSession(path);chunks=[];feature_chunks=[]
            for raw in iter_pcap_chunks(folder/item['file'],chunk_size=2000):
                predicted,enriched=session.predict_with_features(raw)
                selected=predicted.loc[predicted.evaluated].copy()
                selected['packet_number']=raw.loc[selected.index,'packet_number'].to_numpy()+lo-1
                chunks.append(selected);feature_chunks.append(enriched.loc[selected.index,bundle['features']])
            actual=pd.concat(chunks);features=pd.concat(feature_chunks)
            np.testing.assert_array_equal(actual.packet_number.to_numpy(),frame.packet_number.to_numpy())
            np.testing.assert_allclose(features.astype(float).to_numpy(),frame[bundle['features']].astype(float).to_numpy(),equal_nan=True,rtol=1e-9,atol=1e-9)
            np.testing.assert_allclose(actual.detection_score,scores,rtol=1e-10,atol=1e-10)
            np.testing.assert_array_equal(actual.rogue_ap_prediction,expected)
            result={'file':item['file'],'advertisements':len(frame),'all_features_and_scores_match':True};results.append(result);print(json.dumps(result),flush=True)
    Path('docs/v7-error-reduction-capture-parity.json').write_text(json.dumps(results,indent=2))

if __name__=='__main__':run()
