"""Strict label alignment and split-local features for new control captures."""
import hashlib,json
from pathlib import Path
import joblib,numpy as np,pandas as pd
from backend.core.pcap_parser import iter_pcap_chunks
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ap_behavior import APBehaviorBuilder
from backend.core.advertiser_features import AdvertiserFeatureBuilder
from backend.core.multiscale_features import MultiScaleFeatures
from backend.core.ml_engine import protocol_features
from backend.core.detection_features import detection_features

def run(name,role):
    root=Path('data/raw/wpa3');pcap=root/(name+'.pcap');csv=root/(name+'.csv')
    output=Path(f'data/processed/multi_{name.lower()}.joblib')
    if output.exists():raise FileExistsError(output)
    staged=output.with_suffix('.features.joblib')
    if staged.exists():
        stage=joblib.load(staged)
        if stage['source_sha256']!=hashlib.sha256(pcap.read_bytes()).hexdigest():raise ValueError('Source changed after feature extraction')
        return finish(name,role,stage['data'],pcap,csv,output)
    features=joblib.load('backend/models/v7_error_reduction_final/trained_ensemble.joblib')['features']
    parts={};origin=None;current=None;processed=0
    for raw in iter_pcap_chunks(pcap,chunk_size=10000):
        if origin is None:origin=int(raw.timestamp_ns.iloc[0])
        relative=(raw.timestamp_ns-origin)/1e9
        if role=='development':
            raw['_block']=(relative//30).astype(int);raw=raw.loc[(relative%30>=1)&(relative%30<29)].copy()
        else:raw['_block']=0
        for block,f in raw.groupby('_block',sort=False):
            if block!=current:
                temporal=TemporalFeatureBuilder(100);behavior=APBehaviorBuilder(100);ad=AdvertiserFeatureBuilder(100);short=MultiScaleFeatures();current=block
            enriched=temporal.transform(f)
            for extra in [protocol_features(f),detection_features(f),behavior.transform(f),ad.transform(f)]:
                for col,values in extra.items():enriched[col]=values
            for col,values in short.transform(enriched).items():enriched[col]=values
            frame=enriched.loc[(enriched.frame_type==0)&enriched.frame_subtype.isin([5,8]),features+['original_length','packet_number','timestamp_ns','_block']].copy()
            frame['_bssid']=f.loc[frame.index,'bssid']
            part='test' if role=='fresh_control' or block%5==4 else 'validation' if block%5==3 else 'train'
            if len(frame):parts.setdefault(part,[]).append(frame)
        processed+=len(raw)
        if processed//100000!=(processed-len(raw))//100000:print('Read',name,processed,flush=True)
    data={k:pd.concat(v,ignore_index=True) for k,v in parts.items()}
    joblib.dump({'data':data,'source_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest()},staged,compress=3)
    print('FEATURES_READY',name,flush=True)
    return finish(name,role,data,pcap,csv,output)

def finish(name,role,data,pcap,csv,output):
    if not csv.is_file():
        print('Awaiting complete verified label file; no training cache written',flush=True);return
    labels=pd.read_csv(csv,usecols=['frame.number','frame.len','Label']).set_index('frame.number')
    if not labels.index.is_unique:raise ValueError('Duplicate publisher packet numbers')
    mapping={'Normal':'normal','Disassoc':'disassociation','Deauth':'deauthentication','AggregationAttack':'aggregation'}
    known=set(mapping)
    unknown=set(labels.Label)-known
    if unknown:raise ValueError(f'Audit unfamiliar labels before proceeding: {unknown}')
    for frame in data.values():
        match=labels.loc[frame.packet_number.to_numpy(dtype=int)]
        if not np.array_equal(match['frame.len'].to_numpy(),frame.original_length.to_numpy()):raise ValueError('Advertisement packet-length alignment failed')
        frame['original_label']=match.Label.to_numpy()
        frame['label']=match.Label.map(mapping).to_numpy()
    metadata={'source':str(pcap),'source_sha256':hashlib.sha256(pcap.read_bytes()).hexdigest(),
        'label_sha256':hashlib.sha256(csv.read_bytes()).hexdigest(),'role':role,'label_counts':{k:f.label.value_counts().to_dict() for k,f in data.items()},
        'target_interpretation':'Publisher disassociation/aggregation scenario labels are non-RAP classes; not independently verified physical AP identities.'}
    joblib.dump({'data':data,'metadata':metadata},output,compress=3)
    output.with_suffix('.json').write_text(json.dumps(metadata,indent=2));print(json.dumps(metadata),flush=True)

if __name__=='__main__':
    import sys
    run(sys.argv[1],sys.argv[2])
