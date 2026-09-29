"""Build behavior features with partition-local history and untouched capture tests."""
import argparse,json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from backend.core.ap_behavior import APBehaviorBuilder,ALIASES,AP_FEATURES
from backend.core.awid_schema import COLUMNS,STRING_FIELDS,INTEGER_FIELDS
from backend.core.feature_builder import TemporalFeatureBuilder
from backend.core.ml_engine import STATIC,TEMPORAL,PROTOCOL_FIELDS,protocol_features
from backend.core.detection_features import HEADER_FIELDS,DETECTION_FEATURES,detection_features
from backend.core.pcap_parser import iter_pcap_chunks
from backend.prepare_ml_data import sha256


def awid_chunks(cache):
    bundle=joblib.load(cache); frames=pd.concat(bundle['data'].values()).sort_index()
    names=set(STRING_FIELDS.values()) | {v[0] for v in INTEGER_FIELDS.values()} | {'wlan.seq','wlan.fc.ds'}
    names.update(n for aliases in ALIASES.values() for n in aliases)
    names.update(n for aliases in PROTOCOL_FIELDS.values() for n in aliases)
    names.update(HEADER_FIELDS.values()); names &= set(COLUMNS)
    positions=[i for i,n in enumerate(COLUMNS) if n in names]
    source=bundle['metadata']['source']
    if sha256(source)!=bundle['metadata']['sha256']:raise ValueError('Raw source changed')
    for raw in pd.read_csv(source,header=None,usecols=positions,dtype='string',keep_default_na=False,chunksize=10000):
        raw.columns=[COLUMNS[int(i)] for i in raw.columns];raw.index+=1;raw=raw.replace({'?':pd.NA})
        for alias,col in STRING_FIELDS.items():raw[alias]=raw[col]
        for alias,(col,lo,hi,dtype) in INTEGER_FIELDS.items():raw[alias]=pd.to_numeric(raw[col]).astype(dtype)
        raw['timestamp_ns']=frames.loc[raw.index,'timestamp_ns']
        raw['packet_number']=raw.index
        yield raw


def build(source,output,mode,csv=None):
    output=Path(output)
    if output.exists():raise FileExistsError(output)
    chunks=awid_chunks(source) if mode.startswith('awid') else iter_pcap_chunks(source,chunk_size=10000)
    labels=None
    if csv:
        labels=pd.read_csv(csv,usecols=['frame.number','frame.len','Label']).set_index('frame.number')
        if not labels.index.is_unique:raise ValueError('Repeated packet numbers')
    parts={}; origin=None; current=None; count=0
    features=list(dict.fromkeys(STATIC+TEMPORAL+list(PROTOCOL_FIELDS)+DETECTION_FEATURES+AP_FEATURES))
    for raw in chunks:
        if labels is not None:
            match=labels.loc[raw.packet_number.to_numpy(dtype=int)]
            if not np.array_equal(match['frame.len'].to_numpy(),raw.original_length.to_numpy()):raise ValueError('Unaligned CSV')
            mapping={'Normal':'normal','EvilTwin':'evil_twin','Deauth':'deauthentication',
                     'RogueAP':'rogue_ap','BeaconFlood':'beacon_flood'}
            if not set(match.Label)<=set(mapping):raise ValueError('Unknown labels')
            raw['label']=match.Label.map(mapping).to_numpy()
        if origin is None:origin=int(raw.timestamp_ns.iloc[0])
        if mode in {'awid-test','negative'}:
            raw['_block']=0
        else:
            relative=(raw.timestamp_ns-origin)/1e9
            raw['_block']=(relative//30).astype(int)
            raw=raw.loc[(relative%30>=1)&(relative%30<29)].copy()
        for block,group in raw.groupby('_block',sort=False):
            if block!=current:
                temporal=TemporalFeatureBuilder(100);behavior=APBehaviorBuilder(100);current=block
            enriched=temporal.transform(group)
            for extra in [protocol_features(group),detection_features(group),behavior.transform(group)]:
                for name,values in extra.items():enriched[name]=values
            if mode in {'awid-test','negative'}:part='test'
            elif mode=='wpa3' and block%5==4:part='test'
            else:part='validation' if block%5==3 else 'train'
            keep=enriched[features+['label','timestamp_ns','packet_number','_block']].copy()
            # Audit-only group, excluded from all feature allowlists.
            keep['_bssid']=group.bssid
            parts.setdefault(part,[]).append(keep)
        count+=len(raw)
        print('Processed',mode,count,flush=True) if count//100000!=(count-len(raw))//100000 else None
    data={k:pd.concat(v,ignore_index=True) for k,v in parts.items()}
    metadata={'source':str(source),'source_sha256':sha256(source),'mode':mode,'rssi_window':100,
              'behavior_window':100,'split':'30s blocks with 1s guards; mod5=3 validation; WPA3 mod5=4 test; AWID test continuous',
              'counts':{k:v.label.value_counts().to_dict() for k,v in data.items()}}
    if csv:metadata['csv_sha256']=sha256(csv)
    if mode=='wpa3':
        joblib.dump({'data':{'test':data.pop('test')},'metadata':metadata},output.with_name(output.stem+'_holdout.joblib'),compress=3)
    joblib.dump({'data':data,'metadata':metadata},output,compress=3)
    output.with_suffix('.json').write_text(json.dumps(metadata,indent=2),encoding='utf8')
    print(json.dumps(metadata,indent=2),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source');p.add_argument('output')
    p.add_argument('--mode',choices=['awid-train','awid-test','wpa3','negative'],required=True);p.add_argument('--csv')
    a=p.parse_args();build(a.source,a.output,a.mode,a.csv)
