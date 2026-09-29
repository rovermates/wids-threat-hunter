"""Add corrected features to identical existing partitions; preserve old features for comparisons."""
import json
from pathlib import Path
import joblib,pandas as pd
from backend.prepare_behavior_data import awid_chunks
from backend.core.pcap_parser import iter_pcap_chunks
from backend.core.advertiser_features import AdvertiserFeatureBuilder,ADVERTISER_FEATURES

SOURCES=[('behavior_train','data/processed/detection_train.joblib','awid'),
         ('behavior_awid_test','data/processed/detection_test.joblib','awid'),
         ('behavior_wpa3','data/raw/wpa3/evilTwin.pcap','pcap'),
         ('round2_rogue','data/raw/wpa3/RogueAP.pcap','pcap'),
         ('round2_beacon','data/raw/wpa3/BeaconFlood-labelled.pcap','pcap'),
         ('behavior_negative','data/raw/wpa3/Deauth.pcap','pcap')]

def run():
    for name,source,kind in SOURCES:
        output=Path(f'data/processed/ad_{name}.joblib')
        if output.exists():continue
        caches=[name]+([name+'_holdout'] if name in ['behavior_wpa3','round2_rogue','round2_beacon'] else [])
        records={}; bundles={}
        for cache in caches:
            b=joblib.load(f'data/processed/{cache}.joblib');bundles[cache]=b
            for partition,frame in b['data'].items():
                f=frame.loc[(frame.frame_type==0)&frame.frame_subtype.isin([5,8])].copy()
                records[(cache,partition)]=f
        lookup={int(n):(key,int(block)) for key,f in records.items() for n,block in zip(f.packet_number,f['_block'])}
        chunks=awid_chunks(source) if kind=='awid' else iter_pcap_chunks(source,advertisements_only=True)
        state=None;pieces={}
        for raw in chunks:
            raw=raw.loc[raw.packet_number.isin(lookup)].copy()
            if raw.empty:continue
            raw['_key']=[lookup[int(n)] for n in raw.packet_number]
            for key,group in raw.groupby('_key',sort=False):
                if state!=key:builder=AdvertiserFeatureBuilder();state=key
                enriched=builder.transform(group)
                enriched['packet_number']=group.packet_number
                pieces.setdefault(key[0],[]).append(enriched)
        for cache in caches:
            data={}
            for (c,part),f in records.items():
                if c!=cache:continue
                extras=pd.concat(pieces[(c,part)]).set_index('packet_number')
                assert extras.index.is_unique
                joined=f.join(extras,on='packet_number',validate='one_to_one')
                assert len(joined)==len(f)
                data[part]=joined
            target=Path(f'data/processed/ad_{cache}.joblib')
            meta={**bundles[cache]['metadata'],'feature_version':'advertisement-only-v1','source_cache':cache}
            joblib.dump({'data':data,'metadata':meta},target,compress=3)
            print('Prepared',target,{p:len(f) for p,f in data.items()},flush=True)

if __name__=='__main__':run()
