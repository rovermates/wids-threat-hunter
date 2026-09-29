"""Create intact held-out block PCAPs selected by publisher labels, before scoring."""
from pathlib import Path
import json,hashlib,subprocess
import joblib,pandas as pd
from backend.core.pcap_parser import resolve_tshark

def run():
 out=Path('data/dashboard-round2-heldout');out.mkdir(exist_ok=False)
 manifest=[];tool=str(Path(resolve_tshark()).with_name('editcap.exe'))
 for cache,source,labelpath,attack in [('round2_rogue','RogueAP.pcap','RogueAP-labels.csv','rogue_ap'),('round2_beacon','BeaconFlood-labelled.pcap','BeaconFlood.csv','beacon_flood')]:
  bundle=joblib.load('data/processed/'+cache+'_holdout.joblib');frame=bundle['data']['test'];groups=list(frame.groupby('_block'));ranked=sorted(groups,key=lambda kv:int((kv[1].label==attack).sum()),reverse=True)
  chosen=[('attack',ranked[0])]
  if cache=='round2_rogue':
   other=[g for g in ranked[1:] if (g[1].label==attack).any()]
   if other:chosen.append(('attack-second',other[0]))
  normals=[g for g in groups if not (g[1].label==attack).any()]
  if normals:chosen.append(('normal',max(normals,key=lambda kv:len(kv[1]))))
  labels=pd.read_csv('data/raw/wpa3/'+labelpath,usecols=['frame.number','Label']).set_index('frame.number')
  for kind,(block,f) in chosen:
   assert block%5==4
   first,last=int(f.packet_number.min()),int(f.packet_number.max());name=f'{cache}-{kind}-block{block}.pcap';dest=out/name
   subprocess.run([tool,'-F','pcap','-r','data/raw/wpa3/'+source,str(dest),f'{first}-{last}'],check=True,capture_output=True)
   assert dest.stat().st_size < 64*1024*1024
   side=labels.loc[first:last].copy();side['source_packet_number']=side.index;side['local_packet_number']=side.index-first+1;side.to_csv(dest.with_suffix('.labels.csv'),index=False)
   manifest.append({'file':name,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'bytes':dest.stat().st_size,'source':source,'source_sha256':bundle['metadata']['source_sha256'],'source_packet_range':[first,last],'block':int(block),'partition':'heldout; never fitted or used for threshold selection','label_counts':f.label.value_counts().to_dict(),'advertisement_label_counts':f.loc[(f.frame_type==0)&f.frame_subtype.isin([5,8]),'label'].value_counts().to_dict(),'note':'Same-session/device blocked holdout, not independent capture. Contiguous raw packet range with original timestamps and bytes.'})
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest,indent=2))
if __name__=='__main__':run()
