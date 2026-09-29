"""Causal per-BSSID behavior. Identifiers key state but never become model inputs."""
from collections import Counter, deque
from math import sqrt
import numpy as np
import pandas as pd

ALIASES = {
    'length': ('frame.len',), 'protected': ('wlan.fc.protected',), 'retry': ('wlan.fc.retry',),
    'privacy': ('wlan_mgt.fixed.capabilities.privacy','wlan.fixed.capabilities.privacy'),
    'channel': ('wlan_mgt.ds.current_channel','wlan.ds.current_channel'),
    'beacon_tu': ('wlan_mgt.fixed.beacon','wlan.fixed.beacon'),
    'auth_algorithm': ('wlan_mgt.fixed.auth.alg','wlan.fixed.auth.alg'),
}
CATEGORIES = ['beacon','probe','authentication','association','deauth','data','protected','retry','broadcast']
BEHAVIOR_FEATURES = ['ap_window_count','ap_window_span_s','ap_length_mean','ap_length_std','ap_unique_sources',
                     'ap_security_changes','ap_channel_changes','ap_beacon_interval_cv'] + ['ap_'+n+'_fraction' for n in CATEGORIES]
HEADER_FEATURES = ['advertised_privacy','advertised_channel','advertised_beacon_tu','auth_algorithm']
AP_FEATURES = BEHAVIOR_FEATURES + HEADER_FEATURES


def number(raw, aliases):
    name = next((n for n in aliases if n in raw), None)
    if name is None:
        return pd.Series(np.nan,index=raw.index)
    values = raw[name].astype('string').str.split(',').str[0].replace({'?':pd.NA,'':pd.NA,
        'True':'1','False':'0','true':'1','false':'0','<MISSING>':pd.NA})
    return pd.to_numeric(values,errors='raise').astype(float)


class APBehaviorBuilder:
    def __init__(self, window=100, max_bssids=100000):
        if not isinstance(window,int) or isinstance(window,bool) or window < 2:
            raise ValueError('Window must be an integer >= 2')
        self.window=window; self.max_bssids=max_bssids; self.states={}; self.last_time=None

    def transform(self, raw):
        numeric={k:number(raw,v) for k,v in ALIASES.items()}
        selected=raw[['timestamp_ns','bssid','source_mac','destination_mac','frame_type','frame_subtype']].copy()
        for k,v in numeric.items(): selected[k]=v
        result=[]
        for values in selected.itertuples(index=False,name=None):
            t,mac,src,dst,kind,sub,length,protected,retry,privacy,channel,beacon_tu,auth=values
            kind=-1 if pd.isna(kind) else int(kind)
            sub=-1 if pd.isna(sub) else int(sub)
            t=int(t)
            if self.last_time is not None and t < self.last_time: raise ValueError('Unordered AP history')
            self.last_time=t
            header=[privacy,channel,beacon_tu,auth]
            if pd.isna(mac) or not mac or str(mac).lower()=='ff:ff:ff:ff:ff:ff':
                result.append([np.nan]*len(BEHAVIOR_FEATURES)+header); continue
            mac=str(mac).lower(); src=None if pd.isna(src) else str(src).lower()
            broadcast=not pd.isna(dst) and str(dst).lower()=='ff:ff:ff:ff:ff:ff'
            if mac not in self.states:
                if len(self.states)>=self.max_bssids: raise ValueError('AP state limit exceeded')
                self.states[mac]={'frames':deque(),'counts':np.zeros(len(CATEGORIES),dtype=int),'sources':Counter(),
                    'sum':0.,'sum2':0.,'lengths':0,'sec_changes':0,'ch_changes':0,'privacy':None,'channel':None,'beacon':None,'intervals':deque(maxlen=20)}
            state=self.states[mac]; frames=state['frames']
            flags=np.array([kind==0 and sub==8,kind==0 and sub in (4,5),kind==0 and sub==11,
                kind==0 and sub in (0,1,2,3),kind==0 and sub in (10,12),kind==2,
                protected==1,retry==1,broadcast],dtype=int)
            sec_change=int(not np.isnan(privacy) and state['privacy'] is not None and privacy!=state['privacy'])
            ch_change=int(not np.isnan(channel) and state['channel'] is not None and channel!=state['channel'])
            if not np.isnan(privacy):state['privacy']=privacy
            if not np.isnan(channel):state['channel']=channel
            if flags[0]:
                if state['beacon'] is not None:state['intervals'].append((t-state['beacon'])/1e9)
                state['beacon']=t
            frames.append((t,flags,src,length,sec_change,ch_change))
            state['counts']+=flags
            state['sec_changes']+=sec_change;state['ch_changes']+=ch_change
            if src:state['sources'][src]+=1
            if not np.isnan(length):state['sum']+=length;state['sum2']+=length*length;state['lengths']+=1
            if len(frames)>self.window:
                _,old_flags,old_src,old_len,old_sec,old_ch=frames.popleft();state['counts']-=old_flags
                state['sec_changes']-=old_sec;state['ch_changes']-=old_ch
                if old_src:
                    state['sources'][old_src]-=1
                    if not state['sources'][old_src]:del state['sources'][old_src]
                if not np.isnan(old_len):state['sum']-=old_len;state['sum2']-=old_len*old_len;state['lengths']-=1
            n=state['lengths']; mean=state['sum']/n if n else np.nan
            std=sqrt(max(0,state['sum2']/n-mean*mean)) if n else np.nan
            intervals=state['intervals']; cv=np.nan
            if len(intervals)>=2:
                average=sum(intervals)/len(intervals)
                if average>0:cv=sqrt(sum((v-average)**2 for v in intervals)/len(intervals))/average
            result.append([len(frames),(t-frames[0][0])/1e9,mean,std,len(state['sources']),
                state['sec_changes'],state['ch_changes'],cv,
                *(state['counts']/len(frames)),*header])
        return pd.DataFrame(result,index=raw.index,columns=AP_FEATURES,dtype=float)
