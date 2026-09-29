"""Refine evidence without rescaling the deployed score's decision threshold."""
import numpy as np
from sklearn.base import BaseEstimator,ClassifierMixin

def refine_scores(base,evidence,threshold,confirmation,recovery):
    confirmed=base if confirmation==0 else np.minimum(base,threshold*evidence/confirmation)
    if recovery is not None:confirmed=np.maximum(confirmed,threshold*evidence/recovery)
    return np.clip(confirmed,0,1)

class EvidenceRefiner(ClassifierMixin,BaseEstimator):
    def __init__(self,base,evidence,features,threshold,confirmation=0.,recovery=None):
        self.base=base;self.evidence=evidence;self.features=features;self.threshold=threshold
        self.confirmation=confirmation;self.recovery=recovery;self.classes_=np.array([0,1])

    @property
    def named_steps(self):return self.evidence.named_steps

    def fit(self,x,y,**kwargs):raise ValueError('Train components separately')

    def predict_proba(self,x):
        a=self.base.predict_proba(x[self.features])[:,1]
        b=self.evidence.predict_proba(x[self.features])[:,1]
        score=refine_scores(a,b,self.threshold,self.confirmation,self.recovery)
        return np.column_stack([1-score,score])

    def predict(self,x):return (self.predict_proba(x)[:,1]>=self.threshold).astype(int)
