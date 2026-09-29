"""Combine a sensitive detector with a separately fitted behavior confirmer."""
import numpy as np
from sklearn.base import BaseEstimator,ClassifierMixin

class ConfirmedClassifier(ClassifierMixin,BaseEstimator):
    def __init__(self,sensitive,confirmer,sensitive_features,confirm_features,alert_threshold,confirmation_threshold,recovery_threshold):
        self.sensitive=sensitive;self.confirmer=confirmer
        self.sensitive_features=sensitive_features;self.confirm_features=confirm_features
        self.alert_threshold=alert_threshold;self.confirmation_threshold=confirmation_threshold
        self.recovery_threshold=recovery_threshold;self.classes_=np.array([0,1])

    @property
    def named_steps(self):
        return self.confirmer.named_steps

    def fit(self,x,y,**kwargs):
        raise ValueError('Fit component models separately on development data')

    def predict_proba(self,x):
        a=self.sensitive.predict_proba(x[self.sensitive_features])[:,1]
        b=self.confirmer.predict_proba(x[self.confirm_features])[:,1]
        # A zero confirmation threshold means no confirmation gate. Avoid 0/0
        # for tree classifiers that can emit exact zero scores.
        confirmed=a/self.alert_threshold if self.confirmation_threshold==0 else np.minimum(a/self.alert_threshold,b/self.confirmation_threshold)
        support=np.maximum(confirmed,b/self.recovery_threshold)
        # Threshold .5 represents confirmation or recovery. This is NOT probability.
        positive=np.clip(.5*support,0,1)
        return np.column_stack([1-positive,positive])

    def predict(self,x):
        return (self.predict_proba(x)[:,1]>=.5).astype(int)
