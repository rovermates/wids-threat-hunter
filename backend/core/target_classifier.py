"""Expose summed target-family scores through the binary inference contract."""
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin


class TargetFamilyClassifier(ClassifierMixin, BaseEstimator):
    def __init__(self, estimator, target_labels):
        self.estimator = estimator
        self.target_labels = target_labels
        self.classes_ = np.array([0, 1])

    @property
    def named_steps(self):
        return self.estimator.named_steps

    def fit(self, x, y, **kwargs):
        self.estimator.fit(x, y, **kwargs)
        self.classes_ = np.array([0, 1])
        return self

    def predict_proba(self, x):
        scores = self.estimator.predict_proba(x)
        mask = np.isin(self.estimator.classes_, self.target_labels)
        positive = scores[:, mask].sum(axis=1)
        return np.column_stack([1-positive, positive])

    def predict(self, x):
        return (self.predict_proba(x)[:, 1] >= .5).astype(int)
