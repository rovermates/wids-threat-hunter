"""Reproducible benign undersampling of an already-isolated training split."""
from math import floor, isfinite
from numbers import Integral, Real
from random import Random

from backend.core.chronological_split import _times, split_temporal_features


def undersample_training(train, *, benign_label="normal", benign_to_attack_ratio=1.0,
                         random_state=42):
    """Return (sampled training copy, audit report); preserve all attack rows.

    Call only after splitting and calculating temporal features on full traffic.
    The ratio caps benign rows relative to ALL non-benign rows, not each class.
    """
    if (isinstance(benign_to_attack_ratio, bool) or
            not isinstance(benign_to_attack_ratio, Real) or
            not isfinite(benign_to_attack_ratio) or benign_to_attack_ratio <= 0):
        raise ValueError("benign_to_attack_ratio must be finite and positive")
    if isinstance(random_state, bool) or not isinstance(random_state, Integral):
        raise ValueError("random_state must be an integer seed")
    if not isinstance(benign_label, str) or not benign_label:
        raise ValueError("benign_label must be a nonempty string")
    _times(train)
    if "label" not in train.columns or train.empty:
        raise ValueError("Training data must be nonempty and contain label")
    labels = train["label"]
    if any(not isinstance(label, str) or not label for label in labels):
        raise ValueError("Training labels must be nonempty strings; unlabelled captures cannot be balanced")
    benign = [i for i, label in enumerate(labels) if label == benign_label]
    attacks = [i for i, label in enumerate(labels) if label != benign_label]
    if not benign or not attacks:
        raise ValueError("Training requires both benign and attack observations; do not borrow held-out rows")
    # Avoid overflow for large finite ratios; never oversample.
    keep = (len(benign) if benign_to_attack_ratio >= len(benign) / len(attacks)
            else floor(benign_to_attack_ratio * len(attacks)))
    if keep < 1:
        raise ValueError("Ratio would remove every benign observation")
    selected = sorted(attacks + Random(int(random_state)).sample(benign, keep))
    sampled = train.iloc[selected].copy()
    report = {
        "benign_label": benign_label, "benign_to_attack_ratio": float(benign_to_attack_ratio),
        "random_state": int(random_state), "rows_before": len(train), "rows_after": len(sampled),
        "removed_benign": len(benign) - keep,
        "class_counts_before": {k: int(v) for k, v in labels.value_counts().items()},
        "class_counts_after": {k: int(v) for k, v in sampled["label"].value_counts().items()},
    }
    return sampled, report


def prepare_training_partitions(raw, *, train_fraction=.70, validation_fraction=.15,
                                rssi_window=100, benign_label="normal",
                                benign_to_attack_ratio=1.0, random_state=42):
    """Phase 2 workflow: split, compute full-traffic features, sample train only."""
    parts = split_temporal_features(raw, train_fraction=train_fraction,
                                    validation_fraction=validation_fraction,
                                    rssi_window=rssi_window)
    parts["train"], report = undersample_training(
        parts["train"], benign_label=benign_label,
        benign_to_attack_ratio=benign_to_attack_ratio, random_state=random_state)
    return parts, report
