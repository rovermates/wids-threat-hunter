"""Phase 2 compatibility initializers; Phase 3 uses core.ml_engine factories."""
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC


def make_random_forest(*, random_state=42, **options):
    """Balanced weights are mandatory for the project's RF initializer."""
    if "class_weight" in options:
        raise ValueError("class_weight is fixed to 'balanced'")
    return RandomForestClassifier(class_weight="balanced", random_state=random_state, **options)


def make_svm(*, random_state=42, **options):
    """Balanced SVC without implicit shuffled probability calibration."""
    if "class_weight" in options:
        raise ValueError("class_weight is fixed to 'balanced'")
    if options.get("probability", False):
        raise ValueError("Use explicit chronological calibration rather than SVC probability=True")
    return SVC(class_weight="balanced", random_state=random_state, **options)
