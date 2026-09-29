"""Deployment contract: unseen traffic is not silently classified as benign."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import pandas as pd
from backend.config import DashboardSettings, PROJECT_ROOT
from backend.core.ml_engine import InferenceSession, PROTOCOL_FIELDS
from backend.dashboard.analysis import analyze_capture
from backend.dashboard.store import DashboardStore
from backend.tests.test_detection_improvement import raw_fixture

ARTIFACT = PROJECT_ROOT / 'backend/models/rogue_advertiser_v6/trained_ensemble.joblib'


def mixed_frames():
    raw = raw_fixture()
    for aliases in PROTOCOL_FIELDS.values():
        if aliases[1] not in raw:
            raw[aliases[1]] = '0'
    raw.loc[raw.index[::2], 'frame_type'] = 2
    raw.loc[raw.index[::2], 'frame_subtype'] = 0
    return raw


class RogueScopeTests(unittest.TestCase):
    def test_context_only_scores_are_missing_and_chunking_preserves_predictions(self):
        raw = mixed_frames()
        whole = InferenceSession(ARTIFACT).predict_chunk(raw)
        session = InferenceSession(ARTIFACT)
        chunks = pd.concat([session.predict_chunk(raw.iloc[:23]), session.predict_chunk(raw.iloc[23:])])
        pd.testing.assert_frame_equal(whole, chunks)
        self.assertTrue(whole.iloc[::2].detection_score.isna().all())
        self.assertFalse(whole.iloc[::2].evaluated.any())
        self.assertTrue(whole.iloc[1::2].evaluated.all())
        self.assertTrue(whole.iloc[1::2].detection_score.between(0, 1).all())

    def test_capture_without_advertisements_is_unknown_not_low_risk(self):
        raw = mixed_frames().iloc[::2].copy()
        with tempfile.TemporaryDirectory() as folder:
            settings = DashboardSettings(model_path=ARTIFACT, state_dir=Path(folder))
            store = DashboardStore(Path(folder) / 'test.sqlite')
            with patch('backend.dashboard.analysis.iter_awid_chunks', return_value=iter_chunks(raw)):
                capture = analyze_capture(Path('fixture.csv'), filename='fixture.csv', variant='CLS',
                    analysis_id='test', settings=settings, store=store, progress=lambda n: None)
            self.assertEqual(capture['threat_level'], 'unknown')
            self.assertEqual(capture['evaluated_packets'], 0)
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM packets WHERE attack_type='not_evaluated'").fetchone()[0], len(raw))
                self.assertEqual(db.execute('SELECT COUNT(*) FROM threats').fetchone()[0], 0)


def iter_chunks(raw):
    yield raw
