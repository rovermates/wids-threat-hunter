import unittest

from pandas.testing import assert_frame_equal

from backend.core.class_balance import undersample_training, prepare_training_partitions
from backend.core.chronological_split import split_temporal_features
from backend.core.models import make_random_forest, make_svm
from backend.tests.test_chronological_split import sample


def labelled():
    data = sample(range(100))
    data["label"] = ["injection" if i % 20 == 0 else
                     "impersonation" if i % 20 == 1 else "normal" for i in range(100)]
    return data


class ClassBalanceTests(unittest.TestCase):
    def test_preserves_attacks_order_duplicate_indices_and_input(self):
        data = labelled()
        data.index = [i // 2 for i in range(100)]
        before = data.copy(deep=True)
        sampled, report = undersample_training(data)
        self.assertEqual(report["class_counts_after"], {"normal": 10, "injection": 5, "impersonation": 5})
        assert_frame_equal(sampled[sampled.label != "normal"], data[data.label != "normal"])
        self.assertTrue(sampled.timestamp_ns.is_monotonic_increasing)
        self.assertEqual(len(sampled), 20)
        assert_frame_equal(data, before)
        assert_frame_equal(sampled, undersample_training(data)[0])
        self.assertNotEqual(sampled.timestamp_ns.tolist(), undersample_training(data, random_state=43)[0].timestamp_ns.tolist())

    def test_ratio_and_no_oversampling(self):
        result, _ = undersample_training(labelled(), benign_to_attack_ratio=2)
        self.assertEqual((result.label == "normal").sum(), 20)
        data = labelled()
        assert_frame_equal(data, undersample_training(data, benign_to_attack_ratio=100)[0])

    def test_invalid_inputs(self):
        for ratio in (0, -1, float("nan"), float("inf"), True, .001):
            with self.assertRaises(ValueError):
                undersample_training(labelled(), benign_to_attack_ratio=ratio)
        for label in (None, "", "normal", "attack"):
            data = labelled()
            data["label"] = label
            with self.assertRaises(ValueError):
                undersample_training(data)
        with self.assertRaises(ValueError):
            undersample_training(labelled().iloc[::-1])
        with self.assertRaises(ValueError):
            undersample_training(labelled(), random_state=None)

    def test_only_train_sampled_after_feature_calculation(self):
        raw = labelled()
        baseline = split_temporal_features(raw)
        parts, report = prepare_training_partitions(raw)
        for name in ("validation", "test"):
            assert_frame_equal(parts[name], baseline[name])
        assert_frame_equal(parts["train"], baseline["train"].loc[parts["train"].index])
        self.assertEqual(report["rows_before"], 70)
        self.assertEqual(report["rows_after"], 16)
        changed = raw.copy()
        changed.loc[70:, "label"] = "normal"
        changed.loc[70:, "rssi_dbm"] = -100
        assert_frame_equal(parts["train"], prepare_training_partitions(changed)[0]["train"])

    def test_initializers_and_small_real_fit(self):
        # Multiclass counts remain unequal even after aggregate benign balancing.
        x = [[i / 8] for i in range(8)]
        y = ["normal"] * 4 + ["injection"] * 3 + ["impersonation"]
        forest = make_random_forest(n_estimators=3, max_depth=2)
        svm = make_svm(kernel="linear")
        for model in (forest, svm):
            self.assertEqual(model.class_weight, "balanced")
            model.fit(x, y)
            self.assertEqual(len(model.predict(x)), len(x))
        weights = dict(zip(svm.classes_, svm.class_weight_))
        self.assertAlmostEqual(weights["normal"], 8 / 12)
        self.assertAlmostEqual(weights["impersonation"], 8 / 3)
        for factory in (make_random_forest, make_svm):
            with self.assertRaises(ValueError):
                factory(class_weight=None)
        with self.assertRaises(ValueError):
            make_svm(probability=True)


if __name__ == "__main__":
    unittest.main()
