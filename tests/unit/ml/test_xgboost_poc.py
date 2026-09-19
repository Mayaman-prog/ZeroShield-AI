import json
import unittest
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    f1_score,
)
from xgboost import XGBClassifier

from src.ml.xgboost_poc.data_loader import CLASS_MAPPING
from src.ml.xgboost_poc.split_dataset import (
    create_known_class_split,
)


MODEL_PATH = Path(
    "models/xgboost/zeroshield_xgboost_known_class_poc.json"
)

METRICS_PATH = Path(
    "experiments/xgboost/xgboost_known_class_metrics.json"
)

FEATURE_SCHEMA_PATH = Path(
    "experiments/xgboost/xgboost_feature_schema.json"
)


class TestXGBoostKnownClassPoC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model file not found: {MODEL_PATH}"
            )

        if not METRICS_PATH.exists():
            raise FileNotFoundError(
                f"Metrics file not found: {METRICS_PATH}"
            )

        if not FEATURE_SCHEMA_PATH.exists():
            raise FileNotFoundError(
                f"Feature schema not found: "
                f"{FEATURE_SCHEMA_PATH}"
            )

        (
            cls.X_train,
            cls.X_test,
            cls.y_train,
            cls.y_test,
            cls.feature_columns
        ) = create_known_class_split()

        cls.saved_metrics = json.loads(
            METRICS_PATH.read_text(
                encoding="utf-8"
            )
        )

        cls.saved_schema = json.loads(
            FEATURE_SCHEMA_PATH.read_text(
                encoding="utf-8"
            )
        )

        cls.model = XGBClassifier()

        cls.model.load_model(
            MODEL_PATH
        )

        cls.predictions = cls.model.predict(
            cls.X_test
        )

        cls.probabilities = cls.model.predict_proba(
            cls.X_test
        )

    def test_feature_schema_matches(self):

        self.assertEqual(
            self.saved_schema["feature_count"],
            71
        )

        self.assertEqual(
            self.saved_schema["feature_columns"],
            self.feature_columns
        )

    def test_reloaded_model_prediction_shape(self):

        self.assertEqual(
            len(self.predictions),
            len(self.X_test)
        )

        self.assertEqual(
            self.probabilities.shape,
            (
                len(self.X_test),
                len(CLASS_MAPPING)
            )
        )

    def test_probabilities_cover_trained_classes_only(self):

        self.assertEqual(
            self.probabilities.shape[1],
            8
        )

        row_sums = self.probabilities.sum(
            axis=1
        )

        self.assertTrue(
            np.allclose(
                row_sums,
                1.0,
                atol=1e-5
            )
        )

    def test_reloaded_accuracy_matches_saved_metrics(self):

        accuracy = accuracy_score(
            self.y_test,
            self.predictions
        )

        self.assertAlmostEqual(
            accuracy,
            self.saved_metrics["accuracy"],
            places=10
        )

    def test_reloaded_macro_f1_matches_saved_metrics(self):

        macro_f1 = f1_score(
            self.y_test,
            self.predictions,
            average="macro"
        )

        self.assertAlmostEqual(
            macro_f1,
            self.saved_metrics["macro_f1"],
            places=10
        )

    def test_known_class_mapping_is_preserved(self):

        self.assertEqual(
            CLASS_MAPPING,
            {
                "benign": 0,
                "bruteforce": 1,
                "ddos": 2,
                "dos": 3,
                "malware": 4,
                "mitm": 5,
                "recon": 6,
                "web": 7,
            }
        )


if __name__ == "__main__":
    unittest.main()