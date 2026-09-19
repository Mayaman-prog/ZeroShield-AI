import json
import unittest

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from src.ml.isolation_forest_poc.data_loader import (
    load_isolation_forest_dataset,
    split_benign_reference_data,
)
from src.ml.isolation_forest_poc.train_isolation_forest import (
    CONTAMINATION,
    FEATURE_SCHEMA_PATH,
    METRICS_PATH,
    MODEL_PATH,
    MODEL_VERSION,
    THRESHOLD_CONFIG_PATH,
    score_records,
)
from src.ml.xgboost_poc.feature_schema import (
    build_feature_schema,
)


class TestIsolationForestPoC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        (
            cls.benign_df,
            cls.attack_df,
            cls.feature_columns,
        ) = load_isolation_forest_dataset()

        (
            cls.benign_train,
            cls.benign_holdout,
        ) = split_benign_reference_data(
            cls.benign_df
        )

        cls.model = joblib.load(
            MODEL_PATH
        )

        with METRICS_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:
            cls.metrics = json.load(
                file
            )

        with FEATURE_SCHEMA_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:
            cls.saved_schema = json.load(
                file
            )

        with THRESHOLD_CONFIG_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:
            cls.threshold_config = json.load(
                file
            )

    def test_01_saved_model_loads(self):

        self.assertIsInstance(
            self.model,
            IsolationForest,
        )

        self.assertEqual(
            self.metrics["model_version"],
            MODEL_VERSION,
        )

    def test_02_feature_schema_matches_xgboost(self):

        shared_schema = (
            build_feature_schema()
        )

        self.assertEqual(
            len(self.feature_columns),
            71,
        )

        self.assertEqual(
            self.feature_columns,
            shared_schema[
                "feature_columns"
            ],
        )

        self.assertEqual(
            self.saved_schema[
                "feature_columns"
            ],
            shared_schema[
                "feature_columns"
            ],
        )

        self.assertEqual(
            self.saved_schema[
                "feature_count"
            ],
            71,
        )

    def test_03_benign_split_is_reproducible(self):

        self.assertEqual(
            len(self.benign_df),
            136800,
        )

        self.assertEqual(
            len(self.benign_train),
            109440,
        )

        self.assertEqual(
            len(self.benign_holdout),
            27360,
        )

        (
            second_train,
            second_holdout,
        ) = split_benign_reference_data(
            self.benign_df
        )

        np.testing.assert_array_equal(
            self.benign_train[
                self.feature_columns
            ].head(100).to_numpy(),
            second_train[
                self.feature_columns
            ].head(100).to_numpy(),
        )

        np.testing.assert_array_equal(
            self.benign_holdout[
                self.feature_columns
            ].head(100).to_numpy(),
            second_holdout[
                self.feature_columns
            ].head(100).to_numpy(),
        )

    def test_04_threshold_configuration_matches_model(self):

        self.assertEqual(
            self.threshold_config[
                "model_version"
            ],
            MODEL_VERSION,
        )

        self.assertAlmostEqual(
            self.threshold_config[
                "contamination"
            ],
            CONTAMINATION,
            places=12,
        )

        self.assertAlmostEqual(
            self.threshold_config[
                "decision_function_threshold"
            ],
            0.0,
            places=12,
        )

        self.assertAlmostEqual(
            self.threshold_config[
                "anomaly_score_threshold"
            ],
            0.0,
            places=12,
        )

        self.assertAlmostEqual(
            self.threshold_config[
                "scikit_learn_offset"
            ],
            float(self.model.offset_),
            places=12,
        )

    def test_05_anomaly_score_semantics(self):

        sample = (
            self.benign_holdout
            .head(1000)
        )

        scores = score_records(
            self.model,
            sample,
            self.feature_columns,
        )

        self.assertEqual(
            len(
                scores[
                    "decision_function"
                ]
            ),
            1000,
        )

        self.assertTrue(
            np.all(
                np.isfinite(
                    scores[
                        "decision_function"
                    ]
                )
            )
        )

        self.assertTrue(
            np.all(
                np.isfinite(
                    scores[
                        "anomaly_score"
                    ]
                )
            )
        )

        np.testing.assert_allclose(
            scores[
                "anomaly_score"
            ],
            -scores[
                "decision_function"
            ],
        )

        expected_flags = (
            scores[
                "decision_function"
            ] < 0
        )

        np.testing.assert_array_equal(
            scores[
                "is_anomalous"
            ],
            expected_flags,
        )

    def test_06_saved_metrics_reproduce(self):

        benign_scores = score_records(
            self.model,
            self.benign_holdout,
            self.feature_columns,
        )

        attack_scores = score_records(
            self.model,
            self.attack_df,
            self.feature_columns,
        )

        benign_rate = float(
            np.mean(
                benign_scores[
                    "is_anomalous"
                ]
            )
        )

        attack_rate = float(
            np.mean(
                attack_scores[
                    "is_anomalous"
                ]
            )
        )

        self.assertAlmostEqual(
            benign_rate,
            self.metrics[
                "heldout_benign"
            ][
                "anomaly_flag_rate"
            ],
            places=12,
        )

        self.assertAlmostEqual(
            attack_rate,
            self.metrics[
                "attack_evaluation"
            ][
                "anomaly_flag_rate"
            ],
            places=12,
        )

        labels = (
            self.attack_df["label2"]
            .astype(str)
            .str.lower()
            .reset_index(drop=True)
        )

        saved_categories = (
            self.metrics[
                "attack_evaluation"
            ][
                "per_attack_category"
            ]
        )

        for label in sorted(
            labels.unique()
        ):

            mask = (
                labels == label
            ).to_numpy()

            actual_count = int(
                np.sum(
                    attack_scores[
                        "is_anomalous"
                    ][mask]
                )
            )

            self.assertEqual(
                actual_count,
                saved_categories[
                    label
                ][
                    "anomalous_rows"
                ],
            )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )