import json
import platform
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest

from src.ml.isolation_forest_poc.data_loader import (
    BENIGN_HOLDOUT_SIZE,
    RANDOM_SEED,
    load_isolation_forest_dataset,
    split_benign_reference_data,
    validate_isolation_forest_dataset,
)
from src.ml.xgboost_poc.feature_schema import TARGET_COLUMN


MODEL_VERSION = "poc-v1"

CONTAMINATION = 0.01

MODEL_DIRECTORY = Path(
    "models/isolation_forest"
)

EXPERIMENT_DIRECTORY = Path(
    "experiments/isolation_forest"
)

MODEL_PATH = (
    MODEL_DIRECTORY
    / "zeroshield_isolation_forest_poc.joblib"
)

METRICS_PATH = (
    EXPERIMENT_DIRECTORY
    / "isolation_forest_metrics.json"
)

FEATURE_SCHEMA_PATH = (
    EXPERIMENT_DIRECTORY
    / "isolation_forest_feature_schema.json"
)

METADATA_PATH = (
    EXPERIMENT_DIRECTORY
    / "isolation_forest_model_metadata.json"
)

THRESHOLD_CONFIG_PATH = (
    EXPERIMENT_DIRECTORY
    / "isolation_forest_threshold_config.json"
)


MODEL_PARAMETERS = {
    "n_estimators": 200,
    "max_samples": "auto",
    "contamination": CONTAMINATION,
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}


def score_records(
    model,
    dataframe,
    feature_columns,
):
    """
    Produce Isolation Forest novelty evidence.

    decision_function:
        Higher values = more normal relative
        to learned reference behaviour.
        Values below 0 are classified as outliers
        using the fitted Isolation Forest threshold.

    anomaly_score:
        Defined by ZeroShield as:
            -decision_function

        Therefore higher values represent
        greater anomaly evidence.

    This score is NOT a maliciousness probability.
    """

    features = dataframe[
        feature_columns
    ].to_numpy(
        dtype=np.float32
    )

    decision_values = model.decision_function(
        features
    )

    raw_score_samples = model.score_samples(
        features
    )

    anomaly_scores = -decision_values

    predictions = model.predict(
        features
    )

    anomaly_flags = predictions == -1

    return {
        "decision_function": decision_values,
        "raw_score_samples": raw_score_samples,
        "anomaly_score": anomaly_scores,
        "is_anomalous": anomaly_flags,
    }


def summarize_scores(values):
    """
    Return reproducible descriptive statistics
    for anomaly-score distributions.
    """

    return {
        "minimum": float(
            np.min(values)
        ),
        "p05": float(
            np.percentile(values, 5)
        ),
        "p25": float(
            np.percentile(values, 25)
        ),
        "median": float(
            np.percentile(values, 50)
        ),
        "p75": float(
            np.percentile(values, 75)
        ),
        "p95": float(
            np.percentile(values, 95)
        ),
        "maximum": float(
            np.max(values)
        ),
    }


def evaluate_attack_categories(
    attack_df,
    attack_scores,
):
    """
    Measure how frequently each attack category
    is flagged as anomalous.

    Attack labels are used only after model fitting
    for evaluation. They do not influence training
    or the PoC threshold.
    """

    labels = (
        attack_df[TARGET_COLUMN]
        .astype(str)
        .str.lower()
        .reset_index(drop=True)
    )

    results = {}

    for label in sorted(
        labels.unique()
    ):
        mask = (
            labels == label
        ).to_numpy()

        category_flags = attack_scores[
            "is_anomalous"
        ][mask]

        category_anomaly_scores = attack_scores[
            "anomaly_score"
        ][mask]

        row_count = int(
            np.sum(mask)
        )

        anomalous_count = int(
            np.sum(category_flags)
        )

        results[label] = {
            "rows": row_count,
            "anomalous_rows": anomalous_count,
            "anomaly_flag_rate": float(
                anomalous_count
                / row_count
            ),
            "anomaly_score_summary": (
                summarize_scores(
                    category_anomaly_scores
                )
            ),
        }

    return results


def save_json(
    path,
    payload,
):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            payload,
            file,
            indent=2,
        )


def main():

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    EXPERIMENT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        benign_df,
        attack_df,
        feature_columns,
    ) = load_isolation_forest_dataset()

    validation = (
        validate_isolation_forest_dataset(
            benign_df,
            attack_df,
            feature_columns,
        )
    )

    (
        benign_train,
        benign_holdout,
    ) = split_benign_reference_data(
        benign_df
    )

    X_train = benign_train[
        feature_columns
    ].to_numpy(
        dtype=np.float32
    )

    model = IsolationForest(
        **MODEL_PARAMETERS
    )

    training_start = (
        time.perf_counter()
    )

    model.fit(
        X_train
    )

    training_seconds = (
        time.perf_counter()
        - training_start
    )

    benign_inference_start = (
        time.perf_counter()
    )

    benign_scores = score_records(
        model,
        benign_holdout,
        feature_columns,
    )

    benign_inference_seconds = (
        time.perf_counter()
        - benign_inference_start
    )

    attack_inference_start = (
        time.perf_counter()
    )

    attack_scores = score_records(
        model,
        attack_df,
        feature_columns,
    )

    attack_inference_seconds = (
        time.perf_counter()
        - attack_inference_start
    )

    benign_anomalous_count = int(
        np.sum(
            benign_scores[
                "is_anomalous"
            ]
        )
    )

    attack_anomalous_count = int(
        np.sum(
            attack_scores[
                "is_anomalous"
            ]
        )
    )

    benign_flag_rate = float(
        benign_anomalous_count
        / len(benign_holdout)
    )

    attack_flag_rate = float(
        attack_anomalous_count
        / len(attack_df)
    )

    per_attack_category = (
        evaluate_attack_categories(
            attack_df,
            attack_scores,
        )
    )

    metrics = {
        "experiment_type": (
            "unsupervised_benign_reference_"
            "novelty_poc"
        ),
        "model_version": MODEL_VERSION,
        "training_reference": (
            "benign DataSense records only"
        ),
        "feature_count": len(
            feature_columns
        ),
        "benign_total_rows": int(
            len(benign_df)
        ),
        "benign_training_rows": int(
            len(benign_train)
        ),
        "benign_holdout_rows": int(
            len(benign_holdout)
        ),
        "attack_evaluation_rows": int(
            len(attack_df)
        ),
        "heldout_benign": {
            "anomalous_rows": (
                benign_anomalous_count
            ),
            "anomaly_flag_rate": (
                benign_flag_rate
            ),
            "anomaly_score_summary": (
                summarize_scores(
                    benign_scores[
                        "anomaly_score"
                    ]
                )
            ),
        },
        "attack_evaluation": {
            "anomalous_rows": (
                attack_anomalous_count
            ),
            "anomaly_flag_rate": (
                attack_flag_rate
            ),
            "anomaly_score_summary": (
                summarize_scores(
                    attack_scores[
                        "anomaly_score"
                    ]
                )
            ),
            "per_attack_category": (
                per_attack_category
            ),
        },
        "timing_seconds": {
            "training": float(
                training_seconds
            ),
            "benign_holdout_inference": (
                float(
                    benign_inference_seconds
                )
            ),
            "attack_inference": float(
                attack_inference_seconds
            ),
        },
        "interpretation": (
            "Anomaly flag rates describe how often "
            "records fall outside the learned benign "
            "reference boundary. They are not "
            "maliciousness probabilities and do not "
            "prove previously unseen attacks."
        ),
    }

    feature_schema = {
        "schema_version": MODEL_VERSION,
        "schema_source": (
            "src/ml/xgboost_poc/"
            "feature_schema.py"
        ),
        "feature_count": len(
            feature_columns
        ),
        "feature_columns": (
            feature_columns
        ),
        "feature_semantics": (
            "Same leakage-controlled numeric "
            "DataSense feature definition used "
            "by the XGBoost PoC."
        ),
    }

    threshold_config = {
        "model_version": MODEL_VERSION,
        "contamination": CONTAMINATION,
        "contamination_interpretation": (
            "Fixed 1 percent PoC reference "
            "contamination assumption. This value "
            "was selected before attack evaluation "
            "and was not tuned using attack labels."
        ),
        "scikit_learn_offset": float(
            model.offset_
        ),
        "decision_function_threshold": 0.0,
        "decision_function_rule": (
            "decision_function < 0 means "
            "outlier under the fitted model."
        ),
        "anomaly_score_definition": (
            "anomaly_score = "
            "-decision_function"
        ),
        "anomaly_score_threshold": 0.0,
        "anomaly_rule": (
            "anomaly_score > 0 is flagged "
            "as anomalous."
        ),
        "formal_threshold_calibration": (
            "Not performed in this initial PoC. "
            "A later planner task will calibrate "
            "the novelty threshold using validation "
            "data only."
        ),
    }

    metadata = {
        "model_name": (
            "ZeroShield Isolation Forest "
            "Novelty PoC"
        ),
        "model_version": MODEL_VERSION,
        "model_role": (
            "anomaly_novelty_evidence"
        ),
        "algorithm": (
            "IsolationForest"
        ),
        "training_reference": (
            "benign_only"
        ),
        "target_column_retained_for_evaluation": (
            TARGET_COLUMN
        ),
        "interpretation_scope": (
            "The model measures unusual behaviour "
            "relative to learned benign reference "
            "data. It does not produce a "
            "maliciousness probability, does not "
            "identify a known attack class and "
            "does not independently prove a "
            "zero-day attack."
        ),
        "random_seed": RANDOM_SEED,
        "benign_holdout_size": (
            BENIGN_HOLDOUT_SIZE
        ),
        "training_rows": int(
            len(benign_train)
        ),
        "benign_holdout_rows": int(
            len(benign_holdout)
        ),
        "attack_evaluation_rows": int(
            len(attack_df)
        ),
        "feature_count": len(
            feature_columns
        ),
        "model_parameters": (
            MODEL_PARAMETERS
        ),
        "software_versions": {
            "python": (
                platform.python_version()
            ),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": (
                sklearn.__version__
            ),
            "joblib": (
                joblib.__version__
            ),
        },
        "validation_summary": (
            validation
        ),
        "model_path": str(
            MODEL_PATH
        ),
        "metrics_path": str(
            METRICS_PATH
        ),
        "feature_schema_path": str(
            FEATURE_SCHEMA_PATH
        ),
        "threshold_config_path": str(
            THRESHOLD_CONFIG_PATH
        ),
    }

    joblib.dump(
        model,
        MODEL_PATH,
    )

    save_json(
        METRICS_PATH,
        metrics,
    )

    save_json(
        FEATURE_SCHEMA_PATH,
        feature_schema,
    )

    save_json(
        METADATA_PATH,
        metadata,
    )

    save_json(
        THRESHOLD_CONFIG_PATH,
        threshold_config,
    )

    print(
        "ZeroShield Isolation Forest "
        "PoC training complete"
    )

    print(
        f"Model version: "
        f"{MODEL_VERSION}"
    )

    print(
        f"Features: "
        f"{len(feature_columns)}"
    )

    print(
        f"Benign training rows: "
        f"{len(benign_train)}"
    )

    print(
        f"Held-out benign rows: "
        f"{len(benign_holdout)}"
    )

    print(
        f"Attack evaluation rows: "
        f"{len(attack_df)}"
    )

    print(
        f"Contamination: "
        f"{CONTAMINATION}"
    )

    print(
        f"Isolation Forest offset: "
        f"{model.offset_:.6f}"
    )

    print(
        f"Held-out benign anomaly "
        f"flag rate: "
        f"{benign_flag_rate:.4f}"
    )

    print(
        f"Attack anomaly flag rate: "
        f"{attack_flag_rate:.4f}"
    )

    print(
        f"Training time: "
        f"{training_seconds:.2f} seconds"
    )

    print()

    print(
        "Per-attack-category anomaly "
        "flag rates:"
    )

    for (
        label,
        result,
    ) in per_attack_category.items():

        print(
            f"  {label}: "
            f"{result['anomaly_flag_rate']:.4f} "
            f"({result['anomalous_rows']}/"
            f"{result['rows']})"
        )

    print()

    print(
        "Interpretation:"
    )

    print(
        "Isolation Forest output is anomaly/"
        "novelty evidence relative to learned "
        "benign reference behaviour."
    )

    print(
        "It is NOT a maliciousness probability "
        "and does NOT independently prove a "
        "previously unseen or zero-day attack."
    )

    print()

    print(
        f"Model saved to: "
        f"{MODEL_PATH}"
    )

    print(
        f"Metrics saved to: "
        f"{METRICS_PATH}"
    )

    print(
        f"Metadata saved to: "
        f"{METADATA_PATH}"
    )

    print(
        f"Threshold config saved to: "
        f"{THRESHOLD_CONFIG_PATH}"
    )


if __name__ == "__main__":
    main()