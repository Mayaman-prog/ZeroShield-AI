import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
import xgboost
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from xgboost import XGBClassifier

from src.ml.xgboost_poc.data_loader import CLASS_MAPPING
from src.ml.xgboost_poc.split_dataset import (
    RANDOM_SEED,
    TEST_SIZE,
    create_known_class_split,
)

# Output directories

MODEL_DIRECTORY = Path("models/xgboost")
EXPERIMENT_DIRECTORY = Path("experiments/xgboost")


# Output files

MODEL_PATH = (
    MODEL_DIRECTORY
    / "zeroshield_xgboost_known_class_poc.json"
)

METRICS_PATH = (
    EXPERIMENT_DIRECTORY
    / "xgboost_known_class_metrics.json"
)

FEATURE_SCHEMA_PATH = (
    EXPERIMENT_DIRECTORY
    / "xgboost_feature_schema.json"
)

METADATA_PATH = (
    EXPERIMENT_DIRECTORY
    / "xgboost_model_metadata.json"
)


# Model version

MODEL_VERSION = "poc-v1"


# Fixed PoC model parameters

MODEL_PARAMETERS = {
    "objective": "multi:softprob",
    "num_class": len(CLASS_MAPPING),
    "n_estimators": 200,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "tree_method": "hist",
    "eval_metric": "mlogloss",
    "random_state": RANDOM_SEED,
    "n_jobs": -1,
}


def main():
    """
    Train and evaluate the initial ZeroShield XGBoost
    known-class proof of concept.

    Important:
    XGBoost output represents supervised evidence only
    for classes that were represented during training.

    It does not represent novelty evidence or a universal
    probability that traffic is malicious.
    """

    # Prepare output directories

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    EXPERIMENT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    # Load deterministic train/test split

    print("Loading and splitting dataset...")

    (
        X_train,
        X_test,
        y_train,
        y_test,
        feature_columns
    ) = create_known_class_split()

    # Create model

    print()
    print("Training XGBoost known-class model...")

    model = XGBClassifier(
        **MODEL_PARAMETERS
    )

    # Train model

    training_start = time.perf_counter()

    model.fit(
        X_train,
        y_train
    )

    training_seconds = (
        time.perf_counter()
        - training_start
    )

    print(
        f"Training completed in "
        f"{training_seconds:.2f} seconds."
    )

    # Run inference

    print("Running inference on test set...")

    inference_start = time.perf_counter()

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )

    inference_seconds = (
        time.perf_counter()
        - inference_start
    )

    # Confirm probability output structure

    expected_probability_shape = (
        len(X_test),
        len(CLASS_MAPPING)
    )

    if probabilities.shape != expected_probability_shape:
        raise ValueError(
            "Unexpected probability output shape. "
            f"Expected {expected_probability_shape}, "
            f"received {probabilities.shape}."
        )

    # Build class names

    reverse_mapping = {
        value: key
        for key, value in CLASS_MAPPING.items()
    }

    class_ids = sorted(
        reverse_mapping.keys()
    )

    class_names = [
        reverse_mapping[class_id]
        for class_id in class_ids
    ]

    # Classification report

    report = classification_report(
        y_test,
        predictions,
        labels=class_ids,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )

    # Confusion matrix

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=class_ids
    )

    # Main evaluation metrics

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    balanced_accuracy = balanced_accuracy_score(
        y_test,
        predictions
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro"
    )

    weighted_f1 = f1_score(
        y_test,
        predictions,
        average="weighted"
    )

    average_inference_ms = (
        inference_seconds
        / len(X_test)
        * 1000
    )

    # Metrics record

    metrics = {
        "experiment_type":
            "supervised_known_class_poc",

        "model_version":
            MODEL_VERSION,

        "interpretation_scope":
            (
                "Predictions and probabilities apply "
                "only to classes represented during "
                "XGBoost training."
            ),

        "training_rows":
            len(X_train),

        "testing_rows":
            len(X_test),

        "feature_count":
            len(feature_columns),

        "class_count":
            len(CLASS_MAPPING),

        "accuracy":
            float(accuracy),

        "balanced_accuracy":
            float(balanced_accuracy),

        "macro_f1":
            float(macro_f1),

        "weighted_f1":
            float(weighted_f1),

        "training_seconds":
            float(training_seconds),

        "inference_seconds":
            float(inference_seconds),

        "average_inference_ms_per_record":
            float(average_inference_ms),

        "classification_report":
            report,

        "confusion_matrix":
            matrix.tolist(),

        "class_mapping":
            CLASS_MAPPING
    }

    # Feature schema

    feature_schema = {
        "schema_version":
            "poc-v1",

        "feature_count":
            len(feature_columns),

        "feature_columns":
            feature_columns
    }

    # Model metadata

    metadata = {
        "model_name":
            "ZeroShield XGBoost Known-Class PoC",

        "model_version":
            MODEL_VERSION,

        "model_role":
            "supervised_known_class_evidence",

        "target":
            "label2",

        "interpretation_scope":
            (
                "This model provides evidence only "
                "for classes represented during training. "
                "Its probabilities must not be interpreted "
                "as novelty scores or universal maliciousness "
                "probabilities."
            ),

        "random_seed":
            RANDOM_SEED,

        "test_size":
            TEST_SIZE,

        "training_rows":
            len(X_train),

        "testing_rows":
            len(X_test),

        "feature_count":
            len(feature_columns),

        "class_count":
            len(CLASS_MAPPING),

        "model_parameters":
            MODEL_PARAMETERS,

        "software_versions": {
            "numpy":
                np.__version__,

            "pandas":
                pd.__version__,

            "scikit_learn":
                sklearn.__version__,

            "xgboost":
                xgboost.__version__,
        },

        "class_mapping":
            CLASS_MAPPING,

        "model_file":
            str(MODEL_PATH),

        "feature_schema_file":
            str(FEATURE_SCHEMA_PATH),

        "metrics_file":
            str(METRICS_PATH),
    }

    # Save model

    model.save_model(
        MODEL_PATH
    )

    # Save metrics

    METRICS_PATH.write_text(
        json.dumps(
            metrics,
            indent=2
        ),
        encoding="utf-8"
    )

    # Save feature schema

    FEATURE_SCHEMA_PATH.write_text(
        json.dumps(
            feature_schema,
            indent=2
        ),
        encoding="utf-8"
    )

    # Save metadata

    METADATA_PATH.write_text(
        json.dumps(
            metadata,
            indent=2
        ),
        encoding="utf-8"
    )

    # Console summary

    print()
    print("Known-class XGBoost PoC completed.")

    print(
        f"Model version: "
        f"{MODEL_VERSION}"
    )

    print(
        f"Accuracy: "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"Balanced accuracy: "
        f"{metrics['balanced_accuracy']:.4f}"
    )

    print(
        f"Macro F1: "
        f"{metrics['macro_f1']:.4f}"
    )

    print(
        f"Weighted F1: "
        f"{metrics['weighted_f1']:.4f}"
    )

    print(
        f"Training time: "
        f"{metrics['training_seconds']:.2f} seconds"
    )

    print(
        f"Average inference time: "
        f"{metrics['average_inference_ms_per_record']:.6f} ms/record"
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
        f"Feature schema saved to: "
        f"{FEATURE_SCHEMA_PATH}"
    )

    print(
        f"Metadata saved to: "
        f"{METADATA_PATH}"
    )

    print()

    print(
        "IMPORTANT: XGBoost output represents "
        "known trained-class evidence only."
    )

    print(
        "It must not be interpreted as novelty evidence "
        "or a universal maliciousness probability."
    )


if __name__ == "__main__":
    main()