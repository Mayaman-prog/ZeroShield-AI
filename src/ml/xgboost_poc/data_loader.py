import json

import numpy as np
import pandas as pd

from src.ml.xgboost_poc.feature_schema import (
    ATTACK_CSV,
    BENIGN_CSV,
    TARGET_COLUMN,
    build_feature_schema,
)


# Stable mapping for this known-class PoC.
# The numeric values are identifiers only.
CLASS_MAPPING = {
    "benign": 0,
    "bruteforce": 1,
    "ddos": 2,
    "dos": 3,
    "malware": 4,
    "mitm": 5,
    "recon": 6,
    "web": 7,
}


def load_known_class_dataset():
    """
    Load only the selected numeric features and label2.

    This avoids loading excluded metadata and label columns
    that are not needed for the XGBoost known-class PoC.
    """

    schema = build_feature_schema()

    feature_columns = schema["feature_columns"]

    columns_to_load = (
        feature_columns
        + [TARGET_COLUMN]
    )

    print("Loading attack dataset...")

    attack_df = pd.read_csv(
        ATTACK_CSV,
        usecols=columns_to_load
    )

    print("Loading benign dataset...")

    benign_df = pd.read_csv(
        BENIGN_CSV,
        usecols=columns_to_load
    )

    dataset = pd.concat(
        [attack_df, benign_df],
        ignore_index=True
    )

    return dataset, feature_columns


def validate_known_class_dataset(
    dataset,
    feature_columns
):
    """
    Validate the dataset before any train/test split
    or XGBoost training occurs.
    """

    missing_features = [
        column
        for column in feature_columns
        if column not in dataset.columns
    ]

    if missing_features:
        raise ValueError(
            "Missing feature columns: "
            + ", ".join(missing_features)
        )

    if TARGET_COLUMN not in dataset.columns:
        raise ValueError(
            f"Target column '{TARGET_COLUMN}' is missing."
        )

    detected_classes = set(
        dataset[TARGET_COLUMN]
        .dropna()
        .unique()
        .tolist()
    )

    expected_classes = set(
        CLASS_MAPPING.keys()
    )

    if detected_classes != expected_classes:
        raise ValueError(
            "Known-class labels do not match expected "
            f"mapping. Detected: {sorted(detected_classes)}"
        )

    missing_values = int(
        dataset[
            feature_columns + [TARGET_COLUMN]
        ].isna().sum().sum()
    )

    numeric_values = dataset[
        feature_columns
    ].to_numpy()

    infinite_values = int(
        np.isinf(numeric_values).sum()
    )

    if missing_values != 0:
        raise ValueError(
            f"Dataset contains {missing_values} missing values."
        )

    if infinite_values != 0:
        raise ValueError(
            f"Dataset contains {infinite_values} infinite values."
        )

    return {
        "rows": len(dataset),
        "feature_count": len(feature_columns),
        "target_column": TARGET_COLUMN,
        "class_count": len(detected_classes),
        "class_mapping": CLASS_MAPPING,
        "class_distribution": {
            str(label): int(count)
            for label, count in dataset[
                TARGET_COLUMN
            ].value_counts().sort_index().items()
        },
        "missing_values": missing_values,
        "infinite_values": infinite_values,
    }


if __name__ == "__main__":

    dataset, feature_columns = (
        load_known_class_dataset()
    )

    validation = validate_known_class_dataset(
        dataset,
        feature_columns
    )

    print()
    print("Dataset validation successful.")
    print(
        json.dumps(
            validation,
            indent=2
        )
    )