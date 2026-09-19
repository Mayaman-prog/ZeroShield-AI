import json

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.ml.xgboost_poc.feature_schema import (
    ATTACK_CSV,
    BENIGN_CSV,
    TARGET_COLUMN,
    build_feature_schema,
)


RANDOM_SEED = 42
BENIGN_HOLDOUT_SIZE = 0.20


def load_isolation_forest_dataset():
    """
    Load the DataSense data required for the initial
    Isolation Forest novelty-detection proof of concept.

    Isolation Forest is fitted only on benign reference data.

    Attack records and their labels are loaded only for
    post-training evaluation. Attack labels are never used
    to fit the Isolation Forest.
    """

    schema = build_feature_schema()
    feature_columns = schema["feature_columns"]

    if len(feature_columns) != 71:
        raise ValueError(
            f"Expected 71 leakage-controlled features, "
            f"but found {len(feature_columns)}."
        )

    columns_to_load = feature_columns + [TARGET_COLUMN]

    benign_df = pd.read_csv(
        BENIGN_CSV,
        usecols=columns_to_load,
    )

    attack_df = pd.read_csv(
        ATTACK_CSV,
        usecols=columns_to_load,
    )

    return benign_df, attack_df, feature_columns


def validate_isolation_forest_dataset(
    benign_df,
    attack_df,
    feature_columns,
):
    """
    Validate the data before any Isolation Forest fitting occurs.
    """

    benign_labels = set(
        benign_df[TARGET_COLUMN]
        .astype(str)
        .str.lower()
        .unique()
    )

    if benign_labels != {"benign"}:
        raise ValueError(
            f"Benign reference file contains unexpected labels: "
            f"{sorted(benign_labels)}"
        )

    attack_labels = set(
        attack_df[TARGET_COLUMN]
        .astype(str)
        .str.lower()
        .unique()
    )

    if "benign" in attack_labels:
        raise ValueError(
            "Attack evaluation file unexpectedly contains benign records."
        )

    benign_missing = int(
        benign_df[feature_columns]
        .isna()
        .sum()
        .sum()
    )

    attack_missing = int(
        attack_df[feature_columns]
        .isna()
        .sum()
        .sum()
    )

    benign_values = benign_df[
        feature_columns
    ].to_numpy(dtype=float)

    attack_values = attack_df[
        feature_columns
    ].to_numpy(dtype=float)

    benign_infinite = int(
        np.isinf(benign_values).sum()
    )

    attack_infinite = int(
        np.isinf(attack_values).sum()
    )

    if benign_missing != 0:
        raise ValueError(
            f"Benign reference data contains "
            f"{benign_missing} missing feature values."
        )

    if attack_missing != 0:
        raise ValueError(
            f"Attack evaluation data contains "
            f"{attack_missing} missing feature values."
        )

    if benign_infinite != 0:
        raise ValueError(
            f"Benign reference data contains "
            f"{benign_infinite} infinite feature values."
        )

    if attack_infinite != 0:
        raise ValueError(
            f"Attack evaluation data contains "
            f"{attack_infinite} infinite feature values."
        )

    attack_distribution = {
        str(label): int(count)
        for label, count in (
            attack_df[TARGET_COLUMN]
            .value_counts()
            .sort_index()
            .items()
        )
    }

    return {
        "feature_count": len(feature_columns),
        "benign_rows": int(len(benign_df)),
        "attack_rows": int(len(attack_df)),
        "benign_labels": sorted(benign_labels),
        "attack_labels": sorted(attack_labels),
        "attack_distribution": attack_distribution,
        "benign_missing_values": benign_missing,
        "attack_missing_values": attack_missing,
        "benign_infinite_values": benign_infinite,
        "attack_infinite_values": attack_infinite,
        "training_semantics": (
            "Isolation Forest fitting uses benign reference "
            "records only. Attack labels are retained solely "
            "for post-training evaluation."
        ),
    }


def split_benign_reference_data(
    benign_df,
):
    """
    Split benign observations into:

    80% benign reference training data
    20% held-out benign evaluation data

    The random seed is fixed for reproducibility.
    """

    benign_train, benign_holdout = train_test_split(
        benign_df,
        test_size=BENIGN_HOLDOUT_SIZE,
        random_state=RANDOM_SEED,
        shuffle=True,
    )

    benign_train = benign_train.reset_index(
        drop=True
    )

    benign_holdout = benign_holdout.reset_index(
        drop=True
    )

    return benign_train, benign_holdout


if __name__ == "__main__":

    (
        benign_df,
        attack_df,
        feature_columns,
    ) = load_isolation_forest_dataset()

    validation = validate_isolation_forest_dataset(
        benign_df,
        attack_df,
        feature_columns,
    )

    (
        benign_train,
        benign_holdout,
    ) = split_benign_reference_data(
        benign_df
    )

    output = {
        "experiment": (
            "ZeroShield Isolation Forest "
            "Novelty-Detection PoC"
        ),
        "random_seed": RANDOM_SEED,
        "benign_holdout_size": (
            BENIGN_HOLDOUT_SIZE
        ),
        "feature_count": len(
            feature_columns
        ),
        "benign_total_rows": int(
            len(benign_df)
        ),
        "benign_reference_training_rows": int(
            len(benign_train)
        ),
        "benign_holdout_rows": int(
            len(benign_holdout)
        ),
        "attack_evaluation_rows": int(
            len(attack_df)
        ),
        "validation": validation,
        "interpretation": (
            "Isolation Forest produces anomaly/novelty "
            "evidence relative to learned benign reference "
            "behaviour. Anomaly does not by itself mean "
            "malicious behaviour or prove a zero-day attack."
        ),
    }

    print(
        json.dumps(
            output,
            indent=2,
        )
    )