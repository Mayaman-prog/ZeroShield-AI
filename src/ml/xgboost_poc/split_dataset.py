import json

from sklearn.model_selection import train_test_split

from src.ml.xgboost_poc.data_loader import (
    CLASS_MAPPING,
    load_known_class_dataset,
    validate_known_class_dataset,
)
from src.ml.xgboost_poc.feature_schema import TARGET_COLUMN


RANDOM_SEED = 42
TEST_SIZE = 0.20


def create_known_class_split():
    """
    Create a reproducible stratified train/test split.

    All eight label2 classes are represented in training
    and testing for this initial known-class XGBoost PoC.
    """

    dataset, feature_columns = load_known_class_dataset()

    validate_known_class_dataset(
        dataset,
        feature_columns
    )

    X = dataset[feature_columns].copy()

    y_text = dataset[TARGET_COLUMN].copy()

    y = y_text.map(CLASS_MAPPING)

    if y.isna().any():
        raise ValueError(
            "One or more labels could not be mapped."
        )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_SEED,
            stratify=y
        )
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
        feature_columns
    )


def build_split_summary(
    X_train,
    X_test,
    y_train,
    y_test,
    feature_columns
):
    """
    Produce reproducibility information for the split.
    """

    reverse_mapping = {
        value: key
        for key, value in CLASS_MAPPING.items()
    }

    train_distribution = {
        reverse_mapping[int(label)]: int(count)
        for label, count
        in y_train.value_counts().sort_index().items()
    }

    test_distribution = {
        reverse_mapping[int(label)]: int(count)
        for label, count
        in y_test.value_counts().sort_index().items()
    }

    summary = {
        "random_seed": RANDOM_SEED,
        "test_size": TEST_SIZE,

        "feature_count": len(feature_columns),

        "training_rows": len(X_train),
        "testing_rows": len(X_test),

        "training_class_distribution": (
            train_distribution
        ),

        "testing_class_distribution": (
            test_distribution
        ),

        "class_mapping": CLASS_MAPPING
    }

    return summary


if __name__ == "__main__":

    (
        X_train,
        X_test,
        y_train,
        y_test,
        feature_columns
    ) = create_known_class_split()

    summary = build_split_summary(
        X_train,
        X_test,
        y_train,
        y_test,
        feature_columns
    )

    print()
    print("Known-class split successful.")
    print(
        json.dumps(
            summary,
            indent=2
        )
    )