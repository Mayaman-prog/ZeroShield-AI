import json
from pathlib import Path

import pandas as pd


ATTACK_CSV = Path(
    r"D:\Zero-Shield-Dataset\extracted\attack\attack_samples_1sec.csv"
)

BENIGN_CSV = Path(
    r"D:\Zero-Shield-Dataset\extracted\benign\benign_samples_1sec.csv"
)

TARGET_COLUMN = "label2"

EXCLUDED_COLUMNS = [
    "device_name",
    "device_mac",
    "label_full",
    "label1",
    "label2",
    "label3",
    "label4",
    "timestamp",
    "timestamp_start",
    "timestamp_end",
    "log_data-types",
    "network_ips_all",
    "network_ips_dst",
    "network_ips_src",
    "network_macs_all",
    "network_macs_dst",
    "network_macs_src",
    "network_ports_all",
    "network_ports_dst",
    "network_ports_src",
    "network_protocols_all",
    "network_protocols_dst",
    "network_protocols_src",
]


def inspect_schema(csv_path):
    """
    Read only a small sample for schema inspection.
    No model training occurs here.
    """

    return pd.read_csv(
        csv_path,
        nrows=1000
    )


def build_feature_schema():
    """
    Build the initial ZeroShield XGBoost feature schema.

    Only numeric engineered features are used.
    Labels, identifiers, timestamps and high-cardinality
    metadata are excluded.
    """

    attack_sample = inspect_schema(ATTACK_CSV)
    benign_sample = inspect_schema(BENIGN_CSV)

    if list(attack_sample.columns) != list(benign_sample.columns):
        raise ValueError(
            "Attack and benign CSV schemas do not match."
        )

    numeric_columns = attack_sample.select_dtypes(
        include="number"
    ).columns.tolist()

    feature_columns = [
        column
        for column in numeric_columns
        if column not in EXCLUDED_COLUMNS
    ]

    schema = {
        "target_column": TARGET_COLUMN,
        "total_dataset_columns": len(
            attack_sample.columns
        ),
        "numeric_columns_detected": len(
            numeric_columns
        ),
        "feature_count": len(feature_columns),
        "excluded_columns": EXCLUDED_COLUMNS,
        "feature_columns": feature_columns,
    }

    return schema


if __name__ == "__main__":

    schema = build_feature_schema()

    print(
        json.dumps(
            schema,
            indent=2
        )
    )