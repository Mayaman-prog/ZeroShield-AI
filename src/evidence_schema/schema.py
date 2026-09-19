from datetime import datetime
from math import isclose


SCHEMA_VERSION = "1.0.0"


SOURCE_EVIDENCE_TYPES = {
    "suricata": "signature_alert",
    "zeek": "network_telemetry",
    "xgboost": "supervised_classification",
    "isolation_forest": "anomaly_evidence",
}


SOURCE_ROLES = {
    "suricata": "signature_detection",
    "zeek": "passive_network_telemetry",
    "xgboost": "supervised_known_class_evidence",
    "isolation_forest": "anomaly_novelty_evidence",
}


COMMON_REQUIRED_FIELDS = [
    "schema_version",
    "evidence_id",
    "incident_id",
    "source",
    "evidence_type",
    "timestamp",
    "ingested_at",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "detector_data",
    "provenance",
    "interpretation",
    "raw_evidence",
]


PROVENANCE_REQUIRED_FIELDS = [
    "producer",
    "producer_type",
    "producer_version",
    "role",
    "interpretation_scope",
    "artifacts",
]


INTERPRETATION_REQUIRED_FIELDS = [
    "meaning",
    "limitations",
]


PROHIBITED_UNIVERSAL_FIELDS = {
    "malicious_probability",
    "zero_day_probability",
    "universal_threat_probability",
    "overall_attack_probability",
}


def _validate_non_empty_string(
    value,
    field_name,
):
    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    if not value.strip():
        raise ValueError(
            f"{field_name} must not be empty."
        )


def _validate_optional_identifier(
    value,
    field_name,
):
    if value is None:
        return

    _validate_non_empty_string(
        value,
        field_name,
    )


def _validate_timestamp(
    value,
    field_name,
):
    _validate_non_empty_string(
        value,
        field_name,
    )

    normalized = value.replace(
        "Z",
        "+00:00",
    )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be "
            f"ISO 8601 compatible."
        ) from exc

    if parsed.tzinfo is None:
        raise ValueError(
            f"{field_name} must include "
            f"timezone information."
        )


def _validate_port(
    value,
    field_name,
):
    if value is None:
        return

    if isinstance(value, bool):
        raise ValueError(
            f"{field_name} must be an integer "
            f"or null."
        )

    if not isinstance(value, int):
        raise ValueError(
            f"{field_name} must be an integer "
            f"or null."
        )

    if not 0 <= value <= 65535:
        raise ValueError(
            f"{field_name} must be between "
            f"0 and 65535."
        )


def _require_dictionary_fields(
    dictionary,
    required_fields,
    dictionary_name,
):
    if not isinstance(
        dictionary,
        dict,
    ):
        raise ValueError(
            f"{dictionary_name} must be "
            f"a dictionary."
        )

    missing = [
        field
        for field in required_fields
        if field not in dictionary
    ]

    if missing:
        raise ValueError(
            f"{dictionary_name} is missing "
            f"required fields: {missing}"
        )


def _reject_universal_probability_fields(
    record,
):
    locations = [
        (
            "top-level record",
            record,
        ),
        (
            "detector_data",
            record.get(
                "detector_data",
                {},
            ),
        ),
    ]

    for (
        location_name,
        dictionary,
    ) in locations:

        if not isinstance(
            dictionary,
            dict,
        ):
            continue

        detected = (
            PROHIBITED_UNIVERSAL_FIELDS
            .intersection(
                dictionary.keys()
            )
        )

        if detected:
            raise ValueError(
                f"Prohibited universal probability "
                f"field(s) found in "
                f"{location_name}: "
                f"{sorted(detected)}"
            )


def _validate_provenance(
    source,
    provenance,
):
    _require_dictionary_fields(
        provenance,
        PROVENANCE_REQUIRED_FIELDS,
        "provenance",
    )

    for field in [
        "producer",
        "producer_type",
        "producer_version",
        "role",
        "interpretation_scope",
    ]:
        _validate_non_empty_string(
            provenance[field],
            f"provenance.{field}",
        )

    if not isinstance(
        provenance["artifacts"],
        dict,
    ):
        raise ValueError(
            "provenance.artifacts must "
            "be a dictionary."
        )

    expected_role = (
        SOURCE_ROLES[source]
    )

    if (
        provenance["role"]
        != expected_role
    ):
        raise ValueError(
            f"Expected provenance.role "
            f"'{expected_role}' for "
            f"source '{source}', got "
            f"'{provenance['role']}'."
        )

    if source == "xgboost":

        for field in [
            "model_version",
            "feature_schema_version",
        ]:
            _validate_non_empty_string(
                provenance.get(field),
                f"provenance.{field}",
            )

    if source == "isolation_forest":

        for field in [
            "model_version",
            "feature_schema_version",
            "threshold_config_version",
        ]:
            _validate_non_empty_string(
                provenance.get(field),
                f"provenance.{field}",
            )


def _validate_interpretation(
    interpretation,
):
    _require_dictionary_fields(
        interpretation,
        INTERPRETATION_REQUIRED_FIELDS,
        "interpretation",
    )

    _validate_non_empty_string(
        interpretation["meaning"],
        "interpretation.meaning",
    )

    limitations = (
        interpretation[
            "limitations"
        ]
    )

    if not isinstance(
        limitations,
        list,
    ):
        raise ValueError(
            "interpretation.limitations "
            "must be a list."
        )

    if not limitations:
        raise ValueError(
            "interpretation.limitations "
            "must contain at least one "
            "limitation."
        )

    for index, limitation in enumerate(
        limitations
    ):
        _validate_non_empty_string(
            limitation,
            (
                "interpretation."
                f"limitations[{index}]"
            ),
        )


def _validate_suricata(
    detector_data,
):
    required = [
        "signature_id",
        "signature",
        "category",
        "severity",
        "action",
    ]

    _require_dictionary_fields(
        detector_data,
        required,
        "detector_data",
    )


def _validate_zeek(
    detector_data,
):
    _require_dictionary_fields(
        detector_data,
        [
            "connection_uid",
        ],
        "detector_data",
    )

    _validate_non_empty_string(
        detector_data[
            "connection_uid"
        ],
        "detector_data.connection_uid",
    )


def _validate_xgboost(
    detector_data,
):
    required = [
        "predicted_class",
        "class_probabilities",
    ]

    _require_dictionary_fields(
        detector_data,
        required,
        "detector_data",
    )

    _validate_non_empty_string(
        detector_data[
            "predicted_class"
        ],
        "detector_data.predicted_class",
    )

    probabilities = (
        detector_data[
            "class_probabilities"
        ]
    )

    if not isinstance(
        probabilities,
        dict,
    ):
        raise ValueError(
            "detector_data.class_probabilities "
            "must be a dictionary."
        )

    if not probabilities:
        raise ValueError(
            "detector_data.class_probabilities "
            "must not be empty."
        )

    total = 0.0

    for (
        class_name,
        probability,
    ) in probabilities.items():

        _validate_non_empty_string(
            class_name,
            "class probability name",
        )

        if isinstance(
            probability,
            bool,
        ):
            raise ValueError(
                "XGBoost class probabilities "
                "must be numeric."
            )

        if not isinstance(
            probability,
            (int, float),
        ):
            raise ValueError(
                "XGBoost class probabilities "
                "must be numeric."
            )

        if not 0 <= probability <= 1:
            raise ValueError(
                "XGBoost class probabilities "
                "must be between 0 and 1."
            )

        total += float(
            probability
        )

    if not isclose(
        total,
        1.0,
        rel_tol=1e-6,
        abs_tol=1e-6,
    ):
        raise ValueError(
            "XGBoost class probabilities "
            f"must sum to 1.0; got {total}."
        )


def _validate_isolation_forest(
    detector_data,
):
    required = [
        "decision_function",
        "anomaly_score",
        "threshold",
        "is_anomalous",
    ]

    _require_dictionary_fields(
        detector_data,
        required,
        "detector_data",
    )

    for field in [
        "decision_function",
        "anomaly_score",
        "threshold",
    ]:

        value = detector_data[
            field
        ]

        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                f"detector_data.{field} "
                "must be numeric."
            )

        if not isinstance(
            value,
            (int, float),
        ):
            raise ValueError(
                f"detector_data.{field} "
                "must be numeric."
            )

    if not isinstance(
        detector_data[
            "is_anomalous"
        ],
        bool,
    ):
        raise ValueError(
            "detector_data.is_anomalous "
            "must be Boolean."
        )

    decision_function = float(
        detector_data[
            "decision_function"
        ]
    )

    anomaly_score = float(
        detector_data[
            "anomaly_score"
        ]
    )

    threshold = float(
        detector_data[
            "threshold"
        ]
    )

    if not isclose(
        anomaly_score,
        -decision_function,
        rel_tol=1e-9,
        abs_tol=1e-9,
    ):
        raise ValueError(
            "Isolation Forest anomaly_score "
            "must equal -decision_function."
        )

    expected_flag = (
        anomaly_score
        > threshold
    )

    if (
        detector_data[
            "is_anomalous"
        ]
        != expected_flag
    ):
        raise ValueError(
            "Isolation Forest is_anomalous "
            "does not match the configured "
            "anomaly threshold."
        )


def validate_evidence_record(
    record,
):
    """
    Validate one ZeroShield evidence record.

    The common envelope is shared by all
    detector sources, while source-specific
    detector semantics remain separate.
    """

    _require_dictionary_fields(
        record,
        COMMON_REQUIRED_FIELDS,
        "evidence record",
    )

    if (
        record[
            "schema_version"
        ]
        != SCHEMA_VERSION
    ):
        raise ValueError(
            f"Unsupported schema_version: "
            f"{record['schema_version']}"
        )

    _validate_non_empty_string(
        record[
            "evidence_id"
        ],
        "evidence_id",
    )

    _validate_optional_identifier(
        record[
            "incident_id"
        ],
        "incident_id",
    )

    source = record[
        "source"
    ]

    _validate_non_empty_string(
        source,
        "source",
    )

    if (
        source
        not in SOURCE_EVIDENCE_TYPES
    ):
        raise ValueError(
            f"Unsupported evidence source: "
            f"{source}"
        )

    expected_evidence_type = (
        SOURCE_EVIDENCE_TYPES[
            source
        ]
    )

    if (
        record[
            "evidence_type"
        ]
        != expected_evidence_type
    ):
        raise ValueError(
            f"Source '{source}' requires "
            f"evidence_type "
            f"'{expected_evidence_type}'."
        )

    _validate_timestamp(
        record[
            "timestamp"
        ],
        "timestamp",
    )

    _validate_timestamp(
        record[
            "ingested_at"
        ],
        "ingested_at",
    )

    _validate_optional_identifier(
        record[
            "source_ip"
        ],
        "source_ip",
    )

    _validate_optional_identifier(
        record[
            "destination_ip"
        ],
        "destination_ip",
    )

    _validate_port(
        record[
            "source_port"
        ],
        "source_port",
    )

    _validate_port(
        record[
            "destination_port"
        ],
        "destination_port",
    )

    _validate_optional_identifier(
        record[
            "protocol"
        ],
        "protocol",
    )

    if not isinstance(
        record[
            "detector_data"
        ],
        dict,
    ):
        raise ValueError(
            "detector_data must be "
            "a dictionary."
        )

    if not isinstance(
        record[
            "raw_evidence"
        ],
        dict,
    ):
        raise ValueError(
            "raw_evidence must be "
            "a dictionary."
        )

    _reject_universal_probability_fields(
        record
    )

    _validate_provenance(
        source,
        record[
            "provenance"
        ],
    )

    _validate_interpretation(
        record[
            "interpretation"
        ],
    )

    if source == "suricata":
        _validate_suricata(
            record[
                "detector_data"
            ]
        )

    elif source == "zeek":
        _validate_zeek(
            record[
                "detector_data"
            ]
        )

    elif source == "xgboost":
        _validate_xgboost(
            record[
                "detector_data"
            ]
        )

    elif source == "isolation_forest":
        _validate_isolation_forest(
            record[
                "detector_data"
            ]
        )

    return True