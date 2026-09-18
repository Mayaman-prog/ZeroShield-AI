def validate_common_evidence(record):
    """
    Validate fields shared by all normalized
    ZeroShield evidence records.
    """

    if not isinstance(record, dict):
        raise ValueError(
            "Normalized evidence must be a dictionary."
        )

    required_fields = [
        "source",
        "evidence_type",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "raw_evidence"
    ]

    missing_fields = []

    for field in required_fields:
        if field not in record or record[field] is None:
            missing_fields.append(field)

    if missing_fields:
        raise ValueError(
            "Missing required evidence fields: "
            + ", ".join(missing_fields)
        )

    if not isinstance(record["raw_evidence"], dict):
        raise ValueError(
            "raw_evidence must contain the original record."
        )

    return True


def validate_suricata_evidence(record):
    """
    Validate Suricata signature-alert evidence.
    """

    validate_common_evidence(record)

    if record.get("source") != "suricata":
        raise ValueError(
            "Suricata evidence must have source='suricata'."
        )

    if record.get("evidence_type") != "signature_alert":
        raise ValueError(
            "Suricata evidence must have "
            "evidence_type='signature_alert'."
        )

    detector_data = record.get("detector_data")

    if not isinstance(detector_data, dict):
        raise ValueError(
            "Suricata detector_data is missing or invalid."
        )

    required_detector_fields = [
        "signature_id",
        "signature",
        "action"
    ]

    missing_detector_fields = []

    for field in required_detector_fields:
        if (
            field not in detector_data
            or detector_data[field] is None
        ):
            missing_detector_fields.append(field)

    if missing_detector_fields:
        raise ValueError(
            "Missing required Suricata detector fields: "
            + ", ".join(missing_detector_fields)
        )

    return True

def validate_zeek_evidence(record):
    """
    Validate Zeek network-telemetry evidence.

    Zeek provides passive network context.
    It is not treated as an attack classifier.
    """

    validate_common_evidence(record)

    if record.get("source") != "zeek":
        raise ValueError(
            "Zeek evidence must have source='zeek'."
        )

    if record.get("evidence_type") != "network_telemetry":
        raise ValueError(
            "Zeek evidence must have "
            "evidence_type='network_telemetry'."
        )

    detector_data = record.get("detector_data")

    if not isinstance(detector_data, dict):
        raise ValueError(
            "Zeek detector_data is missing or invalid."
        )

    if detector_data.get("connection_uid") is None:
        raise ValueError(
            "Missing required Zeek detector field: connection_uid"
        )

    return True