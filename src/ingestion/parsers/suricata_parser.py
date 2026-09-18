import json
from pathlib import Path

from src.ingestion.validation import validate_suricata_evidence

def parse_suricata_alert(record):
    """
    Convert one Suricata EVE alert record into
    ZeroShield's normalized evidence format.

    Suricata remains signature-based evidence.
    """

    if not isinstance(record, dict):
        raise ValueError("Suricata record must be a JSON object.")

    if record.get("event_type") != "alert":
        raise ValueError("Suricata record is not an alert event.")

    alert = record.get("alert")

    if not isinstance(alert, dict):
        raise ValueError("Suricata alert object is missing or invalid.")

    normalized = {
        "source": "suricata",
        "evidence_type": "signature_alert",

        "timestamp": record.get("timestamp"),

        "source_ip": record.get("src_ip"),
        "source_port": record.get("src_port"),

        "destination_ip": record.get("dest_ip"),
        "destination_port": record.get("dest_port"),

        "protocol": record.get("proto"),

        "detector_data": {
            "signature_id": alert.get("signature_id"),
            "signature": alert.get("signature"),
            "category": alert.get("category"),
            "severity": alert.get("severity"),
            "action": alert.get("action"),
            "gid": alert.get("gid"),
            "revision": alert.get("rev")
    },

    "raw_evidence": record
}

    validate_suricata_evidence(normalized)

    return normalized

def parse_suricata_eve_file(input_path):
    """
    Read a Suricata EVE JSON/JSONL file line-by-line.

    Only alert events are normalized.
    Non-alert events remain outside the Suricata
    signature-alert evidence stream.
    """

    input_path = Path(input_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Suricata input file not found: {input_path}"
        )

    normalized_records = []

    stats = {
        "total_lines": 0,
        "alerts_parsed": 0,
        "non_alert_events_skipped": 0,
        "malformed_json_lines": 0,
        "invalid_alert_records": 0
    }

    with input_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            stats["total_lines"] += 1

            try:
                record = json.loads(line)

            except json.JSONDecodeError as error:
                stats["malformed_json_lines"] += 1

                print(
                    f"Skipping malformed JSON on line "
                    f"{line_number}: {error}"
                )

                continue

            if record.get("event_type") != "alert":
                stats["non_alert_events_skipped"] += 1
                continue

            try:
                normalized = parse_suricata_alert(record)

            except ValueError as error:
                stats["invalid_alert_records"] += 1

                print(
                    f"Skipping invalid Suricata alert "
                    f"on line {line_number}: {error}"
                )

                continue

            normalized_records.append(normalized)
            stats["alerts_parsed"] += 1

    return normalized_records, stats