import json
from pathlib import Path
from datetime import datetime, timezone

from src.ingestion.validation import validate_zeek_evidence

def convert_timestamp(timestamp):
    """Convert Zeek Unix timestamp to ISO 8601 UTC."""
    if timestamp is None:
        return None

    try:
        return datetime.fromtimestamp(
            float(timestamp),
            tz=timezone.utc
        ).isoformat()
    except (ValueError, TypeError):
        return None


def parse_zeek_conn(record):
    """
    Convert one Zeek conn.log JSON record into
    ZeroShield's normalized evidence format.

    Zeek remains passive network telemetry.
    It is not treated as an attack alert.
    """

    if not isinstance(record, dict):
        raise ValueError(
            "Zeek record must be a JSON object."
        )

    normalized = {
        "source": "zeek",
        "evidence_type": "network_telemetry",

        "timestamp": convert_timestamp(record.get("ts")),

        "source_ip": record.get("id.orig_h"),
        "source_port": record.get("id.orig_p"),

        "destination_ip": record.get("id.resp_h"),
        "destination_port": record.get("id.resp_p"),

        "protocol": record.get("proto"),

        "detector_data": {
            "zeek_timestamp": record.get("ts"),
            "connection_uid": record.get("uid"),

            "ip_protocol": record.get("ip_proto"),
            "duration": record.get("duration"),

            "source_bytes": record.get("orig_bytes"),
            "destination_bytes": record.get("resp_bytes"),

            "source_packets": record.get("orig_pkts"),
            "destination_packets": record.get("resp_pkts"),

            "source_ip_bytes": record.get("orig_ip_bytes"),
            "destination_ip_bytes": record.get("resp_ip_bytes"),

            "connection_state": record.get("conn_state"),

            "local_source": record.get("local_orig"),
            "local_destination": record.get("local_resp"),

            "missed_bytes": record.get("missed_bytes", 0)
        },

        "raw_evidence": record
    }

    validate_zeek_evidence(normalized)

    return normalized

def parse_zeek_conn_file(input_path):
    """
    Read a Zeek conn.log JSON/JSONL file line-by-line.

    Zeek records remain passive network telemetry.
    """

    input_path = Path(input_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Zeek input file not found: {input_path}"
        )

    normalized_records = []

    stats = {
        "total_lines": 0,
        "telemetry_parsed": 0,
        "malformed_json_lines": 0,
        "invalid_telemetry_records": 0
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
                    f"Skipping malformed Zeek JSON on line "
                    f"{line_number}: {error}"
                )

                continue

            try:
                normalized = parse_zeek_conn(record)

            except ValueError as error:
                stats["invalid_telemetry_records"] += 1

                print(
                    f"Skipping invalid Zeek telemetry "
                    f"on line {line_number}: {error}"
                )

                continue

            normalized_records.append(normalized)
            stats["telemetry_parsed"] += 1

    return normalized_records, stats


def parse_conn_log(input_path, output_path):
    normalized_records = []

    with input_path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                normalized = parse_zeek_conn(record)

                normalized_records.append(normalized)

            except json.JSONDecodeError as error:
                print(
                    f"Skipping invalid JSON "
                    f"on line {line_number}: {error}"
                )

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            normalized_records,
            file,
            indent=2
        )

    print(
        f"Successfully parsed "
        f"{len(normalized_records)} Zeek records."
    )

    print(
        f"Output saved to: {output_path}"
    )


if __name__ == "__main__":

    base_directory = (
        Path.home()
        / "zeroshield-zeek-baseline"
    )

    input_file = (
        base_directory
        / "raw"
        / "conn.log"
    )

    output_file = (
        base_directory
        / "export"
        / "zeroshield-zeek-telemetry.json"
    )

    if not input_file.exists():
        print(
            f"Error: Zeek conn.log not found: "
            f"{input_file}"
        )

        raise SystemExit(1)

    parse_conn_log(
        input_file,
        output_file
    )
