import json
from pathlib import Path

from src.ingestion.parsers.suricata_parser import parse_suricata_eve_file
from src.ingestion.parsers.zeek_parser import parse_zeek_conn_file


def run_ingestion(
    suricata_input,
    zeek_input,
    output_path
):
    """
    Run the ZeroShield ingestion proof of concept.

    Suricata signature alerts and Zeek network telemetry
    enter one ingestion pipeline while preserving their
    original evidence meaning and provenance.
    """

    suricata_records, suricata_stats = (
        parse_suricata_eve_file(suricata_input)
    )

    zeek_records, zeek_stats = (
        parse_zeek_conn_file(zeek_input)
    )

    combined_records = (
        suricata_records
        + zeek_records
    )

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        for record in combined_records:
            file.write(
                json.dumps(record)
                + "\n"
            )

    summary = {
        "total_normalized_records": len(combined_records),

        "suricata_records": len(suricata_records),
        "zeek_records": len(zeek_records),

        "evidence_types": {
            "signature_alert": sum(
                1
                for record in combined_records
                if record.get("evidence_type")
                == "signature_alert"
            ),

            "network_telemetry": sum(
                1
                for record in combined_records
                if record.get("evidence_type")
                == "network_telemetry"
            )
        },

        "suricata_stats": suricata_stats,
        "zeek_stats": zeek_stats,

        "output_path": str(output_path)
    }

    return summary


if __name__ == "__main__":

    suricata_file = (
        Path("data")
        / "raw"
        / "ingestion"
        / "suricata"
        / "suricata-alert-sample.json"
    )

    zeek_file = (
        Path("data")
        / "raw"
        / "ingestion"
        / "zeek"
        / "zeek-conn-sample.jsonl"
    )

    output_file = (
        Path("data")
        / "processed"
        / "ingestion"
        / "zeroshield-ingestion-poc.jsonl"
    )

    result = run_ingestion(
        suricata_file,
        zeek_file,
        output_file
    )

    print(
        json.dumps(
            result,
            indent=2
        )
    )