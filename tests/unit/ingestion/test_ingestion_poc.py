import json
import tempfile
import unittest
from pathlib import Path

from src.ingestion.ingestion_runner import run_ingestion
from src.ingestion.parsers.suricata_parser import parse_suricata_eve_file
from src.ingestion.parsers.zeek_parser import parse_zeek_conn_file


class TestZeroShieldIngestionPoC(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_directory.name)

        self.suricata_file = (
            self.base_path / "suricata-sample.jsonl"
        )

        self.zeek_file = (
            self.base_path / "zeek-sample.jsonl"
        )

        self.output_file = (
            self.base_path / "zeroshield-output.jsonl"
        )

        self.suricata_record = {
            "timestamp": "2026-09-07T08:49:10.369329-0400",
            "event_type": "alert",
            "src_ip": "192.168.171.7",
            "dest_ip": "192.168.171.3",
            "proto": "ICMP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 1000001,
                "rev": 1,
                "signature": "ZEROSHIELD LAB ICMP TEST",
                "category": "",
                "severity": 3
            }
        }

        self.zeek_record = {
            "ts": 1789115403.452199,
            "uid": "CZnaFh2oI3M3w4CZ63",
            "id.orig_h": "192.168.171.7",
            "id.orig_p": 8,
            "id.resp_h": "192.168.171.3",
            "id.resp_p": 0,
            "proto": "icmp",
            "duration": 3.0096030235290527,
            "orig_bytes": 224,
            "resp_bytes": 224,
            "conn_state": "OTH",
            "orig_pkts": 4,
            "resp_pkts": 4,
            "orig_ip_bytes": 336,
            "resp_ip_bytes": 336,
            "ip_proto": 1
        }

        self.suricata_file.write_text(
            json.dumps(self.suricata_record) + "\n",
            encoding="utf-8"
        )

        self.zeek_file.write_text(
            json.dumps(self.zeek_record) + "\n",
            encoding="utf-8"
        )

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_multi_source_ingestion_preserves_semantics(self):
        summary = run_ingestion(
            self.suricata_file,
            self.zeek_file,
            self.output_file
        )

        self.assertEqual(
            summary["total_normalized_records"],
            2
        )

        self.assertEqual(
            summary["suricata_records"],
            1
        )

        self.assertEqual(
            summary["zeek_records"],
            1
        )

        lines = self.output_file.read_text(
            encoding="utf-8"
        ).splitlines()

        self.assertEqual(len(lines), 2)

        records = [
            json.loads(line)
            for line in lines
        ]

        suricata = records[0]
        zeek = records[1]

        self.assertEqual(
            suricata["source"],
            "suricata"
        )

        self.assertEqual(
            suricata["evidence_type"],
            "signature_alert"
        )

        self.assertEqual(
            zeek["source"],
            "zeek"
        )

        self.assertEqual(
            zeek["evidence_type"],
            "network_telemetry"
        )

        self.assertEqual(
            suricata["detector_data"]["signature_id"],
            1000001
        )

        self.assertEqual(
            zeek["detector_data"]["connection_uid"],
            "CZnaFh2oI3M3w4CZ63"
        )

        self.assertNotIn(
            "connection_uid",
            suricata["detector_data"]
        )

        self.assertNotIn(
            "signature_id",
            zeek["detector_data"]
        )

        self.assertEqual(
            suricata["raw_evidence"],
            self.suricata_record
        )

        self.assertEqual(
            zeek["raw_evidence"],
            self.zeek_record
        )

        self.assertNotIn(
            "probability",
            suricata
        )

        self.assertNotIn(
            "probability",
            zeek
        )

    def test_malformed_suricata_does_not_crash_parser(self):
        with self.suricata_file.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write("{invalid json\n")

        records, stats = parse_suricata_eve_file(
            self.suricata_file
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            stats["malformed_json_lines"],
            1
        )

    def test_malformed_zeek_does_not_crash_parser(self):
        with self.zeek_file.open(
            "a",
            encoding="utf-8"
        ) as file:
            file.write("{invalid json\n")

        records, stats = parse_zeek_conn_file(
            self.zeek_file
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(
            stats["malformed_json_lines"],
            1
        )


if __name__ == "__main__":
    unittest.main()