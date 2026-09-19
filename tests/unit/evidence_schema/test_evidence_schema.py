import copy
import unittest

from src.evidence_schema.example_records import (
    build_isolation_forest_example,
    build_suricata_example,
    build_xgboost_example,
    build_zeek_example,
)
from src.evidence_schema.schema import (
    SCHEMA_VERSION,
    validate_evidence_record,
)


class TestEvidenceSchema(unittest.TestCase):

    def test_01_all_valid_examples_pass(self):

        records = [
            build_suricata_example(),
            build_zeek_example(),
            build_xgboost_example(),
            build_isolation_forest_example(),
        ]

        for record in records:
            self.assertTrue(
                validate_evidence_record(
                    record
                )
            )

    def test_02_source_and_evidence_type_mismatch_rejected(self):

        record = (
            build_suricata_example()
        )

        record[
            "evidence_type"
        ] = "network_telemetry"

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_03_universal_probability_field_rejected(self):

        record = (
            build_xgboost_example()
        )

        record[
            "detector_data"
        ][
            "malicious_probability"
        ] = 0.95

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_04_xgboost_probabilities_must_sum_to_one(self):

        record = (
            build_xgboost_example()
        )

        record[
            "detector_data"
        ][
            "class_probabilities"
        ][
            "recon"
        ] = 0.50

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_05_isolation_forest_score_semantics_enforced(self):

        record = (
            build_isolation_forest_example()
        )

        record[
            "detector_data"
        ][
            "anomaly_score"
        ] = 0.99

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_06_isolation_forest_flag_must_match_threshold(self):

        record = (
            build_isolation_forest_example()
        )

        record[
            "detector_data"
        ][
            "is_anomalous"
        ] = False

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_07_missing_model_provenance_rejected(self):

        record = (
            build_xgboost_example()
        )

        del record[
            "provenance"
        ][
            "model_version"
        ]

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_08_timestamp_without_timezone_rejected(self):

        record = (
            build_zeek_example()
        )

        record[
            "timestamp"
        ] = "2026-09-19T12:00:00"

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_09_unsupported_schema_version_rejected(self):

        record = (
            build_suricata_example()
        )

        record[
            "schema_version"
        ] = "99.0.0"

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )

    def test_10_raw_evidence_must_be_dictionary(self):

        record = (
            build_zeek_example()
        )

        record[
            "raw_evidence"
        ] = "not-a-dictionary"

        with self.assertRaises(
            ValueError
        ):
            validate_evidence_record(
                record
            )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )