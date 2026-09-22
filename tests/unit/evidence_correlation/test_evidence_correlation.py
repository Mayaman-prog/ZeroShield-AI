import copy
import unittest

from src.evidence_correlation import (
    AgreementState,
    CorrelationEngine,
    CorrelationPolicy,
    DecisionType,
    MatchType,
)
from src.evidence_schema.example_records import (
    build_isolation_forest_example,
    build_suricata_example,
    build_xgboost_example,
    build_zeek_example,
)


class TestEvidenceCorrelation(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine(
            CorrelationPolicy(
                correlation_window_seconds=5.0,
                incident_inactivity_timeout_seconds=30.0,
            )
        )

    def test_01_first_record_creates_incident(self):
        record = build_xgboost_example()
        incident, decision = self.engine.process(record)

        self.assertIsNotNone(incident)
        self.assertEqual(decision.decision, DecisionType.CREATED.value)
        self.assertEqual(
            incident.agreement_state,
            AgreementState.SUPERVISED_ONLY.value,
        )
        self.assertEqual(incident.evidence_ids, [record["evidence_id"]])

    def test_02_exact_flow_is_attached(self):
        xgb = build_xgboost_example()
        isolation = build_isolation_forest_example()
        isolation["evidence_id"] = "evidence-isolation-exact-002"
        isolation["timestamp"] = "2026-09-19T12:00:03+00:00"

        first, _ = self.engine.process(xgb)
        second, decision = self.engine.process(isolation)

        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(decision.decision, DecisionType.ATTACHED.value)
        self.assertEqual(decision.match_type, MatchType.EXACT_FLOW.value)
        self.assertEqual(
            second.agreement_state,
            AgreementState.CORROBORATED.value,
        )

    def test_03_partial_flow_supports_missing_ports(self):
        suricata = build_suricata_example()
        zeek = build_zeek_example()
        zeek["evidence_id"] = "evidence-zeek-partial-002"
        zeek["timestamp"] = "2026-09-19T12:00:02+00:00"

        first, _ = self.engine.process(suricata)
        second, decision = self.engine.process(zeek)

        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(decision.match_type, MatchType.PARTIAL_FLOW.value)
        self.assertEqual(
            second.agreement_state,
            AgreementState.PARTIAL_SUPPORT.value,
        )

    def test_04_reverse_flow_is_supported(self):
        xgb = build_xgboost_example()
        reverse = build_isolation_forest_example()
        reverse["evidence_id"] = "evidence-reverse-002"
        reverse["source_ip"] = xgb["destination_ip"]
        reverse["destination_ip"] = xgb["source_ip"]
        reverse["source_port"] = xgb["destination_port"]
        reverse["destination_port"] = xgb["source_port"]
        reverse["timestamp"] = "2026-09-19T12:00:01+00:00"

        first, _ = self.engine.process(xgb)
        second, decision = self.engine.process(reverse)

        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(decision.match_type, MatchType.REVERSE_FLOW.value)

    def test_05_outside_window_creates_new_incident(self):
        first_record = build_xgboost_example()
        second_record = build_isolation_forest_example()
        second_record["evidence_id"] = "evidence-late-002"
        second_record["timestamp"] = "2026-09-19T12:00:10+00:00"

        first, _ = self.engine.process(first_record)
        second, decision = self.engine.process(second_record)

        self.assertNotEqual(first.incident_id, second.incident_id)
        self.assertEqual(decision.decision, DecisionType.CREATED.value)

    def test_06_protocol_mismatch_does_not_correlate(self):
        first_record = build_xgboost_example()
        second_record = build_isolation_forest_example()
        second_record["evidence_id"] = "evidence-protocol-002"
        second_record["protocol"] = "UDP"

        first, _ = self.engine.process(first_record)
        second, decision = self.engine.process(second_record)

        self.assertNotEqual(first.incident_id, second.incident_id)
        self.assertEqual(decision.decision, DecisionType.CREATED.value)

    def test_07_duplicate_evidence_is_ignored(self):
        record = build_xgboost_example()

        first, _ = self.engine.process(record)
        second, decision = self.engine.process(copy.deepcopy(record))

        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(
            decision.decision,
            DecisionType.DUPLICATE_IGNORED.value,
        )
        self.assertEqual(len(second.evidence_ids), 1)

    def test_08_novelty_only_remains_novelty_only(self):
        record = build_isolation_forest_example()

        incident, _ = self.engine.process(record)

        self.assertEqual(
            incident.agreement_state,
            AgreementState.NOVELTY_ONLY.value,
        )
        self.assertEqual(
            incident.response_eligibility_state,
            "NOT_EVALUATED",
        )

    def test_09_context_only_zeek_is_not_detection(self):
        record = build_zeek_example()

        incident, _ = self.engine.process(record)

        self.assertEqual(
            incident.agreement_state,
            AgreementState.CONTEXT_ONLY.value,
        )

    def test_10_conflicting_evidence_is_preserved(self):
        xgb = build_xgboost_example()
        xgb["detector_data"]["predicted_class"] = "benign"
        xgb["detector_data"]["class_probabilities"] = {
            "benign": 0.79,
            "bruteforce": 0.02,
            "ddos": 0.03,
            "dos": 0.04,
            "malware": 0.02,
            "mitm": 0.03,
            "recon": 0.05,
            "web": 0.02,
        }

        isolation = build_isolation_forest_example()
        isolation["evidence_id"] = "evidence-conflict-002"

        first, _ = self.engine.process(xgb)
        second, _ = self.engine.process(isolation)

        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(
            second.agreement_state,
            AgreementState.CONFLICTING.value,
        )

    def test_11_inactive_incident_can_be_closed(self):
        record = build_xgboost_example()
        incident, _ = self.engine.process(record)

        closed = self.engine.close_inactive(
            "2026-09-19T12:00:31+00:00"
        )

        self.assertIn(incident.incident_id, closed)
        self.assertFalse(incident.is_open)

    def test_12_invalid_schema_record_is_rejected(self):
        record = build_zeek_example()
        record["timestamp"] = "2026-09-19T12:00:00"

        with self.assertRaises(ValueError):
            self.engine.process(record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
