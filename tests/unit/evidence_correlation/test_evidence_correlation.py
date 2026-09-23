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
        """
        Create a fresh correlation engine before every test.

        Initial implementation values:
        - Correlation window: 5 seconds
        - Incident inactivity timeout: 30 seconds
        """
        self.engine = CorrelationEngine(
            CorrelationPolicy(
                correlation_window_seconds=5.0,
                incident_inactivity_timeout_seconds=30.0,
            )
        )

    def test_01_first_record_creates_incident(self):
        """
        The first valid evidence record should create
        a new incident.
        """

        record = build_xgboost_example()

        incident, decision = self.engine.process(
            record
        )

        self.assertIsNotNone(
            incident
        )

        self.assertEqual(
            decision.decision,
            DecisionType.CREATED.value,
        )

        self.assertEqual(
            incident.agreement_state,
            AgreementState.SUPERVISED_ONLY.value,
        )

        self.assertEqual(
            incident.evidence_ids,
            [
                record[
                    "evidence_id"
                ]
            ],
        )

    def test_02_exact_flow_is_correlated(self):
        """
        Evidence with the same:
        source IP,
        destination IP,
        source port,
        destination port,
        protocol,
        and timestamp window
        should correlate as an exact flow.
        """

        xgboost_record = (
            build_xgboost_example()
        )

        isolation_record = (
            build_isolation_forest_example()
        )

        isolation_record[
            "evidence_id"
        ] = "evidence-isolation-exact-002"

        isolation_record[
            "timestamp"
        ] = "2026-09-19T12:00:03+00:00"

        first_incident, _ = (
            self.engine.process(
                xgboost_record
            )
        )

        second_incident, decision = (
            self.engine.process(
                isolation_record
            )
        )

        self.assertEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.decision,
            DecisionType.ATTACHED.value,
        )

        self.assertEqual(
            decision.match_type,
            MatchType.EXACT_FLOW.value,
        )

        self.assertEqual(
            second_incident.agreement_state,
            AgreementState.CORROBORATED.value,
        )

    def test_03_partial_flow_supports_missing_ports(self):
        """
        Suricata and Zeek examples contain no ports.

        They should still be correlatable using:
        source IP,
        destination IP,
        protocol,
        and time.
        """

        suricata_record = (
            build_suricata_example()
        )

        zeek_record = (
            build_zeek_example()
        )

        zeek_record[
            "evidence_id"
        ] = "evidence-zeek-partial-002"

        zeek_record[
            "timestamp"
        ] = "2026-09-19T12:00:02+00:00"

        first_incident, _ = (
            self.engine.process(
                suricata_record
            )
        )

        second_incident, decision = (
            self.engine.process(
                zeek_record
            )
        )

        self.assertEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.match_type,
            MatchType.PARTIAL_FLOW.value,
        )

        self.assertEqual(
            second_incident.agreement_state,
            AgreementState.PARTIAL_SUPPORT.value,
        )

    def test_04_reverse_flow_is_supported(self):
        """
        Evidence describing the same communication
        in the opposite direction should be recognised
        as a reverse-flow match.
        """

        xgboost_record = (
            build_xgboost_example()
        )

        reverse_record = (
            build_isolation_forest_example()
        )

        reverse_record[
            "evidence_id"
        ] = "evidence-reverse-002"

        reverse_record[
            "source_ip"
        ] = xgboost_record[
            "destination_ip"
        ]

        reverse_record[
            "destination_ip"
        ] = xgboost_record[
            "source_ip"
        ]

        reverse_record[
            "source_port"
        ] = xgboost_record[
            "destination_port"
        ]

        reverse_record[
            "destination_port"
        ] = xgboost_record[
            "source_port"
        ]

        reverse_record[
            "timestamp"
        ] = "2026-09-19T12:00:01+00:00"

        first_incident, _ = (
            self.engine.process(
                xgboost_record
            )
        )

        second_incident, decision = (
            self.engine.process(
                reverse_record
            )
        )

        self.assertEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.match_type,
            MatchType.REVERSE_FLOW.value,
        )

    def test_05_event_outside_window_creates_new_incident(self):
        """
        Events more than five seconds apart should
        not be correlated under the initial policy.
        """

        first_record = (
            build_xgboost_example()
        )

        second_record = (
            build_isolation_forest_example()
        )

        second_record[
            "evidence_id"
        ] = "evidence-late-002"

        second_record[
            "timestamp"
        ] = "2026-09-19T12:00:10+00:00"

        first_incident, _ = (
            self.engine.process(
                first_record
            )
        )

        second_incident, decision = (
            self.engine.process(
                second_record
            )
        )

        self.assertNotEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.decision,
            DecisionType.CREATED.value,
        )

    def test_06_protocol_mismatch_does_not_correlate(self):
        """
        Matching hosts and timestamps should not be
        enough when the protocol clearly conflicts.
        """

        first_record = (
            build_xgboost_example()
        )

        second_record = (
            build_isolation_forest_example()
        )

        second_record[
            "evidence_id"
        ] = "evidence-protocol-002"

        second_record[
            "protocol"
        ] = "UDP"

        first_incident, _ = (
            self.engine.process(
                first_record
            )
        )

        second_incident, decision = (
            self.engine.process(
                second_record
            )
        )

        self.assertNotEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.decision,
            DecisionType.CREATED.value,
        )

    def test_07_duplicate_evidence_id_is_ignored(self):
        """
        The same evidence_id must not be added twice
        to an incident.
        """

        record = (
            build_xgboost_example()
        )

        first_incident, _ = (
            self.engine.process(
                record
            )
        )

        duplicate_record = (
            copy.deepcopy(
                record
            )
        )

        second_incident, decision = (
            self.engine.process(
                duplicate_record
            )
        )

        self.assertEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            decision.decision,
            DecisionType.DUPLICATE_IGNORED.value,
        )

        self.assertEqual(
            len(
                second_incident.evidence_ids
            ),
            1,
        )

    def test_08_isolation_forest_only_is_novelty_only(self):
        """
        Isolation Forest anomaly evidence by itself
        must remain novelty evidence.

        It must not automatically become a confirmed
        malicious incident.
        """

        record = (
            build_isolation_forest_example()
        )

        incident, _ = (
            self.engine.process(
                record
            )
        )

        self.assertEqual(
            incident.agreement_state,
            AgreementState.NOVELTY_ONLY.value,
        )

        self.assertEqual(
            incident.response_eligibility_state,
            "NOT_EVALUATED",
        )

    def test_09_zeek_only_is_context_only(self):
        """
        Zeek telemetry alone must remain contextual
        network evidence.

        Zeek must not be treated as an attack classifier.
        """

        record = (
            build_zeek_example()
        )

        incident, _ = (
            self.engine.process(
                record
            )
        )

        self.assertEqual(
            incident.agreement_state,
            AgreementState.CONTEXT_ONLY.value,
        )

    def test_10_detector_conflict_is_preserved(self):
        """
        If XGBoost indicates benign while Isolation
        Forest indicates anomaly for the same flow,
        the disagreement should remain visible.
        """

        xgboost_record = (
            build_xgboost_example()
        )

        xgboost_record[
            "detector_data"
        ][
            "predicted_class"
        ] = "benign"

        xgboost_record[
            "detector_data"
        ][
            "class_probabilities"
        ] = {
            "benign": 0.79,
            "bruteforce": 0.02,
            "ddos": 0.03,
            "dos": 0.04,
            "malware": 0.02,
            "mitm": 0.03,
            "recon": 0.05,
            "web": 0.02,
        }

        isolation_record = (
            build_isolation_forest_example()
        )

        isolation_record[
            "evidence_id"
        ] = "evidence-conflict-002"

        first_incident, _ = (
            self.engine.process(
                xgboost_record
            )
        )

        second_incident, _ = (
            self.engine.process(
                isolation_record
            )
        )

        self.assertEqual(
            first_incident.incident_id,
            second_incident.incident_id,
        )

        self.assertEqual(
            second_incident.agreement_state,
            AgreementState.CONFLICTING.value,
        )

    def test_11_inactive_incident_can_be_closed(self):
        """
        An incident should be closable after the
        configured inactivity timeout.
        """

        record = (
            build_xgboost_example()
        )

        incident, _ = (
            self.engine.process(
                record
            )
        )

        closed_incidents = (
            self.engine.close_inactive(
                "2026-09-19T12:00:31+00:00"
            )
        )

        self.assertIn(
            incident.incident_id,
            closed_incidents,
        )

        self.assertFalse(
            incident.is_open
        )

    def test_12_invalid_evidence_schema_is_rejected(self):
        """
        Correlation must not bypass Evidence
        Schema v1.0.0 validation.
        """

        record = (
            build_zeek_example()
        )

        record[
            "timestamp"
        ] = "2026-09-19T12:00:00"

        with self.assertRaises(
            ValueError
        ):
            self.engine.process(
                record
            )


if __name__ == "__main__":
    unittest.main(
        verbosity=2
    )