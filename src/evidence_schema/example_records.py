import json

from src.evidence_schema.schema import (
    SCHEMA_VERSION,
    validate_evidence_record,
)


def build_suricata_example():
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "evidence-suricata-001",
        "incident_id": "incident-demo-001",
        "source": "suricata",
        "evidence_type": "signature_alert",
        "timestamp": "2026-09-19T12:00:00+00:00",
        "ingested_at": "2026-09-19T12:00:01+00:00",
        "source_ip": "192.168.171.7",
        "source_port": None,
        "destination_ip": "192.168.171.3",
        "destination_port": None,
        "protocol": "ICMP",
        "detector_data": {
            "signature_id": 1000001,
            "signature": "ZEROSHIELD LAB ICMP TEST",
            "category": "ZeroShield Lab Test",
            "severity": 3,
            "action": "allowed",
        },
        "provenance": {
            "producer": "Suricata",
            "producer_type": "network_ids",
            "producer_version": "8.0.6",
            "role": "signature_detection",
            "interpretation_scope": (
                "Deterministic signature/rule-match evidence. "
                "A rule match does not create a universal "
                "maliciousness probability."
            ),
            "artifacts": {
                "ruleset": "ET Open + ZeroShield local rules",
                "signature_id": 1000001,
            },
        },
        "interpretation": {
            "meaning": (
                "Suricata matched a configured signature against "
                "the observed network traffic."
            ),
            "limitations": [
                "A signature match only represents the semantics of the matched rule.",
                "This evidence does not represent anomaly scoring.",
                "This evidence does not represent an XGBoost class probability.",
            ],
        },
        "raw_evidence": {
            "event_type": "alert",
            "src_ip": "192.168.171.7",
            "dest_ip": "192.168.171.3",
            "proto": "ICMP",
            "alert": {
                "signature_id": 1000001,
                "signature": "ZEROSHIELD LAB ICMP TEST",
                "category": "ZeroShield Lab Test",
                "severity": 3,
                "action": "allowed",
            },
        },
    }


def build_zeek_example():
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "evidence-zeek-001",
        "incident_id": "incident-demo-001",
        "source": "zeek",
        "evidence_type": "network_telemetry",
        "timestamp": "2026-09-19T12:00:00+00:00",
        "ingested_at": "2026-09-19T12:00:01+00:00",
        "source_ip": "192.168.171.7",
        "source_port": None,
        "destination_ip": "192.168.171.3",
        "destination_port": None,
        "protocol": "ICMP",
        "detector_data": {
            "connection_uid": "CZEEKDEMO001",
            "duration": 0.001,
            "source_bytes": 84,
            "destination_bytes": 84,
            "source_packets": 1,
            "destination_packets": 1,
            "connection_state": "OTH",
        },
        "provenance": {
            "producer": "Zeek",
            "producer_type": "network_telemetry_sensor",
            "producer_version": "8.0.10",
            "role": "passive_network_telemetry",
            "interpretation_scope": (
                "Passive network connection telemetry and context only. "
                "Zeek evidence is not treated as an attack classification."
            ),
            "artifacts": {
                "log_type": "conn.log",
                "connection_uid": "CZEEKDEMO001",
            },
        },
        "interpretation": {
            "meaning": (
                "Zeek observed connection-level network telemetry "
                "associated with the traffic."
            ),
            "limitations": [
                "Telemetry does not independently establish malicious behaviour.",
                "No attack class is inferred from this record.",
                "This record is contextual evidence only.",
            ],
        },
        "raw_evidence": {
            "uid": "CZEEKDEMO001",
            "id.orig_h": "192.168.171.7",
            "id.resp_h": "192.168.171.3",
            "proto": "icmp",
            "orig_pkts": 1,
            "resp_pkts": 1,
        },
    }


def build_xgboost_example():
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "evidence-xgboost-001",
        "incident_id": "incident-demo-001",
        "source": "xgboost",
        "evidence_type": "supervised_classification",
        "timestamp": "2026-09-19T12:00:00+00:00",
        "ingested_at": "2026-09-19T12:00:02+00:00",
        "source_ip": "192.168.171.7",
        "source_port": 44444,
        "destination_ip": "192.168.171.3",
        "destination_port": 80,
        "protocol": "TCP",
        "detector_data": {
            "predicted_class": "recon",
            "class_probabilities": {
                "benign": 0.05,
                "bruteforce": 0.02,
                "ddos": 0.03,
                "dos": 0.04,
                "malware": 0.02,
                "mitm": 0.03,
                "recon": 0.79,
                "web": 0.02,
            },
        },
        "provenance": {
            "producer": "ZeroShield XGBoost Known-Class PoC",
            "producer_type": "supervised_ml_model",
            "producer_version": "XGBoost 3.4.1",
            "role": "supervised_known_class_evidence",
            "interpretation_scope": (
                "Probabilities apply only across classes represented "
                "during supervised training and are not universal "
                "maliciousness or novelty probabilities."
            ),
            "model_version": "poc-v1",
            "feature_schema_version": "poc-v1",
            "artifacts": {
                "model_metadata": (
                    "experiments/xgboost/"
                    "xgboost_model_metadata.json"
                ),
                "feature_schema": (
                    "experiments/xgboost/"
                    "xgboost_feature_schema.json"
                ),
            },
        },
        "interpretation": {
            "meaning": (
                "The supervised model assigned the largest trained-class "
                "probability to the recon class."
            ),
            "limitations": [
                "Only classes represented during training are considered.",
                "The probabilities are not novelty scores.",
                "The probabilities are not universal maliciousness probabilities.",
            ],
        },
        "raw_evidence": {
            "feature_count": 71,
            "model_version": "poc-v1",
            "prediction_source": "example_record",
        },
    }


def build_isolation_forest_example():
    return {
        "schema_version": SCHEMA_VERSION,
        "evidence_id": "evidence-isolation-forest-001",
        "incident_id": "incident-demo-001",
        "source": "isolation_forest",
        "evidence_type": "anomaly_evidence",
        "timestamp": "2026-09-19T12:00:00+00:00",
        "ingested_at": "2026-09-19T12:00:02+00:00",
        "source_ip": "192.168.171.7",
        "source_port": 44444,
        "destination_ip": "192.168.171.3",
        "destination_port": 80,
        "protocol": "TCP",
        "detector_data": {
            "decision_function": -0.035,
            "anomaly_score": 0.035,
            "threshold": 0.0,
            "is_anomalous": True,
        },
        "provenance": {
            "producer": "ZeroShield Isolation Forest Novelty PoC",
            "producer_type": "unsupervised_ml_model",
            "producer_version": "scikit-learn 1.9.1",
            "role": "anomaly_novelty_evidence",
            "interpretation_scope": (
                "Measures unusual behaviour relative to learned benign "
                "reference behaviour. The anomaly score is not a "
                "maliciousness probability and does not independently "
                "prove a zero-day attack."
            ),
            "model_version": "poc-v1",
            "feature_schema_version": "poc-v1",
            "threshold_config_version": "poc-v1",
            "artifacts": {
                "model_metadata": (
                    "experiments/isolation_forest/"
                    "isolation_forest_model_metadata.json"
                ),
                "threshold_config": (
                    "experiments/isolation_forest/"
                    "isolation_forest_threshold_config.json"
                ),
            },
        },
        "interpretation": {
            "meaning": (
                "The record falls outside the fitted benign-reference "
                "boundary under the current PoC threshold."
            ),
            "limitations": [
                "Anomalous behaviour does not necessarily mean malicious behaviour.",
                "The anomaly score is not a probability.",
                "This evidence does not independently prove a previously unseen attack.",
            ],
        },
        "raw_evidence": {
            "feature_count": 71,
            "model_version": "poc-v1",
            "prediction_source": "example_record",
        },
    }


def build_all_examples():
    return [
        build_suricata_example(),
        build_zeek_example(),
        build_xgboost_example(),
        build_isolation_forest_example(),
    ]


if __name__ == "__main__":

    records = build_all_examples()

    validation_results = []

    for record in records:

        validate_evidence_record(
            record
        )

        validation_results.append(
            {
                "evidence_id": record[
                    "evidence_id"
                ],
                "source": record[
                    "source"
                ],
                "evidence_type": record[
                    "evidence_type"
                ],
                "schema_version": record[
                    "schema_version"
                ],
                "validation": "passed",
            }
        )

    output = {
        "schema_version": SCHEMA_VERSION,
        "validated_records": len(
            validation_results
        ),
        "results": validation_results,
        "design_statement": (
            "All four detector sources share the common "
            "ZeroShield evidence envelope while retaining "
            "source-specific detector semantics and provenance."
        ),
    }

    print(
        json.dumps(
            output,
            indent=2,
        )
    )