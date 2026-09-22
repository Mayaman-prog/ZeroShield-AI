from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from src.evidence_correlation.policy import CorrelationPolicy
from src.evidence_schema.schema import validate_evidence_record


class MatchType(str, Enum):
    EXACT_FLOW = "EXACT_FLOW"
    REVERSE_FLOW = "REVERSE_FLOW"
    PARTIAL_FLOW = "PARTIAL_FLOW"


class AgreementState(str, Enum):
    CORROBORATED = "CORROBORATED"
    PARTIAL_SUPPORT = "PARTIAL_SUPPORT"
    CONFLICTING = "CONFLICTING"
    NOVELTY_ONLY = "NOVELTY_ONLY"
    SIGNATURE_ONLY = "SIGNATURE_ONLY"
    SUPERVISED_ONLY = "SUPERVISED_ONLY"
    CONTEXT_ONLY = "CONTEXT_ONLY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class DecisionType(str, Enum):
    CREATED = "CREATED"
    ATTACHED = "ATTACHED"
    DUPLICATE_IGNORED = "DUPLICATE_IGNORED"
    UNRESOLVED = "UNRESOLVED"


@dataclass
class Incident:
    incident_id: str
    first_seen: datetime
    last_seen: datetime
    source_ip: Optional[str]
    source_port: Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    evidence_ids: list[str] = field(default_factory=list)
    detector_sources_present: set[str] = field(default_factory=set)
    evidence_types_present: set[str] = field(default_factory=set)
    correlation_match_types: list[str] = field(default_factory=list)
    agreement_state: str = AgreementState.INSUFFICIENT_EVIDENCE.value
    response_eligibility_state: str = "NOT_EVALUATED"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None

    @property
    def is_open(self):
        return self.closed_at is None

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "evidence_ids": list(self.evidence_ids),
            "detector_sources_present": sorted(self.detector_sources_present),
            "evidence_types_present": sorted(self.evidence_types_present),
            "correlation_match_types": list(self.correlation_match_types),
            "agreement_state": self.agreement_state,
            "response_eligibility_state": self.response_eligibility_state,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


@dataclass
class CorrelationDecision:
    evidence_id: str
    candidate_incident_ids: list[str]
    selected_incident_id: Optional[str]
    match_type: Optional[str]
    timestamp_delta_seconds: Optional[float]
    fields_compared: list[str]
    fields_missing: list[str]
    decision: str
    reason: str
    correlation_policy_version: str
    created_at: datetime

    def to_dict(self):
        return {
            "evidence_id": self.evidence_id,
            "candidate_incident_ids": list(self.candidate_incident_ids),
            "selected_incident_id": self.selected_incident_id,
            "match_type": self.match_type,
            "timestamp_delta_seconds": self.timestamp_delta_seconds,
            "fields_compared": list(self.fields_compared),
            "fields_missing": list(self.fields_missing),
            "decision": self.decision,
            "reason": self.reason,
            "correlation_policy_version": self.correlation_policy_version,
            "created_at": self.created_at.isoformat(),
        }


_MATCH_RANK = {
    MatchType.EXACT_FLOW: 3,
    MatchType.REVERSE_FLOW: 2,
    MatchType.PARTIAL_FLOW: 1,
}


def _parse_timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).astimezone(timezone.utc)


def _normalise_protocol(value):
    return value.strip().lower() if value is not None else None


class CorrelationEngine:
    """
    Group schema-valid evidence into incidents without collapsing detector
    semantics into a universal maliciousness probability.

    Correlation is deliberately separate from response authorisation.
    """

    def __init__(self, policy=None):
        self.policy = policy or CorrelationPolicy()
        self._incidents = {}
        self._evidence_records = {}
        self._decisions = []
        self._unresolved_evidence_ids = set()

    @property
    def incidents(self):
        return list(self._incidents.values())

    @property
    def decisions(self):
        return list(self._decisions)

    @property
    def unresolved_evidence_ids(self):
        return sorted(self._unresolved_evidence_ids)

    def get_incident(self, incident_id):
        return self._incidents.get(incident_id)

    def process(self, record):
        validate_evidence_record(record)
        evidence_id = record["evidence_id"]

        existing = self._incident_for_evidence_id(evidence_id)
        if existing is not None:
            return existing, self._record_decision(
                evidence_id=evidence_id,
                candidate_incident_ids=[existing.incident_id],
                selected_incident_id=existing.incident_id,
                decision=DecisionType.DUPLICATE_IGNORED.value,
                reason="evidence_id is already attached to this incident.",
            )

        if evidence_id in self._unresolved_evidence_ids:
            return None, self._record_decision(
                evidence_id=evidence_id,
                candidate_incident_ids=[],
                selected_incident_id=None,
                decision=DecisionType.DUPLICATE_IGNORED.value,
                reason="evidence_id is already recorded as unresolved.",
            )

        event_time = _parse_timestamp(record["timestamp"])
        candidates = self._find_candidates(record, event_time)

        if not candidates:
            self._evidence_records[evidence_id] = record
            incident = self._create_incident(record, event_time)
            return incident, self._record_decision(
                evidence_id=evidence_id,
                candidate_incident_ids=[],
                selected_incident_id=incident.incident_id,
                fields_missing=self._missing_fields(record),
                decision=DecisionType.CREATED.value,
                reason=(
                    "No existing incident satisfied the correlation policy; "
                    "a new incident was created."
                ),
            )

        selected = self._select_candidate(candidates)

        if selected is None:
            self._evidence_records[evidence_id] = record
            self._unresolved_evidence_ids.add(evidence_id)
            return None, self._record_decision(
                evidence_id=evidence_id,
                candidate_incident_ids=[
                    candidate["incident"].incident_id
                    for candidate in candidates
                ],
                selected_incident_id=None,
                fields_missing=self._missing_fields(record),
                decision=DecisionType.UNRESOLVED.value,
                reason=(
                    "Multiple incidents remained equally strong after the "
                    "deterministic matching rules; evidence was not forced "
                    "into an incident."
                ),
            )

        self._evidence_records[evidence_id] = record
        incident = selected["incident"]
        self._attach(
            incident,
            record,
            event_time,
            selected["match_type"],
        )

        return incident, self._record_decision(
            evidence_id=evidence_id,
            candidate_incident_ids=[
                candidate["incident"].incident_id
                for candidate in candidates
            ],
            selected_incident_id=incident.incident_id,
            match_type=selected["match_type"].value,
            timestamp_delta_seconds=selected["timestamp_delta_seconds"],
            fields_compared=selected["fields_compared"],
            fields_missing=selected["fields_missing"],
            decision=DecisionType.ATTACHED.value,
            reason=(
                "Evidence matched an existing incident under the configured "
                "correlation policy."
            ),
        )

    def close_inactive(self, reference_time):
        if isinstance(reference_time, str):
            reference_time = _parse_timestamp(reference_time)
        elif reference_time.tzinfo is None:
            raise ValueError("reference_time must include timezone information.")
        else:
            reference_time = reference_time.astimezone(timezone.utc)

        closed = []
        timeout = self.policy.incident_inactivity_timeout_seconds

        for incident in self._incidents.values():
            if not incident.is_open:
                continue
            if (reference_time - incident.last_seen).total_seconds() > timeout:
                incident.closed_at = reference_time
                incident.updated_at = reference_time
                closed.append(incident.incident_id)

        return closed

    def _find_candidates(self, record, event_time):
        candidates = []

        for incident in self._incidents.values():
            if not incident.is_open:
                continue

            if (
                event_time - incident.last_seen
            ).total_seconds() > self.policy.incident_inactivity_timeout_seconds:
                continue

            timestamp_delta = self._timestamp_delta(event_time, incident)
            if timestamp_delta > self.policy.correlation_window_seconds:
                continue

            network_match = self._network_match(record, incident)
            if network_match is None:
                continue

            match_type, compared, missing = network_match
            candidates.append(
                {
                    "incident": incident,
                    "match_type": match_type,
                    "timestamp_delta_seconds": timestamp_delta,
                    "fields_compared": compared,
                    "fields_missing": missing,
                    "completeness": self._completeness(record, incident),
                }
            )

        return candidates

    @staticmethod
    def _timestamp_delta(event_time, incident):
        if incident.first_seen <= event_time <= incident.last_seen:
            return 0.0
        if event_time < incident.first_seen:
            return (incident.first_seen - event_time).total_seconds()
        return (event_time - incident.last_seen).total_seconds()

    def _network_match(self, record, incident):
        protocol = _normalise_protocol(record["protocol"])
        incident_protocol = _normalise_protocol(incident.protocol)

        if (
            protocol is not None
            and incident_protocol is not None
            and protocol != incident_protocol
        ):
            return None

        if (
            record["source_ip"] is None
            or record["destination_ip"] is None
            or incident.source_ip is None
            or incident.destination_ip is None
        ):
            return None

        same_direction = (
            record["source_ip"] == incident.source_ip
            and record["destination_ip"] == incident.destination_ip
        )
        reverse_direction = (
            record["source_ip"] == incident.destination_ip
            and record["destination_ip"] == incident.source_ip
        )

        if not same_direction and not reverse_direction:
            return None

        compared = ["source_ip", "destination_ip"]
        if protocol is not None and incident_protocol is not None:
            compared.append("protocol")

        missing = self._missing_fields(record, incident)

        if same_direction:
            ports = self._compare_ports(
                record["source_port"],
                record["destination_port"],
                incident.source_port,
                incident.destination_port,
            )
            if ports is False:
                return None
            if ports is True:
                compared.extend(["source_port", "destination_port"])
                return MatchType.EXACT_FLOW, compared, missing
            return MatchType.PARTIAL_FLOW, compared, missing

        ports = self._compare_ports(
            record["source_port"],
            record["destination_port"],
            incident.destination_port,
            incident.source_port,
        )
        if ports is False:
            return None
        if ports is True:
            compared.extend(["source_port", "destination_port"])
        return MatchType.REVERSE_FLOW, compared, missing

    @staticmethod
    def _compare_ports(record_source, record_destination, expected_source, expected_destination):
        pairs = [
            (record_source, expected_source),
            (record_destination, expected_destination),
        ]

        for current, expected in pairs:
            if current is not None and expected is not None and current != expected:
                return False

        if all(current is not None and expected is not None for current, expected in pairs):
            return True

        return None

    @staticmethod
    def _select_candidate(candidates):
        ranked = sorted(
            candidates,
            key=lambda item: (
                -_MATCH_RANK[item["match_type"]],
                item["timestamp_delta_seconds"],
                -item["completeness"],
            ),
        )
        best = ranked[0]
        best_signature = (
            _MATCH_RANK[best["match_type"]],
            best["timestamp_delta_seconds"],
            best["completeness"],
        )

        ties = [
            item
            for item in ranked
            if (
                _MATCH_RANK[item["match_type"]],
                item["timestamp_delta_seconds"],
                item["completeness"],
            )
            == best_signature
        ]

        return None if len(ties) > 1 else best

    def _create_incident(self, record, event_time):
        now = datetime.now(timezone.utc)
        incident = Incident(
            incident_id=str(uuid4()),
            first_seen=event_time,
            last_seen=event_time,
            source_ip=record["source_ip"],
            source_port=record["source_port"],
            destination_ip=record["destination_ip"],
            destination_port=record["destination_port"],
            protocol=record["protocol"],
            evidence_ids=[record["evidence_id"]],
            detector_sources_present={record["source"]},
            evidence_types_present={record["evidence_type"]},
            created_at=now,
            updated_at=now,
        )
        self._incidents[incident.incident_id] = incident
        incident.agreement_state = self._derive_agreement_state(incident)
        return incident

    def _attach(self, incident, record, event_time, match_type):
        incident.evidence_ids.append(record["evidence_id"])
        incident.detector_sources_present.add(record["source"])
        incident.evidence_types_present.add(record["evidence_type"])
        incident.correlation_match_types.append(match_type.value)

        incident.first_seen = min(incident.first_seen, event_time)
        incident.last_seen = max(incident.last_seen, event_time)

        if match_type != MatchType.REVERSE_FLOW:
            if incident.source_port is None and record["source_port"] is not None:
                incident.source_port = record["source_port"]
            if (
                incident.destination_port is None
                and record["destination_port"] is not None
            ):
                incident.destination_port = record["destination_port"]

        if incident.protocol is None and record["protocol"] is not None:
            incident.protocol = record["protocol"]

        incident.updated_at = datetime.now(timezone.utc)
        incident.agreement_state = self._derive_agreement_state(incident)

    def _derive_agreement_state(self, incident):
        records = [
            self._evidence_records[evidence_id]
            for evidence_id in incident.evidence_ids
        ]
        sources = {record["source"] for record in records}

        if len(sources) == 1:
            source = next(iter(sources))
            if source == "suricata":
                return AgreementState.SIGNATURE_ONLY.value
            if source == "zeek":
                return AgreementState.CONTEXT_ONLY.value
            if source == "xgboost":
                return AgreementState.SUPERVISED_ONLY.value
            if source == "isolation_forest":
                anomalous = any(
                    record["detector_data"]["is_anomalous"]
                    for record in records
                )
                return (
                    AgreementState.NOVELTY_ONLY.value
                    if anomalous
                    else AgreementState.INSUFFICIENT_EVIDENCE.value
                )

        suricata_present = "suricata" in sources
        xgb_records = [
            record for record in records if record["source"] == "xgboost"
        ]
        isolation_records = [
            record
            for record in records
            if record["source"] == "isolation_forest"
        ]

        xgb_attack = any(
            record["detector_data"]["predicted_class"].strip().lower()
            != "benign"
            for record in xgb_records
        )
        xgb_benign = any(
            record["detector_data"]["predicted_class"].strip().lower()
            == "benign"
            for record in xgb_records
        )
        anomalous = any(
            record["detector_data"]["is_anomalous"]
            for record in isolation_records
        )

        if xgb_benign and (suricata_present or anomalous):
            return AgreementState.CONFLICTING.value

        positive_detection_sources = sum(
            [suricata_present, xgb_attack, anomalous]
        )

        if positive_detection_sources >= 2:
            return AgreementState.CORROBORATED.value
        if positive_detection_sources == 1:
            return AgreementState.PARTIAL_SUPPORT.value
        return AgreementState.INSUFFICIENT_EVIDENCE.value

    @staticmethod
    def _completeness(record, incident):
        record_values = [
            record["source_ip"],
            record["destination_ip"],
            record["source_port"],
            record["destination_port"],
            record["protocol"],
        ]
        incident_values = [
            incident.source_ip,
            incident.destination_ip,
            incident.source_port,
            incident.destination_port,
            incident.protocol,
        ]
        return sum(value is not None for value in record_values + incident_values)

    @staticmethod
    def _missing_fields(record, incident=None):
        fields = [
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
        ]
        missing = [field for field in fields if record.get(field) is None]

        if incident is not None:
            incident_values = {
                "source_ip": incident.source_ip,
                "destination_ip": incident.destination_ip,
                "source_port": incident.source_port,
                "destination_port": incident.destination_port,
                "protocol": incident.protocol,
            }
            missing.extend(
                f"incident.{field}"
                for field, value in incident_values.items()
                if value is None
            )

        return missing

    def _incident_for_evidence_id(self, evidence_id):
        for incident in self._incidents.values():
            if evidence_id in incident.evidence_ids:
                return incident
        return None

    def _record_decision(
        self,
        evidence_id,
        candidate_incident_ids,
        selected_incident_id,
        decision,
        reason,
        match_type=None,
        timestamp_delta_seconds=None,
        fields_compared=None,
        fields_missing=None,
    ):
        correlation_decision = CorrelationDecision(
            evidence_id=evidence_id,
            candidate_incident_ids=list(candidate_incident_ids),
            selected_incident_id=selected_incident_id,
            match_type=match_type,
            timestamp_delta_seconds=timestamp_delta_seconds,
            fields_compared=list(fields_compared or []),
            fields_missing=list(fields_missing or []),
            decision=decision,
            reason=reason,
            correlation_policy_version=self.policy.version,
            created_at=datetime.now(timezone.utc),
        )
        self._decisions.append(correlation_decision)
        return correlation_decision
