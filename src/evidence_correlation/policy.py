from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationPolicy:
    """Configuration for deterministic ZeroShield evidence correlation."""

    version: str = "correlation-policy-v1"
    correlation_window_seconds: float = 5.0
    incident_inactivity_timeout_seconds: float = 30.0

    def __post_init__(self):
        if not isinstance(self.version, str) or not self.version.strip():
            raise ValueError("version must be a non-empty string.")

        if self.correlation_window_seconds <= 0:
            raise ValueError(
                "correlation_window_seconds must be greater than zero."
            )

        if self.incident_inactivity_timeout_seconds <= 0:
            raise ValueError(
                "incident_inactivity_timeout_seconds must be greater than zero."
            )
