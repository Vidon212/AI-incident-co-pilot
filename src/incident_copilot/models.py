"""Validated, provider-neutral contracts between reasoning and authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal


class ValidationError(ValueError):
    """Raised when untrusted model output does not meet the contract."""


Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["investigate", "rollback", "no_change"]


@dataclass(frozen=True)
class IncidentContext:
    service: str
    namespace: str
    deployment: str
    http_503_rate: float
    pod_restarts: int
    cpu_percent: float
    memory_percent: float
    recent_events: list[str]
    current_image_tag: str
    previous_image_tag: str
    deployment_minutes_before_alert: int

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "IncidentContext":
        required = {
            "service", "namespace", "deployment", "http_503_rate", "pod_restarts",
            "cpu_percent", "memory_percent", "recent_events", "current_image_tag",
            "previous_image_tag", "deployment_minutes_before_alert",
        }
        missing = required - raw.keys()
        if missing:
            raise ValidationError(f"context missing fields: {', '.join(sorted(missing))}")
        if not isinstance(raw["recent_events"], list) or not all(isinstance(x, str) for x in raw["recent_events"]):
            raise ValidationError("recent_events must be a list of strings")
        return cls(**{key: raw[key] for key in required})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Diagnosis:
    service: str
    severity: Severity
    suspected_cause: str
    confidence: float
    evidence: list[str]
    recommended_action: Action
    requires_human_approval: bool

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Diagnosis":
        required = {
            "service", "severity", "suspected_cause", "confidence", "evidence",
            "recommended_action", "requires_human_approval",
        }
        missing = required - raw.keys()
        if missing:
            raise ValidationError(f"diagnosis missing fields: {', '.join(sorted(missing))}")
        if raw["severity"] not in {"low", "medium", "high", "critical"}:
            raise ValidationError("severity must be low, medium, high, or critical")
        if raw["recommended_action"] not in {"investigate", "rollback", "no_change"}:
            raise ValidationError("recommended_action is not permitted")
        confidence = raw["confidence"]
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            raise ValidationError("confidence must be a number between 0 and 1")
        if not isinstance(raw["evidence"], list) or not all(isinstance(x, str) for x in raw["evidence"]):
            raise ValidationError("evidence must be a list of strings")
        if not isinstance(raw["requires_human_approval"], bool):
            raise ValidationError("requires_human_approval must be a boolean")
        return cls(**{key: raw[key] for key in required})

