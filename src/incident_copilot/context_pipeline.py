"""Deterministic normalization and correlation for incident evidence.

This module is deliberately provider-neutral and read-only. It converts source
records into a compact context payload; it does not diagnose an incident or
perform remediation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .models import ValidationError


_WEIGHTS = {"temporal": 0.25, "dependency": 0.35, "blast_radius": 0.30, "metric": 0.10}


def _number(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValidationError(f"{field} must be a number")
    return float(value)


def _required(raw: dict[str, Any], field: str) -> Any:
    if field not in raw:
        raise ValidationError(f"context source missing field: {field}")
    return raw[field]


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    return value


def _objects(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValidationError(f"{field} must be a list of objects")
    return value


@dataclass(frozen=True)
class RankedChange:
    source: str
    type: str
    resource: str
    minutes_before_incident: int
    score: float
    rank: str
    features: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _temporal_proximity(minutes: int) -> float:
    """Map a change in the preceding hour onto an explicit 0..1 feature."""
    return round(max(0.0, min(1.0, 1 - (minutes / 60))), 2)


def _rank_change(change: dict[str, Any], service: str) -> RankedChange:
    minutes = _required(change, "minutes_before_incident")
    if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 0:
        raise ValidationError("minutes_before_incident must be a non-negative integer")
    affected = _required(change, "affected_services")
    if not isinstance(affected, list) or not all(isinstance(item, str) for item in affected):
        raise ValidationError("affected_services must be a list of strings")
    dependency = 1.0 if service in affected else 0.2
    blast_radius = 1.0 if affected == [service] else (0.5 if service in affected else 0.2)
    metric = 1.0 if change.get("metric_correlation", False) else 0.2
    features = {
        "temporal": _temporal_proximity(minutes),
        "dependency": dependency,
        "blast_radius": blast_radius,
        "metric": metric,
    }
    score = round(sum(features[name] * weight for name, weight in _WEIGHTS.items()), 2)
    rank = "high" if score >= 0.75 else "medium" if score >= 0.50 else "low"
    return RankedChange(
        source=_string(_required(change, "source"), "change source"),
        type=_string(_required(change, "type"), "change type"),
        resource=_string(_required(change, "resource"), "change resource"),
        minutes_before_incident=minutes,
        score=score,
        rank=rank,
        features=features,
    )


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    reason = _string(_required(event, "reason"), "event reason")
    message = _string(_required(event, "message"), "event message")
    result: dict[str, Any] = {"type": reason, "message": message}
    status = event.get("status")
    if status is not None:
        if not isinstance(status, int) or isinstance(status, bool):
            raise ValidationError("event status must be an integer")
        result["status"] = status
    return result


def build_incident_context(raw: dict[str, Any]) -> dict[str, Any]:
    """Return curated facts for an LLM or a downstream policy-free API.

    Expected inputs are source records already retrieved by trusted collectors.
    Correlation ranks evidence relevance; it does not establish causality.
    """
    if not isinstance(raw, dict):
        raise ValidationError("context source must be an object")
    incident = _required(raw, "incident")
    metrics = _required(raw, "metrics")
    if not isinstance(incident, dict) or not isinstance(metrics, dict):
        raise ValidationError("incident and metrics must be objects")
    incident_id = _string(_required(incident, "id"), "incident.id")
    service = _string(_required(incident, "service"), "incident.service")
    window = _string(_required(incident, "window"), "incident.window")

    signals = {
        "error_rate": _number(_required(metrics, "error_rate"), "metrics.error_rate"),
        "cpu": _number(_required(metrics, "cpu"), "metrics.cpu"),
        "memory": _number(_required(metrics, "memory"), "metrics.memory"),
    }
    events = _required(raw, "kubernetes_events")
    changes = _required(raw, "changes")
    dependencies = _required(raw, "dependency_health")
    traces = _required(raw, "traces")
    infrastructure = _required(raw, "infrastructure")
    similar_incidents = raw.get("similar_incidents", [])
    if not isinstance(dependencies, dict):
        raise ValidationError("dependency_health must be an object")

    events = _objects(events, "kubernetes_events")
    changes = _objects(changes, "changes")
    traces = _objects(traces, "traces")
    infrastructure = _objects(infrastructure, "infrastructure")
    similar_incidents = _objects(similar_incidents, "similar_incidents")

    ranked_changes = sorted((_rank_change(change, service) for change in changes), key=lambda item: item.score, reverse=True)
    return {
        "incident_id": incident_id,
        "service": service,
        "window": window,
        "symptoms": signals,
        "kubernetes_events": [_normalize_event(event) for event in events],
        "recent_changes": [change.to_dict() for change in ranked_changes],
        "dependency_health": dependencies,
        "trace_findings": traces,
        "infrastructure_changes": infrastructure,
        "similar_incidents": similar_incidents,
        "correlation_method": {
            "features": list(_WEIGHTS),
            "weights": _WEIGHTS,
            "note": "Scores rank relevance; they do not prove a change caused the incident.",
        },
    }
