"""Small, correlated event contracts for a provider-neutral incident control loop."""

import base64
from datetime import datetime
import json
import re

from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer
from .rollout import digest, fingerprint, identifiers


SOURCES = {
    "incident.created": "monitoring",
    "evidence.requested": "investigator",
    "evidence.collected": "collectors",
    "hypothesis.updated": "investigator",
    "investigation.failed": "investigator",
    "remediation.proposed": "investigator",
    "remediation.approved": "approval-service",
    "remediation.executed": "gitops-controller",
    "remediation.verified": "verifier",
}
TOOLS = {"get_service_health", "get_dependency_health", "get_recent_changes",
         "get_cloudsql_health"}
PAYLOADS = {
    "incident.created": {"service", "environment", "signal", "value", "threshold", "started_at"},
    "evidence.requested": {"request_id", "tool", "target"},
    "evidence.collected": {"request_id", "evidence_ref", "evidence_sha256", "evidence_ids"},
    "hypothesis.updated": {"request_id", "attempt", "hypotheses", "evidence_ids",
                           "falsification_completed"},
    "investigation.failed": {"request_id", "attempt", "reason"},
    "remediation.proposed": {"hypothesis_id", "resource", "intent_ref", "intent_sha256",
                             "plan_ref", "plan_sha256", "verification_sha256", "evidence_ids"},
    "remediation.approved": {"proposal_event_id", "approval_id", "intent_sha256",
                             "plan_sha256", "verification_sha256"},
    "remediation.executed": {"proposal_event_id", "approval_id", "plan_sha256", "revision"},
    "remediation.verified": {"proposal_event_id", "revision", "verification_sha256",
                             "outcome", "report_ref", "report_sha256"},
}


def timestamp(value):
    """Require a full date and explicit timezone for cross-service correlation."""
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a timezone-aware ISO string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamp must include timezone")
    return parsed


def validate_context(context):
    """Validate platform-owned scope, identities, authority, and investigation bounds."""
    object_fields(context, {"agent_version", "environment", "services", "resources",
                            "principals", "limits"}, "event context")
    for key in ("agent_version", "environment"):
        identifier(context[key], key)
    identifiers(context["services"], "services")
    if not context["services"]:
        raise ValidationError("services must not be empty")
    object_fields(context["principals"], set(SOURCES.values()), "principals")
    for principal in context["principals"].values():
        if not isinstance(principal, str) or not principal.strip():
            raise ValidationError("principal must be nonempty")
    if len(set(context["principals"].values())) != len(context["principals"]):
        raise ValidationError("investigation and authority identities must differ")
    if not isinstance(context["resources"], dict):
        raise ValidationError("resources must be an object")
    for resource_id, resource in context["resources"].items():
        _validate_resource(resource_id, resource, context["services"])
    limits = context["limits"]
    object_fields(limits, {"max_tool_calls", "max_investigation_seconds", "max_delivery_attempts",
                           "max_reasoning_attempts", "retry_base_seconds", "max_event_bytes"},
                  "limits")
    for key, value in limits.items():
        positive_integer(value, key)
    if not 3 <= limits["max_tool_calls"] <= 20:
        raise ValidationError("tool budget requires three initial collectors and at most 20 reads")
    if (limits["max_investigation_seconds"] > 900
            or limits["max_delivery_attempts"] > 10 or limits["max_reasoning_attempts"] > 5
            or limits["max_event_bytes"] > 65536):
        raise ValidationError("event limits exceed platform bounds")


def _validate_resource(resource_id, resource, services):
    """Pin declarative ownership to a platform-owned catalog entry."""
    identifier(resource_id, "resource id")
    object_fields(resource, {"service", "controller", "git_path"}, "resource")
    if resource["service"] not in services:
        raise ValidationError("resource service is outside scope")
    if resource["controller"] not in ("terraform", "crossplane", "argocd"):
        raise ValidationError("resource controller is unsupported")
    path = resource["git_path"]
    if (not isinstance(path, str) or path.startswith("/") or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise ValidationError("resource git_path must be repository-relative")


def validate_event(event, context, principal, received_at):
    """Bind a small typed event to an independently authenticated delivery principal."""
    object_fields(event, {"event_id", "type", "incident_id", "trace_id", "agent_version",
                          "timestamp", "source", "payload"}, "event")
    for key in ("event_id", "incident_id", "agent_version", "source"):
        identifier(event[key], key)
        if len(event[key]) > 128:
            raise ValidationError(f"{key} exceeds 128 characters")
    if not isinstance(event["type"], str) or event["type"] not in SOURCES:
        raise ValidationError("unsupported event type")
    if (not isinstance(event["trace_id"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", event["trace_id"])
            or event["trace_id"] == "0" * 32):
        raise ValidationError("trace_id must be a nonzero 32-character lowercase hex string")
    expected_source = SOURCES[event["type"]]
    if event["source"] != expected_source or principal != context["principals"][expected_source]:
        raise ValidationError("event source is not authorized by authenticated principal")
    if event["agent_version"] != context["agent_version"]:
        raise ValidationError("event agent_version differs from assigned investigator")
    if timestamp(event["timestamp"]) > timestamp(received_at):
        raise ValidationError("event timestamp is from the future")
    if len(json.dumps(event).encode("utf-8")) > context["limits"]["max_event_bytes"]:
        raise ValidationError("event exceeds maximum size; use context-store references")
    _validate_payload(event["type"], event["payload"])
    return fingerprint(event)


def _validate_payload(kind, payload):
    """Restrict payloads to facts, canonical references, and reviewed artifact digests."""
    object_fields(payload, PAYLOADS[kind], f"{kind} payload")
    for key, value in payload.items():
        if key.endswith("sha256"):
            digest(value, key)
        elif key in {"request_id", "tool", "target", "resource", "hypothesis_id", "approval_id",
                     "proposal_event_id", "intent_ref", "plan_ref", "report_ref", "evidence_ref"}:
            identifier(value, key)
        elif key == "evidence_ids":
            identifiers(value, key)
    if kind == "incident.created":
        _validate_trigger(payload)
    if kind == "evidence.requested" and payload["tool"] not in TOOLS:
        raise ValidationError("only narrow read-only platform tools may be requested")
    if kind in {"hypothesis.updated", "investigation.failed"}:
        positive_integer(payload["attempt"], "attempt")
    if kind == "hypothesis.updated":
        _validate_hypotheses(payload)
    if kind == "investigation.failed" and payload["reason"] not in (
            "timeout", "unavailable", "quota"):
        raise ValidationError("unsupported transient failure reason")
    if "revision" in payload and (
            not isinstance(payload["revision"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", payload["revision"])):
        raise ValidationError("revision must be a full Git commit SHA")
    if kind == "remediation.verified" and payload["outcome"] not in (
            "SUCCESS", "FAILED", "INCONCLUSIVE"):
        raise ValidationError("unsupported verification outcome")


def _validate_trigger(payload):
    """Use comparable numeric signals and an explicit incident start time."""
    for key in ("service", "environment"):
        identifier(payload[key], key)
    if payload["signal"] not in ("http_5xx_rate", "p99_latency_ms"):
        raise ValidationError("unsupported incident signal")
    upper = 1 if payload["signal"] == "http_5xx_rate" else None
    number(payload["value"], "incident value", 0, upper)
    number(payload["threshold"], "incident threshold", 0, upper)
    timestamp(payload["started_at"])


def _validate_hypotheses(payload):
    """Require competing normalized beliefs without accepting a reasoning transcript."""
    items = payload["hypotheses"]
    if not isinstance(items, list) or not 3 <= len(items) <= 10:
        raise ValidationError("hypotheses requires 3 to 10 competing explanations")
    ids = []
    for item in items:
        object_fields(item, {"id", "cause", "confidence"}, "hypothesis")
        identifier(item["id"], "hypothesis id")
        identifier(item["cause"], "hypothesis cause")
        number(item["confidence"], "confidence", 0, 1)
        ids.append(item["id"])
    if len(ids) != len(set(ids)) or abs(sum(item["confidence"] for item in items) - 1) > 1e-9:
        raise ValidationError("hypotheses must have unique ids and confidence summing to 1")
    if not isinstance(payload["falsification_completed"], bool):
        raise ValidationError("falsification_completed must be boolean")


def decode_pubsub_push(envelope, max_bytes=65536):
    """Decode canonical events from wrapped Pub/Sub data; does not authenticate JWTs.

    Raw Cloud Monitoring notifications need a separate normalization adapter.
    Transport attributes are deliberately not used as authorization credentials.
    """
    if not isinstance(envelope, dict) or not isinstance(envelope.get("message"), dict):
        raise ValidationError("invalid Pub/Sub push envelope")
    encoded = envelope["message"].get("data")
    if not isinstance(encoded, str) or len(encoded) > ((max_bytes + 2) // 3) * 4:
        raise ValidationError("Pub/Sub data is missing or too large")
    try:
        decoded = base64.b64decode(encoded, validate=True)
        if len(decoded) > max_bytes:
            raise ValidationError("decoded Pub/Sub message is too large")
        return json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ValidationError("Pub/Sub data must be base64-encoded JSON") from error
