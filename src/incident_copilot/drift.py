"""Deterministic policy for reviewing AI-proposed drift classifications.

Trusted collectors detect the difference and provide provenance, resource
semantics, and reliability signals. The AI assessment is untrusted and can only
recommend a classification; this module never reconciles or mutates resources.
"""

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import math

from .models import ValidationError
from .remediation import identifier, number, object_fields


CLASSIFICATIONS = {
    "ACCIDENTAL_DRIFT", "EMERGENCY_DRIFT", "CONTROLLER_STATE",
    "EXPECTED_DRIFT", "UNKNOWN",
}
ACTIONS = {
    "IGNORE", "INVESTIGATE", "BACKPORT_TO_GIT", "UPDATE_DESIRED_STATE",
    "RECONCILE_VIA_GITOPS",
}
RISKS = {"LOW", "MEDIUM", "HIGH"}
SOURCES = {"manual", "controller", "provider", "gitops", "unknown"}
CONTROLLERS = {"argocd", "kubernetes", "terraform", "crossplane", "gcp"}


def _optional_text(value, name):
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValidationError(f"{name} must be null or a nonempty string")


def _timestamp(value, name):
    if value is None:
        return
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be null or a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{name} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{name} must include a timezone")


def _state_value(value, name):
    if type(value) not in (str, int, float, bool):
        raise ValidationError(f"{name} must be a scalar value")
    if isinstance(value, str) and not value.strip():
        raise ValidationError(f"{name} must not be empty")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError(f"{name} must be finite")


@dataclass(frozen=True)
class DriftRecord:
    """A normalized difference assembled from trusted read-only collectors."""

    resource: str
    environment: str
    controller: str
    field: str
    desired: str | int | float | bool
    observed: str | int | float | bool
    provenance: dict
    semantics: dict
    reliability: dict

    @classmethod
    def from_dict(cls, raw):
        object_fields(raw, [field.name for field in fields(cls)], "drift_record")
        for key in ("resource", "environment", "field"):
            identifier(raw[key], key)
        if raw["controller"] not in CONTROLLERS:
            raise ValidationError("controller is not supported")
        _state_value(raw["desired"], "desired")
        _state_value(raw["observed"], "observed")
        if type(raw["desired"]) is not type(raw["observed"]):
            raise ValidationError("desired and observed values must have the same type")

        provenance = raw["provenance"]
        object_fields(provenance, {"source", "actor", "changed_at", "change_ticket",
                                   "incident_active", "auto_reconcile_enabled"},
                      "provenance")
        if provenance["source"] not in SOURCES:
            raise ValidationError("provenance.source is not supported")
        _optional_text(provenance["actor"], "provenance.actor")
        _optional_text(provenance["change_ticket"], "provenance.change_ticket")
        _timestamp(provenance["changed_at"], "provenance.changed_at")
        for key in ("incident_active", "auto_reconcile_enabled"):
            if not isinstance(provenance[key], bool):
                raise ValidationError(f"provenance.{key} must be boolean")

        semantics = raw["semantics"]
        object_fields(semantics, {"expected_runtime_adaptation",
                                  "observed_to_desired_safe"}, "semantics")
        if not all(isinstance(value, bool) for value in semantics.values()):
            raise ValidationError("semantics values must be boolean")

        reliability = raw["reliability"]
        object_fields(reliability, {"before", "after", "preferred_direction"},
                      "reliability")
        before, after, directions = (reliability[key] for key in
                                     ("before", "after", "preferred_direction"))
        if not all(isinstance(value, dict) for value in (before, after, directions)):
            raise ValidationError("reliability fields must be objects")
        if set(before) != set(after) or set(before) != set(directions):
            raise ValidationError("reliability snapshots and directions must use the same metrics")
        for metric in before:
            identifier(metric, f"reliability metric {metric}")
            number(before[metric], f"reliability.before.{metric}")
            number(after[metric], f"reliability.after.{metric}")
            if directions[metric] not in {"higher", "lower"}:
                raise ValidationError("preferred_direction must be higher or lower")
        return cls(**raw)

    @property
    def differs(self):
        return self.desired != self.observed

    @property
    def reliability_improved(self):
        """Require at least one improvement and no trusted signal regression."""
        before = self.reliability["before"]
        after = self.reliability["after"]
        directions = self.reliability["preferred_direction"]
        changes = [
            after[name] > before[name] if directions[name] == "higher"
            else after[name] < before[name]
            for name in before
        ]
        regressions = [
            after[name] < before[name] if directions[name] == "higher"
            else after[name] > before[name]
            for name in before
        ]
        return bool(changes) and any(changes) and not any(regressions)


@dataclass(frozen=True)
class DriftAssessment:
    """Strict contract for an untrusted AI classification proposal."""

    classification: str
    confidence: float
    recommended_action: str
    risk_of_reconciliation: str
    evidence: list[str]

    @classmethod
    def from_dict(cls, raw):
        object_fields(raw, [field.name for field in fields(cls)], "assessment")
        if raw["classification"] not in CLASSIFICATIONS:
            raise ValidationError("classification is not supported")
        if raw["recommended_action"] not in ACTIONS:
            raise ValidationError("recommended_action is not supported")
        if raw["risk_of_reconciliation"] not in RISKS:
            raise ValidationError("risk_of_reconciliation is not supported")
        number(raw["confidence"], "confidence", 0, 1)
        if not isinstance(raw["evidence"], list) or not raw["evidence"] or not all(
            isinstance(item, str) and item.strip() for item in raw["evidence"]
        ):
            raise ValidationError("evidence must contain nonempty strings")
        return cls(**raw)


@dataclass(frozen=True)
class DriftResult:
    """Policy outcome for review; it is never an execution credential."""

    drift_detected: bool
    difference: dict
    classification: str
    decision: str
    recommended_action: str
    risk_of_reconciliation: str
    reasons: list[str]
    evidence: list[str]
    requires_human_approval: bool
    approval: str | None

    def to_dict(self):
        return asdict(self)


def _policy_expectation(record):
    source = record.provenance["source"]
    semantics = record.semantics
    if semantics["expected_runtime_adaptation"] and source == "controller":
        return "CONTROLLER_STATE", "IGNORE", "LOW"
    if semantics["expected_runtime_adaptation"] and source == "provider":
        return "EXPECTED_DRIFT", "UPDATE_DESIRED_STATE", "MEDIUM"
    if (source == "manual" and record.provenance["incident_active"]
            and record.provenance["actor"] is not None
            and record.provenance["changed_at"] is not None
            and not record.provenance["auto_reconcile_enabled"]
            and record.reliability_improved):
        return "EMERGENCY_DRIFT", "BACKPORT_TO_GIT", "HIGH"
    if (source == "manual" and not record.provenance["incident_active"]
            and record.provenance["change_ticket"] is None):
        return "ACCIDENTAL_DRIFT", "INVESTIGATE", (
            "HIGH" if not semantics["observed_to_desired_safe"] else "MEDIUM"
        )
    return "UNKNOWN", "INVESTIGATE", (
        "HIGH" if not semantics["observed_to_desired_safe"] else "MEDIUM"
    )


def evaluate_drift(raw_record, raw_assessment):
    """Compare an AI recommendation with deterministic provenance policy."""
    record = DriftRecord.from_dict(raw_record)
    assessment = DriftAssessment.from_dict(raw_assessment)
    difference = {
        "resource": record.resource, "environment": record.environment,
        "controller": record.controller, "field": record.field,
        "desired": record.desired, "observed": record.observed,
    }
    if not record.differs:
        return DriftResult(False, difference, "NO_DRIFT", "no_action", "IGNORE", "LOW",
                           ["Desired and observed values are equal."], assessment.evidence,
                           False, None)

    expected_class, expected_action, expected_risk = _policy_expectation(record)
    reasons = []
    if assessment.confidence < 0.80:
        reasons.append("AI confidence is below 0.80.")
    if assessment.classification != expected_class:
        reasons.append("AI classification conflicts with trusted provenance and semantics.")
    if assessment.recommended_action != expected_action:
        reasons.append("AI action conflicts with deterministic drift policy.")
    if assessment.risk_of_reconciliation != expected_risk:
        reasons.append("AI reconciliation risk conflicts with resource semantics.")
    if reasons:
        return DriftResult(True, difference, "UNKNOWN", "investigate", "INVESTIGATE",
                           expected_risk, reasons, assessment.evidence, False, None)

    if expected_action == "IGNORE":
        reasons.append("A trusted controller produced expected runtime state.")
        return DriftResult(True, difference, expected_class, "no_action", expected_action,
                           expected_risk, reasons, assessment.evidence, False, None)
    if expected_action == "INVESTIGATE":
        reasons.append("Provenance is insufficient for safe reconciliation.")
        if not record.semantics["observed_to_desired_safe"]:
            reasons.append("Reversing observed state may be destructive or unsupported.")
        return DriftResult(True, difference, expected_class, "investigate", expected_action,
                           expected_risk, reasons, assessment.evidence, False, None)

    if expected_action == "BACKPORT_TO_GIT":
        reasons.extend([
            "A manual incident change is associated with non-regressing reliability signals.",
            "Back-port the reviewed observed value before restoring reconciliation.",
        ])
        approval = "incident_commander"
    else:
        reasons.append("Review whether expected provider state should become desired state.")
        if not record.semantics["observed_to_desired_safe"]:
            reasons.append("Do not reverse the provider change; the reverse direction is unsafe.")
        approval = "platform_owner"
    return DriftResult(True, difference, expected_class, "requires_human_approval",
                       expected_action, expected_risk, reasons, assessment.evidence,
                       True, approval)
