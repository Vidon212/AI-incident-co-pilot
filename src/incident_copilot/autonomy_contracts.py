"""Normalized proposal and independently collected ActionRisk contracts for Session 15."""

from .events import timestamp
from .models import ValidationError
from .remediation import (identifier, number, object_fields, positive_integer,
                          validate_verification_contract)
from .rollout import digest, fingerprint, identifiers


ACTIONS = {"increase_hpa_max": "hpa.maxReplicas", "rollback": "image.tag",
           "change_capacity": "max_connections", "change_network": "route_revision",
           "recreate_database": "lifecycle", "restart_pod": "restart"}
TIERS = ("operator", "engineer", "senior", "incident_commander")


def _boolean(value, name):
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be boolean")


def proposal_contract(proposal):
    """The model can propose typed intent and confidence, never permissions or risk facts."""
    object_fields(proposal, {"action", "service", "resource", "namespace", "environment",
                             "confidence", "desired_state", "rollback_plan", "verification",
                             "evidence"}, "autonomy proposal")
    for key in ("action", "service", "resource", "namespace", "environment"):
        identifier(proposal[key], key)
    if proposal["action"] not in ACTIONS:
        raise ValidationError("unsupported autonomy action")
    number(proposal["confidence"], "confidence", 0, 1)
    field = ACTIONS[proposal["action"]]
    states = [proposal["desired_state"]]
    if proposal["rollback_plan"] is not None:
        states.append(proposal["rollback_plan"])
    for state in states:
        object_fields(state, {field}, "proposed state")
        if field in {"hpa.maxReplicas", "max_connections"}:
            positive_integer(state[field], field)
        elif field == "restart":
            _boolean(state[field], "restart")
        else:
            identifier(state[field], field)
    if proposal["verification"] is not None:
        validate_verification_contract(proposal["verification"])
    evidence = proposal["evidence"]
    if (not isinstance(evidence, list) or not 1 <= len(evidence) <= 50
            or any(not isinstance(item, str) or not 1 <= len(item) <= 2000 for item in evidence)):
        raise ValidationError("proposal evidence must be bounded nonempty text")


# Validate every independent risk dimension before the ordered autonomy rules run.
# pylint: disable-next=too-many-branches
def risk_contract(context, proposal):
    """Risk, policy scope, clocks, and evidence are outside model control in live adapters."""
    object_fields(context, {"proposal_sha256", "evaluated_at", "observed_at", "enabled",
                            "allowed_actions", "service", "resource", "namespace", "environment",
                            "affected_services", "reversibility", "requires_recreation",
                            "backward_incompatible_migration", "gitops_managed",
                            "cluster_headroom", "downstream_headroom", "historical_attempts",
                            "historical_successes", "error_budget_remaining", "burn_rate",
                            "change_risk", "transition", "remediation_context", "plan", "approval"},
                  "ActionRisk context")
    if context["proposal_sha256"] != fingerprint(proposal):
        raise ValidationError("ActionRisk is not bound to this exact proposal")
    if any(context[key] != proposal[key] for key in (
            "service", "resource", "namespace", "environment")):
        raise ValidationError("proposal target differs from independently resolved identity")
    timestamp(context["evaluated_at"])
    timestamp(context["observed_at"])
    for key in ("enabled", "requires_recreation", "backward_incompatible_migration",
                "gitops_managed"):
        _boolean(context[key], key)
    identifiers(context["allowed_actions"], "allowed actions")
    if not set(context["allowed_actions"]) <= ACTIONS.keys():
        raise ValidationError("unknown action in platform policy")
    identifiers(context["affected_services"], "affected services")
    if proposal["service"] not in context["affected_services"]:
        raise ValidationError("affected services must include target service")
    if context["reversibility"] not in ("high", "low", "unknown"):
        raise ValidationError("reversibility must be high, low, or unknown")
    if context["change_risk"] not in ("low", "medium", "high", "critical", "unknown"):
        raise ValidationError("unsupported change risk")
    if context["transition"] not in ("in_place", "rolling_update", "restart", "replacement",
                                      "unknown"):
        raise ValidationError("unsupported transition")
    for key in ("cluster_headroom", "downstream_headroom", "error_budget_remaining"):
        number(context[key], key, 0, 1)
    number(context["burn_rate"], "burn rate", 0, 1000)
    for key in ("historical_attempts", "historical_successes"):
        value = context[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 1000000:
            raise ValidationError("history counters must be integers from 0 to 1000000")
    if context["historical_successes"] > context["historical_attempts"]:
        raise ValidationError("historical successes exceed attempts")
    approval = context["approval"]
    if approval is not None:
        object_fields(approval, {"id", "approved_by_tier", "expires_at", "binding_sha256"},
                      "independent approval")
        identifier(approval["id"], "approval id")
        if approval["approved_by_tier"] not in TIERS:
            raise ValidationError("unknown approval tier")
        timestamp(approval["expires_at"])
        digest(approval["binding_sha256"], "approval binding")


def manual_approval_binding(proposal, context, simulation_sha256=None):
    """Bind independent approval to the complete proposal, risk, plan, and optional simulation."""
    return fingerprint({"proposal": proposal,
                        "context": {key: value for key, value in context.items()
                                    if key != "approval"},
                        "simulation_sha256": simulation_sha256})
