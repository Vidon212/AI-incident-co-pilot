"""Session 15: a deterministic autonomy ladder; no production authority or execution."""

from .autonomy_contracts import (TIERS, manual_approval_binding, proposal_contract, risk_contract)
from .capability import review_capability
from .events import timestamp
from .impact import simulate_change
from .models import ValidationError
from .remediation import evaluate_remediation, object_fields
from .rollout import fingerprint


LEVELS = ("EXPLAIN", "INVESTIGATE", "RECOMMEND", "PREPARE_CHANGE",
          "EXECUTE_WITH_APPROVAL", "EXECUTE_AND_VERIFY")


def _intent(proposal):
    """Translate only existing Stage 3 action profiles; other actions remain advisory."""
    if proposal["action"] not in ("increase_hpa_max", "rollback"):
        return None
    return {**{key: value for key, value in proposal.items() if key not in ("action", "service")},
            "action": "ROLLBACK" if proposal["action"] == "rollback" else "CONFIG_CHANGE"}


def _remediation(proposal, context):
    """Retain complete-plan checks, rollback validation, approval tiers, and SLO contracts."""
    intent = _intent(proposal)
    if intent is None or proposal["verification"] is None or proposal["rollback_plan"] is None:
        return None
    if context["remediation_context"] is None:
        return None
    stage3 = evaluate_remediation(intent, context["remediation_context"], context["plan"]).to_dict()
    facts = context["remediation_context"]
    if (facts["blast_radius"] != len(context["affected_services"])
            or facts.get("error_budget_remaining") != context["error_budget_remaining"]):
        raise ValidationError("remediation scope or error budget disagrees with ActionRisk")
    if proposal["action"] == "increase_hpa_max" and proposal["desired_state"][
            "hpa.maxReplicas"] <= facts["current_state"].get("hpa.maxReplicas", 0):
        raise ValidationError("HPA profile only permits ceiling increases")
    return stage3


def _impact(proposal, context, bundle):
    """Recompute Stage 14 from source inputs instead of accepting a model's risk report."""
    if bundle is None:
        return None
    object_fields(bundle, {"change", "context", "graph"}, "impact source bundle")
    if proposal["action"] != "change_capacity":
        raise ValidationError("impact adapter currently supports only database capacity changes")
    change = bundle["change"]
    if not isinstance(change, dict):
        raise ValidationError("impact change must be an object")
    if (change.get("model") != "database_connections"
            or change.get("resource_id") != proposal["resource"]
            or change.get("environment") != proposal["environment"]
            or change.get("after") != proposal["desired_state"]):
        raise ValidationError("impact change differs from exact proposed target or state")
    report = simulate_change(change, bundle["context"], bundle["graph"])
    if (report["evaluated_at"] != context["evaluated_at"]
            or report["transition"]["operation"] != context["transition"]):
        raise ValidationError("impact clock or transition differs from ActionRisk")
    services = {node["name"] for node in report["topology"]["nodes"] if node["kind"] == "Service"}
    if services != set(context["affected_services"]):
        raise ValidationError("impact affected services differ from ActionRisk")
    return report


def _capability(proposal, context, platform, replay):
    """Level 5 reuses the existing independently scoped HPA preapproval and rollout gates."""
    if platform is None and replay is None:
        return None
    if platform is None or replay is None:
        raise ValidationError("capability platform and replay are required together")
    if proposal["action"] != "increase_hpa_max":
        raise ValidationError("only the existing HPA catalog supports preapproved execution")
    result = review_capability(platform, _intent(proposal), context["plan"], replay)
    if (platform["remediation_context"] != context["remediation_context"]
            or platform["evaluated_at"] != context["evaluated_at"]
            or platform["capability"]["service"] != proposal["service"]):
        raise ValidationError("capability scope, clock, or plan context differs from ActionRisk")
    observations = platform["observations"]
    expected = {"historical_attempts": observations["historical_attempts"],
                "historical_successes": observations["historical_successes"],
                "error_budget_remaining": observations["error_budget_remaining"],
                "cluster_headroom": observations["available_capacity_fraction"],
                "downstream_headroom": min(1 - observations["db_cpu_fraction"],
                                           1 - observations["db_connections_fraction"])}
    if any(context[key] != value for key, value in expected.items()):
        raise ValidationError("capability observations disagree with ActionRisk")
    return result


def _auto_gaps(proposal, context, capability):
    """Every dimension is an independent gate; urgency and confidence cannot buy permission."""
    attempts = context["historical_attempts"]
    checks = {
        "confidence_below_auto_threshold": proposal["confidence"] >= .90,
        "blast_radius_exceeds_single_service": len(context["affected_services"]) == 1,
        "insufficient_history": (attempts >= 10
                                 and context["historical_successes"] / attempts >= .95),
        "insufficient_cluster_headroom": context["cluster_headroom"] >= .30,
        "insufficient_downstream_headroom": context["downstream_headroom"] >= .30,
        "error_budget_restricts_autonomy": context["error_budget_remaining"] > .50,
        "change_risk_exceeds_low": context["change_risk"] == "low",
        "disruptive_transition": context["transition"] in ("in_place", "rolling_update"),
        "missing_valid_preapproval": capability is not None and capability[
            "decision"] == "eligible_for_preapproved_gitops",
    }
    return [reason for reason, passed in checks.items() if not passed]


def _manual_approved(proposal, context, stage3, impact):
    """A local receipt is an eligibility attestation, never a credential or signature."""
    approval = context["approval"]
    if approval is None or stage3 is None or stage3["decision"] != "requires_human_approval":
        return False
    return (approval["binding_sha256"] == manual_approval_binding(
        proposal, context, impact["simulation_sha256"] if impact else None)
        and timestamp(approval["expires_at"]) > timestamp(context["evaluated_at"])
        and TIERS.index(approval["approved_by_tier"]) >= TIERS.index(stage3["approval"]))


# Ordered vetoes stay explicit so that no later eligibility rule bypasses a safety cap.
# pylint: disable-next=too-many-return-statements,too-many-branches
def _choose_level(proposal, context, reviews):
    """Order hard vetoes before policy preparation, approval, and bounded auto eligibility."""
    stage3, impact, capability = reviews
    if not context["enabled"] or proposal["action"] not in context["allowed_actions"]:
        return 0, ["action_disabled_by_policy"]
    age = (timestamp(context["evaluated_at"]) - timestamp(context["observed_at"])).total_seconds()
    if not 0 <= age <= 300 or proposal["confidence"] < .80:
        return 1, ["stale_or_future_risk_evidence_or_low_confidence"]
    if context["change_risk"] == "unknown" or context["transition"] == "unknown":
        return 1, ["unknown_change_or_transition_risk"]
    if proposal["action"] == "change_capacity" and (impact is None or impact[
            "decision"] == "investigate"):
        return 1, ["missing_or_incomplete_change_simulation"]
    if (context["requires_recreation"] or proposal["action"] == "recreate_database"
            or context["backward_incompatible_migration"] or context["reversibility"] != "high"):
        return 2, ["destructive_or_unverified_reversal_requires_human_control"]
    if (impact is not None and impact["decision"] == "block"
            or stage3 is not None and stage3["decision"] == "deny"):
        return 2, ["existing_policy_blocks_execution"]
    if proposal["confidence"] < .90 or proposal["verification"] is None:
        return 2, ["insufficient_confidence_or_missing_verification_contract"]
    if not context["gitops_managed"] or proposal["rollback_plan"] is None:
        return 2, ["missing_authoritative_control_or_rollback_path"]
    if proposal["action"] == "restart_pod":
        return 2, ["no_approved_pod_restart_profile"]
    if stage3 is not None and stage3["decision"] == "investigate":
        return 1, ["stage3_evidence_requires_investigation"]
    # Recomputed transition/critical-SLO signals cannot be downgraded by a risk label.
    high_risk = (context["change_risk"] in ("high", "critical")
                 or context["transition"] in ("restart", "replacement")
                 or len(context["affected_services"]) > 1
                 or impact is not None and (impact["risk_level"] in ("high", "critical")
                                            or impact["critical_slo_ids"]))
    if high_risk:
        return 3, ["blast_radius_or_change_risk_requires_human_change_review"]
    gaps = _auto_gaps(proposal, context, capability)
    if not gaps and stage3 is not None and stage3["decision"] == "requires_human_approval":
        return 5, ["existing_hpa_preapproval_and_all_autonomy_gates_pass"]
    if _manual_approved(proposal, context, stage3, impact):
        return 4, ["exact_plan_has_current_independent_approval", *gaps]
    return 3, ["prepare_only_until_independent_approval", *gaps]


def review_autonomy(proposal, context, capability_platform=None, replay=None, impact_bundle=None):
    """Return a bounded capability level and predeclared transaction, never execution authority."""
    proposal_contract(proposal)
    risk_contract(context, proposal)
    stage3 = _remediation(proposal, context)
    impact = _impact(proposal, context, impact_bundle)
    capability = _capability(proposal, context, capability_platform, replay)
    level, reasons = _choose_level(proposal, context, (stage3, impact, capability))
    high_urgency = context["error_budget_remaining"] <= .10 or context["burn_rate"] >= 10
    risky = (context["requires_recreation"] or context["backward_incompatible_migration"]
             or context["reversibility"] != "high" or context["change_risk"] in ("high", "critical")
             or len(context["affected_services"]) > 1
             or context["transition"] in ("restart", "replacement")
             or impact is not None and impact["decision"] == "block")
    transaction = None
    if level >= 4:
        transaction = {"preconditions_sha256": fingerprint(context),
                       "verification": proposal["verification"],
                       "rollback_plan": proposal["rollback_plan"],
                       "timeout_minutes": proposal["verification"]["observation_window_minutes"],
                       "stages": ["preconditions", "reviewed_git_change", "controller_convergence",
                                  "observe", "verify"],
                       "success": "close_after_independent_verification",
                       "no_improvement": "request_reviewed_git_revert",
                       "degradation": "request_immediate_reviewed_git_revert",
                       "unexpected_signal": "freeze_and_escalate"}
    result = {"policy_version": "session15-v1", "autonomy_level": level,
              "capability_level": LEVELS[level], "reasons": reasons,
              "urgency": "high" if high_urgency else "normal",
              "escalation": ("immediate_human" if high_urgency and (risky or level < 4)
                             else "normal"),
              "proposal_sha256": fingerprint(proposal), "context_sha256": fingerprint(context),
              "stage3_review": stage3, "impact_review": impact, "capability_review": capability,
              "transaction": transaction, "execution_authorized": False, "merge_authorized": False,
              "eligibility_only": True,
              "input_sha256": fingerprint({"proposal": proposal, "context": context,
                                           "platform": capability_platform, "replay": replay,
                                           "impact": impact_bundle})}
    result["review_sha256"] = fingerprint(result)
    return result
