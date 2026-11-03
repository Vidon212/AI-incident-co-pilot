"""Review a pre-approved, reversible HPA capability without executing it."""

from datetime import datetime

from .models import ValidationError
from .remediation import evaluate_remediation, identifier, number, object_fields, positive_integer
from .rollout import fingerprint, review_rollout


def _timestamp(value):
    """Require explicit timezones for collector and preapproval timestamps."""
    if not isinstance(value, str):
        raise ValidationError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("invalid timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError("timestamp must include a timezone")
    return parsed


def approval_binding(release, capability, intent, plan):
    """Bind preapproval to the release, exact capability, plan, and SLO contract."""
    return fingerprint({"release": release, "capability": capability,
                        "verification": intent["verification"], "plan": plan})


def _validate_platform(platform):
    """Validate the authenticated platform's capability and collector snapshots."""
    object_fields(platform, {"rollout_context", "rollout_request", "capability",
                             "remediation_context", "observations", "preapproval",
                             "evaluated_at"}, "capability platform")
    capability = platform["capability"]
    object_fields(capability, {"id", "service", "resource", "namespace", "environment",
                               "git_path", "field", "maximum_multiplier",
                               "minimum_historical_successes", "minimum_error_budget",
                               "maximum_blast_radius"}, "capability")
    for key in ("id", "service", "resource", "namespace", "environment", "field"):
        identifier(capability[key], f"capability.{key}")
    if not isinstance(capability["git_path"], str):
        raise ValidationError("capability git_path must be a string")
    number(capability["maximum_multiplier"], "maximum_multiplier", 1, 2)
    number(capability["minimum_error_budget"], "minimum_error_budget", 0.5, 1)
    positive_integer(capability["minimum_historical_successes"], "minimum_historical_successes")
    positive_integer(capability["maximum_blast_radius"], "maximum_blast_radius")
    if capability["maximum_blast_radius"] != 1:
        raise ValidationError("HPA capability must be limited to one service")
    observations = platform["observations"]
    object_fields(observations, {"observed_at", "cpu_percent", "traffic_ratio",
                                 "db_cpu_fraction", "db_connections_fraction",
                                 "available_capacity_fraction", "historical_attempts",
                                 "historical_successes", "error_budget_remaining"}, "observations")
    number(observations["cpu_percent"], "cpu_percent", 0, 100)
    number(observations["traffic_ratio"], "traffic_ratio")
    for key in ("db_cpu_fraction", "db_connections_fraction", "available_capacity_fraction",
                "error_budget_remaining"):
        number(observations[key], key, 0, 1)
    for key in ("historical_attempts", "historical_successes"):
        positive_integer(observations[key], key)
    if observations["historical_successes"] > observations["historical_attempts"]:
        raise ValidationError("historical successes exceed attempts")
    _timestamp(observations["observed_at"])
    _timestamp(platform["evaluated_at"])
    approval = platform["preapproval"]
    if approval is not None:
        object_fields(approval, {"id", "approved_by_tier", "expires_at", "binding_sha256"},
                      "preapproval")
        identifier(approval["id"], "preapproval id")
        identifier(approval["approved_by_tier"], "approval tier")
        _timestamp(approval["expires_at"])


def _scope_findings(platform, intent, policy):
    """Retain Stage 3 plan checks and constrain this catalog entry to one HPA."""
    grant = platform["capability"]
    context = platform["remediation_context"]
    reasons = []
    for key in ("resource", "namespace", "environment"):
        if intent[key] != grant[key]:
            reasons.append(f"Intent {key} is outside capability scope.")
    rollout = platform["rollout_request"]
    if (grant["service"] not in rollout["services"]
            or grant["environment"] != rollout["environment"]
            or grant["id"] not in platform["rollout_context"]["capability_ids"]):
        reasons.append("Capability is outside the approved rollout scope.")
    if (grant["field"] != "hpa.maxReplicas" or intent["action"] != "CONFIG_CHANGE"
            or set(intent["desired_state"]) != {grant["field"]}
            or context["git_path"] != grant["git_path"]
            or context["controller"] not in {"argocd", "terraform", "crossplane"}):
        reasons.append("Only the catalog's exact HPA Git/IaC change is eligible.")
    current = context["current_state"].get("hpa.maxReplicas")
    desired = intent["desired_state"].get("hpa.maxReplicas")
    if current is None or desired is None or not current < desired <= (
            current * grant["maximum_multiplier"]):
        reasons.append("HPA increase exceeds capability bounds.")
    if current is None or intent["rollback_plan"] != {"hpa.maxReplicas": current}:
        reasons.append("Rollback must restore the reviewed HPA limit.")
    if context["blast_radius"] > grant["maximum_blast_radius"]:
        reasons.append("Capability blast radius exceeded.")
    if policy.decision != "requires_human_approval":
        reasons.append(f"Stage 3 remediation checks did not pass: {policy.decision}.")
    return reasons


def _evidence_findings(platform, intent):
    """Require the capacity pattern, a healthy budget, and repeated historical success."""
    data = platform["observations"]
    grant = platform["capability"]
    context = platform["remediation_context"]
    reasons = []
    healthy_pattern = (
        data["cpu_percent"] > 90 and data["traffic_ratio"] > 1.5
        and data["db_cpu_fraction"] < 0.7 and data["db_connections_fraction"] < 0.7
        and data["available_capacity_fraction"] > 0.3 and intent["confidence"] > 0.90
        and context["observed_replicas"] == context["hpa_max_replicas"]
    )
    if not healthy_pattern:
        reasons.append("Required capacity evidence or confidence threshold was not met.")
    if (data["error_budget_remaining"] <= grant["minimum_error_budget"]
            or context.get("error_budget_remaining") != data["error_budget_remaining"]
            or context["db_utilization"] != data["db_cpu_fraction"]):
        reasons.append("Error budget or downstream observations are insufficient or conflicting.")
    if (data["historical_successes"] < grant["minimum_historical_successes"]
            or data["historical_successes"] != data["historical_attempts"]):
        reasons.append("Capability lacks the required successful historical pattern.")
    age = (_timestamp(platform["evaluated_at"])
           - _timestamp(data["observed_at"])).total_seconds()
    if not 0 <= age <= 300:
        reasons.append("Capacity observations are stale or from the future.")
    verification = intent["verification"]
    success = set(verification["success_criteria"])
    if ("http_error_rate" not in success
            or not {"p95_latency_ms", "p99_latency_ms"} & success
            or not {"pod_cpu_percent", "db_connections"}.issubset(
                verification["failure_criteria"])):
        reasons.append("Verification requires error, latency, and saturation criteria.")
    return reasons


def review_capability(platform, intent, plan, replay):
    """Review an exact pre-approved GitOps proposal; return no execution authority."""
    _validate_platform(platform)
    rollout = review_rollout(platform["rollout_context"], platform["rollout_request"],
                             replay)
    policy = evaluate_remediation(intent, platform["remediation_context"], plan)
    reasons = _scope_findings(platform, intent, policy) + _evidence_findings(platform, intent)
    if (rollout["decision"] != "eligible_for_next_stage"
            or rollout["to_stage"] not in {"limited_autonomy", "production"}):
        reasons.append("Release is not eligible for bounded autonomy.")
    approval = platform["preapproval"]
    binding = approval_binding(platform["rollout_context"]["release"],
                               platform["capability"], intent, plan)
    if approval is None:
        reasons.append("Independent capability preapproval is missing.")
    elif (approval["binding_sha256"] != binding or approval["approved_by_tier"] != policy.approval
          or _timestamp(approval["expires_at"]) <= _timestamp(platform["evaluated_at"])):
        reasons.append("Preapproval is expired or does not bind release, scope, plan, and SLOs.")
    return {
        "decision": "requires_human_review" if reasons else "eligible_for_preapproved_gitops",
        "reasons": reasons, "capability_id": platform["capability"]["id"],
        "preapproval_binding_sha256": binding, "proposed_change": policy.proposed_change,
        "execution_path": "Git PR and external policy-controlled merge",
        "failure_path": "External verification failure triggers reviewed Git revert",
        "rollback_plan": intent["rollback_plan"], "verification": intent["verification"],
        "stage3_decision": policy.decision, "required_approval_tier": policy.approval,
        "input_sha256": fingerprint({"platform": platform, "intent": intent, "plan": plan,
                                     "replay": replay}),
    }
