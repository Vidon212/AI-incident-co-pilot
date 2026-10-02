"""Session 3 safety contract. Inputs produce review artifacts, never execution.

Intent is untrusted model output. Context and normalized plan must come from
trusted collectors and platform tooling, never from the model itself.
"""

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import math
import re

from .models import ValidationError


FIELDS = {
    "SCALE": {"replicas"},
    "ROLLBACK": {"image.tag"},
    "CONFIG_CHANGE": {"hpa.maxReplicas", "memory.limitMi", "node_pool.max_nodes"},
}
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*\Z")
METRIC_BOUNDS = {
    "checkout_completion_rate": (0, 1), "http_error_rate": (0, 1),
    "p95_latency_ms": (0, None), "p99_latency_ms": (0, None),
    "throughput_rps": (0, None), "pod_cpu_percent": (0, 100),
    "db_connections": (0, None), "db_p95_latency_ms": (0, None),
    "oomkills": (0, None), "memory_working_set_mi": (0, None),
}
USER_FACING_METRICS = {"checkout_completion_rate", "http_error_rate",
                       "p95_latency_ms", "p99_latency_ms"}
OPERATORS = {"lt", "lte", "gt", "gte", "eq"}


def object_fields(value, required, name):
    """Reject missing and extra fields, including model-supplied authority."""
    if not isinstance(value, dict) or set(value) != set(required):
        raise ValidationError(f"{name} must contain exactly: {', '.join(sorted(required))}")


def number(value, name, minimum=0, maximum=None):
    """Validate finite numeric measurements, excluding Python booleans."""
    if (type(value) not in (int, float) or not math.isfinite(value)
            or value < minimum or (maximum is not None and value > maximum)):
        raise ValidationError(f"{name} is outside its numeric bounds")


def positive_integer(value, name):
    """Validate a replica, node, or memory quantity."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValidationError(f"{name} must be a positive integer")


def identifier(value, name):
    """Keep target identities nonempty and free from path traversal."""
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValidationError(f"{name} must be an identifier")


def state(value, name):
    """Allow exactly one supported, typed desired-state field per intent."""
    if not isinstance(value, dict) or len(value) != 1:
        raise ValidationError(f"{name} must contain one supported field")
    field, desired = next(iter(value.items()))
    if field not in set().union(*FIELDS.values()):
        raise ValidationError(f"Unsupported state field: {field}")
    if field == "image.tag":
        identifier(desired, field)
    else:
        positive_integer(desired, field)
    return field


def validate_verification_contract(contract):
    """Require measurable, bounded criteria before a proposal can be reviewed."""
    object_fields(contract, {"observation_window_minutes", "success_criteria",
                             "failure_criteria", "new_critical_alert_fails",
                             "max_traffic_drop_fraction",
                             "max_dependency_improvement_fraction", "baseline_guardrails"},
                  "verification")
    positive_integer(contract["observation_window_minutes"], "observation_window_minutes")
    if contract["observation_window_minutes"] > 60:
        raise ValidationError("observation_window_minutes exceeds 60")
    if contract["new_critical_alert_fails"] is not True:
        raise ValidationError("new_critical_alert_fails must be true")
    number(contract["max_traffic_drop_fraction"], "max_traffic_drop_fraction", 0, 0.99)
    number(contract["max_dependency_improvement_fraction"],
           "max_dependency_improvement_fraction", 0, 0.99)
    for kind in ("success_criteria", "failure_criteria"):
        criteria = contract[kind]
        if not isinstance(criteria, dict) or not criteria:
            raise ValidationError(f"{kind} must contain metric thresholds")
        for metric, rule in criteria.items():
            if metric not in METRIC_BOUNDS:
                raise ValidationError(f"Unknown verification metric: {metric}")
            object_fields(rule, {"op", "value"}, f"{kind}.{metric}")
            if not isinstance(rule["op"], str) or rule["op"] not in OPERATORS:
                raise ValidationError(f"Unsupported operator for {metric}")
            lower, upper = METRIC_BOUNDS[metric]
            number(rule["value"], f"{kind}.{metric}", lower, upper)
    if not USER_FACING_METRICS.intersection(contract["success_criteria"]):
        raise ValidationError("success_criteria requires a user-facing SLI")
    guardrails = contract["baseline_guardrails"]
    if not isinstance(guardrails, dict):
        raise ValidationError("baseline_guardrails must be an object")
    for metric, ratio in guardrails.items():
        if metric != "memory_working_set_mi":
            raise ValidationError(f"Unsupported baseline guardrail: {metric}")
        number(ratio, f"baseline_guardrails.{metric}", 1)


def verification_digest(contract):
    """Fingerprint the reviewed contract for an external approval service to bind."""
    return hashlib.sha256(json.dumps(contract, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RemediationIntent:
    """A narrow proposal without approval or execution privileges."""

    action: str
    resource: str
    namespace: str
    environment: str
    desired_state: dict
    confidence: float
    evidence: list[str]
    rollback_plan: dict
    verification: dict

    @classmethod
    def from_dict(cls, raw):
        """Validate the complete untrusted intent before policy evaluation."""
        object_fields(raw, [field.name for field in fields(cls)], "intent")
        if not isinstance(raw["action"], str) or raw["action"] not in FIELDS:
            raise ValidationError("action must be SCALE, ROLLBACK, or CONFIG_CHANGE")
        for key in ("resource", "namespace", "environment"):
            identifier(raw[key], key)
        number(raw["confidence"], "confidence", 0, 1)
        if not isinstance(raw["evidence"], list) or not raw["evidence"] or not all(
            isinstance(item, str) and item.strip() for item in raw["evidence"]
        ):
            raise ValidationError("evidence must contain nonempty strings")
        field = state(raw["desired_state"], "desired_state")
        if field not in FIELDS[raw["action"]]:
            raise ValidationError("desired_state does not match action")
        if state(raw["rollback_plan"], "rollback_plan") != field:
            raise ValidationError("rollback_plan must restore the same field")
        validate_verification_contract(raw["verification"])
        return cls(**raw)


@dataclass(frozen=True)
class RemediationResult:
    """Auditable routing decision; approval is always external to this module."""

    decision: str
    risk: str
    reasons: list[str]
    proposed_change: dict | None = None
    approval: str | None = None
    verification_contract_sha256: str | None = None

    def to_dict(self):
        """Return the CLI representation."""
        return asdict(self)


def validate_context(context):
    """Validate trusted facts and platform-owned bounds independently of intent."""
    required = {
        "resource", "namespace", "environment", "current_state", "observed_replicas",
        "db_utilization", "hpa_max_replicas", "approved_bounds", "checks",
        "blast_radius", "max_blast_radius", "git_path", "controller",
        "known_good_version",
    }
    if isinstance(context, dict) and "error_budget_remaining" in context:
        required.add("error_budget_remaining")
        number(context["error_budget_remaining"], "error_budget_remaining", 0, 1)
    object_fields(context, required, "context")
    for key in ("resource", "namespace", "environment"):
        identifier(context[key], key)
    current = context["current_state"]
    if not isinstance(current, dict) or not current:
        raise ValidationError("current_state must contain trusted observed state")
    for field, value in current.items():
        state({field: value}, "current_state")
    positive_integer(context["observed_replicas"], "observed_replicas")
    positive_integer(context["hpa_max_replicas"], "hpa_max_replicas")
    number(context["db_utilization"], "db_utilization", 0, 1)
    for key in ("blast_radius", "max_blast_radius"):
        positive_integer(context[key], key)
    if context["controller"] not in ("argocd", "terraform", "crossplane"):
        raise ValidationError("Unknown controller")
    path = context["git_path"]
    if (not isinstance(path, str) or not path or path.startswith("/")
            or "\\" in path or any(part in ("", ".", "..") for part in path.split("/"))):
        raise ValidationError("git_path must be a repository-relative path")
    if context["known_good_version"] is not None:
        identifier(context["known_good_version"], "known_good_version")
    bounds = context["approved_bounds"]
    if not isinstance(bounds, dict):
        raise ValidationError("approved_bounds must be an object")
    for field, value in bounds.items():
        if field not in FIELDS["SCALE"] | FIELDS["CONFIG_CHANGE"]:
            raise ValidationError("Unknown approved bound")
        positive_integer(value, field)
    if not isinstance(context["checks"], dict) or not all(
        isinstance(key, str) and isinstance(value, bool)
        for key, value in context["checks"].items()
    ):
        raise ValidationError("checks must map evidence check names to booleans")


def capacity_findings(field, desired, current, context):
    """Check platform bounds and downstream capacity for numeric changes."""
    denied, missing, checks = [], [], []
    bound = context["approved_bounds"].get(field)
    if bound is None:
        missing.append(f"No platform-approved bound for {field}.")
    elif desired > bound:
        denied.append(f"{field} exceeds the platform-approved bound.")
    if field in ("replicas", "hpa.maxReplicas", "node_pool.max_nodes"):
        if desired <= current:
            denied.append("Only capacity increases are supported by this policy.")
        if desired > current * 2:
            denied.append("Capacity increase exceeds the 2x limit.")
        if context["db_utilization"] > 0.80:
            denied.append("Downstream database utilization exceeds 80%.")
        checks += ["capacity_available", "quota_available", "cost_reviewed",
                   "dependency_capacity_reviewed"]
    return denied, missing, checks


def safety_findings(intent, context):
    """Return denials and investigation gaps based on trusted operational evidence."""
    denied, missing = [], []
    field, desired = next(iter(intent.desired_state.items()))
    current = context["current_state"].get(field)
    if current is None:
        return [], [f"Missing current state for {field}."]
    if intent.rollback_plan[field] != current:
        denied.append("Rollback plan does not restore the trusted current state.")
    if desired == current:
        denied.append("Intent would not change desired state.")
    if context["blast_radius"] > context["max_blast_radius"]:
        denied.append("Blast radius exceeds platform policy.")
    if "replicas" in context["current_state"] and (
        context["current_state"]["replicas"] != context["observed_replicas"]
    ):
        missing.append("Replica observations conflict; reconcile collector evidence first.")
    checks = ["rollback_possible"]
    if field == "image.tag":
        if desired != context["known_good_version"]:
            denied.append("Rollback target is not the trusted known-good version.")
        checks += ["regression_evidence", "dependencies_healthy"]
    else:
        capacity_denials, capacity_gaps, capacity_checks = capacity_findings(
            field, desired, current, context,
        )
        denied.extend(capacity_denials)
        missing.extend(capacity_gaps)
        checks.extend(capacity_checks)
        if field == "replicas" and desired > context["hpa_max_replicas"]:
            missing.append("Requested replicas exceed HPA maxReplicas; investigate the limit "
                           "and submit a separate reviewed configuration intent.")
        if field == "hpa.maxReplicas" and current != context["hpa_max_replicas"]:
            missing.append("HPA observations conflict; reconcile collector evidence first.")
        checks += {
            "hpa.maxReplicas": ["existing_limit_reviewed", "load_test_supported"],
            "node_pool.max_nodes": ["existing_limit_reviewed", "load_test_supported",
                                    "pending_pods_insufficient_cpu"],
        }.get(field, [])
        if field == "memory.limitMi":
            if desired <= current or desired > current * 2:
                denied.append("Memory increases must be above current and at most 2x.")
            checks += ["memory_saturation", "oomkills_observed", "leak_ruled_out",
                       "capacity_available", "quota_available", "cost_reviewed",
                       "existing_limit_reviewed", "memory_request_reviewed"]
    missing.extend(f"Missing or failed evidence check: {check}." for check in checks
                   if context["checks"].get(check) is not True)
    return denied, missing


def plan_matches(plan, change):
    """Compare the entire trusted normalized diff, including old values and identity.

    Adapters must include every change, deletion, replacement, and unknown value.
    No filtering to the requested resource is permitted before this comparison.
    """
    object_fields(plan, {"changes"}, "plan")
    if not isinstance(plan["changes"], list):
        raise ValidationError("plan.changes must be a list")
    for item in plan["changes"]:
        object_fields(item, change, "plan change")
        if any(type(item[key]) is not type(value) for key, value in change.items()):
            return False
    return plan["changes"] == [change]


def approval_tier(risk, context):
    """Budget pressure can raise, but never lower, the action's approval tier."""
    approval = "senior" if risk == "high" else "operator"
    budget = context.get("error_budget_remaining")
    if budget is None:
        return approval, "Error budget unavailable; the existing human approval tier applies."
    if budget <= 0.10:
        return "incident_commander", "Error budget at or below 10%; incident commander required."
    if budget <= 0.50:
        return ("senior" if risk == "high" else "engineer",
                "Error budget at or below 50%; at least engineer approval required.")
    return approval, "Error budget above 50%; the existing human approval tier applies."


def evaluate_remediation(raw_intent, context, plan=None):
    """Fail closed, then emit a proposal requiring independent human approval.

    No input can mark a proposal approved. The result is not an execution token.
    """
    intent = RemediationIntent.from_dict(raw_intent)
    validate_context(context)
    risk = "high" if intent.action in ("ROLLBACK", "CONFIG_CHANGE") else "medium"
    if any(getattr(intent, key) != context[key]
           for key in ("resource", "namespace", "environment")):
        return RemediationResult("deny", risk, ["Intent target does not match trusted context."])
    denied, missing = safety_findings(intent, context)
    if denied:
        return RemediationResult("deny", risk, denied + missing)
    if intent.confidence < 0.80:
        missing.append("Confidence is below 0.80.")
    if missing:
        return RemediationResult("investigate", risk, missing)
    field, desired = next(iter(intent.desired_state.items()))
    change = {
        "resource": intent.resource, "namespace": intent.namespace,
        "environment": intent.environment, "path": context["git_path"],
        "controller": context["controller"], "operation": "update", "field": field,
        "before": context["current_state"][field], "after": desired,
    }
    if plan is None:
        return RemediationResult("requires_plan", risk,
                                 ["Provide a complete trusted normalized Git/IaC plan."], change,
                                 verification_contract_sha256=verification_digest(
                                     intent.verification))
    if not plan_matches(plan, change):
        return RemediationResult(
            "deny", risk, ["Plan does not exactly match intent; unexpected changes blocked."],
        )
    approval, budget_reason = approval_tier(risk, context)
    return RemediationResult(
        "requires_human_approval", risk,
        ["Intent matches plan. Human approval is required before a Git PR or apply.",
         budget_reason],
        change, approval,
        verification_digest(intent.verification),
    )
