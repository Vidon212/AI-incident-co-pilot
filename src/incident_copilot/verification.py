"""Deterministic post-change SLO verification from trusted, normalized observations.

The module performs no metric queries, approvals, Git operations, or production
mutations. The caller must supply independently collected evidence and bind the
approved contract hash to the executed change.
"""

from dataclasses import asdict, dataclass
from datetime import datetime

from .models import ValidationError
from .remediation import (METRIC_BOUNDS, USER_FACING_METRICS, RemediationIntent, identifier, number,
                          object_fields, verification_digest)


@dataclass(frozen=True)
class VerificationResult:
    """Mitigation outcome and separately assessed underlying problem."""

    outcome: str
    underlying_problem: str
    reasons: list[str]
    evaluated_signals: dict
    verification_contract_sha256: str

    def to_dict(self):
        """Return a serializable audit artifact."""
        return asdict(self)


def timestamp(value, name):
    """Require an unambiguous timezone-aware timestamp."""
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{name} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{name} must include a timezone")
    return parsed


def validate_metrics(metrics, name):
    """Accept only known, finite metrics with explicit units in their names."""
    if not isinstance(metrics, dict):
        raise ValidationError(f"{name}.metrics must be an object")
    for metric, value in metrics.items():
        if metric not in METRIC_BOUNDS:
            raise ValidationError(f"Unknown observation metric: {metric}")
        lower, upper = METRIC_BOUNDS[metric]
        number(value, f"{name}.{metric}", lower, upper)


def validate_window(window, name, minutes):
    """Check a complete, ordered observation window."""
    object_fields(window, {"start", "end", "metrics"}, name)
    start = timestamp(window["start"], f"{name}.start")
    end = timestamp(window["end"], f"{name}.end")
    if (end - start).total_seconds() < minutes * 60:
        raise ValidationError(f"{name} is shorter than the contracted window")
    validate_metrics(window["metrics"], name)
    return start, end


def validate_observations(observations, minutes):
    """Validate collector facts without granting them execution authority."""
    object_fields(observations, {"execution", "before", "after",
                                 "historical_baseline", "new_critical_alert"},
                  "observations")
    execution = observations["execution"]
    object_fields(execution, {"resource", "namespace", "environment", "action", "field",
                              "before", "after", "completed_at", "controller_healthy",
                              "approved_contract_sha256"}, "execution")
    for key in ("resource", "namespace", "environment", "action", "field"):
        identifier(execution[key], f"execution.{key}")
    for key in ("controller_healthy", "new_critical_alert"):
        value = (execution if key == "controller_healthy" else observations)[key]
        if not isinstance(value, bool):
            raise ValidationError(f"{key} must be boolean")
    digest = execution["approved_contract_sha256"]
    if (not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)):
        raise ValidationError("approved_contract_sha256 must be a SHA-256 hex digest")
    completed = timestamp(execution["completed_at"], "execution.completed_at")
    _, before_end = validate_window(observations["before"], "before", minutes)
    after_start, _ = validate_window(observations["after"], "after", minutes)
    if before_end > completed or after_start < completed:
        raise ValidationError("Observation windows must bracket completed execution")
    baseline = observations["historical_baseline"]
    validate_metrics(baseline, "historical_baseline")


def matches(value, rule):
    """Evaluate a predeclared threshold; the model never chooses this result."""
    op, threshold = rule["op"], rule["value"]
    return {"lt": value < threshold, "lte": value <= threshold,
            "gt": value > threshold, "gte": value >= threshold,
            "eq": value == threshold}[op]


def preflight_findings(intent, observations, digest):
    """Find missing signals or mismatches before evaluating service health."""
    contract = intent.verification
    before = observations["before"]["metrics"]
    after = observations["after"]["metrics"]
    execution = observations["execution"]
    needed = (set(contract["success_criteria"]) | set(contract["failure_criteria"])
              | {"throughput_rps", "db_p95_latency_ms"})
    if intent.action == "SCALE":
        needed |= {"p95_latency_ms", "p99_latency_ms", "http_error_rate",
                   "pod_cpu_percent", "db_connections"}
    missing = (needed - before.keys()) | (needed - after.keys())
    field, desired = next(iter(intent.desired_state.items()))
    identity = ("resource", "namespace", "environment", "action")
    target_matches = all(execution[key] == getattr(intent, key) for key in identity)
    state_matches = (execution["field"] == field
                     and type(execution["after"]) is type(desired)
                     and execution["after"] == desired
                     and type(execution["before"]) is type(intent.rollback_plan[field])
                     and execution["before"] == intent.rollback_plan[field])
    findings = []
    if not target_matches or not state_matches:
        findings.append("Executed change does not match the reviewed intent.")
    if execution["approved_contract_sha256"] != digest:
        findings.append("Approved contract hash does not match the reviewed criteria.")
    if missing:
        findings.append("Missing required before/after metrics: " + ", ".join(sorted(missing)))
    return findings


def baseline_assessment(contract, observations):
    """Keep mitigation and historical root-cause indicators separate."""
    after = observations["after"]["metrics"]
    findings = []
    for metric, max_ratio in contract["baseline_guardrails"].items():
        baseline = observations["historical_baseline"].get(metric)
        if baseline is None or baseline == 0:
            return "not_assessed", [], f"Missing nonzero historical baseline for {metric}."
        if after.get(metric) is None:
            return "not_assessed", [], f"Missing post-change metric for {metric}."
        if after[metric] > baseline * max_ratio:
            findings.append(f"{metric} remains above {max_ratio}x historical baseline.")
    return ("unresolved" if findings else "not_assessed"), findings, None


def failure_findings(contract, observations):
    """Identify explicit failures independently of controller success."""
    findings = []
    if not observations["execution"]["controller_healthy"]:
        findings.append("Controller reports an unhealthy deployment.")
    if observations["new_critical_alert"]:
        findings.append("A new critical alert appeared.")
    after = observations["after"]["metrics"]
    for metric, rule in contract["failure_criteria"].items():
        if matches(after[metric], rule):
            findings.append(f"Failure threshold triggered: {metric}.")
    return findings


def control_findings(contract, before, after):
    """Flag natural recovery and dependency changes that confound attribution."""
    findings = []
    if before["throughput_rps"] <= 0:
        findings.append("No pre-change traffic for a valid comparison.")
    elif after["throughput_rps"] < before["throughput_rps"] * (
            1 - contract["max_traffic_drop_fraction"]):
        findings.append("Traffic fell beyond the predeclared control tolerance.")
    if (before["db_p95_latency_ms"] > 0 and after["db_p95_latency_ms"]
            < before["db_p95_latency_ms"] * (
                1 - contract["max_dependency_improvement_fraction"])):
        findings.append("Dependency latency improved enough to confound attribution.")
    return findings


def evaluate_verification(raw_intent, observations):
    """Compare user-facing SLIs, side effects, and controls after a full window."""
    intent = RemediationIntent.from_dict(raw_intent)
    contract = intent.verification
    digest = verification_digest(contract)
    validate_observations(observations, contract["observation_window_minutes"])
    signals = {"before": observations["before"]["metrics"],
               "after": observations["after"]["metrics"]}
    reasons = preflight_findings(intent, observations, digest)
    root_status = "not_assessed"
    if reasons:
        outcome = "INCONCLUSIVE"
    else:
        root_status, root_findings, gap = baseline_assessment(contract, observations)
        reasons.extend(root_findings)
        missed = [metric for metric, rule in contract["success_criteria"].items()
                  if not matches(signals["after"][metric], rule)]
        if gap:
            reasons.append(gap)
        if failures := failure_findings(contract, observations):
            outcome = "FAILED"
            reasons.extend(failures)
        elif missed:
            outcome = "FAILED"
            reasons.append("Success thresholds not met: " + ", ".join(sorted(missed)))
        elif gap:
            outcome = "INCONCLUSIVE"
        elif controls := control_findings(contract, signals["before"], signals["after"]):
            outcome = "INCONCLUSIVE"
            reasons.extend(controls)
        else:
            if all(matches(signals["before"][metric], rule)
                   for metric, rule in contract["success_criteria"].items()
                   if metric in USER_FACING_METRICS):
                outcome = "INCONCLUSIVE"
                reasons.append("User-facing success thresholds already passed before the change.")
            else:
                outcome = "SUCCESS"
                reasons.insert(0, "Predeclared user-facing SLI thresholds passed after the change.")
    return VerificationResult(outcome, root_status, reasons, signals, digest)
