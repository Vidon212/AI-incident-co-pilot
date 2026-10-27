"""Deterministic review of multi-hypothesis incident investigations.

The module validates a supplied read-only investigation trace. It does not call
tools, select a remediation, or change production state.
"""

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import math

from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer


TOOLS = {
    "compare_versions": "metrics-by-version",
    "get_cloudsql_health": "cloudsql",
    "get_recent_changes": "change-audit",
    "get_connection_timeline": "cloudsql-timeseries",
}
VERIFICATION_METRICS = {"http_5xx_rate", "p99_latency_ms", "connection_wait_ms"}
OPERATORS = {"lt", "lte"}


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a nonempty string")


def _timestamp(value, name):
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError(f"{name} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{name} must include a timezone")
    return parsed


def _unique_identifiers(value, name, minimum=0):
    if (not isinstance(value, list) or len(value) < minimum
            or len(value) != len(set(value))):
        raise ValidationError(f"{name} must be a duplicate-free list")
    for item in value:
        identifier(item, name)


@dataclass(frozen=True)
class InvestigationContext:
    """Trusted incident identity and platform-owned stopping policy."""

    incident_id: str
    primary_service: str
    database_resource: str
    environment: str
    started_at: str
    budget: dict

    @classmethod
    def from_dict(cls, raw):
        """Validate incident scope and platform-owned investigation budgets."""
        object_fields(raw, [field.name for field in fields(cls)], "investigation context")
        for key in ("incident_id", "primary_service", "database_resource", "environment"):
            identifier(raw[key], key)
        _timestamp(raw["started_at"], "started_at")
        object_fields(raw["budget"], {
            "max_tool_calls", "max_investigation_seconds",
            "minimum_action_confidence", "minimum_independent_evidence",
        }, "investigation budget")
        positive_integer(raw["budget"]["max_tool_calls"], "max_tool_calls")
        positive_integer(raw["budget"]["max_investigation_seconds"],
                         "max_investigation_seconds")
        positive_integer(raw["budget"]["minimum_independent_evidence"],
                         "minimum_independent_evidence")
        number(raw["budget"]["minimum_action_confidence"],
               "minimum_action_confidence", 0, 1)
        if raw["budget"]["max_tool_calls"] > 20:
            raise ValidationError("max_tool_calls exceeds the platform maximum")
        if raw["budget"]["max_investigation_seconds"] > 900:
            raise ValidationError("max_investigation_seconds exceeds the platform maximum")
        if (raw["budget"]["minimum_independent_evidence"]
                > raw["budget"]["max_tool_calls"]):
            raise ValidationError("minimum evidence exceeds the tool-call budget")
        return cls(**raw)


@dataclass(frozen=True)
class InvestigationResult:
    """An evidence review artifact without execution or approval authority."""

    decision: str
    reasons: list[str]
    hypotheses: list[dict]
    primary_hypothesis: dict | None
    causal_change: dict | None
    recommended_action: dict | None
    verification_criteria: list[dict]
    audit: list[dict]

    def to_dict(self):
        """Return the serializable investigation review artifact."""
        return asdict(self)


def _result(decision, reasons, state=None, assessment=None):
    state = state or {"audit": []}
    ranked = sorted((
        {"id": item_id, "summary": item["summary"],
         "confidence": state["confidences"][item_id]}
        for item_id, item in state.get("hypotheses", {}).items()
    ), key=lambda item: item["confidence"], reverse=True)
    if decision == "ready_for_remediation_review" and assessment:
        primary = state["hypotheses"][assessment["primary_hypothesis_id"]]
        primary = {"id": assessment["primary_hypothesis_id"],
                   "summary": primary["summary"], "confidence": assessment["confidence"]}
        return InvestigationResult(
            decision, reasons, ranked, primary, assessment["causal_change"],
            assessment["recommended_action"], assessment["verification_criteria"],
            state["audit"],
        )
    return InvestigationResult(
        decision, reasons, ranked, None, None, {"action": "escalate"}, [], state["audit"]
    )


def _validate_hypotheses(items):
    if not isinstance(items, list) or len(items) < 3:
        raise ValidationError("at least three competing hypotheses are required")
    hypotheses = {}
    for item in items:
        object_fields(item, {"id", "summary", "confidence"}, "hypothesis")
        identifier(item["id"], "hypothesis id")
        _text(item["summary"], "hypothesis summary")
        number(item["confidence"], "hypothesis confidence", 0, 1)
        if item["id"] in hypotheses:
            raise ValidationError("hypothesis ids must be unique")
        hypotheses[item["id"]] = item
    if not math.isclose(sum(item["confidence"] for item in items), 1, abs_tol=1e-9):
        raise ValidationError("hypothesis confidence must sum to 1")
    return hypotheses


def _validate_arguments(context, tool, arguments):
    schemas = {
        "compare_versions": {"service", "environment", "versions"},
        "get_cloudsql_health": {"resource", "environment"},
        "get_recent_changes": {"service", "environment", "window_minutes"},
        "get_connection_timeline": {"resource", "environment", "window_minutes"},
    }
    object_fields(arguments, schemas[tool], f"{tool} arguments")
    if arguments["environment"] != context.environment:
        raise ValidationError("tool environment is outside the incident scope")
    if "service" in arguments and arguments["service"] != context.primary_service:
        raise ValidationError("tool service is outside the incident scope")
    if "resource" in arguments and arguments["resource"] != context.database_resource:
        raise ValidationError("tool resource is outside the incident scope")
    if "window_minutes" in arguments:
        positive_integer(arguments["window_minutes"], "window_minutes")
        if arguments["window_minutes"] > 60:
            raise ValidationError("window_minutes exceeds the platform maximum")
    if tool == "compare_versions":
        _unique_identifiers(arguments["versions"], "versions", minimum=2)
        if len(arguments["versions"]) != 2:
            raise ValidationError("compare_versions requires exactly two versions")


def _validate_version_data(data, arguments):
    object_fields(data, {"service", "versions"}, "version comparison")
    if data["service"] != arguments["service"] or not isinstance(data["versions"], list):
        raise ValidationError("version result does not match its call")
    seen = []
    for item in data["versions"]:
        object_fields(item, {"version", "http_5xx_rate", "p99_latency_ms",
                             "connection_wait_ms"}, "version metrics")
        identifier(item["version"], "version")
        number(item["http_5xx_rate"], "http_5xx_rate", 0, 1)
        number(item["p99_latency_ms"], "p99_latency_ms")
        number(item["connection_wait_ms"], "connection_wait_ms")
        seen.append(item["version"])
    if seen != arguments["versions"]:
        raise ValidationError("version result order or identities do not match the call")


def _validate_cloudsql_data(data, arguments):
    object_fields(data, {"resource", "cpu_percent", "memory_percent", "connections_used",
                         "connections_limit", "connection_wait_ms", "query_p99_ms"},
                  "cloudsql health")
    if data["resource"] != arguments["resource"]:
        raise ValidationError("cloudsql result does not match its call")
    for key in ("cpu_percent", "memory_percent"):
        number(data[key], key, 0, 100)
    for key in ("connections_used", "connections_limit"):
        positive_integer(data[key], key)
    number(data["connection_wait_ms"], "connection_wait_ms")
    number(data["query_p99_ms"], "query_p99_ms")


def _validate_changes_data(data, arguments):
    object_fields(data, {"service", "changes"}, "recent changes")
    if data["service"] != arguments["service"] or not isinstance(data["changes"], list):
        raise ValidationError("recent changes result does not match its call")
    for change in data["changes"]:
        object_fields(change, {"time", "source", "resource", "field", "before", "after"},
                      "recent change")
        _timestamp(change["time"], "change time")
        for key in ("source", "resource", "field"):
            identifier(change[key], f"change {key}")
        for key in ("before", "after"):
            positive_integer(change[key], f"change {key}")


def _validate_timeline_data(data, arguments):
    object_fields(data, {"resource", "change_at", "samples"}, "connection timeline")
    if data["resource"] != arguments["resource"] or not isinstance(data["samples"], list):
        raise ValidationError("timeline result does not match its call")
    _timestamp(data["change_at"], "timeline change_at")
    previous = None
    for sample in data["samples"]:
        object_fields(sample, {"time", "connections_used", "connections_limit",
                               "connection_wait_ms", "http_5xx_rate"}, "timeline sample")
        current = _timestamp(sample["time"], "sample time")
        if previous is not None and current <= previous:
            raise ValidationError("timeline samples must be strictly ordered")
        previous = current
        for key in ("connections_used", "connections_limit"):
            positive_integer(sample[key], key)
        number(sample["connection_wait_ms"], "connection_wait_ms")
        number(sample["http_5xx_rate"], "http_5xx_rate", 0, 1)


def _validate_result(tool, call_id, result, arguments):
    object_fields(result, {"call_id", "status", "source", "observed_at", "data"},
                  "tool result")
    if result["call_id"] != call_id or result["status"] != "ok":
        raise ValidationError("tool result must be a successful result bound to its call")
    if result["source"] != TOOLS[tool]:
        raise ValidationError("tool result source does not match the tool")
    _timestamp(result["observed_at"], "observed_at")
    validators = {
        "compare_versions": _validate_version_data,
        "get_cloudsql_health": _validate_cloudsql_data,
        "get_recent_changes": _validate_changes_data,
        "get_connection_timeline": _validate_timeline_data,
    }
    validators[tool](result["data"], arguments)


def _validate_updates(updates, hypotheses, current):
    if not isinstance(updates, list) or len(updates) != len(hypotheses):
        raise ValidationError("every evidence step must update every hypothesis")
    after = {}
    for update in updates:
        object_fields(update, {"id", "before", "after"}, "hypothesis update")
        if update["id"] not in hypotheses or update["id"] in after:
            raise ValidationError("hypothesis update id is missing, duplicate, or unknown")
        for key in ("before", "after"):
            number(update[key], f"update {key}", 0, 1)
        if not math.isclose(update["before"], current[update["id"]], abs_tol=1e-9):
            raise ValidationError("hypothesis update does not continue the confidence chain")
        after[update["id"]] = update["after"]
    if not math.isclose(sum(after.values()), 1, abs_tol=1e-9):
        raise ValidationError("updated hypothesis confidence must sum to 1")
    return after


def _evidence_findings(tool, data):
    findings = set()
    if tool == "compare_versions":
        first, second = data["versions"]
        error_gap = abs(first["http_5xx_rate"] - second["http_5xx_rate"])
        latency_ratio = max(first["p99_latency_ms"], second["p99_latency_ms"]) / max(
            min(first["p99_latency_ms"], second["p99_latency_ms"]), 1)
        if error_gap <= 0.03 and latency_ratio <= 1.15:
            findings.add("app_regression_weakened")
    elif tool == "get_cloudsql_health":
        if (data["connections_used"] / data["connections_limit"] >= 0.95
                and data["connection_wait_ms"] >= 1000
                and data["query_p99_ms"] <= 500 and data["cpu_percent"] < 80):
            findings.add("connection_exhaustion_supported")
    elif tool == "get_recent_changes":
        if any(change["field"] == "cloudsql.max_connections"
               and change["before"] > change["after"] for change in data["changes"]):
            findings.add("connection_limit_change_found")
    elif tool == "get_connection_timeline":
        change_at = _timestamp(data["change_at"], "timeline change_at")
        before = [sample for sample in data["samples"]
                  if _timestamp(sample["time"], "sample time") < change_at]
        after = [sample for sample in data["samples"]
                 if _timestamp(sample["time"], "sample time") >= change_at]
        if before and after:
            new_limit = min(sample["connections_limit"] for sample in after)
            demand_exceeded = max(sample["connections_used"] for sample in before) > new_limit
            saturated = any(sample["connections_used"] / sample["connections_limit"] >= 0.95
                            and sample["connection_wait_ms"] >= 1000 for sample in after)
            errors = any(sample["http_5xx_rate"] >= 0.05 for sample in after)
            if demand_exceeded and saturated and errors:
                findings.add("causal_timeline_supported")
    return findings


def _review_evidence(context, steps, hypotheses):
    if not isinstance(steps, list) or not steps:
        raise ValidationError("evidence must be a nonempty list")
    current = {item_id: item["confidence"] for item_id, item in hypotheses.items()}
    state = {
        "calls": set(), "findings": set(), "survived_falsification": set(),
        "discriminated": set(), "audit": [], "evidence_by_call": {},
    }
    for sequence, step in enumerate(steps, start=1):
        object_fields(step, {"question", "discriminates", "falsification_target", "call",
                             "result", "hypothesis_updates"}, "evidence step")
        _text(step["question"], "evidence question")
        _unique_identifiers(step["discriminates"], "discriminates", minimum=2)
        if not set(step["discriminates"]).issubset(hypotheses):
            raise ValidationError("evidence discriminates unknown hypotheses")
        state["discriminated"].update(step["discriminates"])
        target = step["falsification_target"]
        if target is not None and target not in hypotheses:
            raise ValidationError("falsification_target is unknown")
        call = step["call"]
        object_fields(call, {"id", "tool", "arguments"}, "tool call")
        identifier(call["id"], "tool call id")
        if call["id"] in state["calls"] or call["tool"] not in TOOLS:
            raise ValidationError("tool call id is duplicate or tool is unsupported")
        state["calls"].add(call["id"])
        _validate_arguments(context, call["tool"], call["arguments"])
        _validate_result(call["tool"], call["id"], step["result"], call["arguments"])
        current = _validate_updates(step["hypothesis_updates"], hypotheses, current)
        step_findings = _evidence_findings(call["tool"], step["result"]["data"])
        state["evidence_by_call"][call["id"]] = {
            "tool": call["tool"], "source": step["result"]["source"],
            "data": step["result"]["data"],
        }
        state["findings"].update(step_findings)
        if target is not None and "causal_timeline_supported" in step_findings:
            state["survived_falsification"].add(target)
        state["audit"].append({
            "sequence": sequence, "call_id": call["id"], "tool": call["tool"],
            "source": step["result"]["source"],
            "observed_at": step["result"]["observed_at"],
            "falsification_target": target,
        })
    state.update(hypotheses=hypotheses, confidences=current, steps=steps)
    return state


def _validate_assessment(assessment, state):
    required = {"primary_hypothesis_id", "confidence", "causal_change",
                "supporting_evidence_call_ids", "recommended_action",
                "verification_criteria"}
    object_fields(assessment, required, "final assessment")
    primary = assessment["primary_hypothesis_id"]
    if primary not in state["hypotheses"]:
        raise ValidationError("primary_hypothesis_id is unknown")
    number(assessment["confidence"], "final confidence", 0, 1)
    if not math.isclose(assessment["confidence"], state["confidences"][primary], abs_tol=1e-9):
        raise ValidationError("final confidence does not match the confidence chain")
    _unique_identifiers(assessment["supporting_evidence_call_ids"],
                        "supporting evidence", minimum=1)
    if not set(assessment["supporting_evidence_call_ids"]).issubset(state["calls"]):
        raise ValidationError("final assessment cites unknown evidence")
    change = assessment["causal_change"]
    object_fields(change, {"resource", "field", "before", "after", "evidence_call_id"},
                  "causal change")
    for key in ("resource", "field", "evidence_call_id"):
        identifier(change[key], f"causal change {key}")
    for key in ("before", "after"):
        positive_integer(change[key], f"causal change {key}")
    if change["evidence_call_id"] not in state["calls"]:
        raise ValidationError("causal change cites unknown evidence")
    action = assessment["recommended_action"]
    object_fields(action, {"action", "resource", "field", "from", "to"},
                  "recommended action")
    if action["action"] != "restore_previous_value":
        raise ValidationError("recommended action is unsupported")
    if (action["resource"] != change["resource"] or action["field"] != change["field"]
            or action["from"] != change["after"] or action["to"] != change["before"]):
        raise ValidationError("recommended action must reverse the causal change")
    criteria = assessment["verification_criteria"]
    if not isinstance(criteria, list) or not criteria:
        raise ValidationError("verification_criteria must be nonempty")
    for criterion in criteria:
        object_fields(criterion, {"metric", "operator", "threshold"},
                      "verification criterion")
        if criterion["metric"] not in VERIFICATION_METRICS:
            raise ValidationError("verification metric is unsupported")
        if criterion["operator"] not in OPERATORS:
            raise ValidationError("verification operator is unsupported")
        number(criterion["threshold"], "verification threshold")


def _stopping_gaps(context, state, assessment, elapsed_seconds):
    budget = context.budget
    gaps = []
    if len(state["steps"]) > budget["max_tool_calls"]:
        gaps.append("Investigation exhausted its tool-call budget.")
    if elapsed_seconds > budget["max_investigation_seconds"]:
        gaps.append("Investigation exhausted its time budget.")
    if assessment["confidence"] <= budget["minimum_action_confidence"]:
        gaps.append("Primary hypothesis confidence does not exceed the action threshold.")
    cited_sources = {
        state["evidence_by_call"][call_id]["source"]
        for call_id in assessment["supporting_evidence_call_ids"]
    }
    if len(cited_sources) < budget["minimum_independent_evidence"]:
        gaps.append("Investigation lacks independent evidence sources.")
    required = {"app_regression_weakened", "connection_exhaustion_supported",
                "connection_limit_change_found", "causal_timeline_supported"}
    if not required.issubset(state["findings"]):
        gaps.append("Evidence does not establish the change-to-impact causal chain.")
    primary = assessment["primary_hypothesis_id"]
    if primary not in state["survived_falsification"]:
        gaps.append("Primary hypothesis did not survive a deliberate falsification test.")
    competitors = set(state["hypotheses"]) - {primary}
    if any(state["confidences"][item] > 0.10 for item in competitors):
        gaps.append("A major competing hypothesis remains plausible.")
    if not competitors.issubset(state["discriminated"]):
        gaps.append("Evidence did not test every competing hypothesis.")
    change = assessment["causal_change"]
    if not _causal_change_matches_timeline(state, change):
        gaps.append("Final causal change does not match its cited change record.")
    if (change["resource"] != context.database_resource
            or change["field"] != "cloudsql.max_connections"
            or change["before"] <= change["after"]):
        gaps.append("Final causal change is not supported by the incident scope.")
    return gaps


def _causal_change_matches_timeline(state, change):
    """Bind the assessed change to audit data and the resource timeline."""
    change_evidence = state["evidence_by_call"][change["evidence_call_id"]]
    if change_evidence["tool"] != "get_recent_changes":
        return False
    recorded = next((item for item in change_evidence["data"].get("changes", [])
                     if item["resource"] == change["resource"]
                     and item["field"] == change["field"]
                     and item["before"] == change["before"]
                     and item["after"] == change["after"]), None)
    if recorded is None:
        return False
    timelines = (evidence["data"] for evidence in state["evidence_by_call"].values()
                 if evidence["tool"] == "get_connection_timeline")
    for timeline in timelines:
        post_change = [sample for sample in timeline["samples"]
                       if _timestamp(sample["time"], "sample time")
                       >= _timestamp(timeline["change_at"], "timeline change_at")]
        if (timeline["resource"] == change["resource"]
                and timeline["change_at"] == recorded["time"] and post_change
                and all(sample["connections_limit"] == change["after"]
                        for sample in post_change)):
            return True
    return False


def evaluate_investigation(raw_context, run):
    """Review hypothesis generation, falsification, confidence, and stopping rules."""
    context = InvestigationContext.from_dict(raw_context)
    object_fields(run, {"hypotheses", "evidence", "elapsed_seconds", "final_assessment"},
                  "investigation run")
    number(run["elapsed_seconds"], "elapsed_seconds")
    hypotheses = _validate_hypotheses(run["hypotheses"])
    state = _review_evidence(context, run["evidence"], hypotheses)
    assessment = run["final_assessment"]
    if assessment is None:
        exhausted = (len(state["steps"]) >= context.budget["max_tool_calls"]
                     or run["elapsed_seconds"] >= context.budget["max_investigation_seconds"])
        reason = ("Investigation budget expired before sufficient evidence was available."
                  if exhausted else "Investigation has no final causal assessment.")
        return _result("inconclusive", [reason], state)
    _validate_assessment(assessment, state)
    gaps = _stopping_gaps(context, state, assessment, run["elapsed_seconds"])
    if gaps:
        return _result("inconclusive", gaps, state)
    return _result(
        "ready_for_remediation_review",
        ["Causal evidence passed the configured confidence, falsification, and stopping rules."],
        state, assessment,
    )
