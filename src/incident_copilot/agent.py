"""Deterministic guardrails for a purpose-built platform agent tool trace.

The module reviews normalized calls and results. It does not invoke tools, hold
credentials, query production, create pull requests, or execute changes.
"""

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import json

from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer


READ_TOOLS = {
    "get_service_health", "get_dependency_health", "get_recent_changes",
    "get_cloudsql_health", "get_logs",
}
PROPOSAL_TOOLS = {"propose_infrastructure_change", "request_service_restart"}
TOOLS = READ_TOOLS | PROPOSAL_TOOLS
SOURCES = {
    "get_service_health": "metrics",
    "get_dependency_health": "dependency-catalog",
    "get_recent_changes": "change-audit",
    "get_cloudsql_health": "cloudsql",
    "get_logs": "logs",
    "propose_infrastructure_change": "policy",
    "request_service_restart": "policy",
}


def _text(value, name):
    """Require nonempty bounded text."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{name} must be a nonempty string")


def _timestamp(value, name):
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


def _identifiers(value, name):
    """Validate a duplicate-free list of identifiers."""
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise ValidationError(f"{name} must be a duplicate-free list")
    for item in value:
        identifier(item, name)


def _validate_resources(resources, readable_services):
    """Validate the trusted service-to-resource catalog."""
    if not isinstance(resources, list):
        raise ValidationError("resources must be a list")
    resource_ids = []
    for resource in resources:
        object_fields(resource, {"resource", "service", "controller", "path",
                                 "allowed_fields"}, "resource")
        for key in ("resource", "service", "controller"):
            identifier(resource[key], f"resource.{key}")
        _text(resource["path"], "resource.path")
        unsafe_path = (resource["path"].startswith("/") or "\\" in resource["path"]
                       or any(part in ("", ".", "..")
                              for part in resource["path"].split("/")))
        if unsafe_path:
            raise ValidationError("resource.path must be repository-relative")
        _identifiers(resource["allowed_fields"], "resource.allowed_fields")
        if resource["service"] not in readable_services:
            raise ValidationError("resource service must be readable")
        resource_ids.append(resource["resource"])
    if len(resource_ids) != len(set(resource_ids)):
        raise ValidationError("resource ids must be unique")


def _validate_limits(limits):
    """Validate local bounds against platform maximums."""
    object_fields(limits, {"max_steps", "max_window_minutes", "max_result_items",
                           "max_result_bytes", "max_log_query_chars"}, "limits")
    for key, value in limits.items():
        positive_integer(value, f"limits.{key}")
    if limits["max_steps"] > 20 or limits["max_window_minutes"] > 60:
        raise ValidationError("agent limits exceed platform maximums")


@dataclass(frozen=True)
class AgentContext:
    """Externally authenticated identity, ownership, and tool limits."""

    incident_id: str
    principal: str
    primary_service: str
    environment: str
    readable_services: list[str]
    proposable_services: list[str]
    granted_tools: list[str]
    resources: list[dict]
    limits: dict

    @classmethod
    def from_dict(cls, raw):
        """Validate trusted platform authorization context."""
        object_fields(raw, [field.name for field in fields(cls)], "agent_context")
        for key in ("incident_id", "primary_service", "environment"):
            identifier(raw[key], key)
        _text(raw["principal"], "principal")
        for key in ("readable_services", "proposable_services", "granted_tools"):
            _identifiers(raw[key], key)
        if raw["primary_service"] not in raw["readable_services"]:
            raise ValidationError("primary_service must be readable")
        if not set(raw["proposable_services"]).issubset(raw["readable_services"]):
            raise ValidationError("proposable_services must be readable")
        if not set(raw["granted_tools"]).issubset(TOOLS):
            raise ValidationError("granted_tools contains an unsupported tool")

        _validate_resources(raw["resources"], raw["readable_services"])
        _validate_limits(raw["limits"])
        return cls(**raw)


@dataclass(frozen=True)
class AgentRunResult:
    """Auditable review result; never an execution credential."""

    decision: str
    reasons: list[str]
    hypothesis: dict | None
    audit: list[dict]
    proposed_change: dict | None
    approval: str | None

    def to_dict(self):
        """Return a serializable agent review artifact."""
        return asdict(self)


def _resource(context, resource_id):
    """Resolve a resource through the trusted platform catalog."""
    return next((item for item in context.resources
                 if item["resource"] == resource_id), None)


def _validate_target(context, tool, arguments):
    """Enforce service ownership, environment, resource, and query boundaries."""
    violations = []
    if arguments.get("environment") != context.environment:
        violations.append("Tool environment is outside the authorized incident environment.")
    if "service" in arguments and arguments["service"] not in context.readable_services:
        violations.append("Tool service is outside the readable service boundary.")
    if tool == "request_service_restart" and (
            arguments["service"] not in context.proposable_services):
        violations.append("Service restart request is outside the ownership boundary.")
    if "resource" in arguments:
        resource = _resource(context, arguments["resource"])
        if resource is None:
            violations.append("Tool resource is outside the platform resource catalog.")
        elif tool == "propose_infrastructure_change" and (
                resource["service"] not in context.proposable_services):
            violations.append("Infrastructure proposal is outside the ownership boundary.")
    if "window_minutes" in arguments:
        positive_integer(arguments["window_minutes"], "window_minutes")
        if arguments["window_minutes"] > context.limits["max_window_minutes"]:
            violations.append("Tool time window exceeds the platform limit.")
    if tool == "get_logs":
        query = arguments["query"]
        _text(query, "logs query")
        if "*" in query or len(query) > context.limits["max_log_query_chars"]:
            violations.append("Log query is too broad.")
        positive_integer(arguments["limit"], "logs limit")
        if arguments["limit"] > context.limits["max_result_items"]:
            violations.append("Log result limit exceeds the platform limit.")
    return violations[0] if violations else None


def _validate_arguments(tool, arguments):
    """Apply an exact, narrow schema to every purpose-built tool."""
    schemas = {
        "get_service_health": {"service", "environment"},
        "get_dependency_health": {"service", "environment"},
        "get_recent_changes": {"service", "environment", "window_minutes"},
        "get_cloudsql_health": {"resource", "environment"},
        "get_logs": {"service", "environment", "query", "window_minutes", "limit"},
        "propose_infrastructure_change": {
            "resource", "environment", "field", "current_state", "desired_state",
            "evidence_call_ids", "expected_outcome", "incident_id",
        },
        "request_service_restart": {
            "service", "environment", "reason", "incident_id", "evidence_call_ids",
        },
    }
    object_fields(arguments, schemas[tool], f"{tool} arguments")
    for key in ("service", "environment", "resource", "field", "incident_id"):
        if key in arguments:
            identifier(arguments[key], f"arguments.{key}")
    if "expected_outcome" in arguments:
        _text(arguments["expected_outcome"], "expected_outcome")
    if "reason" in arguments:
        _text(arguments["reason"], "reason")
    if "evidence_call_ids" in arguments:
        _identifiers(arguments["evidence_call_ids"], "evidence_call_ids")


def _validate_result(tool, call_id, result, limits):
    """Bind typed tool output to its call and enforce redaction and size limits."""
    object_fields(result, {"call_id", "status", "data", "source", "observed_at",
                           "redaction_applied", "truncated"}, "tool result")
    if result["call_id"] != call_id:
        raise ValidationError("tool result call_id does not match its call")
    if result["status"] not in {"ok", "not_found", "error", "proposed"}:
        raise ValidationError("tool result status is not supported")
    if tool in READ_TOOLS and result["status"] == "proposed":
        raise ValidationError("read tools cannot return proposed status")
    if tool in PROPOSAL_TOOLS and result["status"] != "proposed":
        raise ValidationError("proposal tools must return proposed status")
    if result["source"] != SOURCES[tool]:
        raise ValidationError("tool result source does not match the tool")
    _timestamp(result["observed_at"], "tool result observed_at")
    if not isinstance(result["data"], dict):
        raise ValidationError("tool result data must be an object")
    for key in ("redaction_applied", "truncated"):
        if not isinstance(result[key], bool):
            raise ValidationError(f"tool result {key} must be boolean")
    if tool == "get_logs" and result["redaction_applied"] is not True:
        raise ValidationError("log results must attest secret redaction")
    if len(json.dumps(result["data"], sort_keys=True).encode("utf-8")) > (
            limits["max_result_bytes"]):
        raise ValidationError("tool result exceeds max_result_bytes")
    list_items = sum(len(value) for value in result["data"].values()
                     if isinstance(value, list))
    if list_items > limits["max_result_items"]:
        raise ValidationError("tool result exceeds max_result_items")


def _validate_service_health(data):
    """Validate the service health read model."""
    required = {"service", "cpu_percent", "memory_percent", "http_5xx_rate",
                "p99_latency_ms", "database_latency_ms", "pods_healthy"}
    object_fields(data, required, "service health")
    identifier(data["service"], "service health service")
    number(data["cpu_percent"], "cpu_percent", 0, 100)
    number(data["memory_percent"], "memory_percent", 0, 100)
    number(data["http_5xx_rate"], "http_5xx_rate", 0, 1)
    number(data["p99_latency_ms"], "p99_latency_ms")
    number(data["database_latency_ms"], "database_latency_ms")
    if not isinstance(data["pods_healthy"], bool):
        raise ValidationError("pods_healthy must be boolean")


def _validate_dependency_health(data):
    """Validate dependency health summaries."""
    object_fields(data, {"service", "dependencies"}, "dependency health")
    identifier(data["service"], "dependency service")
    if not isinstance(data["dependencies"], list):
        raise ValidationError("dependencies must be a list")
    for item in data["dependencies"]:
        object_fields(item, {"service", "status", "p99_latency_ms"}, "dependency")
        identifier(item["service"], "dependency service")
        if item["status"] not in {"healthy", "unhealthy", "unknown"}:
            raise ValidationError("dependency status is not supported")
        number(item["p99_latency_ms"], "dependency p99_latency_ms")


def _validate_recent_changes(data):
    """Validate normalized cross-system change records."""
    object_fields(data, {"service", "changes"}, "recent changes")
    identifier(data["service"], "recent changes service")
    if not isinstance(data["changes"], list):
        raise ValidationError("changes must be a list")
    for item in data["changes"]:
        object_fields(item, {"type", "time", "source", "field", "before", "after"},
                      "recent change")
        for key in ("type", "source", "field"):
            identifier(item[key], f"recent change {key}")
        _timestamp(item["time"], "recent change time")


def _validate_cloudsql_health(data):
    """Validate the narrow Cloud SQL health contract."""
    required = {"resource", "cpu_percent", "connections_used", "connections_limit",
                "connection_wait_ms", "query_latency_ms"}
    object_fields(data, required, "cloudsql health")
    identifier(data["resource"], "cloudsql resource")
    number(data["cpu_percent"], "cloudsql cpu_percent", 0, 100)
    for key in ("connections_used", "connections_limit"):
        positive_integer(data[key], f"cloudsql {key}")
    number(data["connection_wait_ms"], "connection_wait_ms")
    number(data["query_latency_ms"], "query_latency_ms")


def _validate_logs(data):
    """Validate redacted, bounded log entries."""
    object_fields(data, {"service", "entries"}, "logs")
    identifier(data["service"], "logs service")
    if not isinstance(data["entries"], list) or not all(
            isinstance(item, str) for item in data["entries"]):
        raise ValidationError("log entries must be strings")


def _validate_proposal_result(data):
    """Require a proposal-only result with no execution claim."""
    object_fields(data, {"proposal_only"}, "proposal result")
    if data["proposal_only"] is not True:
        raise ValidationError("proposal tool cannot report execution")


def _validate_typed_data(tool, data):
    """Dispatch to a narrow read-model contract."""
    validators = {
        "get_service_health": _validate_service_health,
        "get_dependency_health": _validate_dependency_health,
        "get_recent_changes": _validate_recent_changes,
        "get_cloudsql_health": _validate_cloudsql_health,
        "get_logs": _validate_logs,
        "propose_infrastructure_change": _validate_proposal_result,
        "request_service_restart": _validate_proposal_result,
    }
    validators[tool](data)


def _validate_result_target(tool, arguments, data):
    """Prevent a tool result for one target from satisfying a different call."""
    if tool in {"get_service_health", "get_dependency_health", "get_recent_changes",
                "get_logs"} and data["service"] != arguments["service"]:
        raise ValidationError("tool result service does not match the call")
    if tool == "get_cloudsql_health" and data["resource"] != arguments["resource"]:
        raise ValidationError("tool result resource does not match the call")


def _expected_plan_change(context, arguments):
    """Build a trusted normalized plan expectation from the resource catalog."""
    resource = _resource(context, arguments["resource"])
    if arguments["field"] not in resource["allowed_fields"]:
        raise ValidationError("proposal field is not permitted for the resource")
    current = arguments["current_state"]
    desired = arguments["desired_state"]
    for value, name in ((current, "current_state"), (desired, "desired_state")):
        positive_integer(value, name)
    if desired == current or desired > current * 2:
        raise ValidationError("infrastructure proposal must change state by at most 2x")
    return {
        "resource": resource["resource"],
        "environment": context.environment,
        "controller": resource["controller"],
        "path": resource["path"],
        "operation": "update",
        "field": arguments["field"],
        "before": current,
        "after": desired,
    }


def _plan_matches(plan, expected):
    """Compare the complete trusted plan with the one proposed agent change."""
    object_fields(plan, {"changes"}, "plan")
    if not isinstance(plan["changes"], list):
        raise ValidationError("plan.changes must be a list")
    for change in plan["changes"]:
        object_fields(change, expected, "plan change")
    return plan["changes"] == [expected]


def _proposal_evidence_gap(arguments, evidence_data):
    """Bind the proposed rollback value to health and trusted change evidence."""
    current = arguments["current_state"]
    desired = arguments["desired_state"]
    field = arguments["field"]
    resource = arguments["resource"]
    health_matches = any(
        data.get("resource") == resource and data.get("connections_limit") == current
        for data in evidence_data
    )
    change_matches = any(
        any(change["field"] == field and change["before"] == desired
            and change["after"] == current for change in data.get("changes", []))
        for data in evidence_data
    )
    if not health_matches:
        return "Proposal current state is not supported by resource health evidence."
    if not change_matches:
        return "Proposal rollback value is not supported by recent change evidence."
    return None


def _decision(decision, reason, **details):
    """Create a consistent policy result."""
    return AgentRunResult(
        decision,
        [reason],
        details.get("hypothesis"),
        details.get("audit", []),
        details.get("change"),
        details.get("approval"),
    )


def _review_steps(context, steps):
    """Validate and summarize the bounded sequence of tool calls."""
    if not isinstance(steps, list) or not steps:
        raise ValidationError("steps must be a nonempty list")
    if len(steps) > context.limits["max_steps"]:
        return None, _decision("deny", "Agent exceeded max_steps.")
    audit = []
    successful_reads = set()
    result_data = {}
    calls = {}
    proposal = None
    for index, step in enumerate(steps):
        object_fields(step, {"call", "result"}, "agent step")
        call = step["call"]
        object_fields(call, {"id", "tool", "arguments"}, "tool call")
        identifier(call["id"], "tool call id")
        identifier(call["tool"], "tool name")
        if call["id"] in calls:
            raise ValidationError("tool call ids must be unique")
        calls[call["id"]] = call
        if call["tool"] not in TOOLS:
            return None, _decision("deny", "Arbitrary or unsupported tool requested.",
                                   audit=audit)
        if call["tool"] not in context.granted_tools:
            return None, _decision("deny", "Tool is not granted to this principal.",
                                   audit=audit)
        _validate_arguments(call["tool"], call["arguments"])
        if reason := _validate_target(context, call["tool"], call["arguments"]):
            return None, _decision("deny", reason, audit=audit)
        _validate_result(call["tool"], call["id"], step["result"], context.limits)
        _validate_typed_data(call["tool"], step["result"]["data"])
        _validate_result_target(call["tool"], call["arguments"], step["result"]["data"])
        result_data[call["id"]] = step["result"]["data"]
        audit.append({"sequence": index + 1, "call_id": call["id"],
                      "tool": call["tool"], "source": step["result"]["source"],
                      "observed_at": step["result"]["observed_at"]})
        if (call["tool"] in READ_TOOLS and step["result"]["status"] == "ok"
                and not step["result"]["truncated"]):
            successful_reads.add(call["id"])
        if call["tool"] in PROPOSAL_TOOLS:
            if proposal is not None or index != len(steps) - 1:
                return None, _decision(
                    "deny", "A single proposal must be the final step.", audit=audit,
                )
            proposal = call
    state = {"audit": audit, "successful_reads": successful_reads,
             "result_data": result_data, "proposal": proposal}
    return state, None


def _validate_hypothesis(hypothesis, successful_reads):
    """Validate the structured hypothesis and its evidence references."""
    object_fields(hypothesis, {"summary", "confidence", "evidence_call_ids",
                               "recommended_action"}, "hypothesis")
    _text(hypothesis["summary"], "hypothesis.summary")
    number(hypothesis["confidence"], "hypothesis.confidence", 0, 1)
    _identifiers(hypothesis["evidence_call_ids"], "hypothesis evidence")
    allowed_actions = PROPOSAL_TOOLS | {"investigate", "no_change"}
    if hypothesis["recommended_action"] not in allowed_actions:
        raise ValidationError("hypothesis recommended_action is not supported")
    if not set(hypothesis["evidence_call_ids"]).issubset(successful_reads):
        return "Hypothesis cites missing or unsuccessful tool calls."
    return None


def _proposal_binding_problem(context, hypothesis, proposal):
    """Bind the proposal to incident identity, action, and cited evidence."""
    problems = []
    arguments = proposal["arguments"]
    if hypothesis["recommended_action"] != proposal["tool"]:
        problems.append("Proposal does not match the hypothesis action.")
    if arguments["incident_id"] != context.incident_id:
        problems.append("Proposal incident_id does not match context.")
    if arguments["evidence_call_ids"] != hypothesis["evidence_call_ids"]:
        problems.append("Proposal evidence does not match the hypothesis.")
    return problems[0] if problems else None


def _review_infrastructure_proposal(context, state, hypothesis, plan):
    """Bind infrastructure values to evidence and compare the complete plan."""
    arguments = state["proposal"]["arguments"]
    evidence_data = [state["result_data"][call_id]
                     for call_id in hypothesis["evidence_call_ids"]]
    if gap := _proposal_evidence_gap(arguments, evidence_data):
        return _decision("investigate", gap, hypothesis=hypothesis,
                         audit=state["audit"])
    expected = _expected_plan_change(context, arguments)
    if plan is None:
        return _decision("requires_plan", "Provide the complete trusted IaC plan.",
                         hypothesis=hypothesis, audit=state["audit"], change=expected)
    if not _plan_matches(plan, expected):
        return _decision("deny", "Plan contains missing, mismatched, or extra changes.",
                         hypothesis=hypothesis, audit=state["audit"])
    return _decision(
        "requires_human_approval",
        "Agent intent exactly matches the complete plan; senior approval is required.",
        hypothesis=hypothesis, audit=state["audit"], change=expected,
        approval="senior",
    )


def _review_proposal(context, state, hypothesis, plan):
    """Route a bound platform intent without directly executing it."""
    proposal = state["proposal"]
    audit = state["audit"]
    if proposal is None:
        return _decision("investigate", "No platform change was proposed.",
                         hypothesis=hypothesis, audit=audit)
    if problem := _proposal_binding_problem(context, hypothesis, proposal):
        return _decision("deny", problem, hypothesis=hypothesis, audit=audit)
    if len(state["successful_reads"]) < 3 or hypothesis["confidence"] < 0.80:
        return _decision("investigate",
                         "Proposal needs three reads and confidence >= 0.80.",
                         hypothesis=hypothesis, audit=audit)
    arguments = proposal["arguments"]
    if proposal["tool"] == "request_service_restart":
        change = {"action": "request_service_restart", "service": arguments["service"],
                  "environment": context.environment, "incident_id": context.incident_id,
                  "reason": arguments["reason"]}
        return _decision(
            "requires_human_approval",
            "Restart request passed tool policy; operator approval required.",
            hypothesis=hypothesis, audit=audit, change=change,
            approval="operator",
        )
    return _review_infrastructure_proposal(context, state, hypothesis, plan)


def evaluate_agent_run(raw_context, run, plan=None):
    """Review a bounded tool trace, hypothesis, proposal, and optional full plan."""
    context = AgentContext.from_dict(raw_context)
    object_fields(run, {"steps", "hypothesis"}, "agent run")
    state, denial = _review_steps(context, run["steps"])
    if denial:
        return denial
    hypothesis = run["hypothesis"]
    if problem := _validate_hypothesis(hypothesis, state["successful_reads"]):
        return _decision("deny", problem, hypothesis=hypothesis,
                         audit=state["audit"])
    return _review_proposal(context, state, hypothesis, plan)
