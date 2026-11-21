"""Strict normalized inputs for the Session 14 capacity screening models."""

import re

from .events import timestamp
from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer
from .rollout import fingerprint, identifiers


PROFILES = {
    "node_pool_cpu": ("allocatable_cpu_cores", {"Cluster", "CloudResource"}, "cpu_cores"),
    "database_connections": ("max_connections", {"Database", "CloudResource"}, "connections"),
    "service_replicas": ("replicas", {"Workload"}, "requests_per_second"),
}
FAILURE_MODES = {"node_pool_cpu": "capacity_exhaustion",
                 "database_connections": "connection_exhaustion", "service_replicas": "overload"}


def boolean(value, name):
    """Do not accept truthy strings as collector attestations."""
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be boolean")


def change_contract(change):
    """A complete supported update is bound to exact repository revisions and graph identity."""
    object_fields(change, {"repository", "base_revision", "head_revision", "environment",
                           "resource_id", "model", "before", "after"}, "impact change")
    if not isinstance(change["repository"], str) or not re.fullmatch(
            r"[\w.-]+/[\w.-]+", change["repository"]):
        raise ValidationError("repository must be owner/name")
    for key in ("base_revision", "head_revision"):
        if not isinstance(change[key], str) or not re.fullmatch(r"[0-9a-f]{40}", change[key]):
            raise ValidationError("revisions must be full lowercase Git SHAs")
    if change["base_revision"] == change["head_revision"]:
        raise ValidationError("base and head must differ")
    for key in ("environment", "resource_id", "model"):
        identifier(change[key], key)
    if change["model"] not in PROFILES:
        raise ValidationError("unsupported impact model")
    field = PROFILES[change["model"]][0]
    for side in ("before", "after"):
        object_fields(change[side], {field}, side)
        if field == "allocatable_cpu_cores":
            number(change[side][field], field, .001, 1e12)
        else:
            positive_integer(change[side][field], field)
            if change[side][field] > 10**12:
                raise ValidationError("capacity exceeds supported model bounds")
    if change["before"] == change["after"]:
        raise ValidationError("change must update supported capacity")


def context_contract(context, change, graph):
    """Collectors, never a model, supply checks, access policy, evidence, and control semantics."""
    object_fields(context, {"change_sha256", "graph_sha256", "query", "checks",
                            "topology_complete", "telemetry", "controller", "transition",
                            "slo_metadata", "similar_incidents", "min_headroom_fraction"},
                  "impact context")
    if (context["change_sha256"] != fingerprint(change)
            or context["graph_sha256"] != fingerprint(graph)):
        raise ValidationError("context is not bound to the exact change and graph")
    query = context["query"]
    if not isinstance(query, dict):
        raise ValidationError("query must be an object")
    if (query.get("root") != change["resource_id"] or query.get("mode") != "impact"
            or query.get("environment") != change["environment"]):
        raise ValidationError("query must screen this change's resource and environment")
    boolean(context["topology_complete"], "topology completeness")
    number(context["min_headroom_fraction"], "minimum headroom", .01, .5)
    object_fields(context["checks"], {"schema", "plan", "organization_policy"}, "checks")
    if any(value not in ("pass", "fail", "unknown") for value in context["checks"].values()):
        raise ValidationError("checks must be pass, fail, or unknown")
    telemetry_contract(context["telemetry"], change)
    controller_contract(context["controller"], change["model"])
    transition_contract(context["transition"])
    if not isinstance(context["slo_metadata"], dict):
        raise ValidationError("SLO metadata must be an object")
    for key, metadata in context["slo_metadata"].items():
        identifier(key, "SLO id")
        object_fields(metadata, {"critical", "target_fraction"}, "SLO metadata")
        boolean(metadata["critical"], "SLO criticality")
        number(metadata["target_fraction"], "SLO target", .9, 1)
    incidents = context["similar_incidents"]
    if not isinstance(incidents, list) or len(incidents) > 100:
        raise ValidationError("similar incidents must be a bounded list")
    seen = set()
    for incident in incidents:
        object_fields(incident, {"incident_id", "failure_mode"}, "incident similarity")
        identifier(incident["incident_id"], "incident id")
        if incident["incident_id"] in seen:
            raise ValidationError("duplicate incident similarity")
        seen.add(incident["incident_id"])
        if incident["failure_mode"] not in (*FAILURE_MODES.values(), "other"):
            raise ValidationError("unsupported historical failure mode")


def telemetry_contract(telemetry, change):
    """Missing evidence is representable; malformed or unrelated evidence is rejected."""
    if telemetry is None:
        return
    object_fields(telemetry, {"id", "resource_id", "observed_at", "window_days",
                              "live_state", "metrics"}, "telemetry")
    identifier(telemetry["id"], "telemetry id")
    if telemetry["resource_id"] != change["resource_id"]:
        raise ValidationError("telemetry belongs to another resource")
    timestamp(telemetry["observed_at"])
    positive_integer(telemetry["window_days"], "history window")
    field = PROFILES[change["model"]][0]
    object_fields(telemetry["live_state"], {field}, "live capacity")
    number(telemetry["live_state"][field], "live capacity", .001, 1e12)
    if field != "allocatable_cpu_cores":
        positive_integer(telemetry["live_state"][field], "live capacity")
    metrics = telemetry["metrics"]
    required = {"current_demand", "peak_demand", "growth_fraction"}
    if change["model"] == "service_replicas":
        required.add("safe_rps_per_pod")
    object_fields(metrics, required, "capacity metrics")
    for key, value in metrics.items():
        number(value, key, .001 if key == "safe_rps_per_pod" else 0,
               1 if key == "growth_fraction" else 1e12)
    if metrics["current_demand"] > metrics["peak_demand"]:
        raise ValidationError("current demand exceeds observed peak")


def controller_contract(controller, model):
    """HPA capacity is conditional on independently verified scaling prerequisites."""
    if controller is None:
        return
    if model != "service_replicas":
        raise ValidationError("controller is only supported for replica changes")
    if not isinstance(controller, dict):
        raise ValidationError("controller must be an object")
    if controller.get("kind") == "static":
        object_fields(controller, {"kind", "observed_at"}, "static controller")
    elif controller.get("kind") == "hpa":
        object_fields(controller, {"kind", "observed_at", "min_replicas", "max_replicas",
                                   "prerequisites"}, "HPA controller")
        for key in ("min_replicas", "max_replicas"):
            positive_integer(controller[key], key)
            if controller[key] > 10**12:
                raise ValidationError("controller replicas exceed supported bounds")
        if controller["min_replicas"] > controller["max_replicas"]:
            raise ValidationError("HPA minimum exceeds maximum")
        object_fields(controller["prerequisites"], {"scaling_signal", "node_cpu", "pod_quota",
                                                   "pod_ips", "database"}, "HPA prerequisites")
        if any(value not in ("pass", "fail", "unknown")
               for value in controller["prerequisites"].values()):
            raise ValidationError("HPA prerequisite statuses must be pass, fail, or unknown")
    else:
        raise ValidationError("unknown controller kind")
    timestamp(controller["observed_at"])


def transition_contract(transition):
    """Treat recovery and canary credits as explicit evidence, separate from capacity policy."""
    object_fields(transition, {"observed_at", "operation", "rollback_plan_id", "canary_plan_id"},
                  "transition")
    timestamp(transition["observed_at"])
    if transition["operation"] not in ("in_place", "rolling_update", "restart", "replacement",
                                       "unknown"):
        raise ValidationError("unsupported transition operation")
    for key in ("rollback_plan_id", "canary_plan_id"):
        if transition[key] is not None:
            identifier(transition[key], key)


def explanation_contract(assessment, report):
    """Bound model explanations to one simulation and each service's own evidence path."""
    if assessment is None:
        return []
    object_fields(assessment, {"simulation_sha256", "explanations"}, "assessment")
    if assessment["simulation_sha256"] != report["simulation_sha256"]:
        raise ValidationError("assessment belongs to another simulation")
    explanations = assessment["explanations"]
    if not isinstance(explanations, list) or len(explanations) > 100:
        raise ValidationError("explanations must be a bounded list")
    paths = {item["service_id"]: item for item in report["failure_propagation"]}
    for explanation in explanations:
        object_fields(explanation, {"service_id", "evidence_ids", "text"}, "model explanation")
        identifier(explanation["service_id"], "explanation service")
        identifiers(explanation["evidence_ids"], "explanation evidence")
        path = paths.get(explanation["service_id"])
        if (path is None or not explanation["evidence_ids"]
                or not set(explanation["evidence_ids"]).issubset(path["evidence_ids"])):
            raise ValidationError("explanation must cite this service's usable evidence")
        if not isinstance(explanation["text"], str) or not 1 <= len(explanation["text"]) <= 2000:
            raise ValidationError("model explanation must be bounded text")
    return explanations
