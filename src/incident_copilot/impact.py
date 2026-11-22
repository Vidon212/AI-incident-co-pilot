"""Deterministic capacity, transition, and graph impact screens; never execute changes."""

import math

from .events import timestamp
from .graph import query_graph
from .impact_contracts import (FAILURE_MODES, PROFILES, boolean, change_contract,
                               context_contract, explanation_contract)
from .models import ValidationError
from .remediation import identifier, number, object_fields
from .rollout import fingerprint, identifiers


SCORE_VERSION = "session14-v1"


def _fresh(observed_at, query):
    """Reject future and stale evidence against the independently supplied review clock."""
    age = (timestamp(query["as_of"]) - timestamp(observed_at)).total_seconds()
    return 0 <= age <= query["max_age_seconds"]


def _topology(change, context, graph):
    """Reuse Stage 13 traversal, scopes, provenance, and bounds instead of model topology."""
    packet = query_graph(graph, context["query"])
    query = context["query"]
    if (query["max_age_seconds"] > 3600 or query["min_confidence"] < .8
            or query["min_observations"] < 100):
        raise ValidationError("impact topology requires age <=1h, confidence >=.8, samples >=100")
    nodes = {node["id"]: node for node in packet["nodes"]}
    if nodes[change["resource_id"]]["kind"] not in PROFILES[change["model"]][1]:
        raise ValidationError("graph resource kind does not support this capacity model")
    missing = []
    if not context["topology_complete"] or packet["truncated"]:
        missing.append("incomplete_topology")
    if any(edge["reason"] in ("stale_relationship", "future_observation")
           for edge in packet["excluded_edges"]):
        missing.append("stale_or_future_topology")
    slo_ids = {edge["to"] for edge in packet["edges"] if edge["relationship"] == "HAS_SLO"}
    if not slo_ids.issubset(context["slo_metadata"]):
        missing.append("missing_slo_criticality")
    critical = sorted(key for key in slo_ids
                      if context["slo_metadata"].get(key, {}).get("critical"))
    incident_ids = {edge["from"] for edge in packet["edges"]
                    if edge["relationship"] == "AFFECTED"}
    similar = sorted(item["incident_id"] for item in context["similar_incidents"]
                     if item["incident_id"] in incident_ids
                     and item["failure_mode"] == FAILURE_MODES[change["model"]])
    if any(item["incident_id"] not in incident_ids for item in context["similar_incidents"]):
        missing.append("unverified_historical_link")
    return packet, critical, similar, missing


def _controller_capacity(change, context, projected_peak, per_pod):
    """An HPA ceiling is not guaranteed usable capacity when prerequisites are unknown."""
    controller = context["controller"]
    if controller is None or not _fresh(controller["observed_at"], context["query"]):
        return {"kind": "unknown", "effective_capacity": None, "ceiling_capacity": None,
                "capacity_constraint": None}, ["missing_or_stale_controller"]
    initial = change["after"]["replicas"] * per_pod
    required = max(1, math.ceil(projected_peak / per_pod))
    if controller["kind"] == "static":
        return {"kind": "static", "required_replicas": required,
                "effective_capacity": initial, "ceiling_capacity": initial,
                "capacity_constraint": projected_peak > initial}, []
    ceiling = controller["max_replicas"] * per_pod
    ready = all(status == "pass" for status in controller["prerequisites"].values())
    missing = [] if ready else ["scaling_prerequisites_unverified"]
    if not controller["min_replicas"] <= change["after"]["replicas"] <= controller["max_replicas"]:
        missing.append("desired_replicas_outside_hpa_bounds")
    return {"kind": "hpa", "required_replicas": required,
            "min_replicas": controller["min_replicas"], "max_replicas": controller["max_replicas"],
            "prerequisites": controller["prerequisites"],
            "effective_capacity": ceiling if ready else None, "ceiling_capacity": ceiling,
            "capacity_constraint": True if projected_peak > ceiling else (False if ready else None),
            "scaling_response_guaranteed": False}, missing


def _capacity(change, context):
    """Screen observed and growth-adjusted demand; do not predict scheduling or latency."""
    telemetry = context["telemetry"]
    if telemetry is None:
        return None, ["missing_telemetry"]
    if not _fresh(telemetry["observed_at"], context["query"]):
        return None, ["stale_or_future_telemetry"]
    if telemetry["live_state"] != change["before"]:
        return None, ["live_baseline_differs_from_change"]
    missing = [] if telemetry["window_days"] >= 30 else ["insufficient_demand_history"]
    metrics = telemetry["metrics"]
    projected = metrics["peak_demand"] * (1 + metrics["growth_fraction"])
    per_unit = metrics.get("safe_rps_per_pod", 1)
    before = next(iter(change["before"].values())) * per_unit
    initial = next(iter(change["after"].values())) * per_unit
    controller = {"kind": "fixed_capacity", "effective_capacity": initial,
                  "ceiling_capacity": initial, "capacity_constraint": projected > initial}
    if change["model"] == "service_replicas":
        controller, problems = _controller_capacity(change, context, projected, per_unit)
        missing.extend(problems)
    effective = controller["effective_capacity"]
    capacity = {"unit": PROFILES[change["model"]][2], "evidence_id": telemetry["id"],
                "current_capacity": before, "initial_proposed_capacity": initial,
                "current_demand": metrics["current_demand"],
                "peak_demand": metrics["peak_demand"],
                "growth_fraction": metrics["growth_fraction"], "growth_horizon_days": 30,
                "projected_peak_demand": projected,
                "current_request_headroom_fraction": (
                    before - metrics["current_demand"]) / before,
                "initial_request_headroom_fraction": (
                    initial - metrics["current_demand"]) / initial,
                "initial_peak_deficit": max(0, metrics["peak_demand"] - initial),
                "projected_headroom_fraction": ((effective - projected) / effective
                                                if effective is not None else None),
                "projected_deficit": (max(0, projected - effective)
                                      if effective is not None else None),
                "controller": controller, "capacity_constraint": controller["capacity_constraint"]}
    # Float overflow in intermediate arithmetic must never produce a JSON Infinity artifact.
    for key, value in capacity.items():
        if type(value) in (float, int) and not math.isfinite(value):
            raise ValidationError(f"capacity arithmetic overflow: {key}")
    return capacity, missing


def _transition(context):
    """Score deployment disruption independently of final-state capacity."""
    transition = context["transition"]
    if not _fresh(transition["observed_at"], context["query"]):
        return {"operation": "unknown", "rollback_plan_id": None, "canary_plan_id": None}, [
            "stale_or_future_transition"]
    missing = ["unknown_transition"] if transition["operation"] == "unknown" else []
    if transition["rollback_plan_id"] is None:
        missing.append("unverified_rollback")
    return transition, missing


def _score(capacity, transition, topology_features, context):
    """Versioned example weights are policy features, never calibrated incident probabilities."""
    components = []

    def add(code, points):
        components.append({"code": code, "points": points})

    if capacity is not None:
        if capacity["capacity_constraint"]:
            add("capacity_violation", 40)
        elif (capacity["projected_headroom_fraction"] is not None
              and capacity["projected_headroom_fraction"] < context["min_headroom_fraction"]):
            add("low_projected_headroom", 20)
    if topology_features["critical_slos"]:
        add("critical_slo_affected", 20)
    if topology_features["service_count"] > 10:
        add("more_than_ten_services", 15)
    if topology_features["similar_incidents"]:
        add("linked_similar_incident", 15)
    operation = transition["operation"]
    if operation in ("restart", "replacement", "rolling_update"):
        add(f"transition_{operation}", {"restart": 20, "replacement": 30, "rolling_update": 10}[
            operation])
    if transition["rollback_plan_id"]:
        add("verified_rollback", -5)
    if transition["canary_plan_id"]:
        add("verified_canary", -10)
    return {"version": SCORE_VERSION, "value": min(100, max(0, sum(
        item["points"] for item in components))), "components": components,
            "is_probability": False}


def _propagation(packet, capacity, model):
    """Describe potential first/second-order effects along real paths; never assert causality."""
    nodes = {node["id"]: node for node in packet["nodes"]}
    scenarios = {"node_pool_cpu": "Capacity loss could leave pods Pending and reduce capacity.",
                 "database_connections": "Connection contention could increase dependent latency.",
                 "service_replicas": "Insufficient capacity could increase queues and errors."}
    propagation = []
    for path in packet["paths"]:
        if nodes[path["node_id"]]["kind"] != "Service":
            continue
        order = sum(nodes[step["to"]]["kind"] == "Service" for step in path["steps"])
        evidence = [step["edge_id"] for step in path["steps"]]
        if capacity is not None:
            evidence.append(capacity["evidence_id"])
        propagation.append({"service_id": path["node_id"], "dependency_order": order,
                            "effect_order": "first_order" if order <= 1 else "second_order",
                            "path": path["steps"], "evidence_ids": evidence,
                            "hypothetical": True, "scenario": scenarios[model],
                            "interpretation": "Callers may inherit errors or latency; retries can "
                            "amplify load only if configured. This is not a latency prediction."})
    return propagation


def _decision(capacity, checks, missing):
    """Credits and prose cannot override failed checks or known capacity contradictions."""
    if "fail" in checks.values() or (capacity is not None
                                     and capacity["capacity_constraint"] is True):
        return "block"
    return "investigate" if missing else "requires_human_review"


def _risk_level(score, missing, decision):
    """An incomplete score cannot label uncertain operational evidence low risk."""
    if missing and decision != "block":
        return "unknown"
    return ("critical" if score["value"] >= 75 else "high" if score["value"] >= 50
            else "medium" if score["value"] >= 20 else "low")


def simulate_change(change, context, graph, assessment=None):
    """Return an evidence-bound screen; human approval and controller execution stay external."""
    change_contract(change)
    context_contract(context, change, graph)
    packet, critical, similar, missing = _topology(change, context, graph)
    capacity, problems = _capacity(change, context)
    missing.extend(problems)
    transition, problems = _transition(context)
    missing.extend(problems)
    propagation = _propagation(packet, capacity, change["model"])
    score = _score(capacity, transition, {"critical_slos": critical, "similar_incidents": similar,
                                          "service_count": len(propagation)}, context)
    if "unknown" in context["checks"].values():
        missing.append("unknown_preflight_checks")
    decision = _decision(capacity, context["checks"], missing)
    report = {"repository": change["repository"], "base_revision": change["base_revision"],
              "head_revision": change["head_revision"], "resource_id": change["resource_id"],
              "environment": change["environment"], "model": change["model"],
              "evaluated_at": context["query"]["as_of"], "decision": decision,
              "risk_level": _risk_level(score, missing, decision),
              "change_sha256": fingerprint(change), "context_sha256": fingerprint(context),
              "graph_sha256": fingerprint(graph), "change": change,
              "checks": context["checks"],
              "capacity": capacity, "transition": transition, "score": score,
              "score_complete": not missing, "missing_context": sorted(set(missing)),
              "affected_service_count": len(propagation),
              "critical_slo_ids": critical,
              "slo_context": {node["id"]: context["slo_metadata"][node["id"]]
                              for node in packet["nodes"] if node["kind"] == "SLO"
                              and node["id"] in context["slo_metadata"]},
              "similar_incident_ids": similar, "failure_propagation": propagation,
              "topology": packet, "merge_authorized": False, "mutation_authorized": False,
              "limitations": ["Capacity screen, not a scheduler or performance simulator.",
                              "Potential graph impact is not demonstrated failure propagation.",
                              "HPA ceilings do not guarantee timely scaling or safe rollout.",
                              "Scores are example policy weights, not incident probabilities."]}
    report["simulation_sha256"] = fingerprint(report)
    report["model_explanations"] = explanation_contract(assessment, report)
    report["model_content_trusted"] = False
    report["report_sha256"] = fingerprint(report)
    return report


def compare_outcome(report, outcome):
    """Compare an independently supplied post-change snapshot with the recorded prediction."""
    object_fields(outcome, {"simulation_sha256", "resource_id", "observed_at", "unit",
                            "capacity", "peak_demand", "change_caused_critical_incident",
                            "incident_ids"}, "outcome")
    if (outcome["simulation_sha256"] != report["simulation_sha256"]
            or outcome["resource_id"] != report["resource_id"]):
        raise ValidationError("outcome belongs to another simulation or resource")
    if timestamp(outcome["observed_at"]) <= timestamp(report["evaluated_at"]):
        raise ValidationError("outcome must follow simulation time")
    identifier(outcome["resource_id"], "outcome resource")
    boolean(outcome["change_caused_critical_incident"], "causal outcome attestation")
    identifiers(outcome["incident_ids"], "outcome incidents")
    if outcome["change_caused_critical_incident"] and not outcome["incident_ids"]:
        raise ValidationError("critical outcome requires incident evidence")
    for key in ("capacity", "peak_demand"):
        number(outcome[key], key, .001 if key == "capacity" else 0)
    capacity = report["capacity"]
    if capacity is None or outcome["unit"] != capacity["unit"]:
        raise ValidationError("outcome requires comparable usable simulation capacity and units")
    predicted = capacity["controller"]["effective_capacity"]
    return {"simulation_sha256": report["simulation_sha256"],
            "outcome_sha256": fingerprint(outcome),
            "predicted_capacity_constraint": capacity["capacity_constraint"],
            "observed_capacity_constraint": outcome["peak_demand"] > outcome["capacity"],
            "capacity_error": outcome["capacity"] - predicted if predicted is not None else None,
            "peak_demand_error": outcome["peak_demand"] - capacity["projected_peak_demand"],
            "critical_incident_after_review": report["decision"] == "requires_human_review"
            and outcome["change_caused_critical_incident"],
            "causality_source": "external_collector_attestation", "mutation_authorized": False}
