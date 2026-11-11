"""Review normalized GitOps changes against trusted operational snapshots.

Inputs are complete, externally normalized projections, not raw YAML or Terraform
plans. No model call, repository write, GitHub comment, merge, or apply occurs here.
"""

import re

from .events import timestamp
from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer
from .rollout import digest, fingerprint, identifiers
from .pr_risk_rules import RULES


LEVELS = ("low", "medium", "high", "critical")
SPEC_FIELDS = {
    "HorizontalPodAutoscaler": {"min_replicas", "max_replicas", "cpu_target_percent"},
    "CloudSQLInstance": {"tier", "cpu_cores", "memory_gib"},
    "PostgreSQLInstance": {"storage_gib"},
    "NetworkPolicy": {"ingress_namespace_selector"},
    "Deployment": {"replicas", "cpu_request_cores", "max_surge", "max_unavailable"},
}
METRICS = {
    "HorizontalPodAutoscaler": {"window_days", "peak_replicas", "days_above_proposed_max",
                               "cpu_signal"},
    "CloudSQLInstance": {"memory_p95_gib", "cpu_p95_fraction", "cpu_peak_fraction"},
    "PostgreSQLInstance": {"used_gib", "growth_30d_gib"},
    "NetworkPolicy": {"inventory_complete", "namespaces"},
    "Deployment": {"free_cpu_cores", "largest_free_node_cpu_cores", "node_autoscaler_at_max",
                   "pdb_min_available", "current_replicas", "ready_replicas",
                   "current_pod_cpu_request_cores"},
}
CONTROLLERS = {
    "HorizontalPodAutoscaler": ("argocd",), "CloudSQLInstance": ("terraform",),
    "PostgreSQLInstance": ("crossplane",), "NetworkPolicy": ("argocd",),
    "Deployment": ("argocd",),
}


def _count(value, name):
    """Accept nonnegative integral counters, including zero, but exclude booleans."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError(f"{name} must be a nonnegative integer")


def _boolean(value, name):
    """Flags are collector facts, never string truthiness."""
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be boolean")


def _labels(value):
    """Validate a matchLabels projection; full Kubernetes schema validation is external."""
    if not isinstance(value, dict) or len(value) > 64:
        raise ValidationError("labels must be a bounded string map")
    if any(not isinstance(key, str) or not key or not isinstance(label, str)
           or len(key) > 253 or len(label) > 63 for key, label in value.items()):
        raise ValidationError("labels must contain string keys and values")


def _path(value):
    """Keep catalog ownership paths relative to the reviewed repository."""
    if (not isinstance(value, str) or value.startswith("/") or "\\" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValidationError("path must be repository-relative")


def _spec(kind, spec):
    """Reject unsupported fields rather than silently dropping part of a change."""
    object_fields(spec, SPEC_FIELDS[kind], f"{kind} spec")
    for key, value in spec.items():
        if key == "ingress_namespace_selector":
            _labels(value)
        elif key == "tier":
            identifier(value, "tier")
        elif key in {"max_surge", "max_unavailable"}:
            _count(value, key)
        elif key in {"min_replicas", "max_replicas", "replicas", "cpu_cores"}:
            positive_integer(value, key)
        else:
            number(value, key, 0.001, 100 if key == "cpu_target_percent" else None)
    if kind == "HorizontalPodAutoscaler" and spec["min_replicas"] > spec["max_replicas"]:
        raise ValidationError("HPA minimum exceeds maximum")
    if kind == "Deployment" and (spec["max_surge"] == 0 and spec["max_unavailable"] == 0):
        raise ValidationError("rolling update must allow surge or unavailability")


def _change_set(change_set):
    """Validate revision identity and recompute the resource/field diff from snapshots."""
    object_fields(change_set, {"repository", "base_revision", "head_revision", "environment",
                               "resources"}, "change set")
    repository = change_set["repository"]
    if not isinstance(repository, str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
        raise ValidationError("repository must be owner/name")
    for key in ("base_revision", "head_revision"):
        if (not isinstance(change_set[key], str)
                or not re.fullmatch(r"[0-9a-f]{40}", change_set[key])):
            raise ValidationError("revisions must be full lowercase Git commit SHAs")
    if change_set["base_revision"] == change_set["head_revision"]:
        raise ValidationError("base and head revisions must differ")
    identifier(change_set["environment"], "environment")
    resources = change_set["resources"]
    if not isinstance(resources, list) or not 1 <= len(resources) <= 100:
        raise ValidationError("provide 1 to 100 normalized resource updates")
    changes, seen = [], set()
    for resource in resources:
        object_fields(resource, {"resource_id", "kind", "service", "path", "before", "after"},
                      "resource update")
        for key in ("resource_id", "kind", "service"):
            identifier(resource[key], key)
        if resource["kind"] not in SPEC_FIELDS or resource["resource_id"] in seen:
            raise ValidationError("unsupported or duplicate resource; manual review required")
        seen.add(resource["resource_id"])
        _path(resource["path"])
        for side in ("before", "after"):
            _spec(resource["kind"], resource[side])
        fields = [{"field": field, "before": resource["before"][field],
                   "after": resource["after"][field]}
                  for field in sorted(SPEC_FIELDS[resource["kind"]])
                  if resource["before"][field] != resource["after"][field]]
        changes.append({key: resource[key] for key in ("resource_id", "kind", "service", "path")})
        changes[-1]["fields"] = fields
    return changes


def _metrics(kind, metrics):
    """Require typed telemetry for the supported invariants."""
    object_fields(metrics, METRICS[kind], f"{kind} metrics")
    for key, value in metrics.items():
        if key in {"cpu_signal", "inventory_complete", "node_autoscaler_at_max"}:
            _boolean(value, key)
        elif key in {"window_days", "peak_replicas", "days_above_proposed_max",
                     "pdb_min_available", "current_replicas", "ready_replicas"}:
            _count(value, key)
        elif key == "namespaces":
            _inventory(value)
        else:
            number(value, key, 0, 1 if key.endswith("fraction") else None)
    if kind == "HorizontalPodAutoscaler" and (
            metrics["days_above_proposed_max"] > metrics["window_days"]):
        raise ValidationError("exceedance days exceed observation window")
    if kind == "CloudSQLInstance" and metrics["cpu_p95_fraction"] > metrics["cpu_peak_fraction"]:
        raise ValidationError("CPU p95 exceeds peak")
    if kind == "Deployment" and (
            metrics["largest_free_node_cpu_cores"] > metrics["free_cpu_cores"]):
        raise ValidationError("largest node headroom exceeds aggregate headroom")
    if kind == "Deployment" and metrics["ready_replicas"] > metrics["current_replicas"]:
        raise ValidationError("ready replicas exceed current replicas")


def _inventory(namespaces):
    """Use actual unique namespace labels and workload counts, not model-supplied totals."""
    if not isinstance(namespaces, list) or len(namespaces) > 10000:
        raise ValidationError("namespaces must be a bounded list")
    seen = set()
    for namespace in namespaces:
        object_fields(namespace, {"name", "labels", "workloads"}, "namespace")
        identifier(namespace["name"], "namespace name")
        if namespace["name"] in seen:
            raise ValidationError("namespace inventory contains duplicates")
        seen.add(namespace["name"])
        _labels(namespace["labels"])
        _count(namespace["workloads"], "namespace workloads")


def _context(context, change_set):
    """Validate a trusted catalog and checks bound to the exact candidate projection."""
    object_fields(context, {"repository", "environment", "change_set_sha256", "evaluated_at",
                            "max_evidence_age_seconds", "storage_safety_margin_gib",
                            "checks", "resources"}, "risk context")
    digest(context["change_set_sha256"], "change_set_sha256")
    if context["change_set_sha256"] != fingerprint(change_set):
        raise ValidationError("trusted context is not bound to the complete change set")
    if any(context[key] != change_set[key] for key in ("repository", "environment")):
        raise ValidationError("repository or environment differs from trusted context")
    timestamp(context["evaluated_at"])
    positive_integer(context["max_evidence_age_seconds"], "maximum evidence age")
    if context["max_evidence_age_seconds"] > 3600:
        raise ValidationError("evidence age policy must be at most one hour")
    number(context["storage_safety_margin_gib"], "storage safety margin", 0.001)
    object_fields(context["checks"], {"schema", "plan", "organization_policy"}, "checks")
    if any(status not in ("pass", "fail", "unknown") for status in context["checks"].values()):
        raise ValidationError("checks must be pass, fail, or unknown")
    object_fields(context["resources"], {item["resource_id"] for item in change_set["resources"]},
                  "catalog resources")
    evidence_ids = []
    for resource in change_set["resources"]:
        catalog = context["resources"][resource["resource_id"]]
        _catalog(catalog, resource)
        if catalog["evidence"] is not None:
            evidence = catalog["evidence"]
            object_fields(evidence, {"id", "observed_at", "metrics"}, "evidence")
            identifier(evidence["id"], "evidence id")
            timestamp(evidence["observed_at"])
            _metrics(resource["kind"], evidence["metrics"])
            evidence_ids.append(evidence["id"])
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValidationError("evidence IDs must be unique across resources")


def _catalog(catalog, resource):
    """Pin authoritative controller, ownership, dependency scope, and operational context."""
    object_fields(catalog, {"kind", "service", "path", "controller", "dependent_services",
                            "slo_target", "prior_incidents", "evidence"}, "catalog entry")
    if any(catalog[key] != resource[key] for key in ("kind", "service", "path")):
        raise ValidationError("changed resource differs from authoritative ownership catalog")
    if catalog["controller"] not in CONTROLLERS[resource["kind"]]:
        raise ValidationError("resource controller is not authoritative for supported profile")
    for key in ("dependent_services", "prior_incidents"):
        identifiers(catalog[key], key)
    number(catalog["slo_target"], "SLO target", .9, 1)


def _evidence_problem(resource, evidence, context):
    """Missing, stale, partial, or short-window facts cannot support a clean risk assessment."""
    if evidence is None:
        return "missing_evidence"
    age = (timestamp(context["evaluated_at"]) - timestamp(evidence["observed_at"])).total_seconds()
    if age < 0 or age > context["max_evidence_age_seconds"]:
        return "future_or_stale_evidence"
    metrics = evidence["metrics"]
    if resource["kind"] == "HorizontalPodAutoscaler" and metrics["window_days"] < 30:
        return "insufficient_history"
    if resource["kind"] == "NetworkPolicy" and not metrics["inventory_complete"]:
        return "incomplete_namespace_inventory"
    if resource["kind"] == "Deployment" and (
            metrics["current_replicas"] != resource["before"]["replicas"]
            or metrics["ready_replicas"] != metrics["current_replicas"]
            or metrics["current_pod_cpu_request_cores"] != resource["before"]["cpu_request_cores"]):
        return "deployment_baseline_changed_or_unhealthy"
    return None


def _assessment(assessment, change_set, context, usable_evidence):
    """Keep model prose untrusted and bind its citations to this exact review and resource."""
    if assessment is None:
        return []
    object_fields(assessment, {"change_set_sha256", "context_sha256", "findings"}, "assessment")
    if (assessment["change_set_sha256"] != fingerprint(change_set)
            or assessment["context_sha256"] != fingerprint(context)):
        raise ValidationError("model assessment belongs to another change or context")
    findings = assessment["findings"]
    if not isinstance(findings, list) or len(findings) > 100:
        raise ValidationError("model findings must be a bounded list")
    for finding in findings:
        object_fields(finding, {"resource_id", "severity", "evidence_ids", "explanation",
                                "recommendation"}, "model finding")
        identifier(finding["resource_id"], "assessment resource")
        if finding["severity"] not in LEVELS:
            raise ValidationError("unsupported model severity")
        identifiers(finding["evidence_ids"], "assessment evidence")
        allowed = usable_evidence.get(finding["resource_id"], set())
        if not finding["evidence_ids"] or not set(finding["evidence_ids"]).issubset(allowed):
            raise ValidationError("model finding must cite fresh evidence for its changed resource")
        for key in ("explanation", "recommendation"):
            if not isinstance(finding[key], str) or not 1 <= len(finding[key].strip()) <= 2000:
                raise ValidationError("model prose must be nonempty bounded text")
    return findings


def _review_resources(change_set, context, changes):
    """Evaluate only changed resources with fresh, scoped evidence."""
    findings, missing, usable_evidence = [], [], {}
    for resource, change in zip(change_set["resources"], changes):
        if not change["fields"]:
            continue
        catalog = context["resources"][resource["resource_id"]]
        evidence = catalog["evidence"]
        problem = _evidence_problem(resource, evidence, context)
        if problem:
            missing.append({"resource_id": resource["resource_id"], "reason": problem})
            continue
        usable_evidence[resource["resource_id"]] = {evidence["id"]}
        for finding in RULES[resource["kind"]](resource, evidence["metrics"], context):
            findings.append({**finding, "resource_id": resource["resource_id"],
                             "evidence_ids": [evidence["id"]]})
    return findings, missing, usable_evidence


def review_pr_risk(change_set, context, assessment=None):
    """Produce deterministic findings plus optional model commentary; never authorize merge."""
    changes = _change_set(change_set)
    _context(context, change_set)
    findings, missing, usable_evidence = _review_resources(change_set, context, changes)
    model_findings = _assessment(assessment, change_set, context, usable_evidence)
    changed = any(change["fields"] for change in changes)
    checks = context["checks"]
    if "fail" in checks.values() or any(item["blocks_merge"] for item in findings):
        decision = "block"
    elif missing or "unknown" in checks.values():
        decision = "investigate"
    else:
        decision = "requires_human_review" if changed else "no_change"
    levels = [item["severity"] for item in findings + model_findings]
    risk = max(levels, key=LEVELS.index) if levels else (
        "unknown" if missing or any(status != "pass" for status in checks.values()) else "low")
    result = {**{key: change_set[key] for key in (
                  "repository", "base_revision", "head_revision", "environment")},
              "evaluated_at": context["evaluated_at"],
              "decision": decision, "risk_level": risk, "merge_authorized": False,
              "change_set_sha256": fingerprint(change_set), "context_sha256": fingerprint(context),
              "assessment_sha256": fingerprint(assessment) if assessment is not None else None,
              "changes": changes, "checks": checks, "findings": findings,
              "missing_context": missing, "model_findings": model_findings,
              "model_content_trusted": False,
              "resource_context": {item["resource_id"]: {
                  key: context["resources"][item["resource_id"]][key]
                  for key in ("controller", "dependent_services", "slo_target", "prior_incidents")}
                  for item in changes if item["fields"]}}
    result["review_sha256"] = fingerprint(result)
    return result
