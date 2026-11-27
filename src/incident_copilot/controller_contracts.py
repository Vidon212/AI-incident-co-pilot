"""Narrow Kubernetes-shaped contracts for the Session 16 local reconciliation core."""

from .autonomy_contracts import proposal_contract
from .events import timestamp
from .models import ValidationError
from .remediation import identifier, number, object_fields, positive_integer
from .rollout import identifiers


API_VERSION = "reliability.platform.io/v1alpha1"
KINDS = {"Investigation", "RemediationProposal", "RemediationPolicy"}
ROLES = {"controller", "collector", "investigator", "reviewer", "gitops", "verifier"}


def validate_platform(platform):
    """Pin transport roles and authoritative HPA/Git mappings independently of proposals."""
    object_fields(platform, {"namespace", "principals", "targets"}, "controller platform")
    identifier(platform["namespace"], "namespace")
    object_fields(platform["principals"], ROLES, "principals")
    identifiers(list(platform["principals"].values()), "distinct role principals")
    if not isinstance(platform["targets"], dict) or not platform["targets"]:
        raise ValidationError("targets must be a nonempty catalog")
    for uid, target in platform["targets"].items():
        identifier(uid, "target UID")
        object_fields(target, {"name", "namespace", "service", "environment", "repository",
                               "gitPath", "controller"}, "authoritative target")
        for field in ("name", "namespace", "service", "environment"):
            identifier(target[field], field)
        if (target["namespace"] != platform["namespace"] or target["controller"] != "argocd"
                or not isinstance(target["repository"], str) or "/" not in target["repository"]):
            raise ValidationError("target requires scoped Argo CD and repository ownership")
        path = target["gitPath"]
        if (not isinstance(path, str) or path.startswith("/") or "\\" in path
                or any(part in ("", ".", "..") for part in path.split("/"))):
            raise ValidationError("gitPath must be repository-relative")


def validate_resource(resource, platform):
    """User/model status is ignored; immutable spec and API metadata identify controller work."""
    required = {"apiVersion", "kind", "metadata", "spec"}
    if isinstance(resource, dict) and "status" in resource:
        required.add("status")
    object_fields(resource, required, "custom resource")
    identifier(resource["kind"], "resource kind")
    if resource["apiVersion"] != API_VERSION or resource["kind"] not in KINDS:
        raise ValidationError("unsupported reliability API kind/version")
    metadata = resource["metadata"]
    object_fields(metadata, {"name", "namespace", "uid", "generation", "resourceVersion",
                             "creationTimestamp"}, "API metadata")
    for field in ("name", "namespace", "uid", "resourceVersion"):
        identifier(metadata[field], field)
    positive_integer(metadata["generation"], "generation")
    timestamp(metadata["creationTimestamp"])
    if metadata["namespace"] != platform["namespace"]:
        raise ValidationError("custom resource is outside controller namespace")
    spec = resource["spec"]
    if resource["kind"] == "Investigation":
        object_fields(spec, {"service", "environment", "signals", "maxToolCalls", "timeoutSeconds"},
                      "Investigation spec")
        identifier(spec["service"], "service")
        identifier(spec["environment"], "environment")
        identifiers(spec["signals"], "signals")
        if not spec["signals"] or not set(spec["signals"]) <= {"http_5xx", "latency", "cpu"}:
            raise ValidationError("unsupported investigation signals")
        number(spec["maxToolCalls"], "tool budget", 3, 10)
        positive_integer(spec["maxToolCalls"], "tool budget")
        number(spec["timeoutSeconds"], "investigation timeout", 1, 300)
        positive_integer(spec["timeoutSeconds"], "investigation timeout")
    elif resource["kind"] == "RemediationPolicy":
        validate_policy(spec)
    else:
        validate_proposal(spec, platform)


def validate_policy(spec):
    """The reference HPA policy can tighten, but cannot relax, its execution envelope."""
    object_fields(spec, {"action", "environments", "services", "minimumConfidence",
                         "maximumIncrease", "minimumClusterHeadroom",
                         "minimumHistoricalSuccessRate", "maximumAutonomyLevel"}, "policy spec")
    if spec["action"] != "increase_hpa_max":
        raise ValidationError("only the existing HPA catalog profile is supported")
    for field in ("environments", "services"):
        identifiers(spec[field], field)
        if not spec[field]:
            raise ValidationError("policy scope cannot be empty")
    number(spec["minimumConfidence"], "minimum confidence", .90, 1)
    number(spec["maximumIncrease"], "maximum increase", 1, 2)
    number(spec["minimumClusterHeadroom"], "minimum headroom", .30, 1)
    number(spec["minimumHistoricalSuccessRate"], "minimum history rate", .95, 1)
    positive_integer(spec["maximumAutonomyLevel"], "autonomy cap")
    if spec["maximumAutonomyLevel"] > 5:
        raise ValidationError("policy autonomy cap exceeds five")


def validate_proposal(spec, platform):
    """Only typed HPA intent at the verified catalog abstraction reaches the execution model."""
    object_fields(spec, {"investigationRef", "policyRef", "targetUid", "currentMaxReplicas",
                         "proposal", "evidenceIds"}, "proposal spec")
    for key in ("investigationRef", "policyRef"):
        object_fields(spec[key], {"name", "uid"}, key)
        for value in spec[key].values():
            identifier(value, key)
    identifier(spec["targetUid"], "target UID")
    positive_integer(spec["currentMaxReplicas"], "current HPA ceiling")
    proposal_contract(spec["proposal"])
    proposal = spec["proposal"]
    if proposal["action"] != "increase_hpa_max":
        raise ValidationError("no execution adapter exists for this proposal action")
    identifiers(spec["evidenceIds"], "evidence IDs")
    if not spec["evidenceIds"]:
        raise ValidationError("proposal requires investigation evidence")
    target = platform["targets"].get(spec["targetUid"])
    if target is None or any(target[key] != proposal[field] for key, field in (
            ("name", "resource"), ("namespace", "namespace"), ("service", "service"),
            ("environment", "environment"))):
        raise ValidationError("proposal differs from catalog resource identity")
